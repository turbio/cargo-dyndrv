use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::{Component, Path, PathBuf},
    str::FromStr,
    sync::{Arc, LazyLock, OnceLock},
};

use color_eyre::eyre::{self, Context};
use harmonia_store_content_address::ContentAddressMethodAlgorithm;
use harmonia_store_derivation::{
    derivation::{Derivation, DerivationOutput, StructuredAttrs},
    derived_path::{OutputName, SingleDerivedPath},
    placeholder::Placeholder,
};
use harmonia_store_path::{StoreDir, StorePath, StorePathName};
use harmonia_store_remote::DaemonStore;
use harmonia_utils_hash::Algorithm::SHA256;
use tokio::sync::Mutex;

use crate::{
    tools::{Tool, Tools},
    util::{CloneBytes, IntoBytes},
};

// TODO: won't work on all platforms, perhaps could be truly static
pub static PLATFORM: LazyLock<bytes::Bytes> =
    LazyLock::new(|| format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS).into());

pub static OUTPUT_OUT: LazyLock<OutputName> = LazyLock::new(OutputName::default);
pub static OUTPUT_FLAGS: LazyLock<OutputName> =
    LazyLock::new(|| OutputName::from_str("flags").unwrap());

/// First argument that turns the binary into the builder of a `<name>-crates` derivation.
pub const LINK_OUTPUTS_ARG: &str = "dyndrv-link-outputs";

pub static OUTPUT_CRATES_DRV: LazyLock<OutputName> =
    LazyLock::new(|| OutputName::from_str("crates.drv").unwrap());

/// The output names the enclosing derivation declares. Nix exports them as `$outputs`; the
/// per-output path variables are not usable here, since in structured-attrs mode names like
/// `crates.drv` are not valid shell identifiers and never reach the builder.
pub fn declared_outputs() -> std::collections::HashSet<String> {
    std::env::var("outputs")
        .map(|s| s.split_whitespace().map(String::from).collect())
        .unwrap_or_default()
}

pub fn is_in_derivation() -> bool {
    static VALUE: OnceLock<bool> = OnceLock::new();
    *VALUE.get_or_init(|| std::env::var_os("CARGO_DYNDRV_IN_DRV").is_some())
}

pub fn daemon_path() -> PathBuf {
    if let Ok(from_env) = std::env::var("NIX_REMOTE") {
        from_env
            .strip_prefix("unix://")
            .map(ToString::to_string)
            .unwrap_or(from_env)
            .into()
    } else {
        "/nix/var/nix/daemon-socket/socket".into()
    }
}

pub async fn add_to_store_nar<T: DaemonStore>(
    store: &mut T,
    real_path: PathBuf,
    name: &str,
) -> eyre::Result<StorePath> {
    static CACHE_MUTEX: Mutex<Option<HashMap<PathBuf, StorePath>>> = Mutex::const_new(None);
    let mut guard = CACHE_MUTEX.lock().await;
    let cache = guard.get_or_insert_default();

    if let Some(store_path) = cache.get(&real_path) {
        Ok(store_path.clone())
    } else {
        // TODO: Don't put the entire nar in memory
        let mut encoder = nix_nar::Encoder::new(&real_path)?;
        let mut buf = Vec::new();
        std::io::copy(&mut encoder, &mut buf)?;
        let store_path = store
            .add_ca_to_store(
                name,
                ContentAddressMethodAlgorithm::NixArchive(SHA256),
                &Default::default(),
                false,
                buf.as_slice(),
            )
            .await?
            .path;
        cache.insert(real_path, store_path.clone());
        Ok(store_path)
    }
}

/// Adds a package's source to the store, along with any `include` paths from its extern
/// configuration. Those are relative to the package root and may reach outside it
/// (`../../openapi.json`), so the source is staged as the smallest tree containing all of
/// them. Returns the store path and the package root's location inside it.
pub async fn add_package_source<T: DaemonStore>(
    store: &mut T,
    store_dir: &StoreDir,
    crate_root: &Path,
    include: &[String],
    name: &str,
) -> eyre::Result<(StorePath, PathBuf)> {
    if include.is_empty() {
        let src_path = add_to_store_nar(store, crate_root.to_path_buf(), name).await?;
        let manifest_dir = src_path.to_absolute_path(store_dir);
        return Ok((src_path, manifest_dir));
    }

    let mut depth = 0;
    for item in include {
        let mut components = Path::new(item).components().peekable();
        let mut item_depth = 0;
        while components.next_if_eq(&Component::ParentDir).is_some() {
            item_depth += 1;
        }
        if !components.all(|component| matches!(component, Component::Normal(_))) {
            eyre::bail!(
                "include path {item:?} for {} must be relative, with `..` only at the start",
                crate_root.display()
            );
        }
        depth = depth.max(item_depth);
    }

    let base = crate_root.ancestors().nth(depth).ok_or_else(|| {
        eyre::eyre!(
            "include paths climb above the filesystem root from {}",
            crate_root.display()
        )
    })?;
    let package_relative = crate_root.strip_prefix(base)?;

    let staging =
        std::env::temp_dir().join(format!("cargo-dyndrv-{}-{}", std::process::id(), name));
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    copy_tree(crate_root, &staging.join(package_relative))?;
    for item in include {
        let source = crate_root.join(item);
        let base_relative =
            package_relative
                .join(item)
                .components()
                .fold(PathBuf::new(), |mut path, component| {
                    match component {
                        Component::ParentDir => {
                            path.pop();
                        }
                        other => path.push(other),
                    }
                    path
                });
        let destination = staging.join(base_relative);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        copy_tree(&source, &destination)
            .wrap_err_with(|| format!("could not include {}", source.display()))?;
    }

    let src_path = add_to_store_nar(store, staging.clone(), name).await?;
    std::fs::remove_dir_all(&staging)?;
    let manifest_dir = src_path.to_absolute_path(store_dir).join(package_relative);
    Ok((src_path, manifest_dir))
}

fn copy_tree(source: &Path, destination: &Path) -> eyre::Result<()> {
    let file_type = std::fs::symlink_metadata(source)
        .wrap_err_with(|| format!("could not read {}", source.display()))?
        .file_type();
    if file_type.is_symlink() {
        std::os::unix::fs::symlink(std::fs::read_link(source)?, destination)?;
    } else if file_type.is_dir() {
        std::fs::create_dir_all(destination)?;
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            copy_tree(&entry.path(), &destination.join(entry.file_name()))?;
        }
    } else {
        std::fs::copy(source, destination)?;
    }
    Ok(())
}

pub async fn add_drv_to_store<T: DaemonStore>(
    store: &mut T,
    store_dir: &StoreDir,
    drv: Derivation,
    drv_name: &str,
) -> eyre::Result<StorePath> {
    let refs = drv.inputs.iter().map(|p| p.root_path().clone()).collect();
    let buf = harmonia_store_aterm::print_derivation_aterm(store_dir, &drv.into_full());
    Ok(store
        .add_ca_to_store(
            &format!("{}.drv", drv_name),
            ContentAddressMethodAlgorithm::Text,
            &refs,
            false,
            buf.as_slice(),
        )
        .await?
        .path)
}

pub async fn submit_wrapper<T: DaemonStore>(
    store: &mut T,
    store_dir: &StoreDir,
    ln: &Tool,
    unit_name: &str,
    base_drv: &StorePath,
) -> eyre::Result<()> {
    // We're only allowed to submit if the name is correct.
    // The easiest way to do this without breaking the inner loop is a symlink
    // If we're running in nixpkgs, we'll get a $name environment variable with the
    // derivation name. outputs should be named "$name-$output_name.drv"
    let base_name = std::env::var("name")
        .wrap_err("could not read derivation name, is this in nixpkgs stdenv?")?;

    let output_name = format!("{}.drv", unit_name);
    let drv_name = format!("{}-{}", base_name, unit_name);

    let wrapper_drv = Derivation {
        name: StorePathName::from_str(&drv_name)?,
        outputs: BTreeMap::from([(
            OUTPUT_OUT.clone(),
            DerivationOutput::CAFloating(ContentAddressMethodAlgorithm::NixArchive(SHA256)),
        )]),
        inputs: BTreeSet::from([
            SingleDerivedPath::Built {
                drv_path: Arc::new(SingleDerivedPath::Opaque(base_drv.clone())),
                output: OUTPUT_OUT.clone(),
            },
            SingleDerivedPath::Opaque(ln.store_path.clone()),
        ]),
        platform: PLATFORM.clone(),
        builder: ln.real_path.clone_bytes(),
        args: Vec::from([
            "-s".into(),
            Placeholder::ca_output(base_drv, &OUTPUT_OUT)
                .render()
                .into_bytes(),
            Placeholder::standard_output(&OUTPUT_OUT)
                .render()
                .into_bytes(),
        ]),

        env: BTreeMap::new(),
        structured_attrs: None,
    };

    let wrapper_drv_path = add_drv_to_store(store, store_dir, wrapper_drv, &drv_name).await?;

    store
        .submit_output(
            &SingleDerivedPath::Opaque(wrapper_drv_path),
            &OutputName::from_str(&output_name)?,
        )
        .await?;

    Ok(())
}

/// Fill the enclosing derivation's `crates.drv` output with one derivation, D, whose outputs are
/// the given crates' own derivations: output `<crate>-<version>.drv` of D is a copy of that unit's
/// `.drv`, so `builtins.outputOf (builtins.outputOf <base>."crates.drv" "<crate>-<version>.drv") "out"`
/// is the crate's build. D depends on the unit derivations as files only, never on their builds:
/// asking for one crate builds that crate and its dependencies, nothing else of the lock file. The
/// unit list travels in structured attrs (a file) and the builder is this binary in
/// `LINK_OUTPUTS_ARG` mode, so the number of crates is not bounded by the builder's environment
/// the way one output per crate on the enclosing derivation would be.
pub async fn submit_crates<T: DaemonStore>(
    store: &mut T,
    store_dir: &StoreDir,
    crates: &BTreeMap<String, StorePath>,
) -> eyre::Result<()> {
    let base_name = std::env::var("name")
        .wrap_err("could not read derivation name, is this in nixpkgs stdenv?")?;
    let drv_name = format!("{}-crates", base_name);
    let me = Tool::current_exe(store_dir)?;

    let mut outputs = BTreeMap::new();
    let mut inputs = BTreeSet::from([SingleDerivedPath::Opaque(me.store_path.clone())]);
    let mut units = serde_json::Map::new();
    for (name, drv_path) in crates {
        let output_name = format!("{}.drv", name);
        outputs.insert(
            OutputName::from_str(&output_name)?,
            DerivationOutput::CAFloating(ContentAddressMethodAlgorithm::Text),
        );
        inputs.insert(SingleDerivedPath::Opaque(drv_path.clone()));
        units.insert(
            output_name,
            serde_json::Value::String(store_dir.display(drv_path).to_string()),
        );
    }

    let drv = Derivation {
        name: StorePathName::from_str(&drv_name)?,
        outputs,
        inputs,
        platform: PLATFORM.clone(),
        builder: me.real_path.clone_bytes(),
        args: Vec::from([LINK_OUTPUTS_ARG.into()]),
        env: BTreeMap::new(),
        structured_attrs: Some(StructuredAttrs {
            attrs: serde_json::Map::from_iter([(
                "units".to_string(),
                serde_json::Value::Object(units),
            )]),
        }),
    };

    let drv_path = add_drv_to_store(store, store_dir, drv, &drv_name).await?;
    store
        .submit_output(&SingleDerivedPath::Opaque(drv_path), &OUTPUT_CRATES_DRV)
        .await?;
    Ok(())
}

pub async fn target_env_drv<T: DaemonStore>(
    store: &mut T,
    store_dir: &StoreDir,
    tools: &Tools,
    target: &Option<String>,
) -> eyre::Result<StorePath> {
    static CACHE_MUTEX: Mutex<Option<HashMap<Option<String>, StorePath>>> = Mutex::const_new(None);
    let mut guard = CACHE_MUTEX.lock().await;
    let cache = guard.get_or_insert_default();
    if let Some(cached) = cache.get(target) {
        return Ok(cached.clone());
    }

    let name = StorePathName::from_str(&format!(
        "cargo-cfg-{}",
        target.as_deref().unwrap_or("host")
    ))?;
    let drv = Derivation {
        name: name.clone(),
        outputs: BTreeMap::from([(
            OUTPUT_OUT.clone(),
            DerivationOutput::CAFloating(ContentAddressMethodAlgorithm::Flat(SHA256)),
        )]),
        inputs: BTreeSet::from([
            SingleDerivedPath::Opaque(tools.rustc.store_path.clone()),
            SingleDerivedPath::Opaque(tools.target_env.store_path.clone()),
        ]),
        platform: PLATFORM.clone(),
        builder: tools.target_env.real_path.clone_bytes(),
        args: Vec::from([
            tools.rustc.real_path.clone_bytes(),
            target.clone().unwrap_or_default().into(),
            Placeholder::standard_output(&OUTPUT_OUT)
                .render()
                .clone_bytes(),
        ]),
        env: BTreeMap::new(),
        structured_attrs: None,
    };

    add_drv_to_store(store, store_dir, drv, &name).await
}
