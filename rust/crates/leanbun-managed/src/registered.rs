use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_evidence::{StrictJson, canonicalize_directory, parse_strict_json, read_provider_pair};
use leanbun_package::{CanonicalSourceUrlV1, PackageKeyV1};
use leanbun_resolver::LeanSourceRequestV1;
use leanbun_store::{LeanStoreLimitsV1, normalized_tar_tree_sha256_v1};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Clone)]
pub(crate) struct RegisteredGitInputV1 {
    pub key: PackageKeyV1,
    pub url: CanonicalSourceUrlV1,
    pub revision: String,
    pub input_revision: Option<String>,
    pub subdir: Option<String>,
    pub inherited: bool,
    pub config_file: String,
    pub manifest_file: Option<String>,
    pub directory: PathBuf,
    pub download_sha256: Sha256,
    pub tree_sha256: Sha256,
    pub config_sha256: Sha256,
    pub manifest_sha256: Option<Sha256>,
    pub selected_source_identity: Sha256,
    pub dependencies: Vec<PackageKeyV1>,
}

impl RegisteredGitInputV1 {
    pub(crate) fn request(&self) -> Result<LeanSourceRequestV1, String> {
        LeanSourceRequestV1::git(
            self.url.clone(),
            self.input_revision.clone(),
            self.subdir.clone(),
        )
        .map_err(|error| error.to_string())
    }
}

pub(crate) fn load_registered_git_closure(
    development: &Path,
    project_manifest: &Path,
) -> Result<Vec<RegisteredGitInputV1>, String> {
    let development_root =
        canonicalize_directory(development).map_err(|error| error.to_string())?;
    let pair = read_provider_pair(
        &development_root,
        "lean/registry/manifest.json",
        "lean/overrides/package-overrides.json",
        "lean/package-set/packages",
    )
    .map_err(|error| error.to_string())?;
    let provider = pair
        .packages
        .iter()
        .map(|package| {
            (
                package.name.as_str(),
                (package.revision.as_str(), package.directory.as_path()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let text = fs::read_to_string(project_manifest)
        .map_err(|error| format!("cannot read managed Git manifest: {error}"))?;
    let json = parse_strict_json(&text).map_err(|error| error.to_string())?;
    let root = object(&json, "managed Git manifest")?;
    let packages = array(root.get("packages"), "managed Git packages")?;
    if packages.is_empty() || packages.len() > 4_096 {
        return Err("managed Git closure package count is invalid".to_owned());
    }
    let mut names = BTreeSet::new();
    let limits = LeanStoreLimitsV1::registered_provider();
    let mut output = Vec::with_capacity(packages.len());
    for value in packages {
        let item = object(value, "managed Git package")?;
        if string(item, "type")? != "git" {
            return Err("registered managed closure contains a non-Git package".to_owned());
        }
        let name = string(item, "name")?;
        if !names.insert(name) {
            return Err(format!(
                "registered managed closure repeats package: {name}"
            ));
        }
        let scope = string_allow_empty(item, "scope")?;
        let revision = string(item, "rev")?;
        let (provider_revision, directory) = provider
            .get(name)
            .ok_or_else(|| format!("managed Git package is not registered: {name}"))?;
        if revision != *provider_revision {
            return Err(format!(
                "managed Git revision differs from provider: {name}"
            ));
        }
        let key = PackageKeyV1::new(scope, name).map_err(|error| error.to_string())?;
        let url =
            CanonicalSourceUrlV1::parse(string(item, "url")?).map_err(|error| error.to_string())?;
        let subdir = nullable_string(item, "subDir")?;
        let input_revision = nullable_string(item, "inputRev")?;
        let config_file = string(item, "configFile")?.to_owned();
        let manifest_file = nullable_string(item, "manifestFile")?;
        let inherited = boolean(item, "inherited")?;
        let directory = directory.to_path_buf();
        let (download_sha256, tree_sha256) =
            git_archive_digests(&directory, revision, subdir.as_deref(), limits)?;
        let config_sha256 = file_sha256(&directory.join(&config_file), 16 * 1024 * 1024)?;
        let manifest_sha256 = manifest_file
            .as_ref()
            .map(|name| file_sha256(&directory.join(name), 16 * 1024 * 1024))
            .transpose()?;
        let mut identity = Sha256Hasher::new();
        identity.update(b"leanbun-registered-git-source-v1\0");
        hash_text(&mut identity, url.as_str());
        hash_text(&mut identity, revision);
        identity.update(tree_sha256.as_bytes());
        output.push(RegisteredGitInputV1 {
            key,
            url,
            revision: revision.to_owned(),
            input_revision,
            subdir,
            inherited,
            config_file,
            manifest_file,
            directory,
            download_sha256,
            tree_sha256,
            config_sha256,
            manifest_sha256,
            selected_source_identity: identity.finalize(),
            dependencies: Vec::new(),
        });
    }
    if names != provider.keys().copied().collect() {
        return Err(
            "managed Git manifest does not equal the registered provider closure".to_owned(),
        );
    }
    let package_keys = output
        .iter()
        .map(|input| (input.key.name().to_owned(), input.key.clone()))
        .collect::<BTreeMap<_, _>>();
    for input in &mut output {
        let Some(manifest_file) = input.manifest_file.as_deref() else {
            continue;
        };
        input.dependencies =
            registered_manifest_dependencies(&input.directory.join(manifest_file), &package_keys)?;
    }
    Ok(output)
}

fn registered_manifest_dependencies(
    manifest: &Path,
    package_keys: &BTreeMap<String, PackageKeyV1>,
) -> Result<Vec<PackageKeyV1>, String> {
    let text = fs::read_to_string(manifest)
        .map_err(|error| format!("cannot read registered package manifest: {error}"))?;
    let json = parse_strict_json(&text).map_err(|error| error.to_string())?;
    let root = object(&json, "registered package manifest")?;
    let packages = array(root.get("packages"), "registered package dependencies")?;
    let mut dependencies = BTreeSet::new();
    for value in packages {
        let item = object(value, "registered package dependency")?;
        let name = string(item, "name")?;
        let key = package_keys
            .get(name)
            .ok_or_else(|| format!("registered package dependency is outside provider: {name}"))?;
        if !dependencies.insert(key.clone()) {
            return Err(format!(
                "registered package manifest repeats dependency: {name}"
            ));
        }
    }
    Ok(dependencies.into_iter().collect())
}

fn git_archive_digests(
    repository: &Path,
    revision: &str,
    subdir: Option<&str>,
    limits: LeanStoreLimitsV1,
) -> Result<(Sha256, Sha256), String> {
    let treeish = subdir.map_or_else(
        || revision.to_owned(),
        |subdir| format!("{revision}:{subdir}"),
    );
    let output = Command::new("/usr/bin/git")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("COPYFILE_DISABLE", "1")
        .arg("--no-optional-locks")
        .args(["-c", "core.hooksPath=/dev/null", "-C"])
        .arg(repository)
        .args(["archive", "--format=tar"])
        .arg(treeish)
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("cannot archive registered Git package: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "registered Git archive failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let mut download = Sha256Hasher::new();
    download.update(&output.stdout);
    let tree =
        normalized_tar_tree_sha256_v1(&output.stdout, limits).map_err(|error| error.to_string())?;
    Ok((download.finalize(), tree))
}

fn file_sha256(path: &Path, maximum: u64) -> Result<Sha256, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect registered package input: {error}"))?;
    if !metadata.file_type().is_file() || metadata.len() > maximum {
        return Err(format!(
            "registered package input is not a bounded regular file: {}",
            path.display()
        ));
    }
    let mut hasher = Sha256Hasher::new();
    hasher.update(
        &fs::read(path)
            .map_err(|error| format!("cannot read registered package input: {error}"))?,
    );
    Ok(hasher.finalize())
}

fn object<'a>(
    value: &'a StrictJson,
    label: &str,
) -> Result<&'a BTreeMap<String, StrictJson>, String> {
    match value {
        StrictJson::Object(value) => Ok(value),
        _ => Err(format!("{label} is not an object")),
    }
}

fn array<'a>(value: Option<&'a StrictJson>, label: &str) -> Result<&'a [StrictJson], String> {
    match value {
        Some(StrictJson::Array(value)) => Ok(value),
        _ => Err(format!("{label} is not an array")),
    }
}

fn string<'a>(value: &'a BTreeMap<String, StrictJson>, field: &str) -> Result<&'a str, String> {
    match value.get(field) {
        Some(StrictJson::String(value)) if !value.is_empty() && value.len() <= 4_096 => Ok(value),
        _ => Err(format!("managed Git field is invalid: {field}")),
    }
}

fn string_allow_empty<'a>(
    value: &'a BTreeMap<String, StrictJson>,
    field: &str,
) -> Result<&'a str, String> {
    match value.get(field) {
        Some(StrictJson::String(value)) if value.len() <= 4_096 => Ok(value),
        _ => Err(format!("managed Git field is invalid: {field}")),
    }
}

fn nullable_string(
    value: &BTreeMap<String, StrictJson>,
    field: &str,
) -> Result<Option<String>, String> {
    match value.get(field) {
        Some(StrictJson::Null) | None => Ok(None),
        Some(StrictJson::String(value)) if !value.is_empty() && value.len() <= 4_096 => {
            Ok(Some(value.clone()))
        }
        _ => Err(format!("managed Git nullable field is invalid: {field}")),
    }
}

fn boolean(value: &BTreeMap<String, StrictJson>, field: &str) -> Result<bool, String> {
    match value.get(field) {
        Some(StrictJson::Bool(value)) => Ok(*value),
        _ => Err(format!("managed Git boolean field is invalid: {field}")),
    }
}

fn hash_text(hasher: &mut Sha256Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}
