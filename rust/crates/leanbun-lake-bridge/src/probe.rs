use crate::{
    LakeBridgeError, LakeBridgeErrorKind, LakeRootDeclarationV1, parse_root_declaration_probe_v1,
};
use leanbun_core::{Sha256, Sha256Hasher};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const MAX_PROBE_OUTPUT_BYTES: usize = 256 * 1_024;
const LAKE_SOURCE_HASHES: &[(&str, &str)] = &[
    (
        "Lake/Load/Manifest.lean",
        "8b01bdff19b7e4cba470755f8d308a9d77d7402486c409e8105e26fee524a43e",
    ),
    (
        "Lake/Load/Resolve.lean",
        "b1cce0ebebbcd620906750760a1c6b5ff50b26e18caba946888f48b391390516",
    ),
    (
        "Lake/Load/Workspace.lean",
        "dd23a173478243833d443dae8ffd28695f9a9b0ca00dd03ee88d039d1f6dd129",
    ),
    (
        "Lake/CLI/Main.lean",
        "4b95ab56b87319c0a1e2b55d0d31e3c077977a376020c326579d0802b9399010",
    ),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeRootProbeRequestV1 {
    pub source_fixture_root: PathBuf,
    pub source_project: PathBuf,
    pub development_root: PathBuf,
    pub staging_directory: PathBuf,
    pub lean_executable: PathBuf,
    pub elan_home: PathBuf,
    pub sandbox_executable: PathBuf,
    pub sandbox_profile: PathBuf,
    pub probe_source: PathBuf,
    pub lake_source_root: PathBuf,
}

pub fn run_lake_root_probe_v1(
    request: &LakeRootProbeRequestV1,
) -> Result<LakeRootDeclarationV1, LakeBridgeError> {
    let source_root = canonical_directory(&request.source_fixture_root, "source fixture root")?;
    let source_project = canonical_directory(&request.source_project, "source project")?;
    require_contained(&source_root, &source_project, "source project")?;
    let development_root = canonical_directory(&request.development_root, "development root")?;
    let staging_parent = request
        .staging_directory
        .parent()
        .ok_or_else(|| boundary("staging directory has no parent"))?;
    let staging_parent = canonical_directory(staging_parent, "staging parent")?;
    require_contained(&development_root, &staging_parent, "staging parent")?;
    if request.staging_directory.exists() {
        return Err(boundary(
            "staging directory must not exist before the probe",
        ));
    }
    let lean = canonical_file(&request.lean_executable, "Lean executable")?;
    require_contained(&development_root, &lean, "Lean executable")?;
    let elan_home = canonical_directory(&request.elan_home, "Elan home")?;
    require_contained(&development_root, &elan_home, "Elan home")?;
    let sandbox = canonical_file(&request.sandbox_executable, "sandbox executable")?;
    let profile = canonical_file(&request.sandbox_profile, "sandbox profile")?;
    let probe = canonical_file(&request.probe_source, "probe source")?;
    let lake_source_root = canonical_directory(&request.lake_source_root, "Lake source root")?;
    verify_lake_source_compatibility_v1(&lake_source_root)?;

    let config_name = select_config(&source_project)?;
    let source_config = source_project.join(config_name);
    let config_before = hash_file(&source_config, 4 * 1_024 * 1_024)?;
    let toolchain = source_project.join("lean-toolchain");
    let toolchain_before = hash_file(&toolchain, 4_096)?;

    fs::create_dir(&request.staging_directory)
        .map_err(|error| probe_failed(format!("cannot create staging directory: {error}")))?;
    fs::copy(&source_config, request.staging_directory.join(config_name))
        .map_err(|error| probe_failed(format!("cannot stage Lake config: {error}")))?;
    fs::copy(&toolchain, request.staging_directory.join("lean-toolchain"))
        .map_err(|error| probe_failed(format!("cannot stage lean-toolchain: {error}")))?;
    let staged_probe_source = request.staging_directory.join("M32RootDeclarations.lean");
    fs::copy(&probe, &staged_probe_source)
        .map_err(|error| probe_failed(format!("cannot stage root probe source: {error}")))?;

    let lean_parent = lean
        .parent()
        .ok_or_else(|| boundary("Lean executable has no parent"))?;
    let lean_sysroot = lean_parent
        .parent()
        .ok_or_else(|| boundary("Lean executable has no sysroot"))?;
    let leanc = canonical_file(&lean_parent.join("leanc"), "Lean C compiler driver")?;
    require_contained(&development_root, &leanc, "Lean C compiler driver")?;
    let path = format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", lean_parent.display());
    let generated_c = request.staging_directory.join("m32-root-probe.c");
    let generated_probe = request.staging_directory.join("m32-root-probe");
    let lean_library_path = lean_sysroot.join("lib/lean");
    let sandbox_repository = profile
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| boundary("sandbox profile has no repository parent"))?;
    let compile = Command::new(&sandbox)
        .arg("-D")
        .arg(format!(
            "LEANBUN_REPOSITORY={}",
            sandbox_repository.display()
        ))
        .arg("-f")
        .arg(&profile)
        .arg(&lean)
        .arg("-c")
        .arg(&generated_c)
        .arg(&staged_probe_source)
        .current_dir(&request.staging_directory)
        .env_clear()
        .env("PATH", &path)
        .env("ELAN_HOME", &elan_home)
        .env("TMPDIR", &request.staging_directory)
        .env("HOME", &request.staging_directory)
        .env("LEAN_SYSROOT", lean_sysroot)
        .env("DYLD_LIBRARY_PATH", &lean_library_path)
        .env("LC_ALL", "C.UTF-8")
        .env("LANG", "C.UTF-8")
        .output()
        .map_err(|error| probe_failed(format!("cannot compile root probe Lean source: {error}")))?;
    require_success("Lean probe compilation", &compile)?;
    let link = Command::new(&sandbox)
        .arg("-D")
        .arg(format!(
            "LEANBUN_REPOSITORY={}",
            sandbox_repository.display()
        ))
        .arg("-f")
        .arg(&profile)
        .arg(&leanc)
        .arg("-o")
        .arg(&generated_probe)
        .arg(&generated_c)
        .arg(format!("-Wl,-rpath,{}", lean_library_path.display()))
        .current_dir(&request.staging_directory)
        .env_clear()
        .env("PATH", &path)
        .env("TMPDIR", &request.staging_directory)
        .env("HOME", &request.staging_directory)
        .env("LEAN_SYSROOT", lean_sysroot)
        .env("DYLD_LIBRARY_PATH", &lean_library_path)
        .env("LC_ALL", "C.UTF-8")
        .env("LANG", "C.UTF-8")
        .output()
        .map_err(|error| probe_failed(format!("cannot link native root probe: {error}")))?;
    require_success("native probe link", &link)?;
    let output = Command::new(&sandbox)
        .arg("-D")
        .arg(format!(
            "LEANBUN_REPOSITORY={}",
            sandbox_repository.display()
        ))
        .arg("-f")
        .arg(&profile)
        .arg(&generated_probe)
        .arg(&request.staging_directory)
        .arg(config_name)
        .current_dir(&request.staging_directory)
        .env_clear()
        .env("PATH", path)
        .env("ELAN_HOME", &elan_home)
        .env("LEAN_SYSROOT", lean_sysroot)
        .env("DYLD_LIBRARY_PATH", &lean_library_path)
        .env("LAKE_NO_CACHE", "1")
        .env("LAKE_ARTIFACT_CACHE", "0")
        .env("TMPDIR", &request.staging_directory)
        .env("HOME", &request.staging_directory)
        .env("DO_NOT_TRACK", "1")
        .env("LC_ALL", "C.UTF-8")
        .env("LANG", "C.UTF-8")
        .output()
        .map_err(|error| probe_failed(format!("cannot execute exact Lean root probe: {error}")))?;
    if output.stdout.len() > MAX_PROBE_OUTPUT_BYTES || output.stderr.len() > MAX_PROBE_OUTPUT_BYTES
    {
        return Err(probe_failed("root probe output exceeds byte limit"));
    }
    if !output.status.success() {
        return Err(probe_failed(format!(
            "root probe exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| probe_failed("root probe stdout is not UTF-8"))?;
    let declaration = parse_root_declaration_probe_v1(stdout.trim())?;

    if hash_file(&source_config, 4 * 1_024 * 1_024)? != config_before
        || hash_file(&toolchain, 4_096)? != toolchain_before
    {
        return Err(LakeBridgeError::new(
            LakeBridgeErrorKind::EvidenceChanged,
            "source fixture changed while probing",
        ));
    }
    if request
        .staging_directory
        .join("lake-manifest.json")
        .exists()
        || request.staging_directory.join(".lake/packages").exists()
    {
        return Err(probe_failed(
            "loadWorkspaceRoot probe created manifest or materialized packages",
        ));
    }
    Ok(declaration)
}

fn require_success(label: &str, output: &std::process::Output) -> Result<(), LakeBridgeError> {
    if output.stdout.len() > MAX_PROBE_OUTPUT_BYTES || output.stderr.len() > MAX_PROBE_OUTPUT_BYTES
    {
        return Err(probe_failed(format!("{label} output exceeds byte limit")));
    }
    if !output.status.success() {
        return Err(probe_failed(format!(
            "{label} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn select_config(project: &Path) -> Result<&'static str, LakeBridgeError> {
    let lean = project.join("lakefile.lean").is_file();
    let toml = project.join("lakefile.toml").is_file();
    match (lean, toml) {
        (true, false) => Ok("lakefile.lean"),
        (false, true) => Ok("lakefile.toml"),
        _ => Err(boundary(
            "source fixture must contain exactly one Lake config file",
        )),
    }
}

/// Fails closed unless the four Lake sources used by the managed-package
/// boundary match the exact Lean 4.32 / Lake 5.0.0 source snapshot.
pub fn verify_lake_source_compatibility_v1(root: &Path) -> Result<(), LakeBridgeError> {
    for (relative, expected) in LAKE_SOURCE_HASHES {
        let actual = hash_file(&root.join(relative), 2 * 1_024 * 1_024)?;
        let expected = Sha256::parse(expected).map_err(|error| probe_failed(error.to_string()))?;
        if actual != expected {
            return Err(LakeBridgeError::new(
                LakeBridgeErrorKind::EvidenceChanged,
                format!("locked Lake source hash differs: {relative}"),
            ));
        }
    }
    Ok(())
}

fn hash_file(path: &Path, maximum: u64) -> Result<Sha256, LakeBridgeError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| probe_failed(format!("cannot inspect {}: {error}", path.display())))?;
    if !metadata.file_type().is_file() || metadata.len() > maximum {
        return Err(boundary(format!(
            "probe input is not a bounded regular file: {}",
            path.display()
        )));
    }
    let bytes = fs::read(path)
        .map_err(|error| probe_failed(format!("cannot read {}: {error}", path.display())))?;
    let mut hasher = Sha256Hasher::new();
    hasher.update(&bytes);
    Ok(hasher.finalize())
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, LakeBridgeError> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| boundary(format!("{label} cannot be canonicalized: {error}")))?;
    if !canonical.is_dir() {
        return Err(boundary(format!("{label} is not a directory")));
    }
    Ok(canonical)
}

fn canonical_file(path: &Path, label: &str) -> Result<PathBuf, LakeBridgeError> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| boundary(format!("{label} cannot be canonicalized: {error}")))?;
    if !canonical.is_file() {
        return Err(boundary(format!("{label} is not a file")));
    }
    Ok(canonical)
}

fn require_contained(root: &Path, candidate: &Path, label: &str) -> Result<(), LakeBridgeError> {
    if candidate != root && !candidate.starts_with(root) {
        return Err(boundary(format!("{label} escapes its allowed root")));
    }
    Ok(())
}

fn boundary(message: impl Into<String>) -> LakeBridgeError {
    LakeBridgeError::new(LakeBridgeErrorKind::ProbeBoundaryViolation, message)
}
fn probe_failed(message: impl Into<String>) -> LakeBridgeError {
    LakeBridgeError::new(LakeBridgeErrorKind::ProbeFailed, message)
}
