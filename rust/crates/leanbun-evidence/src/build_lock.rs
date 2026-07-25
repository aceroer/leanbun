use leanbun_core::{
    BuildTarget, DiagnosticCode, ExecutionId, ImageId, ProjectId, Sha256, Sha256Hasher, project_id,
};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;

use crate::{
    CanonicalDirectory, EvidenceError, MAX_SAFE_JSON_INTEGER, StableTextFile, StrictJson,
    execution_record::lexically_canonical_absolute_path, parse_strict_json,
    project_binding::valid_canonical_timestamp, read_stable_text,
};

pub const BUILD_LOCK_MAX_BYTES: u64 = 32 * 1024;

const MAX_PATH_BYTES: usize = 4_096;
const ROOT_FIELDS: &[&str] = &[
    "acquiredAt",
    "coordinatorPid",
    "executionId",
    "imageId",
    "key",
    "projectId",
    "projectPath",
    "recordType",
    "schemaVersion",
    "target",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildExecutionLockV1 {
    pub key: Sha256,
    pub execution_id: ExecutionId,
    pub project_id: ProjectId,
    pub project_path: String,
    pub image_id: ImageId,
    pub target: BuildTarget,
    pub coordinator_pid: u64,
    pub acquired_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableBuildExecutionLockFile {
    pub file: StableTextFile,
    pub lock: BuildExecutionLockV1,
}

#[must_use]
pub fn build_lock_key(project: ProjectId, image: ImageId) -> Sha256 {
    let material = format!(
        "{{\"schema\":\"leanbun-build-lock-v1\",\"projectId\":\"{project}\",\"imageId\":\"{image}\"}}"
    );
    let mut hasher = Sha256Hasher::new();
    hasher.update(material.as_bytes());
    hasher.finalize()
}

pub fn read_build_execution_lock(
    state_root: &CanonicalDirectory,
    requested_key: Sha256,
) -> Result<StableBuildExecutionLockFile, EvidenceError> {
    let store = state_root.as_path().join("build-locks");
    let store_metadata = fs::symlink_metadata(&store).map_err(|error| {
        EvidenceError::new(
            if error.kind() == std::io::ErrorKind::NotFound {
                DiagnosticCode::EVIDENCE_MISSING
            } else {
                DiagnosticCode::EVIDENCE_READ_FAILED
            },
            format!("build lock store cannot be inspected: {error}"),
        )
    })?;
    if store_metadata.file_type().is_symlink() {
        return Err(EvidenceError::new(
            DiagnosticCode::PATH_ESCAPES_ALLOWED_ROOT,
            format!(
                "build lock store must not be a symlink: {}",
                store.display()
            ),
        ));
    }
    if !store_metadata.is_dir() {
        return Err(invalid(format!(
            "build lock store is not a directory: {}",
            store.display()
        )));
    }

    let candidate = state_root
        .as_path()
        .join("build-locks")
        .join(format!("{requested_key}.lock"));
    let metadata = fs::symlink_metadata(&candidate).map_err(|error| {
        EvidenceError::new(
            if error.kind() == std::io::ErrorKind::NotFound {
                DiagnosticCode::EVIDENCE_MISSING
            } else {
                DiagnosticCode::EVIDENCE_READ_FAILED
            },
            format!("build lock cannot be inspected: {error}"),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid(format!(
            "build lock is not a direct regular file: {}",
            candidate.display()
        )));
    }
    if metadata.mode() & 0o777 != 0o444 {
        return Err(invalid(format!(
            "build lock mode is {:o}, expected 444: {}",
            metadata.mode() & 0o777,
            candidate.display()
        )));
    }

    let relative = format!("build-locks/{requested_key}.lock");
    let file = read_stable_text(state_root, relative, BUILD_LOCK_MAX_BYTES)?;
    let lock = parse_build_execution_lock(&file.text, requested_key)?;
    Ok(StableBuildExecutionLockFile { file, lock })
}

pub fn parse_build_execution_lock(
    text: &str,
    requested_key: Sha256,
) -> Result<BuildExecutionLockV1, EvidenceError> {
    decode_build_execution_lock(&parse_strict_json(text)?, requested_key)
}

pub fn decode_build_execution_lock(
    value: &StrictJson,
    requested_key: Sha256,
) -> Result<BuildExecutionLockV1, EvidenceError> {
    let root = match value {
        StrictJson::Object(root) => root,
        _ => return Err(invalid("build lock root must be an object")),
    };
    if root.len() != ROOT_FIELDS.len()
        || root
            .keys()
            .any(|field| !ROOT_FIELDS.contains(&field.as_str()))
    {
        return Err(invalid("build lock fields are not the exact v1 field set"));
    }
    if required_integer(root, "schemaVersion")? != 1 {
        return Err(invalid("build lock schemaVersion is invalid"));
    }
    if required_string(root, "recordType", 64)? != "build-execution-lock" {
        return Err(invalid("build lock recordType is invalid"));
    }

    let key = required_sha256(root, "key")?;
    if key != requested_key {
        return Err(invalid(
            "build lock key does not match requested filename key",
        ));
    }
    let execution_id = ExecutionId::parse(required_string(root, "executionId", 36)?)
        .map_err(|_| invalid("executionId must be a canonical UUID v4"))?;
    let project_path = required_string(root, "projectPath", MAX_PATH_BYTES)?;
    if project_path.is_empty() || !lexically_canonical_absolute_path(project_path) {
        return Err(invalid("projectPath must be a canonical absolute path"));
    }
    let project = ProjectId::parse(required_string(root, "projectId", 64)?)
        .map_err(|_| invalid("projectId must be lowercase SHA-256"))?;
    if project != project_id(project_path) {
        return Err(invalid("projectId does not match projectPath"));
    }
    let image = ImageId::parse(required_string(root, "imageId", 64)?)
        .map_err(|_| invalid("imageId must be lowercase SHA-256"))?;
    if key != build_lock_key(project, image) {
        return Err(invalid(
            "build lock key does not match project/image identity",
        ));
    }
    let target = BuildTarget::parse(required_string(root, "target", 1_024)?)
        .map_err(|_| invalid("target is invalid"))?;
    let coordinator_pid = required_integer(root, "coordinatorPid")?;
    if coordinator_pid == 0 || coordinator_pid > MAX_SAFE_JSON_INTEGER {
        return Err(invalid("coordinatorPid must be a positive safe integer"));
    }
    let acquired_at = required_string(root, "acquiredAt", 64)?;
    if !valid_canonical_timestamp(acquired_at) {
        return Err(invalid("acquiredAt must be a canonical UTC timestamp"));
    }

    Ok(BuildExecutionLockV1 {
        key,
        execution_id,
        project_id: project,
        project_path: project_path.to_owned(),
        image_id: image,
        target,
        coordinator_pid,
        acquired_at: acquired_at.to_owned(),
    })
}

fn required_string<'a>(
    root: &'a BTreeMap<String, StrictJson>,
    field: &str,
    maximum_bytes: usize,
) -> Result<&'a str, EvidenceError> {
    match root.get(field) {
        Some(StrictJson::String(value)) if value.len() <= maximum_bytes => Ok(value),
        Some(StrictJson::String(_)) => Err(invalid(format!("build lock {field} is too large"))),
        Some(_) => Err(invalid(format!("build lock {field} must be a string"))),
        None => Err(invalid(format!("build lock is missing {field}"))),
    }
}

fn required_sha256(
    root: &BTreeMap<String, StrictJson>,
    field: &str,
) -> Result<Sha256, EvidenceError> {
    Sha256::parse(required_string(root, field, 64)?)
        .map_err(|_| invalid(format!("build lock {field} must be lowercase SHA-256")))
}

fn required_integer(
    root: &BTreeMap<String, StrictJson>,
    field: &str,
) -> Result<u64, EvidenceError> {
    let Some(StrictJson::Number(number)) = root.get(field) else {
        return Err(invalid(format!("build lock {field} must be an integer")));
    };
    if number.as_str().contains(['.', 'e', 'E']) {
        return Err(invalid(format!("build lock {field} must be an integer")));
    }
    number.as_str().parse::<u64>().map_err(|_| {
        invalid(format!(
            "build lock {field} is outside unsigned integer range"
        ))
    })
}

fn invalid(message: impl Into<String>) -> EvidenceError {
    EvidenceError::new(DiagnosticCode::BUILD_LOCK_CONFLICT, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonicalize_directory;
    use std::io;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const KEY: &str = "18e4dd29e1ad67692d960e006a2a52435f4faa57a5e0e59a6f5e481daac49580";
    const PROJECT_ID: &str = "c32fe4e9adb318f7e52427c338c6b6c8079f12fa40b5f29423de8e7a7214e08b";
    static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> io::Result<Self> {
            let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "leanbun-build-lock-reader-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn valid_json() -> String {
        format!(
            "{{\"schemaVersion\":1,\"recordType\":\"build-execution-lock\",\"key\":\"{KEY}\",\"executionId\":\"12345678-1234-4123-8123-123456789abc\",\"projectId\":\"{PROJECT_ID}\",\"projectPath\":\"/fixture/project\",\"imageId\":\"{}\",\"target\":\"Fixture\",\"coordinatorPid\":4242,\"acquiredAt\":\"2026-07-24T00:00:00.000Z\"}}",
            "1".repeat(64)
        )
    }

    #[test]
    fn key_matches_bun_json_stringify_contract() -> Result<(), Box<dyn std::error::Error>> {
        let project = ProjectId::parse(PROJECT_ID)?;
        let image = ImageId::parse(&"1".repeat(64))?;
        assert_eq!(build_lock_key(project, image).to_string(), KEY);
        Ok(())
    }

    #[test]
    fn stable_reader_binds_filename_schema_and_mode() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        fs::create_dir(fixture.0.join("build-locks"))?;
        let path = fixture.0.join(format!("build-locks/{KEY}.lock"));
        fs::write(&path, valid_json())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444))?;
        let root = canonicalize_directory(&fixture.0)?;
        let requested = Sha256::parse(KEY)?;
        let observed = read_build_execution_lock(&root, requested)?;
        assert_eq!(observed.lock.coordinator_pid, 4242);
        assert_eq!(read_build_execution_lock(&root, requested)?, observed);
        Ok(())
    }

    #[test]
    fn reader_rejects_writable_lock() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        fs::create_dir(fixture.0.join("build-locks"))?;
        let path = fixture.0.join(format!("build-locks/{KEY}.lock"));
        fs::write(&path, valid_json())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        let root = canonicalize_directory(&fixture.0)?;
        assert_eq!(
            read_build_execution_lock(&root, Sha256::parse(KEY)?).map_err(|error| error.code),
            Err(DiagnosticCode::BUILD_LOCK_CONFLICT)
        );
        Ok(())
    }

    #[test]
    fn reader_rejects_symlinked_lock_store() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let outside = fixture.0.join("outside");
        fs::create_dir(&outside)?;
        symlink(&outside, fixture.0.join("build-locks"))?;
        let root = canonicalize_directory(&fixture.0)?;
        assert_eq!(
            read_build_execution_lock(&root, Sha256::parse(KEY)?).map_err(|error| error.code),
            Err(DiagnosticCode::PATH_ESCAPES_ALLOWED_ROOT)
        );
        Ok(())
    }

    #[test]
    fn shared_build_lock_contract_cases_match() {
        for line in include_str!("../../../golden/build-lock-cases.tsv").lines() {
            let mut fields = line.splitn(4, '\t');
            let expected = fields.next();
            let label = fields.next();
            let requested = fields.next().and_then(|value| Sha256::parse(value).ok());
            let json = fields.next();
            assert!(expected.is_some() && label.is_some() && requested.is_some() && json.is_some());
            let accepted = requested
                .zip(json)
                .and_then(|(key, text)| parse_build_execution_lock(text, key).ok())
                .is_some();
            assert_eq!(accepted, expected == Some("true"), "{label:?}");
        }
    }
}
