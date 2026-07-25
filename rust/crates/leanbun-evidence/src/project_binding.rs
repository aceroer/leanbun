use leanbun_core::{BuildTarget, DiagnosticCode, ImageId, ProjectId, Sha256, project_id};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use crate::{
    CanonicalDirectory, EvidenceError, StableTextFile, StrictJson, parse_strict_json,
    read_stable_text,
};

pub const PROJECT_BINDING_MAX_BYTES: u64 = 1024 * 1024;
pub const MAX_ALLOWED_TARGETS: usize = 256;

const MAX_SHORT_STRING_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 4_096;
const ROOT_FIELDS: &[&str] = &[
    "allowedTargets",
    "boundAt",
    "imageId",
    "lastVerifiedAt",
    "manifestSha256",
    "policyVersion",
    "projectId",
    "projectPath",
    "providerId",
    "schemaVersion",
    "toolchain",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectBindingV1 {
    pub project_id: ProjectId,
    pub project_path: String,
    pub image_id: ImageId,
    pub provider_id: String,
    pub bound_at: String,
    pub manifest_sha256: Sha256,
    pub toolchain: String,
    pub allowed_targets: Vec<BuildTarget>,
    pub last_verified_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableProjectBindingFile {
    pub file: StableTextFile,
    pub binding: ProjectBindingV1,
}

pub fn read_project_binding(
    project: &CanonicalDirectory,
) -> Result<StableProjectBindingFile, EvidenceError> {
    let control_directory = project.as_path().join(".leanbun");
    let control_metadata = fs::symlink_metadata(&control_directory).map_err(|error| {
        EvidenceError::new(
            if error.kind() == std::io::ErrorKind::NotFound {
                DiagnosticCode::EVIDENCE_MISSING
            } else {
                DiagnosticCode::EVIDENCE_READ_FAILED
            },
            format!("project binding directory cannot be inspected: {error}"),
        )
    })?;
    if control_metadata.file_type().is_symlink() {
        return Err(EvidenceError::new(
            DiagnosticCode::PATH_ESCAPES_ALLOWED_ROOT,
            format!(
                "project binding directory must not be a symlink: {}",
                control_directory.display()
            ),
        ));
    }
    if !control_metadata.is_dir() {
        return Err(invalid(format!(
            "project binding control path is not a directory: {}",
            control_directory.display()
        )));
    }

    let file = read_stable_text(project, ".leanbun/binding.json", PROJECT_BINDING_MAX_BYTES)?;
    let project_path = project.as_path().to_str().ok_or_else(|| {
        invalid(format!(
            "canonical project path is not valid UTF-8: {}",
            project.as_path().display()
        ))
    })?;
    let binding = parse_project_binding(&file.text, project_path)?;
    Ok(StableProjectBindingFile { file, binding })
}

pub fn parse_project_binding(
    text: &str,
    canonical_project_path: &str,
) -> Result<ProjectBindingV1, EvidenceError> {
    decode_project_binding(&parse_strict_json(text)?, canonical_project_path)
}

pub fn decode_project_binding(
    value: &StrictJson,
    canonical_project_path: &str,
) -> Result<ProjectBindingV1, EvidenceError> {
    if canonical_project_path.is_empty() || canonical_project_path.len() > MAX_PATH_BYTES {
        return Err(invalid("canonical project path is empty or exceeds limit"));
    }
    let root = object(value)?;
    reject_unknown_fields(root)?;
    required_one(root, "schemaVersion")?;
    required_one(root, "policyVersion")?;

    let encoded_project_id = required_string(root, "projectId", MAX_SHORT_STRING_BYTES)?;
    let parsed_project_id = ProjectId::parse(encoded_project_id)
        .map_err(|_| invalid("binding projectId must be a lowercase SHA-256 value"))?;
    let expected_project_id = project_id(canonical_project_path);
    if parsed_project_id != expected_project_id {
        return Err(invalid(
            "binding projectId does not match canonical project path",
        ));
    }
    let project_path = required_string(root, "projectPath", MAX_PATH_BYTES)?;
    if project_path != canonical_project_path {
        return Err(invalid(
            "binding projectPath does not match canonical project path",
        ));
    }

    let image_id = ImageId::parse(required_string(root, "imageId", MAX_SHORT_STRING_BYTES)?)
        .map_err(|_| invalid("binding imageId must be a lowercase SHA-256 value"))?;
    let manifest_sha256 = Sha256::parse(required_string(
        root,
        "manifestSha256",
        MAX_SHORT_STRING_BYTES,
    )?)
    .map_err(|_| invalid("binding manifestSha256 must be a lowercase SHA-256 value"))?;
    let provider_id = required_nonempty_string(root, "providerId", MAX_SHORT_STRING_BYTES)?;
    let toolchain = required_nonempty_string(root, "toolchain", MAX_SHORT_STRING_BYTES)?;
    reject_control_characters(provider_id, "providerId")?;
    reject_control_characters(toolchain, "toolchain")?;

    let bound_at = required_string(root, "boundAt", 24)?;
    let last_verified_at = required_string(root, "lastVerifiedAt", 24)?;
    if !valid_canonical_timestamp(bound_at) || !valid_canonical_timestamp(last_verified_at) {
        return Err(invalid(
            "binding timestamps must use canonical YYYY-MM-DDTHH:mm:ss.sssZ UTC format",
        ));
    }
    if last_verified_at < bound_at {
        return Err(invalid("binding lastVerifiedAt precedes boundAt"));
    }

    let targets = match root.get("allowedTargets") {
        Some(StrictJson::Array(targets)) => targets,
        Some(_) => return Err(invalid("binding allowedTargets must be an array")),
        None => return Err(invalid("binding is missing allowedTargets")),
    };
    if targets.is_empty() || targets.len() > MAX_ALLOWED_TARGETS {
        return Err(invalid(format!(
            "binding allowedTargets count must be between 1 and {MAX_ALLOWED_TARGETS}"
        )));
    }
    let mut allowed_targets = Vec::with_capacity(targets.len());
    let mut names = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for target in targets {
        let StrictJson::String(target) = target else {
            return Err(invalid("binding target must be a string"));
        };
        let parsed = BuildTarget::parse(target)
            .map_err(|_| invalid(format!("binding target is invalid: {target}")))?;
        if !names.insert(target.as_str()) {
            return Err(invalid(format!("duplicate binding target: {target}")));
        }
        if previous.is_some_and(|value| value.as_bytes() >= target.as_bytes()) {
            return Err(invalid(
                "binding allowedTargets must be UTF-8 bytewise sorted",
            ));
        }
        previous = Some(target);
        allowed_targets.push(parsed);
    }

    Ok(ProjectBindingV1 {
        project_id: parsed_project_id,
        project_path: project_path.to_owned(),
        image_id,
        provider_id: provider_id.to_owned(),
        bound_at: bound_at.to_owned(),
        manifest_sha256,
        toolchain: toolchain.to_owned(),
        allowed_targets,
        last_verified_at: last_verified_at.to_owned(),
    })
}

fn object(value: &StrictJson) -> Result<&BTreeMap<String, StrictJson>, EvidenceError> {
    match value {
        StrictJson::Object(object) => Ok(object),
        _ => Err(invalid("binding root must be an object")),
    }
}

fn reject_unknown_fields(root: &BTreeMap<String, StrictJson>) -> Result<(), EvidenceError> {
    for field in root.keys() {
        if ROOT_FIELDS.binary_search(&field.as_str()).is_err() {
            return Err(invalid(format!("unknown binding field: {field}")));
        }
    }
    Ok(())
}

fn required_one(root: &BTreeMap<String, StrictJson>, field: &str) -> Result<(), EvidenceError> {
    match root.get(field) {
        Some(StrictJson::Number(number)) if number.as_str() == "1" => Ok(()),
        Some(_) => Err(invalid(format!("binding {field} must be integer 1"))),
        None => Err(invalid(format!("binding is missing {field}"))),
    }
}

fn required_string<'a>(
    root: &'a BTreeMap<String, StrictJson>,
    field: &str,
    maximum_bytes: usize,
) -> Result<&'a str, EvidenceError> {
    match root.get(field) {
        Some(StrictJson::String(value)) if value.len() <= maximum_bytes => Ok(value),
        Some(StrictJson::String(_)) => Err(invalid(format!("binding {field} exceeds byte limit"))),
        Some(_) => Err(invalid(format!("binding {field} must be a string"))),
        None => Err(invalid(format!("binding is missing {field}"))),
    }
}

fn required_nonempty_string<'a>(
    root: &'a BTreeMap<String, StrictJson>,
    field: &str,
    maximum_bytes: usize,
) -> Result<&'a str, EvidenceError> {
    let value = required_string(root, field, maximum_bytes)?;
    if value.is_empty() {
        return Err(invalid(format!("binding {field} must not be empty")));
    }
    Ok(value)
}

fn reject_control_characters(value: &str, field: &str) -> Result<(), EvidenceError> {
    if value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "binding {field} contains control characters"
        )));
    }
    Ok(())
}

pub(crate) fn valid_canonical_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 24
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[23] != b'Z'
    {
        return false;
    }
    for range in [0..4, 5..7, 8..10, 11..13, 14..16, 17..19, 20..23] {
        if !bytes[range].iter().all(u8::is_ascii_digit) {
            return false;
        }
    }
    let Ok(year) = value[0..4].parse::<u16>() else {
        return false;
    };
    let Ok(month) = value[5..7].parse::<u8>() else {
        return false;
    };
    let Ok(day) = value[8..10].parse::<u8>() else {
        return false;
    };
    let Ok(hour) = value[11..13].parse::<u8>() else {
        return false;
    };
    let Ok(minute) = value[14..16].parse::<u8>() else {
        return false;
    };
    let Ok(second) = value[17..19].parse::<u8>() else {
        return false;
    };
    if year == 0 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let maximum_day = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    day >= 1 && day <= maximum_day
}

fn invalid(message: impl Into<String>) -> EvidenceError {
    EvidenceError::new(DiagnosticCode::BINDING_INVALID, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonicalize_directory;
    use std::io;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> io::Result<Self> {
            let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "leanbun-binding-reader-{}-{id}",
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

    fn binding_json(project: &Path) -> Result<String, EvidenceError> {
        let project = project
            .to_str()
            .ok_or_else(|| invalid("test path is not UTF-8"))?;
        Ok(format!(
            "{{\"schemaVersion\":1,\"projectId\":\"{}\",\"projectPath\":\"{}\",\"imageId\":\"{}\",\"providerId\":\"fixture\",\"boundAt\":\"2026-07-24T00:00:00.000Z\",\"manifestSha256\":\"{}\",\"toolchain\":\"leanprover/lean4:v4.32.0\",\"policyVersion\":1,\"allowedTargets\":[\"Fixture\",\"Fixture.Tests\"],\"lastVerifiedAt\":\"2026-07-24T01:00:00.000Z\"}}",
            project_id(project),
            project,
            "1".repeat(64),
            "2".repeat(64)
        ))
    }

    #[test]
    fn stable_reader_binds_document_to_canonical_project() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = Fixture::new()?;
        fs::create_dir(fixture.0.join(".leanbun"))?;
        let root = canonicalize_directory(&fixture.0)?;
        fs::write(
            fixture.0.join(".leanbun/binding.json"),
            binding_json(root.as_path())?,
        )?;
        let observed = read_project_binding(&root)?;
        assert_eq!(
            observed.binding.project_id,
            project_id(observed.binding.project_path.as_str())
        );
        assert_eq!(observed.binding.allowed_targets.len(), 2);
        assert_eq!(read_project_binding(&root)?, observed);
        Ok(())
    }

    #[test]
    fn canonical_timestamp_rejects_calendar_and_order_drift() {
        assert!(valid_canonical_timestamp("2024-02-29T23:59:59.999Z"));
        assert!(!valid_canonical_timestamp("2026-02-29T00:00:00.000Z"));
        assert!(!valid_canonical_timestamp("2026-07-24"));
    }

    #[test]
    fn reader_rejects_symlinked_control_directory() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let outside = fixture.0.join("outside");
        fs::create_dir(&outside)?;
        fs::write(outside.join("binding.json"), binding_json(&fixture.0)?)?;
        symlink(&outside, fixture.0.join(".leanbun"))?;
        let root = canonicalize_directory(&fixture.0)?;
        assert_eq!(
            read_project_binding(&root).map_err(|error| error.code),
            Err(DiagnosticCode::PATH_ESCAPES_ALLOWED_ROOT)
        );
        Ok(())
    }

    #[test]
    fn shared_project_binding_contract_cases_match() {
        for line in include_str!("../../../golden/project-binding-cases.tsv").lines() {
            let mut fields = line.splitn(3, '\t');
            let expected = fields.next();
            let label = fields.next();
            let json = fields.next();
            assert!(expected.is_some() && label.is_some() && json.is_some());
            let accepted = json
                .and_then(|text| parse_project_binding(text, "/fixture/project").ok())
                .is_some();
            assert_eq!(accepted, expected == Some("true"), "{label:?}");
        }
    }
}
