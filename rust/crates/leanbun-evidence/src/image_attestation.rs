use leanbun_core::{DiagnosticCode, ImageId, Sha256, Sha256Hasher};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use crate::{
    CanonicalDirectory, EvidenceError, StableTextFile, StrictJson, parse_strict_json,
    project_binding::valid_canonical_timestamp, read_stable_text,
};

pub const IMAGE_ATTESTATION_MAX_BYTES: u64 = 1024 * 1024;
pub const MAX_MISSING_ARTIFACT_ROOTS: usize = 4_096;
pub const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

const MAX_SHORT_STRING_BYTES: usize = 256;
const ROOT_FIELDS: &[&str] = &[
    "artifactCount",
    "artifactPolicy",
    "artifactTreeHash",
    "dependencyTreeHash",
    "identity",
    "imageId",
    "provider",
    "providerId",
    "schemaVersion",
    "sealedAt",
    "status",
];
const IDENTITY_FIELDS: &[&str] = &[
    "buildRelevantConfigHash",
    "canonicalManifestHash",
    "leanCompilerGithash",
    "leanToolchain",
    "mathlibRevision",
    "packageSourceTreeHash",
    "schemaVersion",
    "targetPlatform",
];
const PROVIDER_FIELDS: &[&str] = &["overridesSha256", "registrySha256"];
const ARTIFACT_POLICY_FIELDS: &[&str] = &["missingRoots"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageIdentityV1 {
    pub lean_toolchain: String,
    pub lean_compiler_githash: String,
    pub mathlib_revision: String,
    pub canonical_manifest_hash: Sha256,
    pub package_source_tree_hash: Sha256,
    pub build_relevant_config_hash: Sha256,
    pub target_platform: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationProviderV1 {
    pub registry_sha256: Sha256,
    pub overrides_sha256: Sha256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactPolicyV1 {
    pub missing_roots: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageAttestationV1 {
    pub image_id: ImageId,
    pub provider_id: String,
    pub identity: ImageIdentityV1,
    pub provider: AttestationProviderV1,
    pub dependency_tree_hash: Sha256,
    pub artifact_tree_hash: Sha256,
    pub artifact_count: u64,
    pub artifact_policy: ArtifactPolicyV1,
    pub sealed_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableImageAttestationFile {
    pub file: StableTextFile,
    pub attestation: ImageAttestationV1,
}

#[must_use]
pub fn image_id(identity: &ImageIdentityV1) -> ImageId {
    let mut canonical = String::from("{\"schemaVersion\":1,\"leanToolchain\":");
    push_json_string(&mut canonical, &identity.lean_toolchain);
    canonical.push_str(",\"leanCompilerGithash\":");
    push_json_string(&mut canonical, &identity.lean_compiler_githash);
    canonical.push_str(",\"mathlibRevision\":");
    push_json_string(&mut canonical, &identity.mathlib_revision);
    canonical.push_str(",\"canonicalManifestHash\":\"");
    canonical.push_str(&identity.canonical_manifest_hash.to_string());
    canonical.push_str("\",\"packageSourceTreeHash\":\"");
    canonical.push_str(&identity.package_source_tree_hash.to_string());
    canonical.push_str("\",\"buildRelevantConfigHash\":\"");
    canonical.push_str(&identity.build_relevant_config_hash.to_string());
    canonical.push_str("\",\"targetPlatform\":");
    push_json_string(&mut canonical, &identity.target_platform);
    canonical.push('}');
    let mut hasher = Sha256Hasher::new();
    hasher.update(canonical.as_bytes());
    ImageId::from_digest(hasher.finalize())
}

pub fn read_image_attestation(
    state_root: &CanonicalDirectory,
    requested_image_id: ImageId,
) -> Result<StableImageAttestationFile, EvidenceError> {
    let store = state_root.as_path().join("attestations");
    let metadata = fs::symlink_metadata(&store).map_err(|error| {
        EvidenceError::new(
            if error.kind() == std::io::ErrorKind::NotFound {
                DiagnosticCode::EVIDENCE_MISSING
            } else {
                DiagnosticCode::EVIDENCE_READ_FAILED
            },
            format!("attestation store cannot be inspected: {error}"),
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(EvidenceError::new(
            DiagnosticCode::PATH_ESCAPES_ALLOWED_ROOT,
            format!(
                "attestation store must not be a symlink: {}",
                store.display()
            ),
        ));
    }
    if !metadata.is_dir() {
        return Err(invalid(format!(
            "attestation store is not a directory: {}",
            store.display()
        )));
    }
    let candidate = format!("attestations/{requested_image_id}.json");
    let file = read_stable_text(state_root, candidate, IMAGE_ATTESTATION_MAX_BYTES)?;
    let attestation = parse_image_attestation(&file.text, requested_image_id)?;
    Ok(StableImageAttestationFile { file, attestation })
}

pub fn parse_image_attestation(
    text: &str,
    requested_image_id: ImageId,
) -> Result<ImageAttestationV1, EvidenceError> {
    decode_image_attestation(&parse_strict_json(text)?, requested_image_id)
}

pub fn decode_image_attestation(
    value: &StrictJson,
    requested_image_id: ImageId,
) -> Result<ImageAttestationV1, EvidenceError> {
    let root = object(value, "attestation root")?;
    reject_unknown_fields(root, ROOT_FIELDS, "attestation root")?;
    required_one(root, "schemaVersion", "attestation")?;
    if required_string(root, "status", MAX_SHORT_STRING_BYTES, "attestation")? != "sealed" {
        return Err(invalid("attestation status must be sealed"));
    }

    let encoded_image_id = required_string(root, "imageId", MAX_SHORT_STRING_BYTES, "attestation")?;
    let document_image_id = ImageId::parse(encoded_image_id)
        .map_err(|_| invalid("attestation imageId must be a lowercase SHA-256 value"))?;
    if document_image_id != requested_image_id {
        return Err(invalid(
            "attestation imageId does not match requested image",
        ));
    }
    let provider_id =
        required_nonempty_string(root, "providerId", MAX_SHORT_STRING_BYTES, "attestation")?;
    reject_control_characters(provider_id, "providerId")?;

    let identity = decode_identity(required_object(root, "identity", "attestation")?)?;
    if image_id(&identity) != requested_image_id {
        return Err(invalid(
            "attestation identity does not derive requested imageId",
        ));
    }
    let provider = decode_provider(required_object(root, "provider", "attestation")?)?;
    if provider.registry_sha256 != identity.canonical_manifest_hash {
        return Err(invalid(
            "attestation provider registry digest differs from canonical manifest digest",
        ));
    }

    let dependency_tree_hash = required_sha256(root, "dependencyTreeHash", "attestation")?;
    let artifact_tree_hash = required_sha256(root, "artifactTreeHash", "attestation")?;
    let artifact_count = required_safe_integer(root, "artifactCount", "attestation")?;
    let artifact_policy =
        decode_artifact_policy(required_object(root, "artifactPolicy", "attestation")?)?;
    let sealed_at = required_string(root, "sealedAt", 24, "attestation")?;
    if !valid_canonical_timestamp(sealed_at) {
        return Err(invalid(
            "attestation sealedAt must use canonical YYYY-MM-DDTHH:mm:ss.sssZ UTC format",
        ));
    }

    Ok(ImageAttestationV1 {
        image_id: document_image_id,
        provider_id: provider_id.to_owned(),
        identity,
        provider,
        dependency_tree_hash,
        artifact_tree_hash,
        artifact_count,
        artifact_policy,
        sealed_at: sealed_at.to_owned(),
    })
}

fn decode_identity(root: &BTreeMap<String, StrictJson>) -> Result<ImageIdentityV1, EvidenceError> {
    reject_unknown_fields(root, IDENTITY_FIELDS, "image identity")?;
    required_one(root, "schemaVersion", "image identity")?;
    let lean_toolchain = required_nonempty_string(
        root,
        "leanToolchain",
        MAX_SHORT_STRING_BYTES,
        "image identity",
    )?;
    let lean_compiler_githash = required_git_revision(root, "leanCompilerGithash")?;
    let mathlib_revision = required_git_revision(root, "mathlibRevision")?;
    let canonical_manifest_hash = required_sha256(root, "canonicalManifestHash", "image identity")?;
    let package_source_tree_hash =
        required_sha256(root, "packageSourceTreeHash", "image identity")?;
    let build_relevant_config_hash =
        required_sha256(root, "buildRelevantConfigHash", "image identity")?;
    let target_platform = required_nonempty_string(
        root,
        "targetPlatform",
        MAX_SHORT_STRING_BYTES,
        "image identity",
    )?;
    reject_control_characters(lean_toolchain, "leanToolchain")?;
    reject_control_characters(target_platform, "targetPlatform")?;
    Ok(ImageIdentityV1 {
        lean_toolchain: lean_toolchain.to_owned(),
        lean_compiler_githash: lean_compiler_githash.to_owned(),
        mathlib_revision: mathlib_revision.to_owned(),
        canonical_manifest_hash,
        package_source_tree_hash,
        build_relevant_config_hash,
        target_platform: target_platform.to_owned(),
    })
}

fn decode_provider(
    root: &BTreeMap<String, StrictJson>,
) -> Result<AttestationProviderV1, EvidenceError> {
    reject_unknown_fields(root, PROVIDER_FIELDS, "attestation provider")?;
    Ok(AttestationProviderV1 {
        registry_sha256: required_sha256(root, "registrySha256", "attestation provider")?,
        overrides_sha256: required_sha256(root, "overridesSha256", "attestation provider")?,
    })
}

fn decode_artifact_policy(
    root: &BTreeMap<String, StrictJson>,
) -> Result<ArtifactPolicyV1, EvidenceError> {
    reject_unknown_fields(root, ARTIFACT_POLICY_FIELDS, "artifact policy")?;
    let roots = match root.get("missingRoots") {
        Some(StrictJson::Array(roots)) => roots,
        Some(_) => return Err(invalid("artifact policy missingRoots must be an array")),
        None => return Err(invalid("artifact policy is missing missingRoots")),
    };
    if roots.len() > MAX_MISSING_ARTIFACT_ROOTS {
        return Err(invalid(format!(
            "artifact policy missingRoots exceeds {MAX_MISSING_ARTIFACT_ROOTS} entries"
        )));
    }
    let mut missing_roots = Vec::with_capacity(roots.len());
    let mut names = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for root in roots {
        let StrictJson::String(root) = root else {
            return Err(invalid("artifact policy missing root must be a string"));
        };
        if root.is_empty() || root.len() > MAX_SHORT_STRING_BYTES {
            return Err(invalid(
                "artifact policy missing root is empty or exceeds limit",
            ));
        }
        reject_control_characters(root, "artifactPolicy.missingRoots")?;
        if !names.insert(root.as_str()) {
            return Err(invalid(format!("duplicate artifact missing root: {root}")));
        }
        if previous.is_some_and(|value| value.as_bytes() >= root.as_bytes()) {
            return Err(invalid(
                "artifact missing roots must be UTF-8 bytewise sorted",
            ));
        }
        previous = Some(root);
        missing_roots.push(root.to_owned());
    }
    Ok(ArtifactPolicyV1 { missing_roots })
}

fn object<'a>(
    value: &'a StrictJson,
    label: &str,
) -> Result<&'a BTreeMap<String, StrictJson>, EvidenceError> {
    match value {
        StrictJson::Object(object) => Ok(object),
        _ => Err(invalid(format!("{label} must be an object"))),
    }
}

fn required_object<'a>(
    root: &'a BTreeMap<String, StrictJson>,
    field: &str,
    label: &str,
) -> Result<&'a BTreeMap<String, StrictJson>, EvidenceError> {
    match root.get(field) {
        Some(value) => object(value, field),
        None => Err(invalid(format!("{label} is missing {field}"))),
    }
}

fn reject_unknown_fields(
    root: &BTreeMap<String, StrictJson>,
    allowed: &[&str],
    label: &str,
) -> Result<(), EvidenceError> {
    for field in root.keys() {
        if allowed.binary_search(&field.as_str()).is_err() {
            return Err(invalid(format!("unknown {label} field: {field}")));
        }
    }
    Ok(())
}

fn required_one(
    root: &BTreeMap<String, StrictJson>,
    field: &str,
    label: &str,
) -> Result<(), EvidenceError> {
    match root.get(field) {
        Some(StrictJson::Number(number)) if number.as_str() == "1" => Ok(()),
        Some(_) => Err(invalid(format!("{label} {field} must be integer 1"))),
        None => Err(invalid(format!("{label} is missing {field}"))),
    }
}

fn required_string<'a>(
    root: &'a BTreeMap<String, StrictJson>,
    field: &str,
    maximum_bytes: usize,
    label: &str,
) -> Result<&'a str, EvidenceError> {
    match root.get(field) {
        Some(StrictJson::String(value)) if value.len() <= maximum_bytes => Ok(value),
        Some(StrictJson::String(_)) => Err(invalid(format!("{label} {field} exceeds byte limit"))),
        Some(_) => Err(invalid(format!("{label} {field} must be a string"))),
        None => Err(invalid(format!("{label} is missing {field}"))),
    }
}

fn required_nonempty_string<'a>(
    root: &'a BTreeMap<String, StrictJson>,
    field: &str,
    maximum_bytes: usize,
    label: &str,
) -> Result<&'a str, EvidenceError> {
    let value = required_string(root, field, maximum_bytes, label)?;
    if value.is_empty() {
        return Err(invalid(format!("{label} {field} must not be empty")));
    }
    Ok(value)
}

fn required_sha256(
    root: &BTreeMap<String, StrictJson>,
    field: &str,
    label: &str,
) -> Result<Sha256, EvidenceError> {
    Sha256::parse(required_string(root, field, 64, label)?)
        .map_err(|_| invalid(format!("{label} {field} must be a lowercase SHA-256 value")))
}

fn required_git_revision<'a>(
    root: &'a BTreeMap<String, StrictJson>,
    field: &str,
) -> Result<&'a str, EvidenceError> {
    let revision = required_string(root, field, 40, "image identity")?;
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(invalid(format!(
            "image identity {field} must be a lowercase 40-character Git revision"
        )));
    }
    Ok(revision)
}

fn required_safe_integer(
    root: &BTreeMap<String, StrictJson>,
    field: &str,
    label: &str,
) -> Result<u64, EvidenceError> {
    let Some(StrictJson::Number(number)) = root.get(field) else {
        return Err(invalid(format!("{label} {field} must be an integer")));
    };
    let lexical = number.as_str();
    if lexical.is_empty() || !lexical.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid(format!(
            "{label} {field} must be a nonnegative integer"
        )));
    }
    let value = lexical
        .parse::<u64>()
        .map_err(|_| invalid(format!("{label} {field} exceeds integer range")))?;
    if value > MAX_SAFE_JSON_INTEGER {
        return Err(invalid(format!(
            "{label} {field} exceeds JSON safe integer range"
        )));
    }
    Ok(value)
}

fn reject_control_characters(value: &str, field: &str) -> Result<(), EvidenceError> {
    if value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "attestation {field} contains control characters"
        )));
    }
    Ok(())
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{0000}'..='\u{001f}' => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", u32::from(character));
            }
            _ => output.push(character),
        }
    }
    output.push('"');
}

fn invalid(message: impl Into<String>) -> EvidenceError {
    EvidenceError::new(DiagnosticCode::ATTESTATION_INVALID, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonicalize_directory;
    use std::io;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> io::Result<Self> {
            let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "leanbun-attestation-reader-{}-{id}",
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

    fn identity() -> Result<ImageIdentityV1, Box<dyn std::error::Error>> {
        Ok(ImageIdentityV1 {
            lean_toolchain: "leanprover/lean4:v4.32.0".to_owned(),
            lean_compiler_githash: "2".repeat(40),
            mathlib_revision: "3".repeat(40),
            canonical_manifest_hash: Sha256::parse(&"1".repeat(64))?,
            package_source_tree_hash: Sha256::parse(&"4".repeat(64))?,
            build_relevant_config_hash: Sha256::parse(&"5".repeat(64))?,
            target_platform: "darwin-arm64-test".to_owned(),
        })
    }

    fn attestation_json(requested: ImageId) -> String {
        format!(
            "{{\"schemaVersion\":1,\"imageId\":\"{requested}\",\"providerId\":\"fixture\",\"status\":\"sealed\",\"identity\":{{\"schemaVersion\":1,\"leanToolchain\":\"leanprover/lean4:v4.32.0\",\"leanCompilerGithash\":\"{}\",\"mathlibRevision\":\"{}\",\"canonicalManifestHash\":\"{}\",\"packageSourceTreeHash\":\"{}\",\"buildRelevantConfigHash\":\"{}\",\"targetPlatform\":\"darwin-arm64-test\"}},\"provider\":{{\"registrySha256\":\"{}\",\"overridesSha256\":\"{}\"}},\"dependencyTreeHash\":\"{}\",\"artifactTreeHash\":\"{}\",\"artifactCount\":7,\"artifactPolicy\":{{\"missingRoots\":[\"Qq\",\"mathlib\"]}},\"sealedAt\":\"2026-07-24T00:00:00.000Z\"}}",
            "2".repeat(40),
            "3".repeat(40),
            "1".repeat(64),
            "4".repeat(64),
            "5".repeat(64),
            "1".repeat(64),
            "6".repeat(64),
            "7".repeat(64),
            "8".repeat(64),
        )
    }

    #[test]
    fn image_id_matches_bun_json_identity() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            image_id(&identity()?).to_string(),
            "bd31ac0053f1686a9d757f1781d8ada79df51a62d5067efa5d05a2a96591ddf9"
        );
        Ok(())
    }

    #[test]
    fn stable_reader_binds_filename_document_and_identity() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = Fixture::new()?;
        let identity = identity()?;
        let requested = image_id(&identity);
        fs::create_dir(fixture.0.join("attestations"))?;
        fs::write(
            fixture.0.join(format!("attestations/{requested}.json")),
            attestation_json(requested),
        )?;
        let root = canonicalize_directory(&fixture.0)?;
        let observed = read_image_attestation(&root, requested)?;
        assert_eq!(observed.attestation.image_id, requested);
        assert_eq!(image_id(&observed.attestation.identity), requested);
        assert_eq!(read_image_attestation(&root, requested)?, observed);
        Ok(())
    }

    #[test]
    fn reader_rejects_symlinked_attestation_store() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let outside = fixture.0.join("outside");
        fs::create_dir(&outside)?;
        symlink(&outside, fixture.0.join("attestations"))?;
        let root = canonicalize_directory(&fixture.0)?;
        assert_eq!(
            read_image_attestation(&root, image_id(&identity()?)).map_err(|error| error.code),
            Err(DiagnosticCode::PATH_ESCAPES_ALLOWED_ROOT)
        );
        Ok(())
    }

    #[test]
    fn shared_image_attestation_contract_cases_match() {
        for line in include_str!("../../../golden/image-attestation-cases.tsv").lines() {
            let mut fields = line.splitn(4, '\t');
            let expected = fields.next();
            let label = fields.next();
            let requested = fields.next().and_then(|value| ImageId::parse(value).ok());
            let json = fields.next();
            assert!(expected.is_some() && label.is_some() && requested.is_some() && json.is_some());
            let accepted = requested
                .zip(json)
                .and_then(|(image, text)| parse_image_attestation(text, image).ok())
                .is_some();
            assert_eq!(accepted, expected == Some("true"), "{label:?}");
        }
    }
}
