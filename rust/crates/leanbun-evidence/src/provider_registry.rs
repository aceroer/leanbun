use leanbun_core::DiagnosticCode;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::{
    CanonicalDirectory, EvidenceError, StableTextFile, StrictJson, parse_strict_json,
    read_stable_text,
};

pub const PROVIDER_REGISTRY_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_PROVIDER_PACKAGES: usize = 4_096;
const MAX_SHORT_STRING_BYTES: usize = 256;
const MAX_URL_BYTES: usize = 4_096;

const ROOT_FIELDS: &[&str] = &["packages", "packagesDir", "version"];
const PACKAGE_FIELDS: &[&str] = &[
    "configFile",
    "inherited",
    "inputRev",
    "manifestFile",
    "name",
    "rev",
    "scope",
    "subDir",
    "type",
    "url",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRegistryPackage {
    pub name: String,
    pub revision: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRegistry {
    pub version: String,
    pub packages_dir: String,
    pub packages: Vec<ProviderRegistryPackage>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableProviderRegistryFile {
    pub file: StableTextFile,
    pub registry: ProviderRegistry,
}

pub fn read_provider_registry(
    root: &CanonicalDirectory,
    candidate: impl AsRef<Path>,
) -> Result<StableProviderRegistryFile, EvidenceError> {
    let file = read_stable_text(root, candidate, PROVIDER_REGISTRY_MAX_BYTES)?;
    let registry = parse_provider_registry(&file.text)?;
    Ok(StableProviderRegistryFile { file, registry })
}

pub fn parse_provider_registry(text: &str) -> Result<ProviderRegistry, EvidenceError> {
    decode_provider_registry(&parse_strict_json(text)?)
}

pub fn decode_provider_registry(value: &StrictJson) -> Result<ProviderRegistry, EvidenceError> {
    let root = object(value, "provider registry root")?;
    reject_unknown_fields(root, ROOT_FIELDS, "provider registry root")?;

    let version = required_string(root, "version", MAX_SHORT_STRING_BYTES, "provider registry")?;
    if !supported_lake_version(version) {
        return Err(EvidenceError::new(
            DiagnosticCode::MANIFEST_SCHEMA_UNSUPPORTED,
            format!("provider registry schema {version} is not supported; supported major=1"),
        ));
    }
    let packages_dir = required_string(
        root,
        "packagesDir",
        MAX_SHORT_STRING_BYTES,
        "provider registry",
    )?;
    if packages_dir.is_empty() {
        return Err(shape("provider registry packagesDir must not be empty"));
    }

    let packages = match root.get("packages") {
        Some(StrictJson::Array(values)) => values,
        Some(_) => return Err(shape("provider registry packages must be an array")),
        None => return Err(shape("provider registry is missing packages")),
    };
    if packages.len() > MAX_PROVIDER_PACKAGES {
        return Err(shape(format!(
            "provider registry package count {} exceeds limit {MAX_PROVIDER_PACKAGES}",
            packages.len()
        )));
    }

    let mut names = BTreeSet::new();
    let mut decoded = Vec::with_capacity(packages.len());
    for (index, package) in packages.iter().enumerate() {
        let label = format!("provider registry package {index}");
        let package = object(package, &label)?;
        reject_unknown_fields(package, PACKAGE_FIELDS, &label)?;

        let name = required_string(package, "name", MAX_SHORT_STRING_BYTES, &label)?;
        if name.is_empty() {
            return Err(shape(format!("{label} name must not be empty")));
        }
        if !names.insert(name) {
            return Err(shape(format!("duplicate provider package name: {name}")));
        }

        let package_type = required_string(package, "type", MAX_SHORT_STRING_BYTES, &label)?;
        if package_type != "git" {
            return Err(shape(format!("{label} type must be git")));
        }
        let revision = required_string(package, "rev", MAX_SHORT_STRING_BYTES, &label)?;
        if revision.len() != 40
            || !revision
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(shape(format!(
                "{label} rev must be 40 lowercase hexadecimal bytes"
            )));
        }

        optional_string(package, "url", MAX_URL_BYTES, &label)?;
        optional_nullable_string(package, "subDir", MAX_SHORT_STRING_BYTES, &label)?;
        for field in ["scope", "manifestFile", "inputRev", "configFile"] {
            optional_string(package, field, MAX_SHORT_STRING_BYTES, &label)?;
        }
        if let Some(value) = package.get("inherited")
            && !matches!(value, StrictJson::Bool(_))
        {
            return Err(shape(format!("{label} inherited must be a boolean")));
        }

        decoded.push(ProviderRegistryPackage {
            name: name.to_owned(),
            revision: revision.to_owned(),
        });
    }

    Ok(ProviderRegistry {
        version: version.to_owned(),
        packages_dir: packages_dir.to_owned(),
        packages: decoded,
    })
}

fn object<'a>(
    value: &'a StrictJson,
    label: &str,
) -> Result<&'a BTreeMap<String, StrictJson>, EvidenceError> {
    match value {
        StrictJson::Object(value) => Ok(value),
        _ => Err(shape(format!("{label} must be an object"))),
    }
}

fn reject_unknown_fields(
    value: &BTreeMap<String, StrictJson>,
    allowed: &[&str],
    label: &str,
) -> Result<(), EvidenceError> {
    if let Some(field) = value
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(shape(format!("{label} has unknown field: {field}")));
    }
    Ok(())
}

fn required_string<'a>(
    value: &'a BTreeMap<String, StrictJson>,
    field: &str,
    maximum_bytes: usize,
    label: &str,
) -> Result<&'a str, EvidenceError> {
    match value.get(field) {
        Some(StrictJson::String(value)) if value.len() <= maximum_bytes => Ok(value),
        Some(StrictJson::String(_)) => Err(shape(format!(
            "{label} {field} exceeds {maximum_bytes} bytes"
        ))),
        Some(_) => Err(shape(format!("{label} {field} must be a string"))),
        None => Err(shape(format!("{label} is missing {field}"))),
    }
}

fn optional_string(
    value: &BTreeMap<String, StrictJson>,
    field: &str,
    maximum_bytes: usize,
    label: &str,
) -> Result<(), EvidenceError> {
    if value.contains_key(field) {
        required_string(value, field, maximum_bytes, label)?;
    }
    Ok(())
}

fn optional_nullable_string(
    value: &BTreeMap<String, StrictJson>,
    field: &str,
    maximum_bytes: usize,
    label: &str,
) -> Result<(), EvidenceError> {
    match value.get(field) {
        None | Some(StrictJson::Null) => Ok(()),
        Some(StrictJson::String(value)) if value.len() <= maximum_bytes => Ok(()),
        Some(StrictJson::String(_)) => Err(shape(format!(
            "{label} {field} exceeds {maximum_bytes} bytes"
        ))),
        Some(_) => Err(shape(format!("{label} {field} must be null or a string"))),
    }
}

fn supported_lake_version(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(major) = parts.next() else {
        return false;
    };
    let Some(minor) = parts.next() else {
        return false;
    };
    let Some(patch) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && [major, minor, patch]
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        && major.parse::<u64>() == Ok(1)
}

fn shape(message: impl Into<String>) -> EvidenceError {
    EvidenceError::new(DiagnosticCode::PROVIDER_SCHEMA_INVALID, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonicalize_directory;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    const REVISION: &str = "81a5d257c8e410db227a6665ed08f64fea08e997";

    #[test]
    fn shared_provider_registry_contract_cases_match() {
        for line in include_str!("../../../golden/provider-registry-cases.tsv").lines() {
            let mut fields = line.splitn(3, '\t');
            let expected = fields.next() == Some("true");
            let label = fields.next().unwrap_or("");
            let text = fields.next().unwrap_or("");
            assert_eq!(parse_provider_registry(text).is_ok(), expected, "{label}");
        }
    }

    #[test]
    fn registry_package_count_and_string_limits_are_enforced() {
        let package = format!(r#"{{"name":"p","type":"git","rev":"{REVISION}"}}"#);
        let packages = std::iter::repeat_n(package, MAX_PROVIDER_PACKAGES + 1)
            .collect::<Vec<_>>()
            .join(",");
        let oversized = format!(
            r#"{{"version":"1.2.0","packagesDir":".lake/packages","packages":[{packages}]}}"#
        );
        assert!(matches!(
            parse_provider_registry(&oversized),
            Err(error) if error.code == DiagnosticCode::PROVIDER_SCHEMA_INVALID
        ));

        let long_name = "a".repeat(MAX_SHORT_STRING_BYTES + 1);
        let long_string = format!(
            r#"{{"version":"1.2.0","packagesDir":".lake/packages","packages":[{{"name":"{long_name}","type":"git","rev":"{REVISION}"}}]}}"#
        );
        assert!(matches!(
            parse_provider_registry(&long_string),
            Err(error) if error.code == DiagnosticCode::PROVIDER_SCHEMA_INVALID
        ));
    }

    #[test]
    fn stable_registry_read_keeps_hash_and_typed_document_together()
    -> Result<(), Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let fixture = std::env::temp_dir().join(format!("leanbun-registry-{nonce}"));
        fs::create_dir(&fixture)?;
        let text = format!(
            r#"{{"version":"1.2.0","packagesDir":".lake/packages","packages":[{{"name":"mathlib","type":"git","rev":"{REVISION}"}}]}}"#
        );
        fs::write(fixture.join("registry.json"), &text)?;
        let root = canonicalize_directory(&fixture)?;
        let result = read_provider_registry(&root, "registry.json")?;
        assert_eq!(result.registry.packages[0].name, "mathlib");
        assert_eq!(result.registry.packages[0].revision, REVISION);
        assert_eq!(result.file.size, u64::try_from(text.len())?);
        fs::remove_dir_all(fixture)?;
        Ok(())
    }
}
