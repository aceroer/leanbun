use leanbun_core::{DiagnosticCode, ProjectId, Sha256, Sha256Hasher, project_id};
use std::collections::BTreeSet;

use crate::{
    EvidenceError, ProjectInputState, ProjectPackageSource, StableProjectInput, StableProviderPair,
};

pub const PROJECT_INPUT_IDENTITY_SCHEMA: &str = "leanbun-project-input-identity-v1";
const HEADER: &[u8] = b"leanbun-project-input-identity-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectInputIdentityPackageKind {
    Git,
    Path,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectInputIdentityPackage {
    pub name: String,
    pub kind: ProjectInputIdentityPackageKind,
    pub revision: Option<String>,
    pub path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectInputIdentityMaterial {
    pub project_path: String,
    pub state: ProjectInputState,
    pub toolchain: String,
    pub toolchain_sha256: Sha256,
    pub manifest_sha256: Sha256,
    pub override_sha256: Option<Sha256>,
    pub provider_registry_sha256: Option<Sha256>,
    pub provider_override_sha256: Option<Sha256>,
    pub packages: Vec<ProjectInputIdentityPackage>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectInputIdentityV1 {
    pub project_id: ProjectId,
    pub digest: Sha256,
    pub canonical_bytes: Vec<u8>,
}

pub fn derive_project_input_identity(
    input: &StableProjectInput,
    provider: Option<&StableProviderPair>,
) -> Result<ProjectInputIdentityV1, EvidenceError> {
    let project_path = utf8_path(input.project_root.as_path(), "project root")?;
    let (provider_registry_sha256, provider_override_sha256) = match input.state {
        ProjectInputState::ProviderBound => {
            let provider = provider.ok_or_else(|| {
                identity_error("provider-bound input identity requires provider evidence")
            })?;
            let project_override = input.overrides.as_ref().ok_or_else(|| {
                identity_error("provider-bound input identity requires project override evidence")
            })?;
            if project_override.file.sha256 != provider.overrides.file.sha256 {
                return Err(identity_error(
                    "provider-bound input override no longer matches provider evidence",
                ));
            }
            (
                Some(provider.registry.file.sha256),
                Some(provider.overrides.file.sha256),
            )
        }
        ProjectInputState::DependencyFree | ProjectInputState::Standalone => {
            if provider.is_some() {
                return Err(identity_error(
                    "non-provider-bound input identity must not accept provider evidence",
                ));
            }
            (None, None)
        }
    };

    let mut packages = Vec::with_capacity(input.manifest.manifest.packages.len());
    for package in &input.manifest.manifest.packages {
        match &package.source {
            ProjectPackageSource::Git { revision } => {
                let path = if let Some(provider) = provider {
                    let binding = provider
                        .packages
                        .iter()
                        .find(|binding| binding.name == package.name)
                        .ok_or_else(|| {
                            identity_error(format!(
                                "provider identity lacks package binding: {}",
                                package.name
                            ))
                        })?;
                    if binding.revision != *revision {
                        return Err(identity_error(format!(
                            "provider identity revision differs for package: {}",
                            package.name
                        )));
                    }
                    Some(utf8_path(
                        binding.directory.as_path(),
                        "provider package directory",
                    )?)
                } else {
                    None
                };
                packages.push(ProjectInputIdentityPackage {
                    name: package.name.clone(),
                    kind: ProjectInputIdentityPackageKind::Git,
                    revision: Some(revision.clone()),
                    path,
                });
            }
            ProjectPackageSource::Path { .. } => {
                let binding = input
                    .path_packages
                    .iter()
                    .find(|binding| binding.name == package.name)
                    .ok_or_else(|| {
                        identity_error(format!(
                            "project input lacks path package binding: {}",
                            package.name
                        ))
                    })?;
                packages.push(ProjectInputIdentityPackage {
                    name: package.name.clone(),
                    kind: ProjectInputIdentityPackageKind::Path,
                    revision: None,
                    path: Some(utf8_path(
                        binding.directory.as_path(),
                        "project path package directory",
                    )?),
                });
            }
        }
    }

    canonical_project_input_identity(&ProjectInputIdentityMaterial {
        project_path,
        state: input.state,
        toolchain: input.toolchain.clone(),
        toolchain_sha256: input.toolchain_file.sha256,
        manifest_sha256: input.manifest.file.sha256,
        override_sha256: input.overrides.as_ref().map(|value| value.file.sha256),
        provider_registry_sha256,
        provider_override_sha256,
        packages,
    })
}

pub fn canonical_project_input_identity(
    material: &ProjectInputIdentityMaterial,
) -> Result<ProjectInputIdentityV1, EvidenceError> {
    validate_material(material)?;
    let mut canonical = Vec::new();
    canonical.extend_from_slice(HEADER);
    push_field(
        &mut canonical,
        b"projectPath",
        material.project_path.as_bytes(),
    )?;
    push_field(
        &mut canonical,
        b"state",
        state_name(material.state).as_bytes(),
    )?;
    push_field(&mut canonical, b"toolchain", material.toolchain.as_bytes())?;
    push_field(
        &mut canonical,
        b"toolchainSha256",
        material.toolchain_sha256.as_bytes(),
    )?;
    push_field(
        &mut canonical,
        b"manifestSha256",
        material.manifest_sha256.as_bytes(),
    )?;
    push_field(
        &mut canonical,
        b"overrideSha256",
        optional_digest(&material.override_sha256),
    )?;
    push_field(
        &mut canonical,
        b"providerRegistrySha256",
        optional_digest(&material.provider_registry_sha256),
    )?;
    push_field(
        &mut canonical,
        b"providerOverrideSha256",
        optional_digest(&material.provider_override_sha256),
    )?;

    let mut packages = material.packages.clone();
    packages.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    push_field(
        &mut canonical,
        b"packageCount",
        &u64::try_from(packages.len())
            .map_err(|_| identity_error("package count cannot be encoded"))?
            .to_be_bytes(),
    )?;
    for package in packages {
        let mut record = Vec::new();
        push_blob(&mut record, package.name.as_bytes())?;
        record.push(match package.kind {
            ProjectInputIdentityPackageKind::Git => 0,
            ProjectInputIdentityPackageKind::Path => 1,
        });
        push_blob(
            &mut record,
            package.revision.as_deref().unwrap_or("").as_bytes(),
        )?;
        push_blob(
            &mut record,
            package.path.as_deref().unwrap_or("").as_bytes(),
        )?;
        push_field(&mut canonical, b"package", &record)?;
    }

    let mut hasher = Sha256Hasher::new();
    hasher.update(&canonical);
    let digest = hasher.finalize();
    Ok(ProjectInputIdentityV1 {
        project_id: project_id(&material.project_path),
        digest,
        canonical_bytes: canonical,
    })
}

fn validate_material(material: &ProjectInputIdentityMaterial) -> Result<(), EvidenceError> {
    if material.project_path.is_empty() || material.toolchain.is_empty() {
        return Err(identity_error(
            "project input identity path and toolchain must not be empty",
        ));
    }
    match material.state {
        ProjectInputState::DependencyFree => {
            if material.override_sha256.is_some()
                || material.provider_registry_sha256.is_some()
                || material.provider_override_sha256.is_some()
                || !material.packages.is_empty()
            {
                return Err(identity_error(
                    "dependency-free identity must not contain override, provider, or package fields",
                ));
            }
        }
        ProjectInputState::Standalone => {
            if material.provider_registry_sha256.is_some()
                || material.provider_override_sha256.is_some()
            {
                return Err(identity_error(
                    "standalone identity must not contain provider digests",
                ));
            }
        }
        ProjectInputState::ProviderBound => {
            if material.override_sha256.is_none()
                || material.provider_registry_sha256.is_none()
                || material.provider_override_sha256.is_none()
                || material.override_sha256 != material.provider_override_sha256
            {
                return Err(identity_error(
                    "provider-bound identity requires matching override and provider digests",
                ));
            }
        }
    }

    let mut names = BTreeSet::new();
    for package in &material.packages {
        if package.name.is_empty() || !names.insert(package.name.as_str()) {
            return Err(identity_error(
                "project input identity package names must be non-empty and unique",
            ));
        }
        match package.kind {
            ProjectInputIdentityPackageKind::Git => {
                if package.revision.as_deref().is_none_or(str::is_empty) {
                    return Err(identity_error("Git identity package requires revision"));
                }
                if material.state == ProjectInputState::ProviderBound
                    && package.path.as_deref().is_none_or(str::is_empty)
                {
                    return Err(identity_error(
                        "provider-bound Git identity package requires canonical path",
                    ));
                }
                if material.state != ProjectInputState::ProviderBound && package.path.is_some() {
                    return Err(identity_error(
                        "non-provider-bound Git identity package must not contain provider path",
                    ));
                }
            }
            ProjectInputIdentityPackageKind::Path => {
                if material.state == ProjectInputState::ProviderBound
                    || package.revision.is_some()
                    || package.path.as_deref().is_none_or(str::is_empty)
                {
                    return Err(identity_error(
                        "path identity package requires non-provider state, canonical path, and no revision",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn push_field(output: &mut Vec<u8>, key: &[u8], value: &[u8]) -> Result<(), EvidenceError> {
    let key_length = u16::try_from(key.len())
        .map_err(|_| identity_error("identity field name cannot be encoded"))?;
    output.extend_from_slice(&key_length.to_be_bytes());
    output.extend_from_slice(key);
    push_blob(output, value)
}

fn push_blob(output: &mut Vec<u8>, value: &[u8]) -> Result<(), EvidenceError> {
    let length = u64::try_from(value.len())
        .map_err(|_| identity_error("identity field value cannot be encoded"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn optional_digest(value: &Option<Sha256>) -> &[u8] {
    match value {
        Some(digest) => digest.as_bytes(),
        None => &[],
    }
}

const fn state_name(state: ProjectInputState) -> &'static str {
    match state {
        ProjectInputState::DependencyFree => "dependency-free",
        ProjectInputState::Standalone => "standalone",
        ProjectInputState::ProviderBound => "provider-bound",
    }
}

fn utf8_path(path: &std::path::Path, label: &str) -> Result<String, EvidenceError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| identity_error(format!("{label} is not valid UTF-8")))
}

fn identity_error(message: impl Into<String>) -> EvidenceError {
    EvidenceError::new(DiagnosticCode::PROJECT_INPUT_DRIFTED, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    fn missing(field: &str) -> io::Error {
        io::Error::other(format!("golden identity is missing {field}"))
    }

    #[test]
    fn shared_binary_identity_material_matches_bun_oracle() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut project_path = None;
        let mut state = None;
        let mut toolchain = None;
        let mut toolchain_sha256 = None;
        let mut manifest_sha256 = None;
        let mut override_sha256 = None;
        let mut provider_registry_sha256 = None;
        let mut provider_override_sha256 = None;
        let mut packages = Vec::new();
        let mut expected_project_id = None;
        let mut expected_digest = None;

        for line in include_str!("../../../golden/project-input-identity.tsv").lines() {
            let fields = line.split('\t').collect::<Vec<_>>();
            match fields.as_slice() {
                ["projectPath", value] => project_path = Some((*value).to_owned()),
                ["state", "provider-bound"] => state = Some(ProjectInputState::ProviderBound),
                ["toolchain", value] => toolchain = Some((*value).to_owned()),
                ["toolchainSha256", value] => toolchain_sha256 = Some(Sha256::parse(value)?),
                ["manifestSha256", value] => manifest_sha256 = Some(Sha256::parse(value)?),
                ["overrideSha256", value] => override_sha256 = Some(Sha256::parse(value)?),
                ["providerRegistrySha256", value] => {
                    provider_registry_sha256 = Some(Sha256::parse(value)?);
                }
                ["providerOverrideSha256", value] => {
                    provider_override_sha256 = Some(Sha256::parse(value)?);
                }
                ["package", name, "git", revision, path] => {
                    packages.push(ProjectInputIdentityPackage {
                        name: (*name).to_owned(),
                        kind: ProjectInputIdentityPackageKind::Git,
                        revision: Some((*revision).to_owned()),
                        path: Some((*path).to_owned()),
                    });
                }
                ["projectId", value] => expected_project_id = Some(ProjectId::parse(value)?),
                ["digest", value] => expected_digest = Some(Sha256::parse(value)?),
                _ => return Err(io::Error::other(format!("invalid golden line: {line}")).into()),
            }
        }

        let material = ProjectInputIdentityMaterial {
            project_path: project_path.ok_or_else(|| missing("projectPath"))?,
            state: state.ok_or_else(|| missing("state"))?,
            toolchain: toolchain.ok_or_else(|| missing("toolchain"))?,
            toolchain_sha256: toolchain_sha256.ok_or_else(|| missing("toolchainSha256"))?,
            manifest_sha256: manifest_sha256.ok_or_else(|| missing("manifestSha256"))?,
            override_sha256,
            provider_registry_sha256,
            provider_override_sha256,
            packages,
        };
        let identity = canonical_project_input_identity(&material)?;
        assert_eq!(
            identity.project_id,
            expected_project_id.ok_or_else(|| missing("projectId"))?
        );
        assert_eq!(
            identity.digest,
            expected_digest.ok_or_else(|| missing("digest"))?
        );
        assert!(identity.canonical_bytes.starts_with(HEADER));
        Ok(())
    }

    #[test]
    fn identity_validation_rejects_mixed_authority_material() {
        let zero = Sha256::from_bytes([0; 32]);
        let material = ProjectInputIdentityMaterial {
            project_path: "/fixture".to_owned(),
            state: ProjectInputState::ProviderBound,
            toolchain: "leanprover/lean4:v4.32.0".to_owned(),
            toolchain_sha256: zero,
            manifest_sha256: zero,
            override_sha256: None,
            provider_registry_sha256: None,
            provider_override_sha256: None,
            packages: Vec::new(),
        };
        assert!(matches!(
            canonical_project_input_identity(&material),
            Err(error) if error.code == DiagnosticCode::PROJECT_INPUT_DRIFTED
        ));
    }
}
