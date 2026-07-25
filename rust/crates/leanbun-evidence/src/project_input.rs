use leanbun_core::DiagnosticCode;
use std::fs;
use std::io;

use crate::{
    CanonicalDirectory, CanonicalPath, EvidenceError, ProjectPackageSource,
    ProjectProviderComparison, ProjectProviderMatchState, StableProjectManifestFile,
    StableProviderOverrideFile, StableProviderPair, StableTextFile, canonicalize_contained,
    compare_project_manifest_to_provider, read_project_manifest, read_provider_override,
    read_stable_text,
};

const TOOLCHAIN_MAX_BYTES: u64 = 16 * 1024;
const TOOLCHAIN_FILE: &str = "lean-toolchain";
const MANIFEST_FILE: &str = "lake-manifest.json";
const OVERRIDE_FILE: &str = ".lake/package-overrides.json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectInputState {
    DependencyFree,
    Standalone,
    ProviderBound,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectPathPackage {
    pub name: String,
    pub directory: CanonicalPath,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableProjectInput {
    pub project_root: CanonicalDirectory,
    pub state: ProjectInputState,
    pub toolchain_file: StableTextFile,
    pub toolchain: String,
    pub manifest: StableProjectManifestFile,
    pub overrides: Option<StableProviderOverrideFile>,
    pub path_packages: Vec<ProjectPathPackage>,
    pub provider_comparison: Option<ProjectProviderComparison>,
}

pub fn read_project_input(
    project_root: &CanonicalDirectory,
    provider: Option<&StableProviderPair>,
) -> Result<StableProjectInput, EvidenceError> {
    let toolchain_file = read_stable_text(project_root, TOOLCHAIN_FILE, TOOLCHAIN_MAX_BYTES)?;
    let toolchain = validate_toolchain(&toolchain_file.text)?;
    let manifest = read_project_manifest(project_root, MANIFEST_FILE)?;
    let overrides = read_optional_override(project_root)?;
    let path_packages = resolve_path_packages(project_root, &manifest)?;

    let (state, provider_comparison) = classify_input(&manifest, overrides.as_ref(), provider)?;

    let toolchain_after = read_stable_text(project_root, TOOLCHAIN_FILE, TOOLCHAIN_MAX_BYTES)?;
    let manifest_after = read_project_manifest(project_root, MANIFEST_FILE)?;
    let overrides_after = read_optional_override(project_root)?;
    let path_packages_after = resolve_path_packages(project_root, &manifest_after)?;
    if toolchain_file.sha256 != toolchain_after.sha256
        || manifest.file.sha256 != manifest_after.file.sha256
        || optional_sha(&overrides) != optional_sha(&overrides_after)
        || path_packages != path_packages_after
    {
        return Err(EvidenceError::new(
            DiagnosticCode::EVIDENCE_CHANGED_DURING_READ,
            "project toolchain, manifest, override, or path package changed during input verification",
        ));
    }

    Ok(StableProjectInput {
        project_root: project_root.clone(),
        state,
        toolchain_file,
        toolchain,
        manifest,
        overrides,
        path_packages,
        provider_comparison,
    })
}

fn validate_toolchain(text: &str) -> Result<String, EvidenceError> {
    let toolchain = text.trim();
    if toolchain.is_empty()
        || !toolchain.is_ascii()
        || !toolchain.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'+' | b'-')
        })
    {
        return Err(EvidenceError::new(
            DiagnosticCode::TOOLCHAIN_INVALID,
            "lean-toolchain must be one non-empty ASCII toolchain identifier",
        ));
    }
    Ok(toolchain.to_owned())
}

fn read_optional_override(
    project_root: &CanonicalDirectory,
) -> Result<Option<StableProviderOverrideFile>, EvidenceError> {
    let candidate = project_root.as_path().join(OVERRIDE_FILE);
    match fs::symlink_metadata(&candidate) {
        Ok(_) => read_provider_override(project_root, OVERRIDE_FILE).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(EvidenceError::new(
            DiagnosticCode::EVIDENCE_READ_FAILED,
            format!("project override cannot be inspected: {error}"),
        )),
    }
}

fn resolve_path_packages(
    project_root: &CanonicalDirectory,
    manifest: &StableProjectManifestFile,
) -> Result<Vec<ProjectPathPackage>, EvidenceError> {
    let mut packages = Vec::new();
    for package in &manifest.manifest.packages {
        let ProjectPackageSource::Path { directory } = &package.source else {
            continue;
        };
        let canonical = canonicalize_contained(project_root, directory)?;
        let metadata = fs::metadata(canonical.as_path()).map_err(|error| {
            EvidenceError::new(
                DiagnosticCode::EVIDENCE_READ_FAILED,
                format!("project path package cannot be inspected: {error}"),
            )
        })?;
        if !metadata.is_dir() {
            return Err(EvidenceError::new(
                DiagnosticCode::PROJECT_NOT_DIRECTORY,
                format!(
                    "project path package is not a directory: {}",
                    canonical.as_path().display()
                ),
            ));
        }
        packages.push(ProjectPathPackage {
            name: package.name.clone(),
            directory: canonical,
        });
    }
    packages.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(packages)
}

fn classify_input(
    manifest: &StableProjectManifestFile,
    overrides: Option<&StableProviderOverrideFile>,
    provider: Option<&StableProviderPair>,
) -> Result<(ProjectInputState, Option<ProjectProviderComparison>), EvidenceError> {
    if manifest.manifest.packages.is_empty() {
        if overrides.is_some() {
            return Err(EvidenceError::new(
                DiagnosticCode::OVERRIDE_DRIFTED,
                "dependency-free project must not contain package overrides",
            ));
        }
        return Ok((ProjectInputState::DependencyFree, None));
    }

    let Some(provider) = provider else {
        return Ok((ProjectInputState::Standalone, None));
    };
    let comparison =
        compare_project_manifest_to_provider(&manifest.manifest, &provider.registry.registry);
    if comparison.state != ProjectProviderMatchState::Matched {
        return Err(EvidenceError::new(
            DiagnosticCode::MANIFEST_PROVIDER_MISMATCH,
            format!(
                "project manifest differs from provider registry in {} field(s)",
                comparison.mismatches.len()
            ),
        ));
    }
    let overrides = overrides.ok_or_else(|| {
        EvidenceError::new(
            DiagnosticCode::OVERRIDE_MISSING,
            "provider-bound project is missing .lake/package-overrides.json",
        )
    })?;
    if overrides.overrides != provider.overrides.overrides
        || overrides.file.sha256 != provider.overrides.file.sha256
    {
        return Err(EvidenceError::new(
            DiagnosticCode::OVERRIDE_DRIFTED,
            "project override differs from provider override typed content or SHA-256",
        ));
    }
    Ok((ProjectInputState::ProviderBound, Some(comparison)))
}

fn optional_sha(value: &Option<StableProviderOverrideFile>) -> Option<leanbun_core::Sha256> {
    value.as_ref().map(|value| value.file.sha256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{canonicalize_directory, read_provider_pair};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    const REVISION: &str = "81a5d257c8e410db227a6665ed08f64fea08e997";

    struct Fixture(PathBuf);

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture(label: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!("leanbun-{label}-{nonce}"));
        fs::create_dir_all(&path)?;
        Ok(Fixture(path.canonicalize()?))
    }

    fn write_toolchain_and_manifest(
        project: &std::path::Path,
        packages: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        fs::write(project.join(TOOLCHAIN_FILE), "leanprover/lean4:v4.32.0\n")?;
        fs::write(
            project.join(MANIFEST_FILE),
            format!(
                r#"{{"version":"1.2.0","packagesDir":".lake/packages","packages":[{packages}],"name":"fixture","lakeDir":".lake","fixedToolchain":false}}"#
            ),
        )?;
        Ok(())
    }

    #[test]
    fn dependency_free_and_contained_path_projects_publish_expected_states()
    -> Result<(), Box<dyn std::error::Error>> {
        let free = fixture("input-free")?;
        write_toolchain_and_manifest(&free.0, "")?;
        let free_root = canonicalize_directory(&free.0)?;
        assert_eq!(
            read_project_input(&free_root, None)?.state,
            ProjectInputState::DependencyFree
        );

        let path = fixture("input-path")?;
        fs::create_dir(path.0.join("dependency"))?;
        write_toolchain_and_manifest(
            &path.0,
            r#"{"name":"local","type":"path","dir":"dependency"}"#,
        )?;
        let path_root = canonicalize_directory(&path.0)?;
        let observed = read_project_input(&path_root, None)?;
        assert_eq!(observed.state, ProjectInputState::Standalone);
        assert_eq!(observed.path_packages.len(), 1);
        Ok(())
    }

    #[test]
    fn path_escape_and_invalid_toolchain_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("input-reject")?;
        write_toolchain_and_manifest(
            &fixture.0,
            r#"{"name":"escape","type":"path","dir":"../outside"}"#,
        )?;
        let root = canonicalize_directory(&fixture.0)?;
        assert!(matches!(
            read_project_input(&root, None),
            Err(error) if error.code == DiagnosticCode::PATH_ESCAPES_ALLOWED_ROOT
        ));

        fs::write(fixture.0.join(TOOLCHAIN_FILE), "bad toolchain\n")?;
        assert!(matches!(
            read_project_input(&root, None),
            Err(error) if error.code == DiagnosticCode::TOOLCHAIN_INVALID
        ));
        Ok(())
    }

    #[test]
    fn exact_override_and_manifest_publish_provider_bound_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("input-bound")?;
        let provider_root = fixture.0.join("provider");
        let package = provider_root.join("packages/mathlib");
        fs::create_dir_all(&package)?;
        let registry = format!(
            r#"{{"version":"1.2.0","packagesDir":".lake/packages","packages":[{{"name":"mathlib","type":"git","rev":"{REVISION}"}}]}}"#
        );
        let overrides = format!(
            r#"{{"version":"1.2.0","packages":[{{"name":"mathlib","type":"path","dir":"{}"}}]}}"#,
            package.display()
        );
        fs::write(provider_root.join("registry.json"), &registry)?;
        fs::write(provider_root.join("overrides.json"), &overrides)?;
        let provider_root = canonicalize_directory(&provider_root)?;
        let provider = read_provider_pair(
            &provider_root,
            "registry.json",
            "overrides.json",
            "packages",
        )?;

        let project = fixture.0.join("project");
        fs::create_dir_all(project.join(".lake"))?;
        write_toolchain_and_manifest(
            &project,
            &format!(r#"{{"name":"mathlib","type":"git","rev":"{REVISION}"}}"#),
        )?;
        fs::write(project.join(OVERRIDE_FILE), &overrides)?;
        let project_root = canonicalize_directory(&project)?;
        let observed = read_project_input(&project_root, Some(&provider))?;
        assert_eq!(observed.state, ProjectInputState::ProviderBound);
        assert!(matches!(
            observed.provider_comparison,
            Some(ProjectProviderComparison {
                state: ProjectProviderMatchState::Matched,
                ..
            })
        ));
        Ok(())
    }
}
