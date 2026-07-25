use leanbun_evidence::{
    ProjectInputState, ProjectProviderMatchState, canonicalize_directory,
    compare_project_manifest_to_provider, derive_project_input_identity, read_project_input,
    read_project_manifest, read_provider_pair,
};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

struct TemporaryProject(PathBuf);

impl Drop for TemporaryProject {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "requires the initialized .leanbun-dev provider snapshot"]
fn isolated_development_provider_pair_matches_typed_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let lean_root = repository.join(".leanbun-dev/lean");
    let root = canonicalize_directory(&lean_root)?;
    let observed = read_provider_pair(
        &root,
        "registry/manifest.json",
        "overrides/package-overrides.json",
        "package-set/packages",
    )?;

    assert_eq!(observed.registry.registry.version, "1.2.0");
    assert_eq!(observed.registry.registry.packages_dir, ".lake/packages");
    assert_eq!(observed.overrides.overrides.version, "1.2.0");
    assert_eq!(observed.packages.len(), 9);
    assert!(observed.packages.iter().any(|package| {
        package.name == "mathlib" && package.revision == "81a5d257c8e410db227a6665ed08f64fea08e997"
    }));
    assert!(observed.packages.iter().all(|package| {
        package
            .directory
            .as_path()
            .starts_with(observed.package_root.as_path())
    }));

    let project_root = canonicalize_directory(repository.join("test/fixtures/mathlib-project"))?;
    let manifest = read_project_manifest(&project_root, "lake-manifest.json")?;
    let comparison =
        compare_project_manifest_to_provider(&manifest.manifest, &observed.registry.registry);
    assert_eq!(comparison.state, ProjectProviderMatchState::Matched);
    assert!(comparison.mismatches.is_empty());

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temporary =
        TemporaryProject(std::env::temp_dir().join(format!("leanbun-nine-package-input-{nonce}")));
    fs::create_dir_all(temporary.0.join(".lake"))?;
    fs::copy(
        project_root.as_path().join("lean-toolchain"),
        temporary.0.join("lean-toolchain"),
    )?;
    fs::copy(
        project_root.as_path().join("lake-manifest.json"),
        temporary.0.join("lake-manifest.json"),
    )?;
    fs::copy(
        lean_root.join("overrides/package-overrides.json"),
        temporary.0.join(".lake/package-overrides.json"),
    )?;
    let temporary_root = canonicalize_directory(&temporary.0)?;
    let input = read_project_input(&temporary_root, Some(&observed))?;
    assert_eq!(input.state, ProjectInputState::ProviderBound);
    assert_eq!(input.manifest.manifest.packages.len(), 9);
    assert!(input.path_packages.is_empty());
    let identity = derive_project_input_identity(&input, Some(&observed))?;
    assert_eq!(identity.project_id.to_string().len(), 64);
    assert_eq!(identity.digest.to_string().len(), 64);
    assert!(identity.canonical_bytes.len() > 512);
    Ok(())
}
