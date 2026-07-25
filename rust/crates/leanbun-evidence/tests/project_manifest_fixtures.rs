use leanbun_evidence::{
    ProjectInputState, ProjectPackageSource, canonicalize_directory, derive_project_input_identity,
    hash_project_input_tree, read_project_input, read_project_manifest,
};
use std::path::PathBuf;

#[test]
fn tracked_project_manifests_pass_stable_typed_read() -> Result<(), Box<dyn std::error::Error>> {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let fixture_root = repository.join("test/fixtures");
    let root = canonicalize_directory(&fixture_root)?;

    let basic = read_project_manifest(&root, "lake-basic/lake-manifest.json")?;
    assert_eq!(basic.manifest.name, "leanbun_lake_fixture");
    assert!(basic.manifest.packages.is_empty());

    let mathlib = read_project_manifest(&root, "mathlib-project/lake-manifest.json")?;
    assert_eq!(mathlib.manifest.name, "leanbun_mathlib_fixture");
    assert_eq!(mathlib.manifest.packages.len(), 9);
    assert!(mathlib.manifest.packages.iter().any(|package| {
        package.name == "mathlib"
            && matches!(
                &package.source,
                ProjectPackageSource::Git { revision }
                    if revision == "81a5d257c8e410db227a6665ed08f64fea08e997"
            )
    }));

    let managed = read_project_manifest(&root, "lake-managed-dependency/lake-manifest.json")?;
    assert_eq!(managed.manifest.name, "leanbun_managed_dependency_fixture");
    assert_eq!(managed.manifest.packages.len(), 1);
    assert!(matches!(
        &managed.manifest.packages[0].source,
        ProjectPackageSource::Path { directory } if directory == "vendor/managed_dep"
    ));

    let basic_root = canonicalize_directory(fixture_root.join("lake-basic"))?;
    let basic_tree = hash_project_input_tree(&basic_root)?;
    assert_eq!(hash_project_input_tree(&basic_root)?, basic_tree);
    assert!(basic_tree.file_count > 0);
    let basic_input = read_project_input(&basic_root, None)?;
    assert_eq!(basic_input.state, ProjectInputState::DependencyFree);
    let basic_identity = derive_project_input_identity(&basic_input, None)?;
    assert_eq!(
        derive_project_input_identity(&basic_input, None)?,
        basic_identity
    );
    let mathlib_root = canonicalize_directory(fixture_root.join("mathlib-project"))?;
    let mathlib_tree = hash_project_input_tree(&mathlib_root)?;
    assert_ne!(mathlib_tree.tree_hash, basic_tree.tree_hash);
    let mathlib_input = read_project_input(&mathlib_root, None)?;
    assert_eq!(mathlib_input.state, ProjectInputState::Standalone);
    let mathlib_identity = derive_project_input_identity(&mathlib_input, None)?;
    assert_ne!(mathlib_identity.digest, basic_identity.digest);
    Ok(())
}
