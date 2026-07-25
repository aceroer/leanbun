#![cfg(target_os = "macos")]

use leanbun_core::project_id;
use leanbun_evidence::{canonicalize_directory, hash_project_input_tree};
use leanbun_generation::LeanGenerationFaultV1;
use leanbun_managed::{
    ManagedProjectControllerV1, ManagedProjectErrorKind, dry_run_external_adoption_v1,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[test]
fn m41_external_adoption_dry_run_snapshots_without_adopting_or_mutating() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap_or_else(|| panic!("repository root missing"))
        .canonicalize()
        .unwrap_or_else(|error| panic!("repository canonicalization failed: {error}"));
    let project = repository
        .join("test/fixtures/lake-managed-dependency")
        .canonicalize()
        .unwrap_or_else(|error| panic!("M41 fixture canonicalization failed: {error}"));
    let root = canonicalize_directory(&project)
        .unwrap_or_else(|error| panic!("M41 fixture boundary failed: {error}"));
    let before = hash_project_input_tree(&root)
        .unwrap_or_else(|error| panic!("M41 pre-snapshot failed: {error}"));
    let report =
        dry_run_external_adoption_v1(&repository, &project, "leanbun_managed_dependency_fixture")
            .unwrap_or_else(|error| panic!("M41 dry-run failed: {error}"));
    assert_eq!(report.project_tree_sha256, before.tree_hash);
    assert_eq!(report.file_count, before.file_count);
    assert_eq!(report.direct_dependency_count, 1);
    assert_eq!(report.manifest_package_count, 1);
    assert_eq!(report.input_state_name(), "standalone");
    assert!(!project.join(".lake").exists());
    assert_eq!(
        hash_project_input_tree(&root)
            .unwrap_or_else(|error| panic!("M41 post-snapshot failed: {error}")),
        before
    );
    let record = repository
        .join(".leanbun-dev-rust/managed-projects/registry")
        .join(format!("{}.record", report.project_id));
    assert!(!record.exists());
    let prefix = format!("m41-adoption-dry-run-{}-", std::process::id());
    assert!(
        fs::read_dir(repository.join(".leanbun-dev/tmp"))
            .unwrap_or_else(|error| panic!("M41 staging parent read failed: {error}"))
            .all(|entry| !entry
                .unwrap_or_else(|error| panic!("M41 staging entry failed: {error}"))
                .file_name()
                .to_string_lossy()
                .starts_with(&prefix))
    );
}

#[test]
fn repository_fixture_cross_process_model_adopts_recovers_updates_and_rolls_back() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap_or_else(|| panic!("repository root missing"))
        .canonicalize()
        .unwrap_or_else(|error| panic!("repository canonicalization failed: {error}"));
    let root = repository
        .join(".leanbun-dev-rust/managed-fixture/m39-controller")
        .join(std::process::id().to_string());
    if root.exists() {
        make_writable(&root);
        fs::remove_dir_all(&root)
            .unwrap_or_else(|error| panic!("stale fixture cleanup failed: {error}"));
    }
    fs::create_dir_all(&root).unwrap_or_else(|error| panic!("fixture root failed: {error}"));
    let project = root.join("project");
    fs::create_dir(&project).unwrap_or_else(|error| panic!("project root failed: {error}"));
    copy_tree(&repository.join("test/fixtures/lake-basic"), &project);
    let project = project
        .canonicalize()
        .unwrap_or_else(|error| panic!("project canonicalization failed: {error}"));
    let controller = ManagedProjectControllerV1::open(&repository, &project, "/usr/bin/true")
        .unwrap_or_else(|error| panic!("controller open failed: {error}"));
    assert!(
        controller
            .adopt_with_fault(
                "leanbun_lake_fixture",
                LeanGenerationFaultV1::BeforeActiveRename,
            )
            .is_err()
    );
    assert!(matches!(
        controller.recover(),
        Err(error) if error.kind == ManagedProjectErrorKind::NotAdopted
    ));
    let adopted = controller
        .adopt("leanbun_lake_fixture")
        .unwrap_or_else(|error| panic!("adopt failed: {error}"));
    assert!(adopted.previous_transaction.is_none());
    assert_eq!(controller.status(), Ok(adopted.clone()));

    let failed = controller.update_with_fault(LeanGenerationFaultV1::BeforeActiveRename);
    assert!(failed.is_err());
    let pending = controller
        .status()
        .unwrap_or_else(|error| panic!("pending status failed: {error}"));
    assert!(pending.pending_transaction.is_some());
    let recovered = controller
        .recover()
        .unwrap_or_else(|error| panic!("update recovery failed: {error}"));
    assert_eq!(recovered.active_transaction, adopted.active_transaction);
    assert!(recovered.pending_transaction.is_none());

    let updated = controller
        .update()
        .unwrap_or_else(|error| panic!("update failed: {error}"));
    assert_ne!(updated.active_transaction, adopted.active_transaction);
    assert_eq!(
        updated.previous_transaction,
        Some(adopted.active_transaction)
    );
    let rolled_back = controller
        .rollback()
        .unwrap_or_else(|error| panic!("rollback failed: {error}"));
    assert_eq!(rolled_back.active_transaction, adopted.active_transaction);
    assert_eq!(
        rolled_back.previous_transaction,
        Some(updated.active_transaction)
    );

    fs::write(project.join("lean-toolchain"), "leanprover/lean4:v4.31.0\n")
        .unwrap_or_else(|error| panic!("toolchain drift injection failed: {error}"));
    assert!(matches!(
        controller.status(),
        Err(error) if error.kind == ManagedProjectErrorKind::InputDrift
    ));

    cleanup(&repository, &project, &root);
}

#[test]
fn repository_dependency_fixture_is_snapshotted_into_bun_decided_generation() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap_or_else(|| panic!("repository root missing"))
        .canonicalize()
        .unwrap_or_else(|error| panic!("repository canonicalization failed: {error}"));
    let root = repository
        .join(".leanbun-dev-rust/managed-fixture/m40-controller")
        .join(std::process::id().to_string());
    if root.exists() {
        make_writable(&root);
        fs::remove_dir_all(&root)
            .unwrap_or_else(|error| panic!("stale fixture cleanup failed: {error}"));
    }
    fs::create_dir_all(&root).unwrap_or_else(|error| panic!("fixture root failed: {error}"));
    let project = root.join("project");
    fs::create_dir(&project).unwrap_or_else(|error| panic!("project root failed: {error}"));
    copy_tree(
        &repository.join("test/fixtures/lake-managed-dependency"),
        &project,
    );
    let project = project
        .canonicalize()
        .unwrap_or_else(|error| panic!("project canonicalization failed: {error}"));
    let source_file = project.join("vendor/managed_dep/ManagedDep/Basic.lean");
    let source_before = fs::read(&source_file)
        .unwrap_or_else(|error| panic!("dependency source read failed: {error}"));
    let controller = ManagedProjectControllerV1::open(&repository, &project, "/usr/bin/true")
        .unwrap_or_else(|error| panic!("controller open failed: {error}"));
    let adopted = controller
        .adopt("leanbun_managed_dependency_fixture")
        .unwrap_or_else(|error| panic!("dependency adopt failed: {error}"));
    assert_eq!(adopted.package_count, 1);
    let id = project_id(
        project
            .to_str()
            .unwrap_or_else(|| panic!("project path is not UTF-8")),
    );
    let generation = repository
        .join(".leanbun-dev-rust/managed-projects/generation-state/projects")
        .join(id.to_string())
        .join("generations")
        .join(adopted.active_transaction.as_str());
    let generated_package = generation.join("packages/managed_dep");
    let generated_source = generated_package.join("ManagedDep/Basic.lean");
    assert!(generated_source.is_file());
    let runtime = fs::read_to_string(generation.join("runtime-packages.json"))
        .unwrap_or_else(|error| panic!("runtime projection read failed: {error}"));
    assert!(runtime.contains("packages/managed_dep"));
    assert!(!runtime.contains("vendor/managed_dep"));
    assert_eq!(
        fs::read(&source_file)
            .unwrap_or_else(|error| panic!("dependency source reread failed: {error}")),
        source_before
    );
    assert!(!project.join("vendor/managed_dep/.lake").exists());
    fs::set_permissions(&generated_package, fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|error| panic!("package cache permission setup failed: {error}"));
    fs::create_dir(generated_package.join(".lake"))
        .unwrap_or_else(|error| panic!("package cache setup failed: {error}"));
    fs::write(generated_package.join(".lake/derived.cache"), b"derived\n")
        .unwrap_or_else(|error| panic!("package cache write failed: {error}"));
    fs::set_permissions(&generated_package, fs::Permissions::from_mode(0o555))
        .unwrap_or_else(|error| panic!("package reseal failed: {error}"));
    assert_eq!(controller.status(), Ok(adopted));
    fs::set_permissions(&generated_source, fs::Permissions::from_mode(0o644))
        .unwrap_or_else(|error| panic!("source tamper permission failed: {error}"));
    fs::write(&generated_source, b"def tampered : Bool := true\n")
        .unwrap_or_else(|error| panic!("source tamper failed: {error}"));
    assert!(matches!(
        controller.status(),
        Err(error) if error.kind == ManagedProjectErrorKind::Generation
    ));
    cleanup(&repository, &project, &root);
}

fn cleanup(repository: &Path, project: &Path, fixture_root: &Path) {
    let id = project_id(
        project
            .to_str()
            .unwrap_or_else(|| panic!("project path is not UTF-8")),
    );
    for path in [
        repository
            .join(".leanbun-dev-rust/managed-projects/registry")
            .join(format!("{id}.record")),
        repository
            .join(".leanbun-dev-rust/managed-projects/generation-state/projects")
            .join(id.to_string()),
        repository
            .join(".leanbun-dev-rust/managed-projects/project-control")
            .join(id.to_string()),
        repository
            .join(".leanbun-dev/store-fixture/m40-managed")
            .join(id.to_string()),
    ] {
        if path.is_dir() {
            make_writable(&path);
            fs::remove_dir_all(&path)
                .unwrap_or_else(|error| panic!("managed state cleanup failed: {error}"));
        } else if path.is_file() {
            fs::remove_file(&path)
                .unwrap_or_else(|error| panic!("managed record cleanup failed: {error}"));
        }
    }
    make_writable(fixture_root);
    fs::remove_dir_all(fixture_root)
        .unwrap_or_else(|error| panic!("fixture cleanup failed: {error}"));
    if let Some(parent) = fixture_root.parent() {
        match fs::remove_dir(parent) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                ) => {}
            Err(error) => panic!("fixture parent cleanup failed: {error}"),
        }
    }
}

fn copy_tree(source: &Path, destination: &Path) {
    for entry in fs::read_dir(source).unwrap_or_else(|error| panic!("source read failed: {error}"))
    {
        let entry = entry.unwrap_or_else(|error| panic!("source entry failed: {error}"));
        let kind = entry
            .file_type()
            .unwrap_or_else(|error| panic!("source type failed: {error}"));
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            fs::create_dir(&target)
                .unwrap_or_else(|error| panic!("copy directory failed: {error}"));
            copy_tree(&entry.path(), &target);
        } else if kind.is_file() {
            fs::copy(entry.path(), target)
                .unwrap_or_else(|error| panic!("copy file failed: {error}"));
        } else {
            panic!("registered fixture contains a symlink or special file");
        }
    }
}

fn make_writable(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_dir() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                make_writable(&entry.path());
            }
        }
    } else if metadata.file_type().is_file() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
}
