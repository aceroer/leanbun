#![cfg(target_os = "macos")]

use leanbun_build::{run_repository_fixture_acceptance_v1, verify_registered_test_project_v1};
use std::path::{Path, PathBuf};

#[test]
fn repository_fixture_completes_failure_build_publication_reuse_and_rollback() {
    let repository = repository();
    let report = run_repository_fixture_acceptance_v1(
        &repository,
        Path::new(env!("CARGO_BIN_EXE_leanbun-process-supervisor")),
    )
    .unwrap_or_else(|error| panic!("M37 repository fixture acceptance failed: {error}"));
    println!("m37-status=passed-and-rolled-back");
    println!("m37-baseline={}", report.baseline_generation_sha256);
    println!("m37-candidate={}", report.candidate_generation_sha256);
    println!("m37-build-image={}", report.build_image_sha256);
    println!("m37-project-artifact={}", report.project_artifact_sha256);
}

#[test]
fn repository_root_is_not_a_registered_fixture_template() {
    let repository = repository();
    let execution_copy = repository.join(".leanbun-dev-rust/generation-fixture");
    std::fs::create_dir_all(&execution_copy)
        .unwrap_or_else(|error| panic!("execution root setup failed: {error}"));
    assert!(verify_registered_test_project_v1(&repository, &repository, &execution_copy).is_err());
}

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap_or_else(|| panic!("repository root missing"))
        .canonicalize()
        .unwrap_or_else(|error| panic!("repository canonicalization failed: {error}"))
}
