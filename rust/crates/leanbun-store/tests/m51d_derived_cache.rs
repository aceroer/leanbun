use leanbun_store::{
    LeanStoreErrorKind, LeanStoreLimitsV1,
    normalized_directory_tree_sha256_excluding_exact_files_v1, normalized_directory_tree_sha256_v1,
};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(1);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .unwrap_or_else(|| panic!("repository root is missing"))
            .join(".leanbun-dev-rust")
            .join(format!(
                "m51d-derived-cache-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(root.join("widget"))
            .unwrap_or_else(|error| panic!("fixture directory failed: {error}"));
        fs::write(root.join("Source.lean"), b"def source := true\n")
            .unwrap_or_else(|error| panic!("fixture source failed: {error}"));
        Self(root)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn exact_derived_cache_exclusion_preserves_source_identity_only_for_that_file() {
    let fixture = Fixture::new();
    let limits = LeanStoreLimitsV1::default();
    let source = normalized_directory_tree_sha256_v1(&fixture.0, limits)
        .unwrap_or_else(|error| panic!("source digest failed: {error}"));

    fs::write(
        fixture.0.join("widget/package-lock.json.hash"),
        b"derived\n",
    )
    .unwrap_or_else(|error| panic!("derived cache failed: {error}"));
    let admitted = normalized_directory_tree_sha256_excluding_exact_files_v1(
        &fixture.0,
        limits,
        &["widget/package-lock.json.hash"],
    )
    .unwrap_or_else(|error| panic!("excluded digest failed: {error}"));
    assert_eq!(admitted, source);

    fs::write(fixture.0.join("Source.lean"), b"def source := false\n")
        .unwrap_or_else(|error| panic!("source mutation failed: {error}"));
    let drifted = normalized_directory_tree_sha256_excluding_exact_files_v1(
        &fixture.0,
        limits,
        &["widget/package-lock.json.hash"],
    )
    .unwrap_or_else(|error| panic!("drift digest failed: {error}"));
    assert_ne!(drifted, source);
}

#[test]
fn derived_cache_exclusions_reject_reserved_or_duplicate_paths() {
    let fixture = Fixture::new();
    for (exclusions, expected) in [
        (
            &[".lake/build/cache"] as &[&str],
            LeanStoreErrorKind::PathTraversal,
        ),
        (
            &["widget/cache", "widget/cache"] as &[&str],
            LeanStoreErrorKind::BoundaryViolation,
        ),
    ] {
        let error = match normalized_directory_tree_sha256_excluding_exact_files_v1(
            &fixture.0,
            LeanStoreLimitsV1::default(),
            exclusions,
        ) {
            Ok(_) => panic!("unsafe exclusion must fail"),
            Err(error) => error,
        };
        assert_eq!(error.kind, expected);
    }
}
