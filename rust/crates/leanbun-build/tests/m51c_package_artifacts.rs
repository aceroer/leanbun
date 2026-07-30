use leanbun_build::{
    PackageArtifactOutcomeV1, PackageArtifactStoreFaultV1, PackageArtifactStoreV1,
    PackageBuildContextV1, PackageBuildDependencyV1, PackageBuildKeyV1, package_build_keys_v1,
};
use leanbun_core::Sha256;
use leanbun_lock::{
    CanonicalSourceUrlV1, LeanBunLockV1, LockedLeanPackageV1, PackageDependencyV1, PackageKeyV1,
    PackageSourceKeyV1, RequestedPackageSourceV1, ResolvedPackageSourceV1,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

static TEST_ID: AtomicU64 = AtomicU64::new(1);
const WORKER_ROOT: &str = "LEANBUN_M51C_WORKER_ROOT";
const WORKER_ARTIFACT: &str = "LEANBUN_M51C_WORKER_ARTIFACT";

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .unwrap_or_else(|| panic!("repository missing"))
            .to_path_buf();
        let root = repository.join(".leanbun-dev-rust").join(format!(
            "m51c-package-artifacts-{}-{}-{label}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap_or_else(|error| panic!("fixture create failed: {error}"));
        Self { root }
    }

    fn store(&self) -> PackageArtifactStoreV1 {
        PackageArtifactStoreV1::open_global(&self.root)
            .unwrap_or_else(|error| panic!("Store open failed: {error}"))
    }

    fn artifact(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let root = self.root.join(name);
        fs::create_dir(&root).unwrap_or_else(|error| panic!("artifact create failed: {error}"));
        fs::write(root.join("Package.olean"), bytes)
            .unwrap_or_else(|error| panic!("artifact write failed: {error}"));
        root
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        make_writable(&self.root);
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn recursive_identity_invalidates_only_changed_package_and_dependants() {
    let build_context = context(1);
    let a1 = key(1, &build_context, vec![]);
    let b1 = key(2, &build_context, vec![dependency("a", a1)]);
    let c1 = key(3, &build_context, vec![]);
    let a2 = key(4, &build_context, vec![]);
    let b2 = key(2, &build_context, vec![dependency("a", a2)]);
    let c2 = key(3, &build_context, vec![]);
    assert_ne!(a1, a2);
    assert_ne!(b1, b2);
    assert_eq!(c1, c2);

    let changed_context = context(9);
    assert_ne!(a1, key(1, &changed_context, vec![]));
    assert_ne!(c1, key(3, &changed_context, vec![]));
}

#[test]
fn lock_derivation_ignores_environment_root_and_propagates_path_ineligibility() {
    let a = locked_git("a", 1, vec![]);
    let b = locked_git("b", 2, vec!["a"]);
    let local = locked_path("local", 3);
    let above_local = locked_git("above-local", 4, vec!["local"]);
    let packages = vec![a, b, local, above_local];
    let first = LeanBunLockV1::new(
        "leanprover/lean4:v4.32.0",
        "1111111111111111111111111111111111111111",
        "5.0.0",
        sha(30),
        sha(31),
        packages.clone(),
    )
    .unwrap_or_else(|error| panic!("first lock failed: {error}"));
    let second = LeanBunLockV1::new(
        "leanprover/lean4:v4.32.0",
        "1111111111111111111111111111111111111111",
        "5.0.0",
        sha(40),
        sha(41),
        packages,
    )
    .unwrap_or_else(|error| panic!("second lock failed: {error}"));
    let first_keys = package_build_keys_v1(&first, &context(1))
        .unwrap_or_else(|error| panic!("first derivation failed: {error}"));
    let second_keys = package_build_keys_v1(&second, &context(1))
        .unwrap_or_else(|error| panic!("second derivation failed: {error}"));
    assert_eq!(first_keys, second_keys);
    assert!(first_keys.contains_key(&package("a")));
    assert!(first_keys.contains_key(&package("b")));
    assert!(!first_keys.contains_key(&package("local")));
    assert!(!first_keys.contains_key(&package("above-local")));
}

#[test]
fn independent_store_instances_publish_once_reuse_and_materialize_private_copy() {
    let fixture = Fixture::new("concurrent");
    let candidate = fixture.artifact("candidate", b"compiled-v1");
    let key = key(1, &context(1), vec![]);
    let barrier = Arc::new(Barrier::new(3));
    let first_store = fixture.store();
    let second_store = fixture.store();
    let first_candidate = candidate.clone();
    let second_candidate = candidate.clone();
    let first_barrier = Arc::clone(&barrier);
    let second_barrier = Arc::clone(&barrier);
    let first = std::thread::spawn(move || {
        first_barrier.wait();
        first_store.publish_or_reuse(key, &first_candidate)
    });
    let second = std::thread::spawn(move || {
        second_barrier.wait();
        second_store.publish_or_reuse(key, &second_candidate)
    });
    barrier.wait();
    let first = first
        .join()
        .unwrap_or_else(|_| panic!("first writer panicked"))
        .unwrap_or_else(|error| panic!("first writer failed: {error}"));
    let second = second
        .join()
        .unwrap_or_else(|_| panic!("second writer panicked"))
        .unwrap_or_else(|error| panic!("second writer failed: {error}"));
    assert!(matches!(
        (first.outcome(), second.outcome()),
        (
            PackageArtifactOutcomeV1::Published,
            PackageArtifactOutcomeV1::Reused
        ) | (
            PackageArtifactOutcomeV1::Reused,
            PackageArtifactOutcomeV1::Published
        )
    ));
    assert_eq!(first.object_path(), second.object_path());
    assert_eq!(
        directory_count(&fixture.store().store_root().join("objects")),
        1
    );

    let destination = fixture.root.join("environment-private-build");
    let materialized = fixture
        .store()
        .materialize_if_present(key, &destination)
        .unwrap_or_else(|error| panic!("materialization failed: {error}"))
        .unwrap_or_else(|| panic!("artifact unexpectedly absent"));
    assert_eq!(
        materialized.outcome(),
        PackageArtifactOutcomeV1::Materialized
    );
    assert_eq!(
        fs::read(destination.join("Package.olean"))
            .unwrap_or_else(|error| panic!("materialized artifact read failed: {error}")),
        b"compiled-v1"
    );
    assert_ne!(
        fs::metadata(&destination)
            .unwrap_or_else(|error| panic!("materialized metadata failed: {error}"))
            .permissions()
            .mode()
            & 0o200,
        0
    );
    assert_eq!(
        fs::metadata(materialized.object_path())
            .unwrap_or_else(|error| panic!("published metadata failed: {error}"))
            .permissions()
            .mode()
            & 0o222,
        0
    );
}

#[test]
fn two_processes_publish_one_package_artifact() {
    let fixture = Fixture::new("processes");
    let candidate = fixture.artifact("candidate", b"compiled-process");
    let executable = std::env::current_exe()
        .unwrap_or_else(|error| panic!("current test executable failed: {error}"));
    let spawn = || {
        Command::new(&executable)
            .args(["--exact", "m51c_cross_process_worker", "--nocapture"])
            .env(WORKER_ROOT, &fixture.root)
            .env(WORKER_ARTIFACT, &candidate)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("worker spawn failed: {error}"))
    };
    let first = spawn();
    let second = spawn();
    let first = first
        .wait_with_output()
        .unwrap_or_else(|error| panic!("first worker wait failed: {error}"));
    let second = second
        .wait_with_output()
        .unwrap_or_else(|error| panic!("second worker wait failed: {error}"));
    assert!(first.status.success());
    assert!(second.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&second.stdout)
    );
    assert!(combined.contains("Published"));
    assert!(combined.contains("Reused"));
    assert_eq!(
        directory_count(&fixture.store().store_root().join("objects")),
        1
    );
}

#[test]
fn m51c_cross_process_worker() {
    let (Ok(root), Ok(candidate)) = (std::env::var(WORKER_ROOT), std::env::var(WORKER_ARTIFACT))
    else {
        return;
    };
    let store = PackageArtifactStoreV1::open_global(root)
        .unwrap_or_else(|error| panic!("worker Store failed: {error}"));
    let result = store
        .publish_or_reuse(key(7, &context(7), vec![]), Path::new(&candidate))
        .unwrap_or_else(|error| panic!("worker publication failed: {error}"));
    println!("m51c-worker-outcome={:?}", result.outcome());
}

#[test]
fn package_artifact_lease_rejects_symlink_redirection() {
    let fixture = Fixture::new("lease-symlink");
    let candidate = fixture.artifact("candidate", b"compiled-symlink");
    let key = key(1, &context(1), vec![]);
    let store = fixture.store();
    let outside = fixture.root.join("outside-lock-target");
    fs::write(&outside, b"preserve")
        .unwrap_or_else(|error| panic!("outside target failed: {error}"));
    let lease = store
        .store_root()
        .join("leases")
        .join(format!("{}.lock", key.digest()));
    symlink(&outside, &lease).unwrap_or_else(|error| panic!("lease symlink failed: {error}"));
    assert!(store.publish_or_reuse(key, &candidate).is_err());
    assert_eq!(
        fs::read(&outside).unwrap_or_else(|error| panic!("outside read failed: {error}")),
        b"preserve"
    );
    assert_eq!(directory_count(&store.store_root().join("objects")), 0);
}

#[test]
fn incompatible_artifact_and_interrupted_publication_fail_closed() {
    let fixture = Fixture::new("fault");
    let first = fixture.artifact("first", b"compiled-v1");
    let other = fixture.artifact("other", b"compiled-v2");
    let key = key(1, &context(1), vec![]);
    let failed = fixture.store().publish_or_reuse_with_fault(
        key,
        &first,
        PackageArtifactStoreFaultV1::AfterRecord,
    );
    assert!(failed.is_err());
    assert_eq!(
        directory_count(&fixture.store().store_root().join("objects")),
        0
    );
    fixture
        .store()
        .publish_or_reuse(key, &first)
        .unwrap_or_else(|error| panic!("recovery publication failed: {error}"));
    let drift = match fixture.store().publish_or_reuse(key, &other) {
        Ok(_) => panic!("same build key with other bytes unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(drift.kind, leanbun_build::BuildErrorKind::ArtifactDrift);
}

fn context(byte: u8) -> PackageBuildContextV1 {
    PackageBuildContextV1 {
        lean_toolchain: "leanprover/lean4:v4.32.0".to_owned(),
        compiler_githash: "1111111111111111111111111111111111111111".to_owned(),
        lake_version: "5.0.0".to_owned(),
        platform: "aarch64-apple-darwin".to_owned(),
        platform_abi_sha256: sha(byte),
        build_policy_sha256: sha(20),
        facets_sha256: sha(21),
        environment_sha256: sha(22),
        lake_executable_sha256: sha(23),
    }
}

fn key(
    byte: u8,
    context: &PackageBuildContextV1,
    dependencies: Vec<PackageBuildDependencyV1>,
) -> PackageBuildKeyV1 {
    let url = CanonicalSourceUrlV1::parse(format!("https://github.com/example/package-{byte}"))
        .unwrap_or_else(|error| panic!("URL failed: {error}"));
    let source = PackageSourceKeyV1::from_git(&url, &format!("{byte:040x}"), None, sha(byte))
        .unwrap_or_else(|error| panic!("source key failed: {error}"));
    PackageBuildKeyV1::new(source, context, dependencies)
        .unwrap_or_else(|error| panic!("build key failed: {error}"))
}

fn dependency(name: &str, build: PackageBuildKeyV1) -> PackageBuildDependencyV1 {
    PackageBuildDependencyV1::new(
        PackageKeyV1::new("", name).unwrap_or_else(|error| panic!("package failed: {error}")),
        build,
    )
}

fn package(name: &str) -> PackageKeyV1 {
    PackageKeyV1::new("", name).unwrap_or_else(|error| panic!("package failed: {error}"))
}

fn locked_git(name: &str, byte: u8, dependencies: Vec<&str>) -> LockedLeanPackageV1 {
    let url = CanonicalSourceUrlV1::parse(format!("https://github.com/example/{name}"))
        .unwrap_or_else(|error| panic!("URL failed: {error}"));
    LockedLeanPackageV1::new(
        package(name),
        RequestedPackageSourceV1::git(url.clone(), None)
            .unwrap_or_else(|error| panic!("request failed: {error}")),
        ResolvedPackageSourceV1::git(url, format!("{byte:040x}"), None)
            .unwrap_or_else(|error| panic!("source failed: {error}")),
        Some(sha(byte + 50)),
        sha(byte),
        sha(byte + 10),
        None,
        dependencies
            .into_iter()
            .map(|name| PackageDependencyV1::new(package(name)))
            .collect(),
        vec![sha(byte + 20)],
        sha(byte + 30),
    )
    .unwrap_or_else(|error| panic!("locked Git package failed: {error}"))
}

fn locked_path(name: &str, byte: u8) -> LockedLeanPackageV1 {
    LockedLeanPackageV1::new(
        package(name),
        RequestedPackageSourceV1::path_snapshot(format!("vendor/{name}"))
            .unwrap_or_else(|error| panic!("path request failed: {error}")),
        ResolvedPackageSourceV1::path_snapshot(format!("vendor/{name}"))
            .unwrap_or_else(|error| panic!("path source failed: {error}")),
        None,
        sha(byte),
        sha(byte + 10),
        None,
        vec![],
        vec![sha(byte + 20)],
        sha(byte + 30),
    )
    .unwrap_or_else(|error| panic!("locked path package failed: {error}"))
}

fn sha(byte: u8) -> Sha256 {
    Sha256::from_bytes([byte; 32])
}

fn directory_count(path: &Path) -> usize {
    fs::read_dir(path)
        .unwrap_or_else(|error| panic!("read dir failed: {error}"))
        .count()
}

fn make_writable(root: &Path) {
    let Ok(metadata) = fs::symlink_metadata(root) else {
        return;
    };
    if metadata.is_dir() {
        let _ = fs::set_permissions(root, fs::Permissions::from_mode(0o700));
        if let Ok(entries) = fs::read_dir(root) {
            for entry in entries.flatten() {
                make_writable(&entry.path());
            }
        }
    } else if metadata.is_file() {
        let _ = fs::set_permissions(root, fs::Permissions::from_mode(0o600));
    }
}
