use leanbun_core::{ExecutionId, Sha256, Sha256Hasher};
use leanbun_generation::{
    LeanBunGenerationV1, LeanGenerationError, LeanGenerationErrorKind, LeanGenerationFaultV1,
    LeanGenerationManagerV1, LeanGenerationStateV1,
};
use leanbun_lake_bridge::{
    LakeDependencySourceV1, LakeManifestProjectionV1, LakePackageProjectionMetadataV1,
    LakeRootDeclarationV1, LakeRootDependencyV1, LakeRuntimePackagesProjectionV1,
};
use leanbun_package::{
    LeanBunLockV1, LockedLeanPackageV1, PackageKeyV1, PackagePathDecisionSetV1,
    PackagePathDecisionV1, PackagePathProvenanceSetV1, PackagePathProvenanceV1,
    RequestedPackageSourceV1, ResolvedPackageSourceV1,
};
use leanbun_resolver::{
    LeanExactSourceV1, LeanPackageCandidateV1, LeanResolutionModeV1, LeanResolutionRequestV1,
    LeanSourceRequestV1, LeanToolchainIdentityV1, resolve_lean_dependencies_v1,
};
use leanbun_store::{
    LeanFetchCancellationV1, LeanFetchFaultV1, LeanFetchRequestV1, LeanFetchSourceV1,
    LeanImmutableStoreV1, LeanStoreLimitsV1, VerifiedPackageObjectV1,
    normalized_directory_tree_sha256_v1,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const TOOLCHAIN: &str = "leanprover/lean4:v4.32.0";
const COMPILER: &str = "8c9756b28d64dab099da31a4c09229a9e6a2ef35";
const LAKE: &str = "5.0.0-src+8c9756b";
static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[test]
fn managed_constructor_separates_private_state_from_explicit_project_source() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap_or_else(|| panic!("repository root missing"));
    let root = repository
        .join(".leanbun-dev-rust/generation-fixture/m35-managed-constructor")
        .join(std::process::id().to_string());
    let authority = root.join("authority");
    let project = root.join("project");
    fs::create_dir_all(&authority)
        .unwrap_or_else(|error| panic!("authority setup failed: {error}"));
    fs::create_dir_all(&project).unwrap_or_else(|error| panic!("project setup failed: {error}"));
    let state = authority.join("state");
    let manager = LeanGenerationManagerV1::open_managed(&authority, &state, &project)
        .unwrap_or_else(|error| panic!("managed manager failed: {error}"));
    let canonical_project = project
        .canonicalize()
        .unwrap_or_else(|error| panic!("project canonicalization failed: {error}"));
    let canonical_authority = authority
        .canonicalize()
        .unwrap_or_else(|error| panic!("authority canonicalization failed: {error}"));
    assert_eq!(manager.project_root(), canonical_project);
    assert!(manager.state_root().starts_with(canonical_authority));
    assert!(
        LeanGenerationManagerV1::open_managed(&authority, root.join("escaped"), &project).is_err()
    );
    fs::remove_dir_all(&root).unwrap_or_else(|error| panic!("cleanup failed: {error}"));
}

struct Fixture {
    root: PathBuf,
    store_root: PathBuf,
    manager: LeanGenerationManagerV1,
    declaration: LakeRootDeclarationV1,
    lock: LeanBunLockV1,
    graph: leanbun_resolver::LeanResolutionGraphV1,
    object: VerifiedPackageObjectV1,
    metadata: Vec<LakePackageProjectionMetadataV1>,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .unwrap_or_else(|| panic!("repository root missing"))
            .to_path_buf();
        let development = repository.join(".leanbun-dev-rust");
        fs::create_dir_all(&development)
            .unwrap_or_else(|error| panic!("development root failed: {error}"));
        let nonce = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let leaf = format!("{}-{nonce}-{label}", std::process::id());
        let root = development
            .join("generation-fixture")
            .join("m35-tests")
            .join(&leaf);
        let project = root.join("project");
        let state = root.join("state");
        fs::create_dir_all(&project).unwrap_or_else(|error| panic!("project failed: {error}"));
        fs::create_dir_all(&state).unwrap_or_else(|error| panic!("state failed: {error}"));
        let source = root.join("source");
        fs::create_dir_all(source.join("Fixture"))
            .unwrap_or_else(|error| panic!("source directory failed: {error}"));
        fs::write(
            source.join("Fixture/Main.lean"),
            b"theorem generated : True := trivial\n",
        )
        .unwrap_or_else(|error| panic!("source file failed: {error}"));
        fs::write(source.join("lakefile.toml"), b"name = \"fixture\"\n")
            .unwrap_or_else(|error| panic!("lakefile failed: {error}"));

        let tree = normalized_directory_tree_sha256_v1(&source, LeanStoreLimitsV1::default())
            .unwrap_or_else(|error| panic!("source tree failed: {error}"));
        let package = key();
        let path_token = "vendor/fixture";
        let source_identity = sha(b"path-source");
        let declaration = LakeRootDeclarationV1::new(
            "fixture_root",
            "lakefile.toml",
            vec![
                LakeRootDependencyV1::new(
                    package.clone(),
                    None,
                    LakeDependencySourceV1::Path {
                        directory: path_token.to_owned(),
                    },
                )
                .unwrap_or_else(|error| panic!("root dependency failed: {error}")),
            ],
        )
        .unwrap_or_else(|error| panic!("declaration failed: {error}"));
        let provenance = PackagePathProvenanceV1::manifest(package.clone(), source_identity);
        let provenance_set = PackagePathProvenanceSetV1::new(vec![provenance.clone()])
            .unwrap_or_else(|error| panic!("provenance failed: {error}"));
        let locked = LockedLeanPackageV1::new(
            package.clone(),
            RequestedPackageSourceV1::path_snapshot(path_token)
                .unwrap_or_else(|error| panic!("locked request failed: {error}")),
            ResolvedPackageSourceV1::path_snapshot(path_token)
                .unwrap_or_else(|error| panic!("locked source failed: {error}")),
            None,
            tree,
            sha(b"config"),
            None,
            Vec::new(),
            vec![provenance_set.digest()],
            source_identity,
        )
        .unwrap_or_else(|error| panic!("locked package failed: {error}"));
        let lock = LeanBunLockV1::new(
            TOOLCHAIN,
            COMPILER,
            LAKE,
            sha(b"root-config"),
            declaration.identity(),
            vec![locked],
        )
        .unwrap_or_else(|error| panic!("lock failed: {error}"));
        let candidate = LeanPackageCandidateV1::new(
            package.clone(),
            LeanSourceRequestV1::path(path_token)
                .unwrap_or_else(|error| panic!("path request failed: {error}")),
            LeanExactSourceV1::path(path_token, source_identity)
                .unwrap_or_else(|error| panic!("exact path failed: {error}")),
            Vec::new(),
            None,
            None,
            tree,
            sha(b"config"),
            None,
            source_identity,
        )
        .unwrap_or_else(|error| panic!("candidate failed: {error}"));
        let resolution_request = LeanResolutionRequestV1::new(
            declaration.clone(),
            None,
            LeanResolutionModeV1::update(Vec::new())
                .unwrap_or_else(|error| panic!("resolution mode failed: {error}")),
            LeanToolchainIdentityV1::new(TOOLCHAIN, COMPILER, LAKE)
                .unwrap_or_else(|error| panic!("toolchain failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("resolution request failed: {error}"));
        let graph = resolve_lean_dependencies_v1(&resolution_request, vec![candidate])
            .unwrap_or_else(|error| panic!("resolution failed: {error}"));

        let store_root = development
            .join("store-fixture")
            .join("m35-tests")
            .join(&leaf);
        let store = LeanImmutableStoreV1::open(&development, &store_root)
            .unwrap_or_else(|error| panic!("M34 store failed: {error}"));
        let fetch = LeanFetchRequestV1::from_graph(
            &graph,
            &package,
            LeanFetchSourceV1::LocalDirectory {
                path: source.clone(),
            },
            &root,
            LeanStoreLimitsV1::default(),
        )
        .unwrap_or_else(|error| panic!("fetch request failed: {error}"));
        let object = store
            .fetch_and_publish(
                &fetch,
                &LeanFetchCancellationV1::default(),
                LeanFetchFaultV1::None,
            )
            .unwrap_or_else(|error| panic!("M34 object failed: {error}"));
        let manager = LeanGenerationManagerV1::open(&development, &state, &project)
            .unwrap_or_else(|error| panic!("M35 manager failed: {error}"));
        let metadata = vec![
            LakePackageProjectionMetadataV1::new(package, false, "lakefile.toml", None, None)
                .unwrap_or_else(|error| panic!("projection metadata failed: {error}")),
        ];
        Self {
            root,
            store_root,
            manager,
            declaration,
            lock,
            graph,
            object,
            metadata,
        }
    }

    fn generation(&self, transaction: &str) -> LeanBunGenerationV1 {
        let transaction = ExecutionId::parse(transaction)
            .unwrap_or_else(|error| panic!("transaction failed: {error}"));
        let generation_root = self.manager.generation_root(transaction);
        let provenance =
            PackagePathProvenanceSetV1::new(vec![PackagePathProvenanceV1::bun_generated_runtime(
                key(),
                self.lock.packages()[0].selected_source_identity(),
            )])
            .unwrap_or_else(|error| panic!("runtime provenance failed: {error}"));
        let decision = PackagePathDecisionV1::new(
            key(),
            &provenance,
            self.lock.packages()[0].selected_source_identity(),
            generation_root
                .to_str()
                .unwrap_or_else(|| panic!("generation root is not UTF-8")),
            generation_root
                .join("packages/fixture")
                .to_str()
                .unwrap_or_else(|| panic!("package path is not UTF-8")),
            self.object.store_object_sha256(),
            self.object.source_tree_sha256(),
            self.graph.identity(),
        )
        .unwrap_or_else(|error| panic!("path decision failed: {error}"));
        let decisions = PackagePathDecisionSetV1::new(&self.lock, vec![decision])
            .unwrap_or_else(|error| panic!("decision set failed: {error}"));
        let manifest =
            LakeManifestProjectionV1::new(&self.declaration, &self.lock, self.metadata.clone())
                .unwrap_or_else(|error| panic!("manifest projection failed: {error}"));
        let runtime = LakeRuntimePackagesProjectionV1::from_bun_decisions(
            &self.lock,
            &decisions,
            self.metadata.clone(),
        )
        .unwrap_or_else(|error| panic!("runtime projection failed: {error}"));
        LeanBunGenerationV1::new(
            transaction,
            self.manager.project_root(),
            generation_root,
            &self.lock,
            &self.graph,
            &decisions,
            &manifest,
            &runtime,
            vec![self.object.clone()],
        )
        .unwrap_or_else(|error| panic!("generation model failed: {error}"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        make_writable(&self.root);
        make_writable(&self.store_root);
        let _ = fs::remove_dir_all(&self.root);
        let _ = fs::remove_dir_all(&self.store_root);
    }
}

#[test]
fn generation_publishes_atomically_and_retains_previous_generations() {
    let fixture = Fixture::new("publish");
    let first = fixture.generation("10000000-0000-4000-8000-000000000001");
    let outcome = fixture
        .manager
        .publish(&first, LeanGenerationFaultV1::None)
        .unwrap_or_else(|error| panic!("first publish failed: {error}"));
    assert_eq!(outcome.state(), LeanGenerationStateV1::Published);
    fixture
        .manager
        .verify_active_generation(&first)
        .unwrap_or_else(|error| panic!("active reverification failed: {error}"));
    assert_eq!(
        fixture
            .manager
            .active_generation_identity()
            .unwrap_or_else(|error| panic!("active read failed: {error}")),
        Some(first.identity())
    );
    assert!(
        outcome
            .generation_root()
            .join("packages/fixture/Fixture/Main.lean")
            .is_file()
    );

    let second = fixture.generation("20000000-0000-4000-8000-000000000002");
    fixture
        .manager
        .publish(&second, LeanGenerationFaultV1::None)
        .unwrap_or_else(|error| panic!("second publish failed: {error}"));
    assert_eq!(
        failure(fixture.manager.verify_active_generation(&first)).kind,
        LeanGenerationErrorKind::GenerationDrift
    );
    fixture
        .manager
        .verify_active_generation(&second)
        .unwrap_or_else(|error| panic!("second active reverification failed: {error}"));
    assert_eq!(
        fixture
            .manager
            .active_generation_identity()
            .unwrap_or_else(|error| panic!("active read failed: {error}")),
        Some(second.identity())
    );
    assert!(first.generation_root().is_dir());
    assert!(second.generation_root().is_dir());
    let retained = fs::read_to_string(
        fixture
            .manager
            .state_root()
            .join("projects")
            .join(fixture.manager.project_id().to_string())
            .join("retained.record"),
    )
    .unwrap_or_else(|error| panic!("retained read failed: {error}"));
    assert!(retained.contains(&first.identity().to_string()));
    assert!(retained.contains(&second.identity().to_string()));
    let cloned_file = first
        .generation_root()
        .join("packages/fixture/Fixture/Main.lean");
    set_mode(first.generation_root(), 0o755);
    set_mode(
        cloned_file
            .parent()
            .unwrap_or_else(|| panic!("cloned file parent missing")),
        0o755,
    );
    set_mode(&cloned_file, 0o644);
    fs::write(&cloned_file, b"mutated generation only\n")
        .unwrap_or_else(|error| panic!("generation mutation failed: {error}"));
    assert_eq!(
        normalized_directory_tree_sha256_v1(
            fixture.object.tree_path(),
            LeanStoreLimitsV1::default(),
        )
        .unwrap_or_else(|error| panic!("store reverify failed: {error}")),
        fixture.object.source_tree_sha256()
    );
}

#[test]
fn rollback_restores_an_exact_published_generation_without_rewriting_it() {
    let fixture = Fixture::new("rollback");
    let baseline = fixture.generation("21000000-0000-4000-8000-000000000021");
    fixture
        .manager
        .publish(&baseline, LeanGenerationFaultV1::None)
        .unwrap_or_else(|error| panic!("baseline publish failed: {error}"));
    let candidate = fixture.generation("22000000-0000-4000-8000-000000000022");
    fixture
        .manager
        .publish(&candidate, LeanGenerationFaultV1::None)
        .unwrap_or_else(|error| panic!("candidate publish failed: {error}"));
    fixture
        .manager
        .rollback_active_generation(&candidate, &baseline)
        .unwrap_or_else(|error| panic!("rollback failed: {error}"));
    fixture
        .manager
        .verify_active_generation(&baseline)
        .unwrap_or_else(|error| panic!("restored baseline failed verification: {error}"));
    assert_eq!(
        fixture
            .manager
            .active_generation_identity()
            .unwrap_or_else(|error| panic!("active read failed: {error}")),
        Some(baseline.identity())
    );
    assert!(candidate.generation_root().is_dir());
}

#[test]
fn every_precommit_crash_preserves_old_active_and_recovers_failed_idempotently() {
    for (index, fault) in [
        LeanGenerationFaultV1::AfterLock,
        LeanGenerationFaultV1::AfterPreparing,
        LeanGenerationFaultV1::AfterLockFile,
        LeanGenerationFaultV1::AfterManifestProjection,
        LeanGenerationFaultV1::AfterRuntimeProjection,
        LeanGenerationFaultV1::AfterPackages,
        LeanGenerationFaultV1::AfterGenerationMetadata,
        LeanGenerationFaultV1::AfterFileSync,
        LeanGenerationFaultV1::AfterDirectorySync,
        LeanGenerationFaultV1::AfterMaterialized,
        LeanGenerationFaultV1::AfterVerified,
        LeanGenerationFaultV1::BeforeActiveRename,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new(&format!("precommit-{index}"));
        let baseline = fixture.generation("30000000-0000-4000-8000-000000000003");
        fixture
            .manager
            .publish(&baseline, LeanGenerationFaultV1::None)
            .unwrap_or_else(|error| panic!("baseline failed: {error}"));
        let candidate = fixture.generation("40000000-0000-4000-8000-000000000004");
        assert_eq!(
            failure(fixture.manager.publish(&candidate, fault)).kind,
            LeanGenerationErrorKind::FaultInjected
        );
        assert_eq!(
            fixture
                .manager
                .active_generation_identity()
                .unwrap_or_else(|error| panic!("active read failed: {error}")),
            Some(baseline.identity())
        );
        let recovered = fixture
            .manager
            .recover(&candidate)
            .unwrap_or_else(|error| panic!("recovery failed: {error}"));
        assert_eq!(recovered.state(), LeanGenerationStateV1::Failed);
        assert!(!recovered.is_active());
        let repeated = fixture
            .manager
            .recover(&candidate)
            .unwrap_or_else(|error| panic!("repeat recovery failed: {error}"));
        assert_eq!(repeated.state(), LeanGenerationStateV1::Failed);
        if fault == LeanGenerationFaultV1::BeforeActiveRename {
            let project_state = fixture
                .manager
                .state_root()
                .join("projects")
                .join(candidate.project_id().to_string());
            let abandoned = fs::read_dir(project_state)
                .unwrap_or_else(|error| panic!("project state read failed: {error}"))
                .filter_map(Result::ok)
                .any(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.starts_with(".active-") && name.ends_with(".tmp"))
                });
            assert!(!abandoned, "recovery left an active publication temp file");
        }
    }
}

#[test]
fn every_postcommit_crash_recovers_published_and_releases_exact_lock() {
    for (index, fault) in [
        LeanGenerationFaultV1::AfterActiveRename,
        LeanGenerationFaultV1::AfterPublishedRecord,
        LeanGenerationFaultV1::AfterRetainedRecord,
        LeanGenerationFaultV1::BeforeLockRelease,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new(&format!("postcommit-{index}"));
        let generation = fixture.generation("50000000-0000-4000-8000-000000000005");
        assert_eq!(
            failure(fixture.manager.publish(&generation, fault)).kind,
            LeanGenerationErrorKind::FaultInjected
        );
        let recovered = fixture
            .manager
            .recover(&generation)
            .unwrap_or_else(|error| panic!("postcommit recovery failed: {error}"));
        assert_eq!(recovered.state(), LeanGenerationStateV1::Published);
        assert!(recovered.is_active());
        assert!(recovered.lock_released());
        let repeated = fixture
            .manager
            .recover(&generation)
            .unwrap_or_else(|error| panic!("repeat recovery failed: {error}"));
        assert_eq!(repeated.state(), LeanGenerationStateV1::Published);
    }
}

#[test]
fn mixed_projection_bytes_cannot_survive_active_reverification() {
    let fixture = Fixture::new("mixed");
    let generation = fixture.generation("60000000-0000-4000-8000-000000000006");
    fixture
        .manager
        .publish(&generation, LeanGenerationFaultV1::None)
        .unwrap_or_else(|error| panic!("publish failed: {error}"));
    let runtime = generation.generation_root().join("runtime-packages.json");
    set_mode(generation.generation_root(), 0o755);
    set_mode(&runtime, 0o644);
    fs::write(&runtime, b"{}")
        .unwrap_or_else(|error| panic!("projection mutation failed: {error}"));
    assert_eq!(
        failure(fixture.manager.recover(&generation)).kind,
        LeanGenerationErrorKind::MixedProjection
    );
}

#[test]
fn project_lock_blocks_competing_transaction_until_exact_owner_recovers() {
    let fixture = Fixture::new("lock");
    let first = fixture.generation("70000000-0000-4000-8000-000000000007");
    let second = fixture.generation("80000000-0000-4000-8000-000000000008");
    assert_eq!(
        failure(
            fixture
                .manager
                .publish(&first, LeanGenerationFaultV1::AfterLock)
        )
        .kind,
        LeanGenerationErrorKind::FaultInjected
    );
    assert_eq!(
        failure(
            fixture
                .manager
                .publish(&second, LeanGenerationFaultV1::None)
        )
        .kind,
        LeanGenerationErrorKind::LockBusy
    );
    fixture
        .manager
        .recover(&first)
        .unwrap_or_else(|error| panic!("owner recovery failed: {error}"));
    let outcome = fixture
        .manager
        .publish(&second, LeanGenerationFaultV1::None)
        .unwrap_or_else(|error| panic!("second publish failed: {error}"));
    assert_eq!(outcome.state(), LeanGenerationStateV1::Published);
}

fn key() -> PackageKeyV1 {
    PackageKeyV1::new("", "fixture").unwrap_or_else(|error| panic!("package key failed: {error}"))
}

fn sha(bytes: &[u8]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn failure<T>(result: Result<T, LeanGenerationError>) -> LeanGenerationError {
    match result {
        Ok(_) => panic!("operation unexpectedly succeeded"),
        Err(error) => error,
    }
}

fn make_writable(root: &Path) {
    if let Ok(metadata) = fs::symlink_metadata(root) {
        if metadata.file_type().is_dir() {
            set_mode(root, 0o755);
            if let Ok(children) = fs::read_dir(root) {
                for child in children.flatten() {
                    make_writable(&child.path());
                }
            }
        } else {
            set_mode(root, 0o644);
        }
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .unwrap_or_else(|error| panic!("permission change failed: {error}"));
}

#[cfg(not(unix))]
fn set_mode(path: &Path, _mode: u32) {
    let mut permissions = fs::metadata(path)
        .unwrap_or_else(|error| panic!("permission read failed: {error}"))
        .permissions();
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions)
        .unwrap_or_else(|error| panic!("permission change failed: {error}"));
}
