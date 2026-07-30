use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_lake_bridge::{LakeDependencySourceV1, LakeRootDeclarationV1, LakeRootDependencyV1};
use leanbun_lock::{CanonicalSourceUrlV1, PackageKeyV1};
use leanbun_resolver::{
    LeanExactSourceV1, LeanPackageCandidateV1, LeanResolutionModeV1, LeanResolutionRequestV1,
    LeanSourceRequestV1, LeanToolchainIdentityV1, resolve_lean_dependencies_v1,
};
use leanbun_store::{
    LeanFetchCancellationV1, LeanFetchFaultV1, LeanFetchRequestV1, LeanFetchSourceV1,
    LeanImmutableStoreV1, LeanStoreError, LeanStoreErrorKind, LeanStoreLimitsV1,
    LeanStorePublicationV1, normalized_tar_tree_sha256_v1,
};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    development: PathBuf,
    sources: PathBuf,
    repository: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .unwrap_or_else(|| panic!("repository root is missing"))
            .to_path_buf();
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let development = repository_root.join(".leanbun-dev-rust").join(format!(
            "m51b-global-source-{}-{id}-{label}",
            std::process::id()
        ));
        let sources = development.join("sources");
        let repository = sources.join("repository");
        fs::create_dir_all(&repository)
            .unwrap_or_else(|error| panic!("fixture repository failed: {error}"));
        git(&repository, &["init", "-q"]);
        git(&repository, &["config", "user.name", "LeanBun"]);
        git(
            &repository,
            &["config", "user.email", "leanbun@example.invalid"],
        );
        fs::write(repository.join("Main.lean"), b"def sharedSource := true\n")
            .unwrap_or_else(|error| panic!("fixture source failed: {error}"));
        git(&repository, &["add", "Main.lean"]);
        git_commit(&repository, "source");
        Self {
            development,
            sources,
            repository,
        }
    }

    fn store(&self) -> LeanImmutableStoreV1 {
        LeanImmutableStoreV1::open_global_package_sources(&self.development)
            .unwrap_or_else(|error| panic!("global source Store failed: {error}"))
    }

    fn revision(&self) -> String {
        git_output(&self.repository, &["rev-parse", "HEAD"])
    }

    fn archive_facts(&self, revision: &str, label: &str) -> (Sha256, Sha256) {
        let archive = self.sources.join(format!("{label}.tar"));
        let output = format!("--output={}", archive.display());
        git(
            &self.repository,
            &["archive", "--format=tar", &output, revision],
        );
        let bytes =
            fs::read(&archive).unwrap_or_else(|error| panic!("control archive failed: {error}"));
        let tree = normalized_tar_tree_sha256_v1(&bytes, LeanStoreLimitsV1::default())
            .unwrap_or_else(|error| panic!("tree digest failed: {error}"));
        (sha(&bytes), tree)
    }

    fn request(
        &self,
        environment: &str,
        revision: &str,
        download: Sha256,
        tree: Sha256,
    ) -> LeanFetchRequestV1 {
        let graph = graph(environment, revision, download, tree);
        LeanFetchRequestV1::from_graph(
            &graph,
            &package_key(),
            LeanFetchSourceV1::LocalGit {
                repository: self.repository.clone(),
            },
            &self.sources,
            LeanStoreLimitsV1::default(),
        )
        .unwrap_or_else(|error| panic!("fetch request failed: {error}"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        make_writable(&self.development);
        let _ = fs::remove_dir_all(&self.development);
    }
}

#[test]
fn two_lake_environments_share_one_exact_source_authority_and_physical_tree() {
    let fixture = Fixture::new("two-envs");
    let revision = fixture.revision();
    let (download, tree) = fixture.archive_facts(&revision, "first");
    let first_request = Arc::new(fixture.request("environment_a", &revision, download, tree));
    let second_request = Arc::new(fixture.request("environment_b", &revision, download, tree));
    assert_ne!(
        first_request.graph_identity(),
        second_request.graph_identity()
    );
    assert_eq!(
        first_request.package_source_key(),
        second_request.package_source_key()
    );

    let first_store = fixture.store();
    let second_store = fixture.store();
    let barrier = Arc::new(Barrier::new(3));
    let first = spawn_fetch(
        first_store,
        Arc::clone(&first_request),
        Arc::clone(&barrier),
    );
    let second = spawn_fetch(
        second_store,
        Arc::clone(&second_request),
        Arc::clone(&barrier),
    );
    barrier.wait();
    let first = first
        .join()
        .unwrap_or_else(|_| panic!("first environment panicked"))
        .unwrap_or_else(|error| panic!("first environment failed: {error}"));
    let second = second
        .join()
        .unwrap_or_else(|_| panic!("second environment panicked"))
        .unwrap_or_else(|error| panic!("second environment failed: {error}"));
    let publications = [first.publication(), second.publication()];
    assert!(publications.contains(&LeanStorePublicationV1::Published));
    assert!(publications.contains(&LeanStorePublicationV1::Reused));
    assert_eq!(first.object_path(), second.object_path());
    assert_eq!(first.package_source_key(), second.package_source_key());
    assert_eq!(
        directory_entry_count(&fixture.store().store_root().join("objects")),
        1
    );
    assert_eq!(
        directory_entry_count(&fixture.store().store_root().join("sources")),
        1
    );

    git(
        &fixture.repository,
        &["commit", "--allow-empty", "-q", "-m", "next"],
    );
    let next_revision = fixture.revision();
    let (next_download, next_tree) = fixture.archive_facts(&next_revision, "next");
    assert_eq!(tree, next_tree);
    let next_request = fixture.request(
        "environment_a_updated",
        &next_revision,
        next_download,
        next_tree,
    );
    assert_ne!(
        first_request.package_source_key(),
        next_request.package_source_key()
    );
    let next = fixture
        .store()
        .fetch_and_publish(
            &next_request,
            &LeanFetchCancellationV1::default(),
            LeanFetchFaultV1::None,
        )
        .unwrap_or_else(|error| panic!("next source failed: {error}"));
    assert_eq!(next.object_path(), first.object_path());
    assert_eq!(
        directory_entry_count(&fixture.store().store_root().join("objects")),
        1
    );
    assert_eq!(
        directory_entry_count(&fixture.store().store_root().join("sources")),
        2
    );
}

#[test]
fn source_record_failure_recovers_after_reopen_and_record_drift_fails_closed() {
    let fixture = Fixture::new("recovery");
    let revision = fixture.revision();
    let (download, tree) = fixture.archive_facts(&revision, "source");
    let request = fixture.request("environment", &revision, download, tree);
    let failed = failure(fixture.store().fetch_and_publish(
        &request,
        &LeanFetchCancellationV1::default(),
        LeanFetchFaultV1::SourceRecordRename,
    ));
    assert_eq!(failed.kind, LeanStoreErrorKind::FaultInjected);
    let store = fixture.store();
    assert_eq!(
        directory_entry_count(&store.store_root().join("objects")),
        1
    );
    assert_eq!(
        directory_entry_count(&store.store_root().join("sources")),
        0
    );

    let recovered = store
        .fetch_and_publish(
            &request,
            &LeanFetchCancellationV1::default(),
            LeanFetchFaultV1::None,
        )
        .unwrap_or_else(|error| panic!("recovery failed: {error}"));
    assert_eq!(recovered.publication(), LeanStorePublicationV1::Reused);
    assert_eq!(
        directory_entry_count(&store.store_root().join("sources")),
        1
    );

    let record = store.store_root().join("sources").join(format!(
        "{}.meta",
        request
            .package_source_key()
            .unwrap_or_else(|| panic!("Git source key missing"))
            .digest()
    ));
    set_mode(&record, 0o644);
    fs::write(&record, b"drift").unwrap_or_else(|error| panic!("record drift failed: {error}"));
    assert_eq!(
        failure(store.verify_object_for_request(&request)).kind,
        LeanStoreErrorKind::SourceRecordDrift
    );
}

#[cfg(unix)]
#[test]
fn source_lease_refuses_symlink_redirection_before_fetch() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new("lease-symlink");
    let revision = fixture.revision();
    let (download, tree) = fixture.archive_facts(&revision, "source");
    let request = fixture.request("environment", &revision, download, tree);
    let store = fixture.store();
    let key = request
        .package_source_key()
        .unwrap_or_else(|| panic!("Git source key missing"));
    let outside = fixture.sources.join("outside-lock-target");
    fs::write(&outside, b"preserve")
        .unwrap_or_else(|error| panic!("outside target failed: {error}"));
    symlink(
        &outside,
        store
            .store_root()
            .join("leases")
            .join(format!("{}.lock", key.digest())),
    )
    .unwrap_or_else(|error| panic!("lease symlink failed: {error}"));
    assert_eq!(
        failure(store.fetch_and_publish(
            &request,
            &LeanFetchCancellationV1::default(),
            LeanFetchFaultV1::None,
        ))
        .kind,
        LeanStoreErrorKind::LeaseFailed
    );
    assert_eq!(
        fs::read(&outside).unwrap_or_else(|error| panic!("outside read failed: {error}")),
        b"preserve"
    );
    assert_eq!(
        directory_entry_count(&store.store_root().join("objects")),
        0
    );
    assert_eq!(
        directory_entry_count(&store.store_root().join("sources")),
        0
    );
}

#[test]
fn two_processes_publish_one_exact_source_authority() {
    let fixture = Fixture::new("two-processes");
    let revision = fixture.revision();
    let (download, tree) = fixture.archive_facts(&revision, "source");
    let first_result = fixture.sources.join("worker-a.result");
    let second_result = fixture.sources.join("worker-b.result");
    let mut first = spawn_worker(
        &fixture,
        "process_a",
        &revision,
        download,
        tree,
        &first_result,
    );
    let mut second = spawn_worker(
        &fixture,
        "process_b",
        &revision,
        download,
        tree,
        &second_result,
    );
    assert!(
        first
            .wait()
            .unwrap_or_else(|error| panic!("first worker wait failed: {error}"))
            .success()
    );
    assert!(
        second
            .wait()
            .unwrap_or_else(|error| panic!("second worker wait failed: {error}"))
            .success()
    );
    let outcomes = [
        fs::read_to_string(&first_result)
            .unwrap_or_else(|error| panic!("first result failed: {error}")),
        fs::read_to_string(&second_result)
            .unwrap_or_else(|error| panic!("second result failed: {error}")),
    ];
    assert!(
        outcomes
            .iter()
            .any(|value| value.starts_with("published\n"))
    );
    assert!(outcomes.iter().any(|value| value.starts_with("reused\n")));
    let store = fixture.store();
    assert_eq!(
        directory_entry_count(&store.store_root().join("objects")),
        1
    );
    assert_eq!(
        directory_entry_count(&store.store_root().join("sources")),
        1
    );
}

#[test]
fn m51b_cross_process_worker() {
    let Ok(development) = env::var("LEANBUN_M51B_WORKER_DEVELOPMENT") else {
        return;
    };
    let sources = required_env("LEANBUN_M51B_WORKER_SOURCES");
    let repository = required_env("LEANBUN_M51B_WORKER_REPOSITORY");
    let environment = required_env("LEANBUN_M51B_WORKER_ENVIRONMENT");
    let revision = required_env("LEANBUN_M51B_WORKER_REVISION");
    let download = parse_sha_env("LEANBUN_M51B_WORKER_DOWNLOAD");
    let tree = parse_sha_env("LEANBUN_M51B_WORKER_TREE");
    let result = required_env("LEANBUN_M51B_WORKER_RESULT");
    let graph = graph(&environment, &revision, download, tree);
    let request = LeanFetchRequestV1::from_graph(
        &graph,
        &package_key(),
        LeanFetchSourceV1::LocalGit {
            repository: PathBuf::from(repository),
        },
        sources,
        LeanStoreLimitsV1::default(),
    )
    .unwrap_or_else(|error| panic!("worker request failed: {error}"));
    let object = LeanImmutableStoreV1::open_global_package_sources(development)
        .unwrap_or_else(|error| panic!("worker Store failed: {error}"))
        .fetch_and_publish(
            &request,
            &LeanFetchCancellationV1::default(),
            LeanFetchFaultV1::None,
        )
        .unwrap_or_else(|error| panic!("worker fetch failed: {error}"));
    let publication = match object.publication() {
        LeanStorePublicationV1::Published => "published",
        LeanStorePublicationV1::Reused => "reused",
        LeanStorePublicationV1::Deduplicated => "deduplicated",
    };
    fs::write(
        result,
        format!("{publication}\n{}\n", object.object_path().display()),
    )
    .unwrap_or_else(|error| panic!("worker result failed: {error}"));
}

fn spawn_fetch(
    store: LeanImmutableStoreV1,
    request: Arc<LeanFetchRequestV1>,
    barrier: Arc<Barrier>,
) -> thread::JoinHandle<Result<leanbun_store::VerifiedPackageObjectV1, LeanStoreError>> {
    thread::spawn(move || {
        barrier.wait();
        store.fetch_and_publish(
            &request,
            &LeanFetchCancellationV1::default(),
            LeanFetchFaultV1::None,
        )
    })
}

fn spawn_worker(
    fixture: &Fixture,
    environment: &str,
    revision: &str,
    download: Sha256,
    tree: Sha256,
    result: &Path,
) -> std::process::Child {
    Command::new(
        env::current_exe().unwrap_or_else(|error| panic!("test executable failed: {error}")),
    )
    .args(["--exact", "m51b_cross_process_worker", "--nocapture"])
    .env("LEANBUN_M51B_WORKER_DEVELOPMENT", &fixture.development)
    .env("LEANBUN_M51B_WORKER_SOURCES", &fixture.sources)
    .env("LEANBUN_M51B_WORKER_REPOSITORY", &fixture.repository)
    .env("LEANBUN_M51B_WORKER_ENVIRONMENT", environment)
    .env("LEANBUN_M51B_WORKER_REVISION", revision)
    .env("LEANBUN_M51B_WORKER_DOWNLOAD", download.to_string())
    .env("LEANBUN_M51B_WORKER_TREE", tree.to_string())
    .env("LEANBUN_M51B_WORKER_RESULT", result)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .unwrap_or_else(|error| panic!("worker spawn failed: {error}"))
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|error| panic!("{name} is missing: {error}"))
}

fn parse_sha_env(name: &str) -> Sha256 {
    Sha256::parse(&required_env(name)).unwrap_or_else(|error| panic!("{name} is invalid: {error}"))
}

fn graph(
    environment: &str,
    revision: &str,
    download: Sha256,
    tree: Sha256,
) -> leanbun_resolver::LeanResolutionGraphV1 {
    let key = package_key();
    let url = source_url();
    let requested = LeanSourceRequestV1::git(url.clone(), Some("main".to_owned()), None)
        .unwrap_or_else(|error| panic!("source request failed: {error}"));
    let candidate = LeanPackageCandidateV1::new(
        key.clone(),
        requested,
        LeanExactSourceV1::git(url.clone(), revision.to_owned(), None)
            .unwrap_or_else(|error| panic!("exact source failed: {error}")),
        Vec::new(),
        None,
        Some(download),
        tree,
        sha(b"config"),
        None,
        sha(b"selected-source"),
    )
    .unwrap_or_else(|error| panic!("candidate failed: {error}"));
    let dependency = LakeRootDependencyV1::new(
        key,
        Some("git#main".to_owned()),
        LakeDependencySourceV1::Git {
            url: url.as_str().to_owned(),
            revision: Some("main".to_owned()),
            subdir: None,
        },
    )
    .unwrap_or_else(|error| panic!("root dependency failed: {error}"));
    let root = LakeRootDeclarationV1::new(environment, "lakefile.toml", vec![dependency])
        .unwrap_or_else(|error| panic!("root declaration failed: {error}"));
    let request = LeanResolutionRequestV1::new(
        root,
        None,
        LeanResolutionModeV1::update(Vec::new())
            .unwrap_or_else(|error| panic!("resolution mode failed: {error}")),
        LeanToolchainIdentityV1::new(
            "leanprover/lean4:v4.32.0",
            "8c9756b28d64dab099da31a4c09229a9e6a2ef35",
            "5.0.0-src+8c9756b",
        )
        .unwrap_or_else(|error| panic!("toolchain failed: {error}")),
    )
    .unwrap_or_else(|error| panic!("resolution request failed: {error}"));
    resolve_lean_dependencies_v1(&request, vec![candidate])
        .unwrap_or_else(|error| panic!("resolution failed: {error}"))
}

fn package_key() -> PackageKeyV1 {
    PackageKeyV1::new("", "shared").unwrap_or_else(|error| panic!("package key failed: {error}"))
}

fn source_url() -> CanonicalSourceUrlV1 {
    CanonicalSourceUrlV1::parse("https://github.com/leanbun/shared-source")
        .unwrap_or_else(|error| panic!("source URL failed: {error}"))
}

fn sha(bytes: &[u8]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn git_commit(repository: &Path, message: &str) {
    let status = Command::new("/usr/bin/git")
        .env("COPYFILE_DISABLE", "1")
        .env("GIT_AUTHOR_NAME", "LeanBun")
        .env("GIT_AUTHOR_EMAIL", "leanbun@example.invalid")
        .env("GIT_COMMITTER_NAME", "LeanBun")
        .env("GIT_COMMITTER_EMAIL", "leanbun@example.invalid")
        .args(["-C"])
        .arg(repository)
        .args(["commit", "-q", "-m", message])
        .status()
        .unwrap_or_else(|error| panic!("Git commit failed: {error}"));
    assert!(status.success());
}

fn git(repository: &Path, arguments: &[&str]) {
    let status = Command::new("/usr/bin/git")
        .env("COPYFILE_DISABLE", "1")
        .args(["-C"])
        .arg(repository)
        .args(arguments)
        .status()
        .unwrap_or_else(|error| panic!("Git failed to launch: {error}"));
    assert!(status.success(), "Git failed: {arguments:?}");
}

fn git_output(repository: &Path, arguments: &[&str]) -> String {
    let output = Command::new("/usr/bin/git")
        .env("COPYFILE_DISABLE", "1")
        .args(["-C"])
        .arg(repository)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("Git output failed: {error}"));
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap_or_else(|error| panic!("Git output is not UTF-8: {error}"))
        .trim()
        .to_owned()
}

fn directory_entry_count(path: &Path) -> usize {
    fs::read_dir(path)
        .unwrap_or_else(|error| panic!("directory read failed: {error}"))
        .count()
}

fn failure<T>(result: Result<T, LeanStoreError>) -> LeanStoreError {
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
