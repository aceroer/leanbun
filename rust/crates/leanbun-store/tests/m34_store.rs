use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_lake_bridge::{LakeDependencySourceV1, LakeRootDeclarationV1, LakeRootDependencyV1};
use leanbun_package::{
    CanonicalSourceUrlV1, PackageKeyV1, PackagePathDecisionV1, PackagePathProvenanceSetV1,
    PackagePathProvenanceV1,
};
use leanbun_resolver::{
    LeanExactSourceV1, LeanPackageCandidateV1, LeanResolutionModeV1, LeanResolutionRequestV1,
    LeanSourceRequestV1, LeanToolchainIdentityV1, resolve_lean_dependencies_v1,
};
use leanbun_store::{
    LeanFetchCancellationV1, LeanFetchFaultV1, LeanFetchRequestV1, LeanFetchSourceV1,
    LeanImmutableStoreV1, LeanStoreErrorKind, LeanStoreLimitsV1, LeanStorePublicationV1,
    normalized_tar_tree_sha256_v1,
};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    development: PathBuf,
    root: PathBuf,
    sources: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .unwrap_or_else(|| panic!("repository root is missing"))
            .to_path_buf();
        let development = repository.join(".leanbun-dev-rust");
        fs::create_dir_all(&development)
            .unwrap_or_else(|error| panic!("development root failed: {error}"));
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = development
            .join("store-fixture")
            .join("m34-tests")
            .join(format!("{}-{id}-{label}", std::process::id()));
        let sources = root.join("sources");
        fs::create_dir_all(&sources)
            .unwrap_or_else(|error| panic!("fixture source failed: {error}"));
        Self {
            development,
            root,
            sources,
        }
    }

    fn store(&self) -> LeanImmutableStoreV1 {
        LeanImmutableStoreV1::open(&self.development, self.root.join("store"))
            .unwrap_or_else(|error| panic!("store open failed: {error}"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        make_writable(&self.root);
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn sha(bytes: &[u8]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn key() -> PackageKeyV1 {
    PackageKeyV1::new("", "fixture").unwrap_or_else(|error| panic!("package key failed: {error}"))
}

fn source_url() -> CanonicalSourceUrlV1 {
    CanonicalSourceUrlV1::parse("https://github.com/leanbun/fixture")
        .unwrap_or_else(|error| panic!("source URL failed: {error}"))
}

fn graph(
    revision: &str,
    download: Sha256,
    tree: Sha256,
) -> leanbun_resolver::LeanResolutionGraphV1 {
    let package = key();
    let url = source_url();
    let requested = LeanSourceRequestV1::git(url.clone(), Some("main".to_owned()), None)
        .unwrap_or_else(|error| panic!("source request failed: {error}"));
    let candidate = LeanPackageCandidateV1::new(
        package.clone(),
        requested,
        LeanExactSourceV1::git(url.clone(), revision.to_owned(), None)
            .unwrap_or_else(|error| panic!("exact source failed: {error}")),
        Vec::new(),
        None,
        Some(download),
        tree,
        sha(b"config"),
        Some(sha(b"manifest")),
        sha(b"selected-source"),
    )
    .unwrap_or_else(|error| panic!("candidate failed: {error}"));
    let root_dependency = LakeRootDependencyV1::new(
        package,
        Some("git#main".to_owned()),
        LakeDependencySourceV1::Git {
            url: url.as_str().to_owned(),
            revision: Some("main".to_owned()),
            subdir: None,
        },
    )
    .unwrap_or_else(|error| panic!("root dependency failed: {error}"));
    let root = LakeRootDeclarationV1::new("store_fixture", "lakefile.toml", vec![root_dependency])
        .unwrap_or_else(|error| panic!("root failed: {error}"));
    let request = LeanResolutionRequestV1::new(
        root,
        None,
        LeanResolutionModeV1::update(Vec::new())
            .unwrap_or_else(|error| panic!("mode failed: {error}")),
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

fn archive_request(fixture: &Fixture, archive: &Path, bytes: &[u8]) -> LeanFetchRequestV1 {
    let tree = normalized_tar_tree_sha256_v1(bytes, LeanStoreLimitsV1::default())
        .unwrap_or_else(|error| panic!("tree digest failed: {error}"));
    let graph = graph("0000000000000000000000000000000000000001", sha(bytes), tree);
    LeanFetchRequestV1::from_graph(
        &graph,
        &key(),
        LeanFetchSourceV1::LocalArchive {
            path: archive.to_path_buf(),
        },
        &fixture.sources,
        LeanStoreLimitsV1::default(),
    )
    .unwrap_or_else(|error| panic!("fetch request failed: {error}"))
}

#[test]
fn local_archive_publishes_once_reverifies_offline_and_rejects_drift() {
    let fixture = Fixture::new("archive");
    let bytes = tar(&[
        TarEntry::directory("LeanFixture"),
        TarEntry::file(
            "LeanFixture/Main.lean",
            b"theorem ok : True := trivial\n",
            0o644,
        ),
        TarEntry::file("lakefile.toml", b"name = \"fixture\"\n", 0o644),
    ]);
    let archive = fixture.sources.join("source.tar");
    fs::write(&archive, &bytes).unwrap_or_else(|error| panic!("archive write failed: {error}"));
    let request = archive_request(&fixture, &archive, &bytes);
    let store = fixture.store();
    let published = store
        .fetch_and_publish(
            &request,
            &LeanFetchCancellationV1::default(),
            LeanFetchFaultV1::None,
        )
        .unwrap_or_else(|error| panic!("publish failed: {error}"));
    assert_eq!(published.publication(), LeanStorePublicationV1::Published);
    assert_eq!(
        published.source_tree_sha256(),
        request.candidate().source_tree_sha256()
    );
    assert_eq!(
        published.download().map(|blob| blob.sha256()),
        Some(sha(&bytes))
    );
    assert!(
        published
            .tree_path()
            .join("LeanFixture/Main.lean")
            .is_file()
    );

    fs::remove_file(&archive).unwrap_or_else(|error| panic!("archive removal failed: {error}"));
    let verified = store
        .verify_object_for_request(&request)
        .unwrap_or_else(|error| panic!("offline verification failed: {error}"));
    assert_eq!(verified.publication(), LeanStorePublicationV1::Reused);
    assert_eq!(
        verified.store_object_sha256(),
        published.store_object_sha256()
    );
    assert_eq!(
        verified.candidate_identity(),
        request.candidate().identity()
    );
    let provenance =
        PackagePathProvenanceSetV1::new(vec![PackagePathProvenanceV1::bun_generated_runtime(
            key(),
            request.candidate().selected_source_identity(),
        )])
        .unwrap_or_else(|error| panic!("M31 provenance failed: {error}"));
    let generation_root = fixture.root.join("future-generation");
    let final_path = generation_root.join("fixture");
    let decision = PackagePathDecisionV1::new(
        key(),
        &provenance,
        request.candidate().selected_source_identity(),
        generation_root
            .to_str()
            .unwrap_or_else(|| panic!("generation root is not UTF-8")),
        final_path
            .to_str()
            .unwrap_or_else(|| panic!("final path is not UTF-8")),
        verified.store_object_sha256(),
        verified.source_tree_sha256(),
        request.graph_identity(),
    )
    .unwrap_or_else(|error| panic!("M31 path decision failed: {error}"));
    assert_eq!(
        decision.store_object_sha256(),
        verified.store_object_sha256()
    );
    assert_eq!(decision.source_tree_sha256(), verified.source_tree_sha256());

    let file = verified.tree_path().join("LeanFixture/Main.lean");
    set_mode(verified.object_path(), 0o755);
    set_mode(verified.tree_path(), 0o755);
    set_mode(
        file.parent()
            .unwrap_or_else(|| panic!("file parent missing")),
        0o755,
    );
    set_mode(&file, 0o644);
    fs::write(&file, b"different bytes\n")
        .unwrap_or_else(|error| panic!("tree mutation failed: {error}"));
    let error = failure(store.verify_object_for_request(&request));
    assert_eq!(error.kind, LeanStoreErrorKind::TreeDrift);
}

#[test]
fn concurrent_loopback_fetch_is_deduplicated_and_only_one_object_is_published() {
    let fixture = Fixture::new("http");
    let bytes = Arc::new(tar(&[TarEntry::file(
        "Main.lean",
        b"def answer := 42\n",
        0o644,
    )]));
    let tree = normalized_tar_tree_sha256_v1(&bytes, LeanStoreLimitsV1::default())
        .unwrap_or_else(|error| panic!("tree digest failed: {error}"));
    let graph = graph(
        "0000000000000000000000000000000000000002",
        sha(&bytes),
        tree,
    );
    let listener =
        TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("listener failed: {error}"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("listener address failed: {error}"));
    let requests = Arc::new(AtomicUsize::new(0));
    let served = Arc::clone(&requests);
    let body = Arc::clone(&bytes);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener
            .accept()
            .unwrap_or_else(|error| panic!("accept failed: {error}"));
        served.fetch_add(1, Ordering::SeqCst);
        let mut request_bytes = [0u8; 1_024];
        let _ = stream.read(&mut request_bytes);
        let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
        stream
            .write_all(header.as_bytes())
            .unwrap_or_else(|error| panic!("response header failed: {error}"));
        for chunk in body.chunks(512) {
            stream
                .write_all(chunk)
                .unwrap_or_else(|error| panic!("response body failed: {error}"));
            thread::sleep(Duration::from_millis(2));
        }
    });
    let request = Arc::new(
        LeanFetchRequestV1::from_graph(
            &graph,
            &key(),
            LeanFetchSourceV1::LoopbackHttp {
                url: format!("http://{address}/source.tar"),
            },
            &fixture.sources,
            LeanStoreLimitsV1::default(),
        )
        .unwrap_or_else(|error| panic!("HTTP request failed: {error}")),
    );
    let store = Arc::new(fixture.store());
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let request = Arc::clone(&request);
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            store.fetch_and_publish(
                &request,
                &LeanFetchCancellationV1::default(),
                LeanFetchFaultV1::None,
            )
        }));
    }
    barrier.wait();
    let first = workers
        .remove(0)
        .join()
        .unwrap_or_else(|_| panic!("first worker panicked"))
        .unwrap_or_else(|error| panic!("first worker failed: {error}"));
    let second = workers
        .remove(0)
        .join()
        .unwrap_or_else(|_| panic!("second worker panicked"))
        .unwrap_or_else(|error| panic!("second worker failed: {error}"));
    server.join().unwrap_or_else(|_| panic!("server panicked"));
    let publications = [first.publication(), second.publication()];
    assert!(publications.contains(&LeanStorePublicationV1::Published));
    assert!(publications.contains(&LeanStorePublicationV1::Deduplicated));
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    assert_eq!(first.object_path(), second.object_path());
}

#[test]
fn injected_failures_leave_no_visible_object_and_terminal_failure_is_retained() {
    let fixture = Fixture::new("faults");
    let bytes = tar(&[TarEntry::file("Main.lean", b"def safe := true\n", 0o644)]);
    let store = fixture.store();
    for (index, fault) in [
        LeanFetchFaultV1::Download,
        LeanFetchFaultV1::Extract,
        LeanFetchFaultV1::FileSync,
        LeanFetchFaultV1::DirectorySync,
        LeanFetchFaultV1::Rename,
    ]
    .into_iter()
    .enumerate()
    {
        let archive = fixture.sources.join(format!("source-{index}.tar"));
        fs::write(&archive, &bytes).unwrap_or_else(|error| panic!("archive write failed: {error}"));
        let request = archive_request(&fixture, &archive, &bytes);
        let error =
            failure(store.fetch_and_publish(&request, &LeanFetchCancellationV1::default(), fault));
        assert_eq!(error.kind, LeanStoreErrorKind::FaultInjected);
        assert!(
            !store
                .store_root()
                .join("objects")
                .join(request.candidate().source_tree_sha256().to_string())
                .exists()
        );
        let slots = fs::read_dir(store.store_root().join("slots"))
            .unwrap_or_else(|read_error| panic!("slot read failed: {read_error}"))
            .count();
        assert_eq!(slots, 0);
        let retained = failure(store.fetch_and_publish(
            &request,
            &LeanFetchCancellationV1::default(),
            LeanFetchFaultV1::None,
        ));
        assert_eq!(retained, error);
    }
}

#[test]
fn local_git_exact_revision_is_archived_verified_and_published_without_hooks() {
    let fixture = Fixture::new("git");
    let repository = fixture.sources.join("repository");
    fs::create_dir(&repository).unwrap_or_else(|error| panic!("repository failed: {error}"));
    git(&repository, &["init", "-q"]);
    fs::write(repository.join("Main.lean"), b"def fromGit := true\n")
        .unwrap_or_else(|error| panic!("Git source failed: {error}"));
    git(&repository, &["add", "Main.lean"]);
    let status = Command::new("/usr/bin/git")
        .env("COPYFILE_DISABLE", "1")
        .env("GIT_AUTHOR_NAME", "LeanBun")
        .env("GIT_AUTHOR_EMAIL", "leanbun@example.invalid")
        .env("GIT_COMMITTER_NAME", "LeanBun")
        .env("GIT_COMMITTER_EMAIL", "leanbun@example.invalid")
        .args(["-C"])
        .arg(&repository)
        .args(["commit", "-q", "-m", "fixture"])
        .status()
        .unwrap_or_else(|error| panic!("Git commit launch failed: {error}"));
    assert!(status.success());
    let revision = git_output(&repository, &["rev-parse", "HEAD"]);
    let control_archive = fixture.sources.join("control.tar");
    let output_argument = format!("--output={}", control_archive.display());
    git(
        &repository,
        &["archive", "--format=tar", &output_argument, &revision],
    );
    let bytes = fs::read(&control_archive)
        .unwrap_or_else(|error| panic!("control archive failed: {error}"));
    let tree = normalized_tar_tree_sha256_v1(&bytes, LeanStoreLimitsV1::default())
        .unwrap_or_else(|error| panic!("Git tree digest failed: {error}"));
    let graph = graph(&revision, sha(&bytes), tree);
    let request = LeanFetchRequestV1::from_graph(
        &graph,
        &key(),
        LeanFetchSourceV1::LocalGit {
            repository: repository.clone(),
        },
        &fixture.sources,
        LeanStoreLimitsV1::default(),
    )
    .unwrap_or_else(|error| panic!("Git request failed: {error}"));
    let object = fixture
        .store()
        .fetch_and_publish(
            &request,
            &LeanFetchCancellationV1::default(),
            LeanFetchFaultV1::None,
        )
        .unwrap_or_else(|error| panic!("Git publish failed: {error}"));
    assert_eq!(object.publication(), LeanStorePublicationV1::Published);
    assert_eq!(
        object.download().map(|blob| blob.sha256()),
        Some(sha(&bytes))
    );
    assert!(object.tree_path().join("Main.lean").is_file());
}

#[test]
fn archive_parser_rejects_traversal_links_duplicates_and_expansion_bombs() {
    let traversal = tar(&[TarEntry::file("../escape", b"x", 0o644)]);
    assert_eq!(
        failure(normalized_tar_tree_sha256_v1(
            &traversal,
            LeanStoreLimitsV1::default(),
        ))
        .kind,
        LeanStoreErrorKind::PathTraversal
    );
    let link = tar(&[TarEntry::link("link", "target")]);
    assert_eq!(
        failure(normalized_tar_tree_sha256_v1(
            &link,
            LeanStoreLimitsV1::default(),
        ))
        .kind,
        LeanStoreErrorKind::UnsafeSymlink
    );
    assert_eq!(
        normalized_tar_tree_sha256_v1(&link, LeanStoreLimitsV1::registered_provider())
            .unwrap_or_else(|error| panic!("registered Git link omission failed: {error}")),
        normalized_tar_tree_sha256_v1(&tar(&[]), LeanStoreLimitsV1::registered_provider(),)
            .unwrap_or_else(|error| panic!("empty registered archive failed: {error}")),
    );
    let duplicate = tar(&[
        TarEntry::file("same", b"a", 0o644),
        TarEntry::file("same", b"b", 0o644),
    ]);
    assert_eq!(
        failure(normalized_tar_tree_sha256_v1(
            &duplicate,
            LeanStoreLimitsV1::default(),
        ))
        .kind,
        LeanStoreErrorKind::DuplicateArchiveEntry
    );
    let bomb = tar(&[TarEntry::file("large", &[0u8; 32], 0o644)]);
    let limits = LeanStoreLimitsV1 {
        maximum_expanded_bytes: 16,
        ..LeanStoreLimitsV1::default()
    };
    assert_eq!(
        failure(normalized_tar_tree_sha256_v1(&bomb, limits)).kind,
        LeanStoreErrorKind::ExpansionLimit
    );
}

fn failure<T>(result: Result<T, leanbun_store::LeanStoreError>) -> leanbun_store::LeanStoreError {
    match result {
        Ok(_) => panic!("operation unexpectedly succeeded"),
        Err(error) => error,
    }
}

struct TarEntry<'a> {
    path: &'a str,
    bytes: &'a [u8],
    mode: u32,
    kind: u8,
    link: &'a str,
}

impl<'a> TarEntry<'a> {
    fn file(path: &'a str, bytes: &'a [u8], mode: u32) -> Self {
        Self {
            path,
            bytes,
            mode,
            kind: b'0',
            link: "",
        }
    }

    fn directory(path: &'a str) -> Self {
        Self {
            path,
            bytes: &[],
            mode: 0o755,
            kind: b'5',
            link: "",
        }
    }

    fn link(path: &'a str, target: &'a str) -> Self {
        Self {
            path,
            bytes: &[],
            mode: 0o777,
            kind: b'2',
            link: target,
        }
    }
}

fn tar(entries: &[TarEntry<'_>]) -> Vec<u8> {
    let mut output = Vec::new();
    for entry in entries {
        let mut header = [0u8; 512];
        write_field(&mut header[..100], entry.path.as_bytes());
        write_octal(&mut header[100..108], u64::from(entry.mode));
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], entry.bytes.len() as u64);
        write_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = entry.kind;
        write_field(&mut header[157..257], entry.link.as_bytes());
        write_field(&mut header[257..263], b"ustar\0");
        write_field(&mut header[263..265], b"00");
        let checksum = header.iter().map(|byte| u64::from(*byte)).sum();
        write_octal(&mut header[148..156], checksum);
        output.extend_from_slice(&header);
        output.extend_from_slice(entry.bytes);
        let padding = entry.bytes.len().div_ceil(512) * 512 - entry.bytes.len();
        output.resize(output.len() + padding, 0);
    }
    output.resize(output.len() + 1_024, 0);
    output
}

fn write_field(field: &mut [u8], value: &[u8]) {
    assert!(value.len() <= field.len());
    field[..value.len()].copy_from_slice(value);
}

fn write_octal(field: &mut [u8], value: u64) {
    let digits = format!("{value:0width$o}", width = field.len() - 1);
    field.fill(0);
    field[..digits.len()].copy_from_slice(digits.as_bytes());
}

fn git(repository: &Path, arguments: &[&str]) {
    let status = Command::new("/usr/bin/git")
        .env("COPYFILE_DISABLE", "1")
        .args(["-C"])
        .arg(repository)
        .args(arguments)
        .status()
        .unwrap_or_else(|error| panic!("Git launch failed: {error}"));
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
