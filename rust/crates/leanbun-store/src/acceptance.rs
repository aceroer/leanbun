use crate::{
    LeanFetchCancellationV1, LeanFetchFaultV1, LeanFetchRequestV1, LeanFetchSourceV1,
    LeanImmutableStoreV1, LeanStoreError, LeanStoreErrorKind, LeanStoreLimitsV1,
    LeanStorePublicationV1, normalized_tar_tree_sha256_v1,
};
use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_lake_bridge::{LakeDependencySourceV1, LakeRootDeclarationV1, LakeRootDependencyV1};
use leanbun_lock::{CanonicalSourceUrlV1, PackageKeyV1};
use leanbun_resolver::{
    LeanExactSourceV1, LeanPackageCandidateV1, LeanResolutionModeV1, LeanResolutionRequestV1,
    LeanSourceRequestV1, LeanToolchainIdentityV1, resolve_lean_dependencies_v1,
};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoopbackUpdateAcceptanceV1 {
    pub graph_sha256: Sha256,
    pub store_object_sha256: Sha256,
    pub network_request_count: usize,
}

/// Executes M34's explicit network path against a one-request loopback source.
/// The two concurrent consumers must resolve to one immutable store object.
pub fn run_loopback_update_acceptance_v1(
    repository: &Path,
) -> Result<LoopbackUpdateAcceptanceV1, LeanStoreError> {
    let repository = repository
        .canonicalize()
        .map_err(|error| io_error(format!("cannot canonicalize repository: {error}")))?;
    if !repository.join("TEST_PROJECT_BOUNDARY.adoc").is_file() {
        return Err(boundary("network fixture requires the LeanBun repository"));
    }
    let development = repository.join(".leanbun-dev-rust");
    let root = development.join("store-fixture/m38-release-network");
    if root.exists() {
        return Err(boundary("network fixture execution root already exists"));
    }
    let sources = root.join("sources");
    fs::create_dir_all(&sources)
        .map_err(|error| io_error(format!("cannot create network fixture: {error}")))?;
    let cleanup = Cleanup(root.clone());
    let bytes = Arc::new(tar_file(
        "Main.lean",
        b"def leanbunNetworkFixture := 42\n",
        0o644,
    ));
    let tree = normalized_tar_tree_sha256_v1(&bytes, LeanStoreLimitsV1::default())?;
    let download = sha(&bytes);
    let package = PackageKeyV1::new("", "fixture")
        .map_err(|error| boundary(format!("cannot construct package key: {error}")))?;
    let source_url = CanonicalSourceUrlV1::parse("https://github.com/leanbun/fixture")
        .map_err(|error| boundary(format!("cannot construct source URL: {error}")))?;
    let source_request =
        LeanSourceRequestV1::git(source_url.clone(), Some("main".to_owned()), None)
            .map_err(|error| boundary(format!("cannot construct source request: {error}")))?;
    let candidate = LeanPackageCandidateV1::new(
        package.clone(),
        source_request,
        LeanExactSourceV1::git(
            source_url.clone(),
            "0000000000000000000000000000000000000038".to_owned(),
            None,
        )
        .map_err(|error| boundary(format!("cannot construct exact source: {error}")))?,
        Vec::new(),
        None,
        Some(download),
        tree,
        sha(b"config"),
        Some(sha(b"manifest")),
        sha(b"selected-source"),
    )
    .map_err(|error| boundary(format!("cannot construct source candidate: {error}")))?;
    let dependency = LakeRootDependencyV1::new(
        package.clone(),
        Some("git#main".to_owned()),
        LakeDependencySourceV1::Git {
            url: source_url.as_str().to_owned(),
            revision: Some("main".to_owned()),
            subdir: None,
        },
    )
    .map_err(|error| boundary(format!("cannot construct root dependency: {error}")))?;
    let declaration =
        LakeRootDeclarationV1::new("store_fixture", "lakefile.toml", vec![dependency])
            .map_err(|error| boundary(format!("cannot construct root declaration: {error}")))?;
    let request = LeanResolutionRequestV1::new(
        declaration,
        None,
        LeanResolutionModeV1::update(Vec::new())
            .map_err(|error| boundary(format!("cannot construct update mode: {error}")))?,
        LeanToolchainIdentityV1::new(
            "leanprover/lean4:v4.32.0",
            "8c9756b28d64dab099da31a4c09229a9e6a2ef35",
            "5.0.0-src+8c9756b",
        )
        .map_err(|error| boundary(format!("cannot construct toolchain: {error}")))?,
    )
    .map_err(|error| boundary(format!("cannot construct resolution request: {error}")))?;
    let graph = resolve_lean_dependencies_v1(&request, vec![candidate])
        .map_err(|error| boundary(format!("cannot resolve network fixture: {error}")))?;

    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|error| io_error(format!("cannot bind loopback fixture: {error}")))?;
    let address = listener
        .local_addr()
        .map_err(|error| io_error(format!("cannot inspect loopback address: {error}")))?;
    let request_count = Arc::new(AtomicUsize::new(0));
    let served = Arc::clone(&request_count);
    let body = Arc::clone(&bytes);
    let server = thread::spawn(move || -> std::io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        served.fetch_add(1, Ordering::SeqCst);
        let mut request_bytes = [0_u8; 1_024];
        let _ = stream.read(&mut request_bytes)?;
        let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
        stream.write_all(header.as_bytes())?;
        stream.write_all(&body)?;
        Ok(())
    });
    let fetch = Arc::new(LeanFetchRequestV1::from_graph(
        &graph,
        &package,
        LeanFetchSourceV1::LoopbackHttp {
            url: format!("http://{address}/source.tar"),
        },
        &sources,
        LeanStoreLimitsV1::default(),
    )?);
    let store = Arc::new(LeanImmutableStoreV1::open(
        &development,
        root.join("store"),
    )?);
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let fetch = Arc::clone(&fetch);
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            store.fetch_and_publish(
                &fetch,
                &LeanFetchCancellationV1::default(),
                LeanFetchFaultV1::None,
            )
        }));
    }
    barrier.wait();
    let first = workers
        .remove(0)
        .join()
        .map_err(|_| io_error("first network worker panicked"))??;
    let second = workers
        .remove(0)
        .join()
        .map_err(|_| io_error("second network worker panicked"))??;
    server
        .join()
        .map_err(|_| io_error("loopback server panicked"))?
        .map_err(|error| io_error(format!("loopback server failed: {error}")))?;
    let publications = [first.publication(), second.publication()];
    if !publications.contains(&LeanStorePublicationV1::Published)
        || !publications.contains(&LeanStorePublicationV1::Deduplicated)
        || first.store_object_sha256() != second.store_object_sha256()
        || request_count.load(Ordering::SeqCst) != 1
    {
        return Err(boundary(
            "concurrent explicit update did not deduplicate to one publication",
        ));
    }
    let report = LoopbackUpdateAcceptanceV1 {
        graph_sha256: graph.identity(),
        store_object_sha256: first.store_object_sha256(),
        network_request_count: request_count.load(Ordering::SeqCst),
    };
    drop(cleanup);
    Ok(report)
}

fn sha(bytes: &[u8]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn tar_file(path: &str, bytes: &[u8], mode: u32) -> Vec<u8> {
    let mut header = [0_u8; 512];
    write_field(&mut header[..100], path.as_bytes());
    write_octal(&mut header[100..108], u64::from(mode));
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], bytes.len() as u64);
    write_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = b'0';
    write_field(&mut header[257..263], b"ustar\0");
    write_field(&mut header[263..265], b"00");
    let checksum = header.iter().map(|byte| u64::from(*byte)).sum();
    write_octal(&mut header[148..156], checksum);
    let mut output = Vec::from(header);
    output.extend_from_slice(bytes);
    output.resize(
        output.len() + (bytes.len().div_ceil(512) * 512 - bytes.len()),
        0,
    );
    output.resize(output.len() + 1_024, 0);
    output
}

fn write_field(field: &mut [u8], value: &[u8]) {
    field[..value.len()].copy_from_slice(value);
}

fn write_octal(field: &mut [u8], value: u64) {
    let digits = format!("{value:0width$o}", width = field.len() - 1);
    field.fill(0);
    field[..digits.len()].copy_from_slice(digits.as_bytes());
}

fn boundary(message: impl Into<String>) -> LeanStoreError {
    LeanStoreError::new(LeanStoreErrorKind::BoundaryViolation, message)
}

fn io_error(message: impl Into<String>) -> LeanStoreError {
    LeanStoreError::new(LeanStoreErrorKind::DownloadFailed, message)
}

struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        make_writable(&self.0);
        let _ = fs::remove_dir_all(&self.0);
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
