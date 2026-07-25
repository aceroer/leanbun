use crate::archive::{TreePlan, parse_tar, plan_directory};
use crate::model::{
    LeanFetchCancellationV1, LeanFetchFaultV1, LeanFetchRequestV1, LeanFetchSourceV1,
    LeanStoreError, LeanStoreErrorKind, VerifiedDownloadBlobV1, sha256,
};
use leanbun_resolver::LeanExactSourceV1;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) struct FetchedSource {
    pub plan: TreePlan,
    pub download: Option<VerifiedDownloadBlobV1>,
}

pub(crate) fn fetch_and_plan(
    request: &LeanFetchRequestV1,
    slot: &Path,
    cancellation: &LeanFetchCancellationV1,
    fault: LeanFetchFaultV1,
) -> Result<FetchedSource, LeanStoreError> {
    check_cancelled(cancellation)?;
    if fault == LeanFetchFaultV1::Download {
        return Err(injected("download"));
    }
    match request.source() {
        LeanFetchSourceV1::LocalDirectory { path } => {
            let root = bounded_existing_path(path, request.allowed_source_root())?;
            let plan = plan_directory(&root, request.limits())?;
            check_tree(request, &plan)?;
            Ok(FetchedSource {
                plan,
                download: None,
            })
        }
        LeanFetchSourceV1::LocalArchive { path } => {
            let path = bounded_existing_path(path, request.allowed_source_root())?;
            let bytes =
                read_bounded_file(&path, request.limits().maximum_download_bytes, cancellation)?;
            finish_archive(request, bytes, cancellation, fault)
        }
        LeanFetchSourceV1::LoopbackHttp { url } => {
            let bytes = fetch_loopback(request, url, cancellation)?;
            finish_archive(request, bytes, cancellation, fault)
        }
        LeanFetchSourceV1::LocalGit { repository } => {
            let repository = bounded_existing_path(repository, request.allowed_source_root())?;
            let archive = slot.join("git-source.tar");
            fetch_local_git(request, &repository, &archive, cancellation)?;
            let bytes = read_bounded_file(
                &archive,
                request.limits().maximum_download_bytes,
                cancellation,
            )?;
            finish_archive(request, bytes, cancellation, fault)
        }
    }
}

fn finish_archive(
    request: &LeanFetchRequestV1,
    bytes: Vec<u8>,
    cancellation: &LeanFetchCancellationV1,
    fault: LeanFetchFaultV1,
) -> Result<FetchedSource, LeanStoreError> {
    check_cancelled(cancellation)?;
    let digest = sha256(&bytes);
    let expected = request.candidate().download_integrity().ok_or_else(|| {
        LeanStoreError::new(
            LeanStoreErrorKind::IntegrityMismatch,
            "archive source lacks the required M33 download integrity",
        )
    })?;
    if digest != expected {
        return Err(LeanStoreError::new(
            LeanStoreErrorKind::IntegrityMismatch,
            "download SHA-256 differs from the M33 candidate",
        ));
    }
    if fault == LeanFetchFaultV1::Extract {
        return Err(injected("extract"));
    }
    let plan = parse_tar(&bytes, request.limits())?;
    check_tree(request, &plan)?;
    Ok(FetchedSource {
        plan,
        download: Some(VerifiedDownloadBlobV1::new(digest, bytes.len() as u64)),
    })
}

fn check_tree(request: &LeanFetchRequestV1, plan: &TreePlan) -> Result<(), LeanStoreError> {
    if plan.digest != request.candidate().source_tree_sha256() {
        return Err(LeanStoreError::new(
            LeanStoreErrorKind::TreeDigestMismatch,
            "normalized source tree differs from the M33 candidate",
        ));
    }
    Ok(())
}

fn bounded_existing_path(path: &Path, allowed_root: &Path) -> Result<PathBuf, LeanStoreError> {
    let root = allowed_root.canonicalize().map_err(|error| {
        LeanStoreError::new(
            LeanStoreErrorKind::BoundaryViolation,
            format!("cannot canonicalize allowed source root: {error}"),
        )
    })?;
    let path = path.canonicalize().map_err(|error| {
        LeanStoreError::new(
            LeanStoreErrorKind::BoundaryViolation,
            format!("cannot canonicalize local source: {error}"),
        )
    })?;
    if path != root && !path.starts_with(&root) {
        return Err(LeanStoreError::new(
            LeanStoreErrorKind::BoundaryViolation,
            "local source escapes its allowed root",
        ));
    }
    Ok(path)
}

fn read_bounded_file(
    path: &Path,
    maximum: u64,
    cancellation: &LeanFetchCancellationV1,
) -> Result<Vec<u8>, LeanStoreError> {
    let metadata = fs::symlink_metadata(path).map_err(download_error)?;
    if !metadata.file_type().is_file() || metadata.len() > maximum {
        return Err(LeanStoreError::new(
            LeanStoreErrorKind::LimitExceeded,
            "download is not a regular file or exceeds its byte limit",
        ));
    }
    let file = fs::File::open(path).map_err(download_error)?;
    let mut reader = file.take(maximum + 1);
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 64 * 1_024];
    loop {
        check_cancelled(cancellation)?;
        let count = reader.read(&mut chunk).map_err(download_error)?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.len() as u64 > maximum {
            return Err(LeanStoreError::new(
                LeanStoreErrorKind::LimitExceeded,
                "download exceeds its byte limit",
            ));
        }
    }
    Ok(bytes)
}

fn fetch_loopback(
    request: &LeanFetchRequestV1,
    url: &str,
    cancellation: &LeanFetchCancellationV1,
) -> Result<Vec<u8>, LeanStoreError> {
    let (address, target, host_header) = parse_loopback_url(url)?;
    let attempts = usize::from(request.limits().maximum_retries) + 1;
    let mut last = None;
    for attempt in 0..attempts {
        check_cancelled(cancellation)?;
        match fetch_http_once(request, address, &target, &host_header, cancellation) {
            Ok(bytes) => return Ok(bytes),
            Err(error) if attempt + 1 < attempts && is_retryable(&error) => {
                last = Some(error);
                thread::sleep(Duration::from_millis(20 * (attempt as u64 + 1)));
            }
            Err(error) => return Err(error),
        }
    }
    Err(last.unwrap_or_else(|| {
        LeanStoreError::new(
            LeanStoreErrorKind::DownloadFailed,
            "HTTP fetch exhausted retries",
        )
    }))
}

fn fetch_http_once(
    request: &LeanFetchRequestV1,
    address: SocketAddr,
    target: &str,
    host_header: &str,
    cancellation: &LeanFetchCancellationV1,
) -> Result<Vec<u8>, LeanStoreError> {
    let mut stream = TcpStream::connect_timeout(&address, request.limits().connect_timeout)
        .map_err(download_error)?;
    stream
        .set_read_timeout(Some(request.limits().io_timeout))
        .map_err(download_error)?;
    stream
        .set_write_timeout(Some(request.limits().io_timeout))
        .map_err(download_error)?;
    let wire = format!(
        "GET {target} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n"
    );
    stream.write_all(wire.as_bytes()).map_err(download_error)?;
    let maximum = request.limits().maximum_download_bytes;
    let total_limit = maximum
        .checked_add(crate::model::MAX_HTTP_HEADER_BYTES_V1 as u64)
        .ok_or_else(|| {
            LeanStoreError::new(LeanStoreErrorKind::LimitExceeded, "HTTP limit overflow")
        })?;
    let mut response = Vec::new();
    let mut reader = stream.take(total_limit + 1);
    let mut chunk = [0u8; 16 * 1_024];
    loop {
        check_cancelled(cancellation)?;
        let count = reader.read(&mut chunk).map_err(download_error)?;
        if count == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..count]);
        if response.len() as u64 > total_limit {
            return Err(LeanStoreError::new(
                LeanStoreErrorKind::LimitExceeded,
                "HTTP response exceeds its byte limit",
            ));
        }
    }
    parse_http_response(&response, maximum)
}

fn parse_loopback_url(url: &str) -> Result<(SocketAddr, String, String), LeanStoreError> {
    let rest = url.strip_prefix("http://").ok_or_else(http_error)?;
    let (authority, target) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() || authority.contains('@') || authority.len() > 128 {
        return Err(http_error());
    }
    let socket: SocketAddr = authority.parse().map_err(|_| http_error())?;
    if !socket.ip().is_loopback() {
        return Err(LeanStoreError::new(
            LeanStoreErrorKind::BoundaryViolation,
            "only numeric loopback HTTP addresses are allowed",
        ));
    }
    let target = format!("/{target}");
    if target.bytes().any(|byte| byte.is_ascii_control()) || target.contains('#') {
        return Err(http_error());
    }
    let host = match socket.ip() {
        IpAddr::V4(ip) => format!("{ip}:{}", socket.port()),
        IpAddr::V6(ip) => format!("[{ip}]:{}", socket.port()),
    };
    Ok((socket, target, host))
}

fn parse_http_response(response: &[u8], maximum: u64) -> Result<Vec<u8>, LeanStoreError> {
    let marker = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(http_error)?;
    if marker + 4 > crate::model::MAX_HTTP_HEADER_BYTES_V1 {
        return Err(LeanStoreError::new(
            LeanStoreErrorKind::LimitExceeded,
            "HTTP header exceeds its byte limit",
        ));
    }
    let header = std::str::from_utf8(&response[..marker]).map_err(|_| http_error())?;
    let mut lines = header.split("\r\n");
    let status = lines.next().ok_or_else(http_error)?;
    if status.split_whitespace().nth(1) != Some("200") {
        return Err(LeanStoreError::new(
            LeanStoreErrorKind::DownloadFailed,
            format!("HTTP fetch returned {status}"),
        ));
    }
    let mut length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(http_error)?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(http_error());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(http_error());
            }
            length = Some(value.trim().parse::<u64>().map_err(|_| http_error())?);
        }
    }
    let length = length.ok_or_else(http_error)?;
    if length > maximum {
        return Err(LeanStoreError::new(
            LeanStoreErrorKind::LimitExceeded,
            "HTTP body exceeds its byte limit",
        ));
    }
    let body = &response[marker + 4..];
    if body.len() as u64 != length {
        return Err(http_error());
    }
    Ok(body.to_vec())
}

fn fetch_local_git(
    request: &LeanFetchRequestV1,
    repository: &Path,
    output: &Path,
    cancellation: &LeanFetchCancellationV1,
) -> Result<(), LeanStoreError> {
    let (revision, subdir) = match request.candidate().resolved_source() {
        LeanExactSourceV1::Git {
            exact_revision,
            subdir,
            ..
        } => (exact_revision.as_str(), subdir.as_deref()),
        LeanExactSourceV1::Path { .. } => {
            return Err(LeanStoreError::new(
                LeanStoreErrorKind::InvalidField,
                "local Git fetch requires an exact Git candidate",
            ));
        }
    };
    check_cancelled(cancellation)?;
    let mut verify = git_command(repository);
    verify
        .args(["cat-file", "-e"])
        .arg(format!("{revision}^{{commit}}"));
    run_bounded_command(verify, request.limits().git_timeout, cancellation)?;
    let treeish = subdir.map_or_else(
        || revision.to_owned(),
        |subdir| format!("{revision}:{subdir}"),
    );
    let mut command = git_command(repository);
    command
        .args(["archive", "--format=tar"])
        .arg(format!("--output={}", output.display()))
        .arg(treeish);
    run_bounded_command(command, request.limits().git_timeout, cancellation)?;
    Ok(())
}

fn git_command(repository: &Path) -> Command {
    let mut command = Command::new("/usr/bin/git");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("COPYFILE_DISABLE", "1")
        .arg("--no-optional-locks")
        .args(["-c", "core.hooksPath=/dev/null", "-C"])
        .arg(repository);
    command
}

fn run_bounded_command(
    mut command: Command,
    timeout: Duration,
    cancellation: &LeanFetchCancellationV1,
) -> Result<(), LeanStoreError> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(git_error)?;
    let started = Instant::now();
    loop {
        if cancellation.is_cancelled() || started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(if cancellation.is_cancelled() {
                LeanStoreError::new(LeanStoreErrorKind::Cancelled, "fetch was cancelled")
            } else {
                LeanStoreError::new(LeanStoreErrorKind::GitFailed, "Git command timed out")
            });
        }
        match child.try_wait().map_err(git_error)? {
            Some(status) if status.success() => return Ok(()),
            Some(status) => {
                return Err(LeanStoreError::new(
                    LeanStoreErrorKind::GitFailed,
                    format!("Git command failed with {status}"),
                ));
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn check_cancelled(cancellation: &LeanFetchCancellationV1) -> Result<(), LeanStoreError> {
    if cancellation.is_cancelled() {
        return Err(LeanStoreError::new(
            LeanStoreErrorKind::Cancelled,
            "fetch was cancelled",
        ));
    }
    Ok(())
}

fn is_retryable(error: &LeanStoreError) -> bool {
    error.kind == LeanStoreErrorKind::DownloadFailed
}

fn injected(stage: &str) -> LeanStoreError {
    LeanStoreError::new(
        LeanStoreErrorKind::FaultInjected,
        format!("fault injected at {stage} stage"),
    )
}

fn download_error(error: std::io::Error) -> LeanStoreError {
    LeanStoreError::new(
        LeanStoreErrorKind::DownloadFailed,
        format!("download failed: {error}"),
    )
}

fn git_error(error: std::io::Error) -> LeanStoreError {
    LeanStoreError::new(
        LeanStoreErrorKind::GitFailed,
        format!("Git command failed: {error}"),
    )
}

fn http_error() -> LeanStoreError {
    LeanStoreError::new(
        LeanStoreErrorKind::HttpProtocol,
        "HTTP response or loopback URL is outside the v1 protocol",
    )
}
