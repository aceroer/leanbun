use crate::acceptance::run_repository_fixture_acceptance_at_v1;
use crate::{BuildError, BuildErrorKind, RepositoryFixtureAcceptanceV1};
use leanbun_core::{Sha256, Sha256Hasher};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_REGRESSION_RECORD_BYTES: usize = 64 * 1024;
static RUN_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureRegressionV1 {
    pub run_id: Sha256,
    pub fixture: &'static str,
    pub record: PathBuf,
    pub record_sha256: Sha256,
    pub acceptance: RepositoryFixtureAcceptanceV1,
}

pub fn run_lake_basic_regression_v1(
    repository: &Path,
    supervisor_executable: &Path,
) -> Result<FixtureRegressionV1, BuildError> {
    let repository = repository
        .canonicalize()
        .map_err(|error| regression_error(format!("cannot canonicalize repository: {error}")))?;
    let development = repository.join(".leanbun-dev-rust");
    let regression = development.join("regression");
    let records = regression.join("records");
    let runs = development.join("generation-fixture/m42-regression/runs");
    ensure_private_directory(&development, &records)?;
    ensure_private_directory(&development, &runs)?;

    let run_id = allocate_run_id(&repository, &records, &runs)?;
    let execution_root = runs.join(run_id.to_string());
    let acceptance = run_repository_fixture_acceptance_at_v1(
        &repository,
        supervisor_executable,
        &execution_root,
    )?;
    if execution_root.exists() {
        return Err(regression_error(
            "lake-basic regression left its execution root behind",
        ));
    }

    let record = records.join(format!("{run_id}.record"));
    let bytes = record_bytes(run_id, &acceptance);
    let record_sha256 = hash_bytes(&bytes);
    publish_immutable(&record, &bytes)?;
    publish_latest(&regression.join("latest.record"), run_id, record_sha256)?;
    Ok(FixtureRegressionV1 {
        run_id,
        fixture: "lake-basic",
        record,
        record_sha256,
        acceptance,
    })
}

fn allocate_run_id(repository: &Path, records: &Path, runs: &Path) -> Result<Sha256, BuildError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| regression_error(format!("system clock precedes epoch: {error}")))?;
    for _ in 0..32 {
        let nonce = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"leanbun-fixture-regression-run-v1\0");
        hasher.update(repository.to_string_lossy().as_bytes());
        hasher.update(&now.as_nanos().to_be_bytes());
        hasher.update(&std::process::id().to_be_bytes());
        hasher.update(&nonce.to_be_bytes());
        let candidate = hasher.finalize();
        if !records.join(format!("{candidate}.record")).exists()
            && !runs.join(candidate.to_string()).exists()
        {
            return Ok(candidate);
        }
    }
    Err(regression_error(
        "cannot allocate a unique regression run id",
    ))
}

fn record_bytes(run_id: Sha256, report: &RepositoryFixtureAcceptanceV1) -> Vec<u8> {
    format!(
        "leanbun-fixture-regression-v1\t1\nrun-id\t{run_id}\nfixture\tlake-basic\nstatus\tpassed\nbaseline-generation-sha256\t{}\ncandidate-generation-sha256\t{}\nbuild-image-sha256\t{}\nproject-artifact-sha256\t{}\nexecution-copy\tcleaned\nregistered-template\tunchanged\nend-fixture-regression\n",
        report.baseline_generation_sha256,
        report.candidate_generation_sha256,
        report.build_image_sha256,
        report.project_artifact_sha256,
    )
    .into_bytes()
}

fn latest_bytes(run_id: Sha256, record_sha256: Sha256) -> Vec<u8> {
    format!(
        "leanbun-fixture-regression-latest-v1\t1\nrun-id\t{run_id}\nfixture\tlake-basic\nrecord-sha256\t{record_sha256}\nend-fixture-regression-latest\n"
    )
    .into_bytes()
}

fn publish_immutable(path: &Path, bytes: &[u8]) -> Result<(), BuildError> {
    if bytes.len() > MAX_REGRESSION_RECORD_BYTES {
        return Err(regression_error("regression record exceeds byte limit"));
    }
    create_synced(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).map_err(io_error)?;
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(io_error)?;
    sync_parent(path)?;
    if fs::read(path).map_err(io_error)? != bytes {
        return Err(regression_error(
            "regression record changed after publication",
        ));
    }
    Ok(())
}

fn publish_latest(path: &Path, run_id: Sha256, record_sha256: Sha256) -> Result<(), BuildError> {
    let bytes = latest_bytes(run_id, record_sha256);
    let parent = path
        .parent()
        .ok_or_else(|| regression_error("latest record has no parent"))?;
    let temp = parent.join(format!(
        ".latest-{}-{}.next",
        std::process::id(),
        RUN_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    create_synced(&temp, &bytes)?;
    fs::rename(&temp, path).map_err(io_error)?;
    sync_directory(parent)?;
    if fs::read(path).map_err(io_error)? != bytes {
        return Err(regression_error("latest regression pointer changed"));
    }
    Ok(())
}

fn create_synced(path: &Path, bytes: &[u8]) -> Result<(), BuildError> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(io_error)
}

fn sync_parent(path: &Path) -> Result<(), BuildError> {
    sync_directory(
        path.parent()
            .ok_or_else(|| regression_error("record has no parent"))?,
    )
}

fn sync_directory(path: &Path) -> Result<(), BuildError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(io_error)
}

fn ensure_private_directory(base: &Path, target: &Path) -> Result<(), BuildError> {
    let relative = target
        .strip_prefix(base)
        .map_err(|_| regression_error("regression directory escaped development root"))?;
    let mut current = base.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(regression_error("regression directory is not normalized"));
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => return Err(regression_error("regression path contains a link or file")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(io_error)?;
            }
            Err(error) => return Err(io_error(error)),
        }
        fs::set_permissions(&current, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    }
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn regression_error(message: impl Into<String>) -> BuildError {
    BuildError::new(BuildErrorKind::InputDrift, message)
}

fn io_error(error: std::io::Error) -> BuildError {
    BuildError::new(
        BuildErrorKind::Io,
        format!("fixture regression I/O failed: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_latest_codecs_are_canonical() {
        let run_id = Sha256::parse(&"1".repeat(64)).unwrap_or_else(|error| panic!("{error}"));
        let report = RepositoryFixtureAcceptanceV1 {
            baseline_generation_sha256: Sha256::parse(&"2".repeat(64))
                .unwrap_or_else(|error| panic!("{error}")),
            candidate_generation_sha256: Sha256::parse(&"3".repeat(64))
                .unwrap_or_else(|error| panic!("{error}")),
            build_image_sha256: Sha256::parse(&"4".repeat(64))
                .unwrap_or_else(|error| panic!("{error}")),
            project_artifact_sha256: Sha256::parse(&"5".repeat(64))
                .unwrap_or_else(|error| panic!("{error}")),
        };
        let record = record_bytes(run_id, &report);
        assert!(record.starts_with(b"leanbun-fixture-regression-v1\t1\n"));
        assert!(record.ends_with(b"end-fixture-regression\n"));
        let latest = latest_bytes(run_id, hash_bytes(&record));
        assert!(latest.starts_with(b"leanbun-fixture-regression-latest-v1\t1\n"));
        assert!(
            latest
                .windows(19)
                .any(|window| window == b"fixture\tlake-basic\n")
        );
        assert!(latest.ends_with(b"end-fixture-regression-latest\n"));
    }
}
