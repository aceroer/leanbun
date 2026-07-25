use super::external_acceptance::publish_immutable_record;
use super::negative_regression::{NegativeFixtureRegressionV1, run_negative_fixture_regression_v1};
use super::{ManagedProjectError, ensure_private_directory, input_error, io_error, sync_directory};
use leanbun_core::{DiagnosticCode, Sha256, Sha256Hasher};
use leanbun_evidence::parse_project_manifest;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

static HISTORY_COUNTER: AtomicU64 = AtomicU64::new(1);
const MAX_RECORD_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcurrentHistoryRegressionV1 {
    pub run_id: Sha256,
    pub worker_records: [Sha256; 2],
    pub failure_terminal_record: PathBuf,
    pub failure_terminal_sha256: Sha256,
    pub audit_record: PathBuf,
    pub audit_record_sha256: Sha256,
    pub inventory_sha256: Sha256,
    pub positive_record_count: usize,
    pub negative_record_count: usize,
    pub terminal_record_count: usize,
    pub prior_audit_record_count: usize,
}

pub fn run_concurrent_history_regression_v1(
    repository: &Path,
) -> Result<ConcurrentHistoryRegressionV1, ManagedProjectError> {
    let repository = repository
        .canonicalize()
        .map_err(|error| input_error(format!("cannot canonicalize history repository: {error}")))?;
    if !repository.join("TEST_PROJECT_BOUNDARY.adoc").is_file() {
        return Err(input_error("history regression repository is not LeanBun"));
    }
    let development = repository.join(".leanbun-dev-rust");
    let regression = development.join("regression");
    let terminals = regression.join("terminal-records");
    let audits = regression.join("audit-records");
    ensure_private_directory(&development, &terminals)?;
    ensure_private_directory(&development, &audits)?;
    let positive_latest_before = read_regular_with_mode(&regression.join("latest.record"))?;
    let run_id = allocate_run_id(&repository, &audits)?;

    let barrier = Arc::new(Barrier::new(3));
    let left_repository = repository.clone();
    let right_repository = repository.clone();
    let failure_input = repository.join("test/fixtures/m42-negative/malformed-manifest.json");
    let (left, right, failure) = thread::scope(|scope| {
        let left_barrier = Arc::clone(&barrier);
        let left = scope.spawn(move || {
            left_barrier.wait();
            run_negative_fixture_regression_v1(&left_repository)
        });
        let right_barrier = Arc::clone(&barrier);
        let right = scope.spawn(move || {
            right_barrier.wait();
            run_negative_fixture_regression_v1(&right_repository)
        });
        let failure_barrier = Arc::clone(&barrier);
        let failure = scope.spawn(move || {
            failure_barrier.wait();
            malformed_failure(&failure_input)
        });
        (left.join(), right.join(), failure.join())
    });
    let left = left.map_err(|_| input_error("left regression worker panicked"))?;
    let right = right.map_err(|_| input_error("right regression worker panicked"))?;
    let failure = failure.map_err(|_| input_error("failure regression worker panicked"))?;

    let left_terminal =
        publish_worker_terminal(&terminals, run_id, "negative-worker-a", left.as_ref().ok())?;
    let right_terminal =
        publish_worker_terminal(&terminals, run_id, "negative-worker-b", right.as_ref().ok())?;
    let expected_failure = matches!(failure, Err(DiagnosticCode::JSON_MALFORMED));
    let failure_terminal = publish_failure_terminal(
        &terminals,
        run_id,
        if expected_failure {
            "JSON_MALFORMED"
        } else {
            "UNEXPECTED_FAILURE_OUTCOME"
        },
    )?;

    let left = left.map_err(|error| {
        input_error(format!("left concurrent regression worker failed: {error}"))
    })?;
    let right = right.map_err(|error| {
        input_error(format!(
            "right concurrent regression worker failed: {error}"
        ))
    })?;
    if !expected_failure {
        return Err(input_error(
            "injected malformed worker did not reach JSON_MALFORMED",
        ));
    }
    if left.run_id == right.run_id || left.record_sha256 == right.record_sha256 {
        return Err(input_error(
            "concurrent negative workers did not publish unique evidence",
        ));
    }
    if positive_latest_before != read_regular_with_mode(&regression.join("latest.record"))? {
        return Err(input_error(
            "concurrent regression changed positive latest evidence",
        ));
    }

    let inventory = audit_history(&regression)?;
    if inventory.terminal_records.get(&left_terminal.0) != Some(&left_terminal.1)
        || inventory.terminal_records.get(&right_terminal.0) != Some(&right_terminal.1)
        || inventory.terminal_records.get(&failure_terminal.0) != Some(&failure_terminal.1)
    {
        return Err(input_error("history audit omitted a new terminal record"));
    }
    let audit_bytes = audit_record_bytes(run_id, &left, &right, failure_terminal.1, &inventory);
    let audit_record_sha256 = hash_bytes(&audit_bytes);
    let audit_record = audits.join(format!("{run_id}.record"));
    publish_immutable_record(&audit_record, &audit_bytes)?;
    publish_latest(
        &regression.join("audit-latest.record"),
        "leanbun-regression-history-audit-latest-v1\t1",
        "end-regression-history-audit-latest",
        run_id,
        audit_record_sha256,
    )?;
    verify_latest(
        &regression.join("audit-latest.record"),
        &audits,
        "leanbun-regression-history-audit-latest-v1\t1",
        "end-regression-history-audit-latest",
    )?;
    let after = audit_history(&regression)?;
    if inventory.positive_records != after.positive_records
        || inventory.negative_records != after.negative_records
        || inventory.terminal_records != after.terminal_records
        || after.audit_records.len() != inventory.audit_records.len() + 1
        || after.audit_records.get(&format!("{run_id}.record")) != Some(&audit_record_sha256)
    {
        return Err(input_error(
            "retain-all policy changed history outside the new audit record",
        ));
    }
    Ok(ConcurrentHistoryRegressionV1 {
        run_id,
        worker_records: [left.record_sha256, right.record_sha256],
        failure_terminal_record: terminals.join(failure_terminal.0),
        failure_terminal_sha256: failure_terminal.1,
        audit_record,
        audit_record_sha256,
        inventory_sha256: inventory.identity,
        positive_record_count: inventory.positive_records.len(),
        negative_record_count: inventory.negative_records.len(),
        terminal_record_count: inventory.terminal_records.len(),
        prior_audit_record_count: inventory.audit_records.len(),
    })
}

fn malformed_failure(path: &Path) -> Result<(), DiagnosticCode> {
    let text = fs::read_to_string(path).map_err(|_| DiagnosticCode::EVIDENCE_READ_FAILED)?;
    parse_project_manifest(&text)
        .map(|_| ())
        .map_err(|error| error.code)
}

fn publish_worker_terminal(
    root: &Path,
    scheduler: Sha256,
    name: &str,
    report: Option<&NegativeFixtureRegressionV1>,
) -> Result<(String, Sha256), ManagedProjectError> {
    let job_id = job_id(scheduler, name);
    let (terminal, outcome, failure) = report
        .map_or(("failed", "none".to_owned(), "WORKER_FAILED"), |report| {
            ("passed", report.record_sha256.to_string(), "none")
        });
    let bytes = format!(
        "leanbun-regression-terminal-v1\t1\njob-id\t{job_id}\nscheduler-run-id\t{scheduler}\njob\t{name}\nterminal\t{terminal}\noutcome-record-sha256\t{outcome}\nfailure-code\t{failure}\nend-regression-terminal\n"
    )
    .into_bytes();
    publish_terminal(root, job_id, &bytes)
}

fn publish_failure_terminal(
    root: &Path,
    scheduler: Sha256,
    failure: &str,
) -> Result<(String, Sha256), ManagedProjectError> {
    let name = "malformed-manifest-failure";
    let job_id = job_id(scheduler, name);
    let bytes = format!(
        "leanbun-regression-terminal-v1\t1\njob-id\t{job_id}\nscheduler-run-id\t{scheduler}\njob\t{name}\nterminal\tfailed\noutcome-record-sha256\tnone\nfailure-code\t{failure}\nend-regression-terminal\n"
    )
    .into_bytes();
    publish_terminal(root, job_id, &bytes)
}

fn publish_terminal(
    root: &Path,
    job_id: Sha256,
    bytes: &[u8],
) -> Result<(String, Sha256), ManagedProjectError> {
    let name = format!("{job_id}.record");
    let digest = hash_bytes(bytes);
    publish_immutable_record(&root.join(&name), bytes)?;
    Ok((name, digest))
}

fn job_id(scheduler: Sha256, name: &str) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-regression-job-v1\0");
    hasher.update(scheduler.as_bytes());
    hasher.update(&(name.len() as u64).to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.finalize()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HistoryInventory {
    positive_records: BTreeMap<String, Sha256>,
    negative_records: BTreeMap<String, Sha256>,
    terminal_records: BTreeMap<String, Sha256>,
    audit_records: BTreeMap<String, Sha256>,
    identity: Sha256,
}

fn audit_history(regression: &Path) -> Result<HistoryInventory, ManagedProjectError> {
    let positive_records = scan_records(
        &regression.join("records"),
        "leanbun-fixture-regression-v1\t1",
        "run-id",
        "status\tpassed",
        "end-fixture-regression",
    )?;
    let negative_records = scan_records(
        &regression.join("negative-records"),
        "leanbun-negative-fixture-regression-v1\t1",
        "run-id",
        "status\tpassed",
        "end-negative-fixture-regression",
    )?;
    let terminal_records = scan_records(
        &regression.join("terminal-records"),
        "leanbun-regression-terminal-v1\t1",
        "job-id",
        "scheduler-run-id\t",
        "end-regression-terminal",
    )?;
    let audit_records = scan_records(
        &regression.join("audit-records"),
        "leanbun-regression-history-audit-v1\t1",
        "run-id",
        "retention-policy\tretain-all-v1",
        "end-regression-history-audit",
    )?;
    verify_latest(
        &regression.join("latest.record"),
        &regression.join("records"),
        "leanbun-fixture-regression-latest-v1\t1",
        "end-fixture-regression-latest",
    )?;
    verify_latest(
        &regression.join("negative-latest.record"),
        &regression.join("negative-records"),
        "leanbun-negative-fixture-regression-latest-v1\t1",
        "end-negative-fixture-regression-latest",
    )?;
    let identity = inventory_identity([
        ("positive", &positive_records),
        ("negative", &negative_records),
        ("terminal", &terminal_records),
        ("audit-prior", &audit_records),
    ]);
    Ok(HistoryInventory {
        positive_records,
        negative_records,
        terminal_records,
        audit_records,
        identity,
    })
}

fn scan_records(
    root: &Path,
    schema: &str,
    id_field: &str,
    required: &str,
    terminal: &str,
) -> Result<BTreeMap<String, Sha256>, ManagedProjectError> {
    if !root.exists() {
        return Ok(BTreeMap::new());
    }
    let mut records = BTreeMap::new();
    for entry in fs::read_dir(root).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(io_error)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| input_error("history record name is not UTF-8"))?;
        if !metadata.file_type().is_file()
            || metadata.len() > MAX_RECORD_BYTES
            || metadata.permissions().mode() & 0o777 != 0o400
            || !name.ends_with(".record")
        {
            return Err(input_error("history contains a noncanonical record entry"));
        }
        let bytes = fs::read(entry.path()).map_err(io_error)?;
        let text =
            std::str::from_utf8(&bytes).map_err(|_| input_error("history record is not UTF-8"))?;
        if text.lines().next() != Some(schema)
            || !text
                .lines()
                .any(|line| line == required || line.starts_with(required))
            || text.lines().last() != Some(terminal)
        {
            return Err(input_error("history record schema or terminal is invalid"));
        }
        let identity = unique_field(text, id_field)?;
        if name.strip_suffix(".record") != Some(identity) {
            return Err(input_error("history record filename differs from identity"));
        }
        records.insert(name, hash_bytes(&bytes));
    }
    Ok(records)
}

fn verify_latest(
    path: &Path,
    records: &Path,
    schema: &str,
    terminal: &str,
) -> Result<(), ManagedProjectError> {
    let (bytes, mode) = read_regular_with_mode(path)?;
    if mode != 0o600 {
        return Err(input_error("history latest pointer mode is not 0600"));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| input_error("history latest pointer is not UTF-8"))?;
    if text.lines().next() != Some(schema) || text.lines().last() != Some(terminal) {
        return Err(input_error("history latest pointer schema is invalid"));
    }
    let run_id = unique_field(text, "run-id")?;
    let expected = Sha256::parse(unique_field(text, "record-sha256")?)
        .map_err(|_| input_error("history latest record digest is invalid"))?;
    let record = records.join(format!("{run_id}.record"));
    let metadata = fs::symlink_metadata(&record).map_err(io_error)?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o777 != 0o400
        || hash_bytes(&fs::read(record).map_err(io_error)?) != expected
    {
        return Err(input_error(
            "history latest pointer does not bind its record",
        ));
    }
    Ok(())
}

fn unique_field<'a>(text: &'a str, name: &str) -> Result<&'a str, ManagedProjectError> {
    let prefix = format!("{name}\t");
    let values = text
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .collect::<Vec<_>>();
    match values.as_slice() {
        [value] if !value.is_empty() => Ok(value),
        _ => Err(input_error(format!(
            "history field {name} is missing or repeated"
        ))),
    }
}

fn inventory_identity<const N: usize>(
    namespaces: [(&str, &BTreeMap<String, Sha256>); N],
) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-regression-history-inventory-v1\0");
    for (namespace, records) in namespaces {
        for (name, digest) in records {
            hasher.update(&(namespace.len() as u64).to_be_bytes());
            hasher.update(namespace.as_bytes());
            hasher.update(&(name.len() as u64).to_be_bytes());
            hasher.update(name.as_bytes());
            hasher.update(digest.as_bytes());
        }
    }
    hasher.finalize()
}

fn audit_record_bytes(
    run_id: Sha256,
    left: &NegativeFixtureRegressionV1,
    right: &NegativeFixtureRegressionV1,
    failure_terminal: Sha256,
    inventory: &HistoryInventory,
) -> Vec<u8> {
    format!(
        "leanbun-regression-history-audit-v1\t1\nrun-id\t{run_id}\nstatus\tpassed\nconcurrent-worker-count\t2\nworker-record-sha256\t{}\nworker-record-sha256\t{}\nexpected-failure\tJSON_MALFORMED\nfailure-terminal-record-sha256\t{failure_terminal}\npositive-record-count\t{}\nnegative-record-count\t{}\nterminal-record-count\t{}\nprior-audit-record-count\t{}\ninventory-sha256\t{}\npositive-latest\tunchanged\nretention-policy\tretain-all-v1\nautomatic-deletion\tdisabled\nend-regression-history-audit\n",
        left.record_sha256,
        right.record_sha256,
        inventory.positive_records.len(),
        inventory.negative_records.len(),
        inventory.terminal_records.len(),
        inventory.audit_records.len(),
        inventory.identity,
    )
    .into_bytes()
}

fn allocate_run_id(repository: &Path, audits: &Path) -> Result<Sha256, ManagedProjectError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| input_error(format!("system clock precedes epoch: {error}")))?;
    for _ in 0..32 {
        let nonce = HISTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"leanbun-concurrent-history-regression-v1\0");
        hasher.update(repository.to_string_lossy().as_bytes());
        hasher.update(&now.as_nanos().to_be_bytes());
        hasher.update(&std::process::id().to_be_bytes());
        hasher.update(&nonce.to_be_bytes());
        let candidate = hasher.finalize();
        if !audits.join(format!("{candidate}.record")).exists() {
            return Ok(candidate);
        }
    }
    Err(input_error("cannot allocate concurrent history run id"))
}

fn publish_latest(
    path: &Path,
    schema: &str,
    terminal: &str,
    run_id: Sha256,
    record_sha256: Sha256,
) -> Result<(), ManagedProjectError> {
    let bytes = format!(
        "{schema}\nrun-id\t{run_id}\nrecord-sha256\t{record_sha256}\nretention-policy\tretain-all-v1\n{terminal}\n"
    )
    .into_bytes();
    let parent = path
        .parent()
        .ok_or_else(|| input_error("history latest pointer has no parent"))?;
    let temp = parent.join(format!(
        ".audit-latest-{}-{}.next",
        std::process::id(),
        HISTORY_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    super::create_bytes(&temp, &bytes)?;
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(io_error(error));
    }
    sync_directory(parent)?;
    if read_regular_with_mode(path)? != (bytes, 0o600) {
        return Err(input_error(
            "history latest pointer changed after publication",
        ));
    }
    Ok(())
}

fn read_regular_with_mode(path: &Path) -> Result<(Vec<u8>, u32), ManagedProjectError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_RECORD_BYTES {
        return Err(input_error(
            "history evidence is not a bounded regular file",
        ));
    }
    Ok((
        fs::read(path).map_err(io_error)?,
        metadata.permissions().mode() & 0o777,
    ))
}

fn hash_bytes(bytes: &[u8]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_and_audit_records_bind_failure_and_retain_all() {
        let scheduler = Sha256::from_bytes([1; 32]);
        let failure = format!(
            "leanbun-regression-terminal-v1\t1\njob-id\t{}\nscheduler-run-id\t{scheduler}\njob\tmalformed-manifest-failure\nterminal\tfailed\noutcome-record-sha256\tnone\nfailure-code\tJSON_MALFORMED\nend-regression-terminal\n",
            job_id(scheduler, "malformed-manifest-failure")
        );
        assert!(failure.contains("terminal\tfailed\n"));
        assert!(failure.contains("failure-code\tJSON_MALFORMED\n"));
        let empty = BTreeMap::new();
        let identity = inventory_identity([("empty", &empty)]);
        assert_ne!(identity, Sha256::from_bytes([0; 32]));
    }
}
