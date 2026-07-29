use super::external_acceptance::publish_immutable_record;
use super::registered::load_registered_git_closure;
use super::{
    COMPILER, LAKE_VERSION, ManagedProjectError, TOOLCHAIN, ensure_private_directory, input_error,
    io_error, sync_directory,
};
use leanbun_core::{DiagnosticCode, Sha256, Sha256Hasher};
use leanbun_evidence::{
    canonicalize_directory, hash_project_input_tree, parse_project_manifest, read_project_input,
};
use leanbun_lake_bridge::{LakeDependencySourceV1, LakeRootDeclarationV1, LakeRootDependencyV1};
use leanbun_lock::{CanonicalSourceUrlV1, PackageKeyV1};
use leanbun_resolver::{
    LeanDependencyRequirementV1, LeanExactSourceV1, LeanPackageCandidateV1,
    LeanResolutionErrorKind, LeanResolutionModeV1, LeanResolutionRequestV1, LeanSourceRequestV1,
    LeanToolchainIdentityV1, resolve_lean_dependencies_v1,
};
use leanbun_store::{
    LeanFetchCancellationV1, LeanFetchFaultV1, LeanFetchRequestV1, LeanFetchSourceV1,
    LeanImmutableStoreV1, LeanStoreErrorKind, LeanStoreLimitsV1,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEGATIVE_RUN_COUNTER: AtomicU64 = AtomicU64::new(1);

const CASES: [(&str, &str); 5] = [
    ("malformed-manifest", "JSON_MALFORMED"),
    ("path-escape", "PATH_ESCAPES_ALLOWED_ROOT"),
    ("hash-drift", "TREE_DIGEST_MISMATCH"),
    ("cycle", "DEPENDENCY_CYCLE"),
    ("missing-package", "REGISTERED_CLOSURE_INCOMPLETE"),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeFixtureRegressionV1 {
    pub run_id: Sha256,
    pub record: PathBuf,
    pub record_sha256: Sha256,
    pub matrix_tree_sha256: Sha256,
    pub case_count: usize,
}

pub fn run_negative_fixture_regression_v1(
    repository: &Path,
) -> Result<NegativeFixtureRegressionV1, ManagedProjectError> {
    let repository = canonicalize_directory(repository).map_err(evidence_error)?;
    let fixture = canonicalize_directory(repository.as_path().join("test/fixtures/m42-negative"))
        .map_err(evidence_error)?;
    let fixture_before = hash_project_input_tree(&fixture).map_err(evidence_error)?;
    let development = repository.as_path().join(".leanbun-dev-rust");
    let regression = development.join("regression");
    let positive_records = regression.join("records");
    let positive_before = snapshot_positive_records(&positive_records)?;
    let positive_latest_before = read_optional_regular(&regression.join("latest.record"))?;

    reject_malformed(&fixture.as_path().join("malformed-manifest.json"))?;
    reject_path_escape(&fixture.as_path().join("path-escape"))?;
    reject_hash_drift(repository.as_path(), fixture.as_path())?;
    reject_cycle(&fixture.as_path().join("cycle.tsv"))?;
    reject_missing_package(
        repository.as_path(),
        &fixture.as_path().join("missing-package.json"),
    )?;

    let fixture_after = hash_project_input_tree(&fixture).map_err(evidence_error)?;
    if fixture_before != fixture_after {
        return Err(input_error(
            "negative fixture matrix changed during regression",
        ));
    }
    if positive_before != snapshot_positive_records(&positive_records)?
        || positive_latest_before != read_optional_regular(&regression.join("latest.record"))?
    {
        return Err(input_error(
            "negative fixture regression changed positive regression evidence",
        ));
    }

    let negative_records = regression.join("negative-records");
    ensure_private_directory(&development, &negative_records)?;
    let run_id = allocate_run_id(
        repository.as_path(),
        &negative_records,
        fixture_before.tree_hash,
    )?;
    let bytes = record_bytes(run_id, fixture_before.tree_hash);
    let record_sha256 = hash_bytes(&bytes);
    let record = negative_records.join(format!("{run_id}.record"));
    publish_immutable_record(&record, &bytes)?;
    publish_negative_latest(
        &regression.join("negative-latest.record"),
        run_id,
        record_sha256,
    )?;

    if positive_before != snapshot_positive_records(&positive_records)?
        || positive_latest_before != read_optional_regular(&regression.join("latest.record"))?
    {
        return Err(input_error(
            "negative evidence publication contaminated positive regression evidence",
        ));
    }
    Ok(NegativeFixtureRegressionV1 {
        run_id,
        record,
        record_sha256,
        matrix_tree_sha256: fixture_before.tree_hash,
        case_count: CASES.len(),
    })
}

fn reject_malformed(path: &Path) -> Result<(), ManagedProjectError> {
    let text = fs::read_to_string(path).map_err(io_error)?;
    match parse_project_manifest(&text) {
        Err(error) if error.code == DiagnosticCode::JSON_MALFORMED => Ok(()),
        Err(error) => Err(input_error(format!(
            "malformed fixture reached unexpected rejection: {:?}",
            error.code
        ))),
        Ok(_) => Err(input_error("malformed fixture unexpectedly parsed")),
    }
}

fn reject_path_escape(project: &Path) -> Result<(), ManagedProjectError> {
    let project = canonicalize_directory(project).map_err(evidence_error)?;
    match read_project_input(&project, None) {
        Err(error) if error.code == DiagnosticCode::PATH_ESCAPES_ALLOWED_ROOT => Ok(()),
        Err(error) => Err(input_error(format!(
            "path escape fixture reached unexpected rejection: {:?}",
            error.code
        ))),
        Ok(_) => Err(input_error("path escape fixture unexpectedly passed")),
    }
}

fn reject_hash_drift(repository: &Path, fixture: &Path) -> Result<(), ManagedProjectError> {
    let development = repository.join(".leanbun-dev-rust");
    let scratch = development.join("store-fixture/m42-negative").join(format!(
        "{}-{}",
        std::process::id(),
        NEGATIVE_RUN_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    if scratch.exists() {
        return Err(input_error("negative hash drift scratch already exists"));
    }
    let mut cleanup = ScratchCleanup::new(scratch.clone());
    let package = package_key("hash-drift")?;
    let portable = "hash-drift-source";
    let selected = Sha256::from_bytes([81; 32]);
    let candidate = LeanPackageCandidateV1::new(
        package.clone(),
        LeanSourceRequestV1::path(portable).map_err(|error| input_error(error.to_string()))?,
        LeanExactSourceV1::path(portable, selected)
            .map_err(|error| input_error(error.to_string()))?,
        Vec::new(),
        None,
        None,
        Sha256::from_bytes([82; 32]),
        Sha256::from_bytes([83; 32]),
        None,
        selected,
    )
    .map_err(|error| input_error(error.to_string()))?;
    let root_dependency = LakeRootDependencyV1::new(
        package.clone(),
        Some(format!("path:{portable}")),
        LakeDependencySourceV1::Path {
            directory: portable.to_owned(),
        },
    )
    .map_err(|error| input_error(error.to_string()))?;
    let root = LakeRootDeclarationV1::new(
        "m42_negative_hash_drift",
        "lakefile.toml",
        vec![root_dependency],
    )
    .map_err(|error| input_error(error.to_string()))?;
    let graph = resolve_lean_dependencies_v1(&resolution_request(root)?, vec![candidate])
        .map_err(|error| input_error(error.to_string()))?;
    let fetch = LeanFetchRequestV1::from_graph(
        &graph,
        &package,
        LeanFetchSourceV1::LocalDirectory {
            path: fixture.join(portable),
        },
        fixture,
        LeanStoreLimitsV1::default(),
    )
    .map_err(|error| input_error(error.to_string()))?;
    let store = LeanImmutableStoreV1::open(&development, &scratch)
        .map_err(|error| input_error(error.to_string()))?;
    match store.fetch_and_publish(
        &fetch,
        &LeanFetchCancellationV1::default(),
        LeanFetchFaultV1::None,
    ) {
        Err(error) if error.kind == LeanStoreErrorKind::TreeDigestMismatch => {}
        Err(error) => {
            return Err(input_error(format!(
                "hash drift fixture reached unexpected rejection: {:?}",
                error.kind
            )));
        }
        Ok(_) => return Err(input_error("hash drift fixture unexpectedly published")),
    }
    cleanup.clean()?;
    if scratch.exists() {
        return Err(input_error("negative hash drift scratch was not cleaned"));
    }
    Ok(())
}

fn reject_missing_package(repository: &Path, manifest: &Path) -> Result<(), ManagedProjectError> {
    let development = repository.join(".leanbun-dev");
    match load_registered_git_closure(&development, manifest) {
        Err(error)
            if error == "managed Git manifest does not equal the registered provider closure" =>
        {
            Ok(())
        }
        Err(error) => Err(input_error(format!(
            "missing package fixture reached unexpected rejection: {error}"
        ))),
        Ok(_) => Err(input_error("missing package fixture unexpectedly passed")),
    }
}

fn reject_cycle(path: &Path) -> Result<(), ManagedProjectError> {
    let text = fs::read_to_string(path).map_err(io_error)?;
    let (root_name, edges) = parse_cycle_fixture(&text)?;
    let root_key = package_key(&root_name)?;
    let root_dependency = LakeRootDependencyV1::new(
        root_key,
        Some("git#main".to_owned()),
        LakeDependencySourceV1::Git {
            url: source_url(&root_name)?.as_str().to_owned(),
            revision: Some("main".to_owned()),
            subdir: None,
        },
    )
    .map_err(|error| input_error(error.to_string()))?;
    let root =
        LakeRootDeclarationV1::new("m42_negative_cycle", "lakefile.toml", vec![root_dependency])
            .map_err(|error| input_error(error.to_string()))?;
    let request = resolution_request(root)?;
    let mut names = BTreeSet::new();
    names.insert(root_name);
    for (from, dependencies) in &edges {
        names.insert(from.clone());
        names.extend(dependencies.iter().cloned());
    }
    let candidates = names
        .iter()
        .enumerate()
        .map(|(index, name)| candidate(name, edges.get(name), index as u8))
        .collect::<Result<Vec<_>, _>>()?;
    match resolve_lean_dependencies_v1(&request, candidates) {
        Err(error) if error.kind == LeanResolutionErrorKind::DependencyCycle => Ok(()),
        Err(error) => Err(input_error(format!(
            "cycle fixture reached unexpected rejection: {:?}",
            error.kind
        ))),
        Ok(_) => Err(input_error("cycle fixture unexpectedly resolved")),
    }
}

fn parse_cycle_fixture(
    text: &str,
) -> Result<(String, BTreeMap<String, Vec<String>>), ManagedProjectError> {
    let mut root = None;
    let mut edges = BTreeMap::<String, Vec<String>>::new();
    for line in text.lines() {
        let fields = line.split('\t').collect::<Vec<_>>();
        match fields.as_slice() {
            ["root", name] if root.is_none() => root = Some((*name).to_owned()),
            ["edge", from, to] => edges
                .entry((*from).to_owned())
                .or_default()
                .push((*to).to_owned()),
            _ => return Err(input_error("cycle fixture has an invalid row")),
        }
    }
    let root = root.ok_or_else(|| input_error("cycle fixture has no root"))?;
    if edges.is_empty() {
        return Err(input_error("cycle fixture has no edges"));
    }
    Ok((root, edges))
}

fn candidate(
    name: &str,
    dependencies: Option<&Vec<String>>,
    marker: u8,
) -> Result<LeanPackageCandidateV1, ManagedProjectError> {
    let url = source_url(name)?;
    let requirements = dependencies
        .into_iter()
        .flatten()
        .map(|dependency| {
            Ok(LeanDependencyRequirementV1::new(
                package_key(dependency)?,
                source_request(dependency)?,
            ))
        })
        .collect::<Result<Vec<_>, ManagedProjectError>>()?;
    LeanPackageCandidateV1::new(
        package_key(name)?,
        source_request(name)?,
        LeanExactSourceV1::git(url, format!("{:040x}", u64::from(marker) + 1), None)
            .map_err(|error| input_error(error.to_string()))?,
        requirements,
        None,
        Some(Sha256::from_bytes([marker.wrapping_add(1); 32])),
        Sha256::from_bytes([marker.wrapping_add(2); 32]),
        Sha256::from_bytes([marker.wrapping_add(3); 32]),
        None,
        Sha256::from_bytes([marker.wrapping_add(4); 32]),
    )
    .map_err(|error| input_error(error.to_string()))
}

fn package_key(name: &str) -> Result<PackageKeyV1, ManagedProjectError> {
    PackageKeyV1::new("", name).map_err(|error| input_error(error.to_string()))
}

fn source_url(name: &str) -> Result<CanonicalSourceUrlV1, ManagedProjectError> {
    CanonicalSourceUrlV1::parse(format!("https://github.com/leanbun/m42-{name}"))
        .map_err(|error| input_error(error.to_string()))
}

fn source_request(name: &str) -> Result<LeanSourceRequestV1, ManagedProjectError> {
    LeanSourceRequestV1::git(source_url(name)?, Some("main".to_owned()), None)
        .map_err(|error| input_error(error.to_string()))
}

fn resolution_request(
    root: LakeRootDeclarationV1,
) -> Result<LeanResolutionRequestV1, ManagedProjectError> {
    LeanResolutionRequestV1::new(
        root,
        None,
        LeanResolutionModeV1::update(Vec::new()).map_err(|error| input_error(error.to_string()))?,
        LeanToolchainIdentityV1::new(TOOLCHAIN, COMPILER, LAKE_VERSION)
            .map_err(|error| input_error(error.to_string()))?,
    )
    .map_err(|error| input_error(error.to_string()))
}

fn snapshot_positive_records(
    root: &Path,
) -> Result<BTreeMap<String, (Sha256, u32)>, ManagedProjectError> {
    if !root.exists() {
        return Ok(BTreeMap::new());
    }
    let mut snapshot = BTreeMap::new();
    for entry in fs::read_dir(root).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let file_type = entry.file_type().map_err(io_error)?;
        let metadata = entry.metadata().map_err(io_error)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| input_error("positive regression record name is not UTF-8"))?;
        if !file_type.is_file() || !name.ends_with(".record") || metadata.len() > 64 * 1024 {
            return Err(input_error(
                "positive regression record directory contains an unexpected entry",
            ));
        }
        let bytes = fs::read(entry.path()).map_err(io_error)?;
        snapshot.insert(
            name,
            (hash_bytes(&bytes), metadata.permissions().mode() & 0o777),
        );
    }
    Ok(snapshot)
}

fn read_optional_regular(path: &Path) -> Result<Option<(Vec<u8>, u32)>, ManagedProjectError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && metadata.len() <= 64 * 1024 => {
            fs::read(path)
                .map(|bytes| Some((bytes, metadata.permissions().mode() & 0o777)))
                .map_err(io_error)
        }
        Ok(_) => Err(input_error(
            "regression latest pointer is not a regular file",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(error)),
    }
}

fn allocate_run_id(
    repository: &Path,
    records: &Path,
    fixture_tree: Sha256,
) -> Result<Sha256, ManagedProjectError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| input_error(format!("system clock precedes epoch: {error}")))?;
    for _ in 0..32 {
        let nonce = NEGATIVE_RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"leanbun-negative-fixture-regression-run-v1\0");
        hasher.update(repository.to_string_lossy().as_bytes());
        hasher.update(fixture_tree.as_bytes());
        hasher.update(&now.as_nanos().to_be_bytes());
        hasher.update(&std::process::id().to_be_bytes());
        hasher.update(&nonce.to_be_bytes());
        let candidate = hasher.finalize();
        if !records.join(format!("{candidate}.record")).exists() {
            return Ok(candidate);
        }
    }
    Err(input_error(
        "cannot allocate a unique negative regression run id",
    ))
}

fn record_bytes(run_id: Sha256, fixture_tree: Sha256) -> Vec<u8> {
    let mut text = format!(
        "leanbun-negative-fixture-regression-v1\t1\nrun-id\t{run_id}\nfixture\tm42-negative\nstatus\tpassed\nmatrix-tree-sha256\t{fixture_tree}\ncase-count\t{}\n",
        CASES.len()
    );
    for (case, rejection) in CASES {
        text.push_str(&format!("case\t{case}\t{rejection}\trejected\n"));
    }
    text.push_str("positive-records\tunchanged\npositive-latest\tunchanged\nmanaged-project-state\tnone\nend-negative-fixture-regression\n");
    text.into_bytes()
}

fn publish_negative_latest(
    path: &Path,
    run_id: Sha256,
    record_sha256: Sha256,
) -> Result<(), ManagedProjectError> {
    let bytes = format!(
        "leanbun-negative-fixture-regression-latest-v1\t1\nrun-id\t{run_id}\nfixture\tm42-negative\nrecord-sha256\t{record_sha256}\nend-negative-fixture-regression-latest\n"
    )
    .into_bytes();
    let parent = path
        .parent()
        .ok_or_else(|| input_error("negative latest record has no parent"))?;
    let temp = parent.join(format!(
        ".negative-latest-{}-{}.next",
        std::process::id(),
        NEGATIVE_RUN_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    super::create_bytes(&temp, &bytes)?;
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(io_error(error));
    }
    sync_directory(parent)?;
    verify_negative_latest(path)
}

fn verify_negative_latest(path: &Path) -> Result<(), ManagedProjectError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() > 64 * 1024
    {
        return Err(input_error("negative latest pointer has unsafe metadata"));
    }
    let bytes = fs::read(path).map_err(io_error)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| input_error("negative latest pointer is not UTF-8"))?;
    if text.lines().next() != Some("leanbun-negative-fixture-regression-latest-v1\t1")
        || text.lines().last() != Some("end-negative-fixture-regression-latest")
    {
        return Err(input_error("negative latest pointer schema is invalid"));
    }
    let field = |name: &str| {
        let prefix = format!("{name}\t");
        let values = text
            .lines()
            .filter_map(|line| line.strip_prefix(&prefix))
            .collect::<Vec<_>>();
        match values.as_slice() {
            [value] if !value.is_empty() => Ok(*value),
            _ => Err(input_error(format!(
                "negative latest field {name} is missing or repeated"
            ))),
        }
    };
    let run_id = field("run-id")?;
    if field("fixture")? != "m42-negative" {
        return Err(input_error("negative latest fixture is invalid"));
    }
    let expected = Sha256::parse(field("record-sha256")?)
        .map_err(|_| input_error("negative latest digest is invalid"))?;
    let record = path
        .parent()
        .ok_or_else(|| input_error("negative latest pointer has no parent"))?
        .join("negative-records")
        .join(format!("{run_id}.record"));
    let record_metadata = fs::symlink_metadata(&record).map_err(io_error)?;
    if !record_metadata.file_type().is_file()
        || record_metadata.permissions().mode() & 0o777 != 0o400
        || hash_bytes(&fs::read(record).map_err(io_error)?) != expected
    {
        return Err(input_error(
            "negative latest does not bind an immutable record",
        ));
    }
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn evidence_error(error: leanbun_evidence::EvidenceError) -> ManagedProjectError {
    input_error(format!("negative regression evidence rejected: {error}"))
}

struct ScratchCleanup {
    path: PathBuf,
    armed: bool,
}

impl ScratchCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn clean(&mut self) -> Result<(), ManagedProjectError> {
        super::fixture_regression::remove_exact_tree(&self.path)?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for ScratchCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = super::fixture_regression::remove_exact_tree(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_record_names_all_registered_rejections() {
        let record = String::from_utf8(record_bytes(
            Sha256::from_bytes([1; 32]),
            Sha256::from_bytes([2; 32]),
        ))
        .unwrap_or_else(|error| panic!("record UTF-8 failed: {error}"));
        for (case, rejection) in CASES {
            assert!(record.contains(&format!("case\t{case}\t{rejection}\trejected\n")));
        }
        assert!(record.contains("positive-latest\tunchanged\n"));
        assert!(record.ends_with("end-negative-fixture-regression\n"));
    }
}
