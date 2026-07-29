use super::external_acceptance::publish_immutable_record;
use super::{
    ManagedProjectError, canonical_directory, canonical_file, ensure_private_directory,
    input_error, io_error, now_nanos, sync_directory,
};
use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_lock::{
    CanonicalSourceUrlV1, LeanBunLockV1, LockedLeanPackageV1, PackageKeyV1,
    RequestedPackageSourceV1, ReservoirBindingDocumentV1, ReservoirBindingV1,
    ReservoirRegistryIdentityV1, ResolvedPackageSourceV1,
};
use leanbun_resolver::{
    ReservoirBindingOutcomeV1, ReservoirRebindAuthorizationV1, evaluate_reservoir_binding_v1,
};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const FIXTURE: &str = "test/fixtures/m46-reservoir-loopback/registry.tsv";
const HEADER: &str = "label\tregistry_identity\tscope\tname\tversion\tmetadata_sha256\tresolved_url\texact_commit\tdownload_sha256\ttree_sha256\tselected_sha256";
const MAX_FIXTURE_BYTES: u64 = 64 * 1024;
const MAX_ROWS: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservoirLoopbackRegressionV1 {
    pub run_id: Sha256,
    pub run_root: PathBuf,
    pub result_record: PathBuf,
    pub fixture_sha256: Sha256,
    pub old_lock_identity: Sha256,
    pub new_lock_identity: Sha256,
    pub old_binding_identity: Sha256,
    pub new_binding_identity: Sha256,
    pub authorization_identity: Sha256,
    pub audit_record_count: usize,
    pub registry_read_count: u64,
    pub frozen_replay_registry_reads: u64,
}

#[derive(Clone)]
struct FixtureBinding {
    registry: Sha256,
    scope: String,
    name: String,
    version: String,
    metadata: Sha256,
    url: String,
    commit: String,
    download: Sha256,
    tree: Sha256,
    selected: Sha256,
}

struct CandidateArtifacts {
    binding: ReservoirBindingV1,
    lock: LeanBunLockV1,
    document: ReservoirBindingDocumentV1,
    lock_path: PathBuf,
    document_path: PathBuf,
}

pub fn run_reservoir_loopback_regression_v1(
    repository: &Path,
) -> Result<ReservoirLoopbackRegressionV1, ManagedProjectError> {
    let repository = canonical_directory(repository, "LeanBun repository")?;
    if !repository.join("TEST_PROJECT_BOUNDARY.adoc").is_file() {
        return Err(input_error("M46C repository boundary marker is missing"));
    }
    let fixture = canonical_file(&repository.join(FIXTURE), "M46C registry fixture")?;
    if !fixture.starts_with(&repository) {
        return Err(input_error("M46C registry fixture escaped the repository"));
    }
    let fixture_bytes = bounded_read(&fixture, MAX_FIXTURE_BYTES)?;
    let fixture_sha256 = sha256(&fixture_bytes);
    let bindings = parse_fixture(&fixture_bytes)?;
    for required in ["old", "new", "metadata-drift", "content-drift"] {
        if !bindings.contains_key(required) {
            return Err(input_error(format!(
                "M46C registry fixture is missing {required}"
            )));
        }
    }

    let development = repository.join(".leanbun-dev-rust");
    let authority = development.join("reservoir-m46c");
    let runs = authority.join("runs");
    ensure_private_directory(&development, &authority)?;
    ensure_private_directory(&authority, &runs)?;
    let run_id = run_identity(fixture_sha256)?;
    let run_root = runs.join(run_id.to_string());
    ensure_private_directory(&runs, &run_root)?;
    let records = run_root.join("records");
    let locks = run_root.join("locks");
    let companions = run_root.join("companions");
    ensure_private_directory(&run_root, &records)?;
    ensure_private_directory(&run_root, &locks)?;
    ensure_private_directory(&run_root, &companions)?;

    let old = publish_candidate(
        bindings
            .get("old")
            .ok_or_else(|| input_error("M46C old fixture disappeared"))?,
        &locks,
        &companions,
    )?;
    let new = publish_candidate(
        bindings
            .get("new")
            .ok_or_else(|| input_error("M46C new fixture disappeared"))?,
        &locks,
        &companions,
    )?;
    let metadata_drift = binding_of(
        bindings
            .get("metadata-drift")
            .ok_or_else(|| input_error("M46C metadata fixture disappeared"))?,
    )?;
    let content_drift = binding_of(
        bindings
            .get("content-drift")
            .ok_or_else(|| input_error("M46C content fixture disappeared"))?,
    )?;

    let active_pointer = run_root.join("active.record");
    let mut sequence = 1_u64;
    let mut registry_reads = 0_u64;
    let mut audit_record_count = 0_usize;

    registry_reads += 1;
    let first = evaluate_reservoir_binding_v1(None, std::slice::from_ref(&old.binding), None)
        .map_err(policy_error)?;
    require_outcome(
        &first,
        matches!(
            first,
            ReservoirBindingOutcomeV1::FirstResolutionPending { .. }
        ),
        "first-resolution-pending",
    )?;
    let first_pending =
        publish_transition(&records, sequence, "pending-first-resolution", &old, None)?;
    sequence += 1;
    if active_pointer.exists() {
        return Err(input_error(
            "M46C first pending candidate unexpectedly created active state",
        ));
    }
    require_reviewable_pending(&first_pending)?;
    replay_frozen(&old)?;
    let first_verification = publish_verification(&records, sequence, "first-candidate", &old)?;
    sequence += 1;
    require_reviewable_pending(&first_verification)?;

    let first_activation =
        publish_transition(&records, sequence, "activation-first-verified", &old, None)?;
    sequence += 1;
    publish_active(&active_pointer, &first_activation, &old)?;
    let old_active_bytes = fs::read(&active_pointer).map_err(io_error)?;

    for label in ["stable-first", "stable-repeat"] {
        registry_reads += 1;
        let outcome = evaluate_reservoir_binding_v1(
            Some(&old.binding),
            std::slice::from_ref(&old.binding),
            None,
        )
        .map_err(policy_error)?;
        require_outcome(
            &outcome,
            matches!(outcome, ReservoirBindingOutcomeV1::StableBinding { .. }),
            label,
        )?;
        publish_audit(&records, sequence, label, &outcome)?;
        sequence += 1;
        audit_record_count += 1;
    }

    registry_reads += 1;
    let rebound =
        evaluate_reservoir_binding_v1(Some(&old.binding), std::slice::from_ref(&new.binding), None)
            .map_err(policy_error)?;
    require_outcome(
        &rebound,
        matches!(rebound, ReservoirBindingOutcomeV1::VersionRebound { .. }),
        "ordinary-version-rebound",
    )?;
    let rebound_pending = publish_transition(
        &records,
        sequence,
        "pending-version-rebound",
        &new,
        Some(old.binding.identity()),
    )?;
    sequence += 1;
    require_reviewable_pending(&rebound_pending)?;
    publish_audit(
        &records,
        sequence,
        "ordinary-version-rebound-rejected",
        &rebound,
    )?;
    sequence += 1;
    audit_record_count += 1;
    if fs::read(&active_pointer).map_err(io_error)? != old_active_bytes {
        return Err(input_error(
            "M46C ordinary rebound changed the active commit point",
        ));
    }

    registry_reads += 1;
    let oscillation =
        evaluate_reservoir_binding_v1(Some(&old.binding), std::slice::from_ref(&old.binding), None)
            .map_err(policy_error)?;
    require_outcome(
        &oscillation,
        matches!(oscillation, ReservoirBindingOutcomeV1::StableBinding { .. }),
        "oscillation-new-to-old",
    )?;
    publish_audit(&records, sequence, "oscillation-old-new-old", &oscillation)?;
    sequence += 1;
    audit_record_count += 1;

    registry_reads += 1;
    let metadata = evaluate_reservoir_binding_v1(
        Some(&old.binding),
        std::slice::from_ref(&metadata_drift),
        None,
    )
    .map_err(policy_error)?;
    require_outcome(
        &metadata,
        matches!(metadata, ReservoirBindingOutcomeV1::MetadataDrift { .. }),
        "metadata-drift",
    )?;
    publish_audit(&records, sequence, "metadata-drift", &metadata)?;
    sequence += 1;
    audit_record_count += 1;

    registry_reads += 1;
    let content = evaluate_reservoir_binding_v1(
        Some(&old.binding),
        std::slice::from_ref(&content_drift),
        None,
    )
    .map_err(policy_error)?;
    require_outcome(
        &content,
        matches!(content, ReservoirBindingOutcomeV1::ContentMismatch { .. }),
        "content-drift",
    )?;
    publish_audit(&records, sequence, "content-drift", &content)?;
    sequence += 1;
    audit_record_count += 1;

    registry_reads += 1;
    let disappeared =
        evaluate_reservoir_binding_v1(Some(&old.binding), &[], None).map_err(policy_error)?;
    require_outcome(
        &disappeared,
        matches!(
            disappeared,
            ReservoirBindingOutcomeV1::DisappearedBinding {
                active_binding_identity: Some(_)
            }
        ),
        "disappeared-version",
    )?;
    publish_audit(
        &records,
        sequence,
        "disappeared-version-old-commit-unavailable",
        &disappeared,
    )?;
    sequence += 1;
    audit_record_count += 1;
    let reads_before_old_replay = registry_reads;
    replay_frozen(&old)?;
    if registry_reads != reads_before_old_replay {
        return Err(input_error("M46C old frozen replay queried the registry"));
    }

    let authorization =
        ReservoirRebindAuthorizationV1::new(&old.binding, &new.binding).map_err(policy_error)?;
    let authorization_record = records.join(format!(
        "{sequence:03}-authorization-{}.record",
        authorization.identity()
    ));
    publish_immutable_record(
        &authorization_record,
        format!(
            "leanbun-reservoir-authorization-v1\t1\nauthorization-identity\t{}\nactive-binding-identity\t{}\nproposed-binding-identity\t{}\npending-record-sha256\t{}\nsource\tregistered-m46c-fixture-only\nend-reservoir-authorization\n",
            authorization.identity(),
            old.binding.identity(),
            new.binding.identity(),
            file_sha256(&rebound_pending)?,
        )
        .as_bytes(),
    )?;
    sequence += 1;
    registry_reads += 1;
    let accepted = evaluate_reservoir_binding_v1(
        Some(&old.binding),
        std::slice::from_ref(&new.binding),
        Some(&authorization),
    )
    .map_err(policy_error)?;
    require_outcome(
        &accepted,
        matches!(
            accepted,
            ReservoirBindingOutcomeV1::ExplicitRebindAccepted { .. }
        ),
        "explicit-rebind",
    )?;
    publish_audit(&records, sequence, "explicit-rebind-accepted", &accepted)?;
    sequence += 1;
    audit_record_count += 1;
    replay_frozen(&new)?;
    let rebind_verification = publish_verification(&records, sequence, "rebind-candidate", &new)?;
    sequence += 1;
    require_reviewable_pending(&rebind_verification)?;
    let rebind_activation = publish_transition(
        &records,
        sequence,
        "activation-explicit-rebind",
        &new,
        Some(old.binding.identity()),
    )?;
    sequence += 1;
    publish_active(&active_pointer, &rebind_activation, &new)?;

    let frozen_replay_registry_reads = registry_reads;
    replay_frozen(&new)?;
    if registry_reads != frozen_replay_registry_reads {
        return Err(input_error("M46C new frozen replay queried the registry"));
    }
    publish_audit_bytes(
        &records,
        sequence,
        "frozen-offline-replay-new",
        "FrozenReplay",
        new.binding.identity(),
    )?;
    sequence += 1;
    audit_record_count += 1;

    let rollback_activation = publish_transition(
        &records,
        sequence,
        "activation-rollback-old",
        &old,
        Some(new.binding.identity()),
    )?;
    sequence += 1;
    publish_active(&active_pointer, &rollback_activation, &old)?;
    replay_frozen(&old)?;
    if registry_reads != frozen_replay_registry_reads {
        return Err(input_error("M46C rollback replay queried the registry"));
    }
    publish_audit_bytes(
        &records,
        sequence,
        "rollback-offline-replay-old",
        "RollbackReplay",
        old.binding.identity(),
    )?;
    audit_record_count += 1;

    let result_record = run_root.join("result.record");
    let result_bytes = format!(
        "leanbun-reservoir-loopback-regression-v1\t1\nrun-id\t{run_id}\nfixture-sha256\t{fixture_sha256}\nold-lock-identity\t{}\nnew-lock-identity\t{}\nold-binding-identity\t{}\nnew-binding-identity\t{}\nauthorization-identity\t{}\naudit-record-count\t{audit_record_count}\nregistry-read-count\t{registry_reads}\nfrozen-replay-registry-reads\t{frozen_replay_registry_reads}\nordinary-rebind\trejected\nfirst-pending-before-active\tpassed\nold-offline-after-disappearance\tpassed\nexplicit-rebind\tpassed\nrollback-offline\tpassed\nnetwork-access\tnone\npublic-discovery\tclosed\nresult\tpassed\nend-reservoir-loopback-regression\n",
        old.lock.identity(),
        new.lock.identity(),
        old.binding.identity(),
        new.binding.identity(),
        authorization.identity(),
    );
    publish_immutable_record(&result_record, result_bytes.as_bytes())?;

    Ok(ReservoirLoopbackRegressionV1 {
        run_id,
        run_root,
        result_record,
        fixture_sha256,
        old_lock_identity: old.lock.identity(),
        new_lock_identity: new.lock.identity(),
        old_binding_identity: old.binding.identity(),
        new_binding_identity: new.binding.identity(),
        authorization_identity: authorization.identity(),
        audit_record_count,
        registry_read_count: registry_reads,
        frozen_replay_registry_reads,
    })
}

fn parse_fixture(bytes: &[u8]) -> Result<BTreeMap<String, FixtureBinding>, ManagedProjectError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| input_error("M46C registry fixture is not UTF-8"))?;
    if !text.ends_with('\n') || text.contains('\r') {
        return Err(input_error(
            "M46C registry fixture is not canonical LF text",
        ));
    }
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Err(input_error("M46C registry fixture header differs"));
    }
    let mut parsed = BTreeMap::new();
    for line in lines {
        if parsed.len() >= MAX_ROWS {
            return Err(input_error("M46C registry fixture exceeds row limit"));
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 11 || fields.iter().any(|field| field.contains('\0')) {
            return Err(input_error("M46C registry fixture row is malformed"));
        }
        let label = fields[0].to_owned();
        if label.is_empty() || parsed.contains_key(&label) {
            return Err(input_error(
                "M46C registry fixture label is empty or duplicate",
            ));
        }
        let value = FixtureBinding {
            registry: parse_sha(fields[1])?,
            scope: fields[2].to_owned(),
            name: fields[3].to_owned(),
            version: fields[4].to_owned(),
            metadata: parse_sha(fields[5])?,
            url: fields[6].to_owned(),
            commit: fields[7].to_owned(),
            download: parse_sha(fields[8])?,
            tree: parse_sha(fields[9])?,
            selected: parse_sha(fields[10])?,
        };
        binding_of(&value)?;
        parsed.insert(label, value);
    }
    if parsed.is_empty() {
        return Err(input_error("M46C registry fixture has no rows"));
    }
    Ok(parsed)
}

fn binding_of(value: &FixtureBinding) -> Result<ReservoirBindingV1, ManagedProjectError> {
    ReservoirBindingV1::new(
        ReservoirRegistryIdentityV1::new(value.registry),
        PackageKeyV1::new(value.scope.clone(), value.name.clone()).map_err(lock_error)?,
        value.version.clone(),
        value.metadata,
        CanonicalSourceUrlV1::parse(value.url.clone()).map_err(lock_error)?,
        value.commit.clone(),
        value.download,
        value.tree,
        value.selected,
    )
    .map_err(|error| input_error(format!("M46C binding rejected: {error}")))
}

fn lock_of(value: &FixtureBinding) -> Result<LeanBunLockV1, ManagedProjectError> {
    let key = PackageKeyV1::new(value.scope.clone(), value.name.clone()).map_err(lock_error)?;
    let url = CanonicalSourceUrlV1::parse(value.url.clone()).map_err(lock_error)?;
    let package = LockedLeanPackageV1::new(
        key,
        RequestedPackageSourceV1::git(url.clone(), Some(value.version.clone()))
            .map_err(lock_error)?,
        ResolvedPackageSourceV1::git(url, value.commit.clone(), None).map_err(lock_error)?,
        Some(value.download),
        value.tree,
        repeated_sha(0x31)?,
        Some(repeated_sha(0x32)?),
        Vec::new(),
        vec![repeated_sha(0x33)?],
        value.selected,
    )
    .map_err(lock_error)?;
    LeanBunLockV1::new(
        "leanprover/lean4:v4.32.0",
        "3434343434343434343434343434343434343434",
        "5.0.0",
        repeated_sha(0x35)?,
        repeated_sha(0x36)?,
        vec![package],
    )
    .map_err(lock_error)
}

fn publish_candidate(
    value: &FixtureBinding,
    locks: &Path,
    companions: &Path,
) -> Result<CandidateArtifacts, ManagedProjectError> {
    let binding = binding_of(value)?;
    let lock = lock_of(value)?;
    let document = ReservoirBindingDocumentV1::new(&lock, vec![binding.clone()])
        .map_err(|error| input_error(format!("M46C companion rejected: {error}")))?;
    let lock_path = locks.join(format!("{}.lock", lock.identity()));
    let document_path = companions.join(format!("{}.bindings", document.identity()));
    publish_immutable_record(&lock_path, lock.to_canonical_text().as_bytes())?;
    publish_immutable_record(&document_path, document.to_canonical_text().as_bytes())?;
    Ok(CandidateArtifacts {
        binding,
        lock,
        document,
        lock_path,
        document_path,
    })
}

fn publish_transition(
    records: &Path,
    sequence: u64,
    kind: &str,
    candidate: &CandidateArtifacts,
    previous: Option<Sha256>,
) -> Result<PathBuf, ManagedProjectError> {
    let path = records.join(format!("{sequence:03}-{kind}.record"));
    let previous = previous.map_or_else(|| "none".to_owned(), |value| value.to_string());
    let bytes = format!(
        "leanbun-reservoir-transition-v1\t1\nsequence\t{sequence}\nkind\t{kind}\nprevious-binding-identity\t{previous}\ncandidate-binding-identity\t{}\nlock-identity\t{}\ncompanion-identity\t{}\nlock-record-sha256\t{}\ncompanion-record-sha256\t{}\nend-reservoir-transition\n",
        candidate.binding.identity(),
        candidate.lock.identity(),
        candidate.document.identity(),
        file_sha256(&candidate.lock_path)?,
        file_sha256(&candidate.document_path)?,
    );
    publish_immutable_record(&path, bytes.as_bytes())?;
    Ok(path)
}

fn publish_audit(
    records: &Path,
    sequence: u64,
    label: &str,
    outcome: &ReservoirBindingOutcomeV1,
) -> Result<PathBuf, ManagedProjectError> {
    publish_audit_bytes(
        records,
        sequence,
        label,
        outcome_name(outcome),
        outcome_identity(outcome),
    )
}

fn publish_audit_bytes(
    records: &Path,
    sequence: u64,
    label: &str,
    outcome: &str,
    identity: Sha256,
) -> Result<PathBuf, ManagedProjectError> {
    let path = records.join(format!("{sequence:03}-audit-{label}.record"));
    let bytes = format!(
        "leanbun-reservoir-audit-v1\t1\nsequence\t{sequence}\nlabel\t{label}\noutcome\t{outcome}\nsubject-identity\t{identity}\nactive-mutation\tnone\nend-reservoir-audit\n"
    );
    publish_immutable_record(&path, bytes.as_bytes())?;
    Ok(path)
}

fn publish_verification(
    records: &Path,
    sequence: u64,
    label: &str,
    candidate: &CandidateArtifacts,
) -> Result<PathBuf, ManagedProjectError> {
    let path = records.join(format!("{sequence:03}-verification-{label}.record"));
    let bytes = format!(
        "leanbun-reservoir-verification-v1\t1\nsequence\t{sequence}\nlabel\t{label}\nlock-identity\t{}\ncompanion-identity\t{}\nbinding-identity\t{}\ncanonical-lock-roundtrip\tpassed\ncanonical-companion-roundtrip\tpassed\nexact-content-facts\tmatched\nnetwork-access\tnone\nresult\tpassed\nend-reservoir-verification\n",
        candidate.lock.identity(),
        candidate.document.identity(),
        candidate.binding.identity(),
    );
    publish_immutable_record(&path, bytes.as_bytes())?;
    Ok(path)
}

fn publish_active(
    path: &Path,
    activation: &Path,
    candidate: &CandidateArtifacts,
) -> Result<(), ManagedProjectError> {
    require_reviewable_pending(activation)?;
    let parent = path
        .parent()
        .ok_or_else(|| input_error("M46C active pointer has no parent"))?;
    let bytes = format!(
        "leanbun-reservoir-active-v1\t1\nactivation-record-sha256\t{}\nlock-identity\t{}\ncompanion-identity\t{}\nbinding-identity\t{}\nend-reservoir-active\n",
        file_sha256(activation)?,
        candidate.lock.identity(),
        candidate.document.identity(),
        candidate.binding.identity(),
    );
    let temp = parent.join(format!(
        ".active-{}-{}.next",
        std::process::id(),
        now_nanos()?
    ));
    super::create_bytes(&temp, bytes.as_bytes())?;
    fs::set_permissions(&temp, fs::Permissions::from_mode(0o600)).map_err(io_error)?;
    fs::File::open(&temp)
        .and_then(|file| file.sync_all())
        .map_err(io_error)?;
    fs::rename(&temp, path).map_err(io_error)?;
    sync_directory(parent)?;
    if fs::read(path).map_err(io_error)? != bytes.as_bytes() {
        return Err(input_error("M46C active pointer changed after publication"));
    }
    Ok(())
}

fn replay_frozen(candidate: &CandidateArtifacts) -> Result<(), ManagedProjectError> {
    let lock_text = String::from_utf8(bounded_read(&candidate.lock_path, MAX_FIXTURE_BYTES)?)
        .map_err(|_| input_error("M46C frozen lock is not UTF-8"))?;
    let lock = LeanBunLockV1::from_canonical_text(&lock_text).map_err(lock_error)?;
    if lock.identity() != candidate.lock.identity() {
        return Err(input_error("M46C frozen lock identity changed"));
    }
    let document_text =
        String::from_utf8(bounded_read(&candidate.document_path, MAX_FIXTURE_BYTES)?)
            .map_err(|_| input_error("M46C frozen companion is not UTF-8"))?;
    let document = ReservoirBindingDocumentV1::from_canonical_text(&document_text, &lock)
        .map_err(|error| input_error(format!("M46C frozen companion rejected: {error}")))?;
    if document.identity() != candidate.document.identity()
        || document.bindings() != std::slice::from_ref(&candidate.binding)
    {
        return Err(input_error("M46C frozen binding identity changed"));
    }
    Ok(())
}

fn require_reviewable_pending(path: &Path) -> Result<(), ManagedProjectError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o777 != 0o400 {
        return Err(input_error(
            "M46C transition evidence is not immutable 0400",
        ));
    }
    Ok(())
}

fn require_outcome(
    _outcome: &ReservoirBindingOutcomeV1,
    accepted: bool,
    label: &str,
) -> Result<(), ManagedProjectError> {
    if !accepted {
        return Err(input_error(format!(
            "M46C unexpected policy outcome for {label}"
        )));
    }
    Ok(())
}

fn outcome_name(outcome: &ReservoirBindingOutcomeV1) -> &'static str {
    match outcome {
        ReservoirBindingOutcomeV1::FirstResolutionPending { .. } => "FirstResolutionPending",
        ReservoirBindingOutcomeV1::StableBinding { .. } => "StableBinding",
        ReservoirBindingOutcomeV1::AmbiguousCandidates { .. } => "AmbiguousCandidates",
        ReservoirBindingOutcomeV1::MetadataDrift { .. } => "MetadataDrift",
        ReservoirBindingOutcomeV1::VersionRebound { .. } => "VersionRebound",
        ReservoirBindingOutcomeV1::DisappearedBinding { .. } => "DisappearedBinding",
        ReservoirBindingOutcomeV1::ContentMismatch { .. } => "ContentMismatch",
        ReservoirBindingOutcomeV1::ExplicitRebindAccepted { .. } => "ExplicitRebindAccepted",
    }
}

fn outcome_identity(outcome: &ReservoirBindingOutcomeV1) -> Sha256 {
    match outcome {
        ReservoirBindingOutcomeV1::FirstResolutionPending {
            proposed_binding_identity,
        }
        | ReservoirBindingOutcomeV1::VersionRebound {
            proposed_binding_identity,
            ..
        }
        | ReservoirBindingOutcomeV1::ContentMismatch {
            proposed_binding_identity,
            ..
        }
        | ReservoirBindingOutcomeV1::ExplicitRebindAccepted {
            proposed_binding_identity,
            ..
        } => *proposed_binding_identity,
        ReservoirBindingOutcomeV1::StableBinding {
            active_binding_identity,
        }
        | ReservoirBindingOutcomeV1::MetadataDrift {
            active_binding_identity,
            ..
        } => *active_binding_identity,
        ReservoirBindingOutcomeV1::DisappearedBinding {
            active_binding_identity: Some(identity),
        } => *identity,
        ReservoirBindingOutcomeV1::DisappearedBinding {
            active_binding_identity: None,
        }
        | ReservoirBindingOutcomeV1::AmbiguousCandidates { .. } => {
            sha256(b"leanbun-reservoir-audit-no-subject-v1")
        }
    }
}

fn bounded_read(path: &Path, maximum: u64) -> Result<Vec<u8>, ManagedProjectError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.file_type().is_file() || metadata.len() > maximum {
        return Err(input_error("M46C input is not a bounded regular file"));
    }
    fs::read(path).map_err(io_error)
}

fn file_sha256(path: &Path) -> Result<Sha256, ManagedProjectError> {
    Ok(sha256(&bounded_read(path, MAX_FIXTURE_BYTES)?))
}

fn sha256(bytes: &[u8]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn run_identity(fixture: Sha256) -> Result<Sha256, ManagedProjectError> {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-reservoir-loopback-run-v1\0");
    hasher.update(fixture.as_bytes());
    hasher.update(&u64::from(std::process::id()).to_be_bytes());
    hasher.update(&now_nanos()?.to_be_bytes());
    Ok(hasher.finalize())
}

fn parse_sha(value: &str) -> Result<Sha256, ManagedProjectError> {
    Sha256::parse(value).map_err(|error| input_error(format!("M46C SHA rejected: {error}")))
}

fn repeated_sha(byte: u8) -> Result<Sha256, ManagedProjectError> {
    parse_sha(&format!("{byte:02x}").repeat(32))
}

fn lock_error(error: leanbun_lock::LeanBunLockV1Error) -> ManagedProjectError {
    input_error(format!("M46C lock rejected: {error}"))
}

fn policy_error(error: leanbun_resolver::ReservoirPolicyErrorV1) -> ManagedProjectError {
    input_error(format!("M46C policy rejected: {error}"))
}
