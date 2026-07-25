use leanbun_core::{
    BuildTarget, DiagnosticCode, ExecutionId, ImageId, ProjectId, Sha256, project_id,
};
use std::collections::BTreeMap;
use std::fs;

use crate::{
    CanonicalDirectory, EvidenceError, MAX_SAFE_JSON_INTEGER, StableTextFile, StrictJson,
    parse_strict_json, project_binding::valid_canonical_timestamp, read_stable_text,
};

pub const EXECUTION_RECORD_MAX_BYTES: u64 = 64 * 1024;

const MAX_PATH_BYTES: usize = 4_096;
const MAX_FAILURE_MESSAGE_UTF16: usize = 1_024;
const ROOT_FIELDS: &[&str] = &[
    "attestationSha256",
    "bindingSha256",
    "buildLockKey",
    "coordinatorPid",
    "dependencyArtifactBefore",
    "executionId",
    "finishedAt",
    "imageId",
    "outcome",
    "profileSha256",
    "projectId",
    "projectPath",
    "projectProtectedBefore",
    "projectProtectedRecordCount",
    "recordType",
    "reusePolicySha256",
    "schemaVersion",
    "startedAt",
    "status",
    "target",
];
const OUTCOME_FIELDS: &[&str] = &[
    "attestationStable",
    "bindingStable",
    "buildExecution",
    "dependencyArtifactAfter",
    "dependencyArtifactCount",
    "failureMessage",
    "failureStage",
    "inspectionStable",
    "lakeExitCode",
    "processGroupId",
    "processGroupReaped",
    "projectProtectedRecordsStable",
    "reuseEvidence",
    "reusedFromExecutionId",
    "terminationEscalated",
    "terminationReason",
    "triggerSignal",
];
const REUSE_EVIDENCE_FIELDS: &[&str] = &["projectInput", "projectOutput", "schemaVersion"];
const REUSE_TREE_FIELDS: &[&str] = &["byteCount", "entryCount", "fileCount", "schema", "treeHash"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionStatus {
    Running,
    Completed,
    Failed,
    Reused,
}

impl ExecutionStatus {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "running" => Some(Self::Running),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "reused" => Some(Self::Reused),
            _ => None,
        }
    }

    fn terminal_name(self) -> Option<&'static str> {
        match self {
            Self::Running => None,
            Self::Completed => Some("completed"),
            Self::Failed => Some("failed"),
            Self::Reused => Some("reused"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionPolicyIdentity {
    Profile(Sha256),
    Reuse(Sha256),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionRecoveryIdentity {
    pub coordinator_pid: u64,
    pub project_protected_before: Sha256,
    pub project_protected_record_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminationReason {
    Exit,
    Timeout,
    Signal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TriggerSignal {
    Sigint,
    Sigterm,
    Abort,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureStage {
    SandboxExecution,
    PostBuildVerification,
    ReuseVerification,
    Recovery,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReuseTreeEvidenceV1 {
    pub schema: String,
    pub tree_hash: Sha256,
    pub entry_count: u64,
    pub file_count: u64,
    pub byte_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectBuildReuseEvidenceV1 {
    pub project_input: ReuseTreeEvidenceV1,
    pub project_output: ReuseTreeEvidenceV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlledBuildExecutionOutcomeV1 {
    pub build_execution: ExecutionStatus,
    pub lake_exit_code: Option<i64>,
    pub project_protected_records_stable: Option<bool>,
    pub dependency_artifact_after: Option<Sha256>,
    pub dependency_artifact_count: Option<u64>,
    pub binding_stable: Option<bool>,
    pub attestation_stable: Option<bool>,
    pub inspection_stable: Option<bool>,
    pub termination_reason: Option<TerminationReason>,
    pub trigger_signal: Option<TriggerSignal>,
    pub process_group_id: Option<u64>,
    pub termination_escalated: Option<bool>,
    pub process_group_reaped: Option<bool>,
    pub failure_stage: Option<FailureStage>,
    pub failure_message: Option<String>,
    pub reuse_evidence: Option<ProjectBuildReuseEvidenceV1>,
    pub reused_from_execution_id: Option<ExecutionId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlledBuildExecutionRecordV1 {
    pub execution_id: ExecutionId,
    pub status: ExecutionStatus,
    pub project_id: ProjectId,
    pub project_path: String,
    pub target: BuildTarget,
    pub image_id: ImageId,
    pub binding_sha256: Sha256,
    pub attestation_sha256: Sha256,
    pub policy: ExecutionPolicyIdentity,
    pub dependency_artifact_before: Sha256,
    pub build_lock_key: Option<Sha256>,
    pub recovery: Option<ExecutionRecoveryIdentity>,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub outcome: Option<ControlledBuildExecutionOutcomeV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableExecutionRecordFile {
    pub file: StableTextFile,
    pub record: ControlledBuildExecutionRecordV1,
}

pub fn read_execution_record(
    state_root: &CanonicalDirectory,
    requested_execution_id: ExecutionId,
) -> Result<StableExecutionRecordFile, EvidenceError> {
    let store = state_root.as_path().join("executions");
    let metadata = fs::symlink_metadata(&store).map_err(|error| {
        EvidenceError::new(
            if error.kind() == std::io::ErrorKind::NotFound {
                DiagnosticCode::EVIDENCE_MISSING
            } else {
                DiagnosticCode::EVIDENCE_READ_FAILED
            },
            format!("execution record store cannot be inspected: {error}"),
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(EvidenceError::new(
            DiagnosticCode::PATH_ESCAPES_ALLOWED_ROOT,
            format!(
                "execution record store must not be a symlink: {}",
                store.display()
            ),
        ));
    }
    if !metadata.is_dir() {
        return Err(invalid(format!(
            "execution record store is not a directory: {}",
            store.display()
        )));
    }
    let candidate = format!("executions/{requested_execution_id}.json");
    let file = read_stable_text(state_root, candidate, EXECUTION_RECORD_MAX_BYTES)?;
    let record = parse_execution_record(&file.text, requested_execution_id)?;
    Ok(StableExecutionRecordFile { file, record })
}

pub fn parse_execution_record(
    text: &str,
    requested_execution_id: ExecutionId,
) -> Result<ControlledBuildExecutionRecordV1, EvidenceError> {
    decode_execution_record(&parse_strict_json(text)?, requested_execution_id)
}

pub fn decode_execution_record(
    value: &StrictJson,
    requested_execution_id: ExecutionId,
) -> Result<ControlledBuildExecutionRecordV1, EvidenceError> {
    let root = object(value, "execution record root")?;
    reject_unknown_fields(root, ROOT_FIELDS, "execution record")?;
    required_one(root, "schemaVersion", "execution record")?;
    if required_string(root, "recordType", 64, "execution record")? != "controlled-build-execution"
    {
        return Err(invalid("execution record recordType is invalid"));
    }
    let execution_id = ExecutionId::parse(required_string(
        root,
        "executionId",
        36,
        "execution record",
    )?)
    .map_err(|_| invalid("executionId must be a canonical UUID v4"))?;
    if execution_id != requested_execution_id {
        return Err(invalid("executionId does not match requested record"));
    }
    let status = ExecutionStatus::parse(required_string(root, "status", 16, "execution record")?)
        .ok_or_else(|| invalid("execution record status is invalid"))?;

    let project_path =
        required_nonempty_string(root, "projectPath", MAX_PATH_BYTES, "execution record")?;
    if !lexically_canonical_absolute_path(project_path) {
        return Err(invalid(
            "execution record projectPath is not a canonical absolute path",
        ));
    }
    let project_id_value =
        ProjectId::parse(required_string(root, "projectId", 64, "execution record")?)
            .map_err(|_| invalid("execution record projectId must be a lowercase SHA-256 value"))?;
    if project_id(project_path) != project_id_value {
        return Err(invalid(
            "execution record projectId does not match projectPath",
        ));
    }
    let target = BuildTarget::parse(required_string(root, "target", 1024, "execution record")?)
        .map_err(|_| invalid("execution record target is invalid"))?;
    let image_id = ImageId::parse(required_string(root, "imageId", 64, "execution record")?)
        .map_err(|_| invalid("execution record imageId must be a lowercase SHA-256 value"))?;
    let binding_sha256 = required_sha256(root, "bindingSha256", "execution record")?;
    let attestation_sha256 = required_sha256(root, "attestationSha256", "execution record")?;
    let dependency_artifact_before =
        required_sha256(root, "dependencyArtifactBefore", "execution record")?;
    let profile = optional_sha256(root, "profileSha256", "execution record")?;
    let reuse = optional_sha256(root, "reusePolicySha256", "execution record")?;
    let policy = match (profile, reuse) {
        (Some(value), None) => ExecutionPolicyIdentity::Profile(value),
        (None, Some(value)) => ExecutionPolicyIdentity::Reuse(value),
        _ => {
            return Err(invalid(
                "execution record requires exactly one policy digest",
            ));
        }
    };
    if status == ExecutionStatus::Completed
        && !matches!(policy, ExecutionPolicyIdentity::Profile(_))
    {
        return Err(invalid("completed execution must use profileSha256"));
    }
    if status == ExecutionStatus::Reused && !matches!(policy, ExecutionPolicyIdentity::Reuse(_)) {
        return Err(invalid("reused execution must use reusePolicySha256"));
    }

    let build_lock_key = optional_sha256(root, "buildLockKey", "execution record")?;
    let recovery = decode_recovery(root)?;
    let started_at = required_string(root, "startedAt", 24, "execution record")?;
    if !valid_canonical_timestamp(started_at) {
        return Err(invalid("execution startedAt is not canonical UTC"));
    }

    let (finished_at, outcome) = match status {
        ExecutionStatus::Running => {
            require_null(root, "finishedAt", "running execution")?;
            require_null(root, "outcome", "running execution")?;
            (None, None)
        }
        terminal => {
            let finished = required_string(root, "finishedAt", 24, "terminal execution")?;
            if !valid_canonical_timestamp(finished) || finished < started_at {
                return Err(invalid(
                    "execution finishedAt is invalid or precedes startedAt",
                ));
            }
            let outcome = decode_outcome(
                required_object(root, "outcome", "terminal execution")?,
                terminal,
            )?;
            (Some(finished.to_owned()), Some(outcome))
        }
    };

    Ok(ControlledBuildExecutionRecordV1 {
        execution_id,
        status,
        project_id: project_id_value,
        project_path: project_path.to_owned(),
        target,
        image_id,
        binding_sha256,
        attestation_sha256,
        policy,
        dependency_artifact_before,
        build_lock_key,
        recovery,
        started_at: started_at.to_owned(),
        finished_at,
        outcome,
    })
}

fn decode_recovery(
    root: &BTreeMap<String, StrictJson>,
) -> Result<Option<ExecutionRecoveryIdentity>, EvidenceError> {
    let pid = optional_positive_safe_integer(root, "coordinatorPid", "execution record")?;
    let protected = optional_sha256(root, "projectProtectedBefore", "execution record")?;
    let count = optional_safe_integer(root, "projectProtectedRecordCount", "execution record")?;
    match (pid, protected, count) {
        (None, None, None) => Ok(None),
        (
            Some(coordinator_pid),
            Some(project_protected_before),
            Some(project_protected_record_count),
        ) => Ok(Some(ExecutionRecoveryIdentity {
            coordinator_pid,
            project_protected_before,
            project_protected_record_count,
        })),
        _ => Err(invalid(
            "execution recovery identity must be wholly present or absent",
        )),
    }
}

fn decode_outcome(
    root: &BTreeMap<String, StrictJson>,
    status: ExecutionStatus,
) -> Result<ControlledBuildExecutionOutcomeV1, EvidenceError> {
    reject_unknown_fields(root, OUTCOME_FIELDS, "execution outcome")?;
    let terminal_name = status
        .terminal_name()
        .ok_or_else(|| invalid("running execution cannot have an outcome"))?;
    if required_string(root, "buildExecution", 16, "execution outcome")? != terminal_name {
        return Err(invalid("outcome buildExecution differs from record status"));
    }
    let lake_exit_code = optional_signed_integer(root, "lakeExitCode", "execution outcome")?;
    let project_protected_records_stable =
        optional_boolean(root, "projectProtectedRecordsStable", "execution outcome")?;
    let dependency_artifact_after =
        optional_sha256(root, "dependencyArtifactAfter", "execution outcome")?;
    let dependency_artifact_count =
        optional_safe_integer(root, "dependencyArtifactCount", "execution outcome")?;
    let binding_stable = optional_boolean(root, "bindingStable", "execution outcome")?;
    let attestation_stable = optional_boolean(root, "attestationStable", "execution outcome")?;
    let inspection_stable = optional_boolean(root, "inspectionStable", "execution outcome")?;
    let termination_reason = optional_enum(root, "terminationReason", |value| match value {
        "exit" => Some(TerminationReason::Exit),
        "timeout" => Some(TerminationReason::Timeout),
        "signal" => Some(TerminationReason::Signal),
        _ => None,
    })?;
    let trigger_signal = optional_enum(root, "triggerSignal", |value| match value {
        "SIGINT" => Some(TriggerSignal::Sigint),
        "SIGTERM" => Some(TriggerSignal::Sigterm),
        "ABORT" => Some(TriggerSignal::Abort),
        _ => None,
    })?;
    if trigger_signal.is_some() != (termination_reason == Some(TerminationReason::Signal)) {
        return Err(invalid(
            "triggerSignal must be present exactly for signal termination",
        ));
    }
    let process_group_id =
        optional_positive_safe_integer(root, "processGroupId", "execution outcome")?;
    let termination_escalated =
        optional_boolean(root, "terminationEscalated", "execution outcome")?;
    let process_group_reaped = optional_boolean(root, "processGroupReaped", "execution outcome")?;
    let failure_stage = optional_enum(root, "failureStage", |value| match value {
        "sandbox-execution" => Some(FailureStage::SandboxExecution),
        "post-build-verification" => Some(FailureStage::PostBuildVerification),
        "reuse-verification" => Some(FailureStage::ReuseVerification),
        "recovery" => Some(FailureStage::Recovery),
        "internal" => Some(FailureStage::Internal),
        _ => None,
    })?;
    let failure_message = optional_string(root, "failureMessage", "execution outcome")?;
    if failure_message
        .is_some_and(|message| message.encode_utf16().count() > MAX_FAILURE_MESSAGE_UTF16)
    {
        return Err(invalid(
            "execution failureMessage exceeds 1024 UTF-16 code units",
        ));
    }
    if status == ExecutionStatus::Failed && failure_stage.is_none() {
        return Err(invalid("failed execution requires failureStage"));
    }
    if status != ExecutionStatus::Failed && (failure_stage.is_some() || failure_message.is_some()) {
        return Err(invalid(
            "non-failed execution must not carry failure fields",
        ));
    }
    let reuse_evidence = match root.get("reuseEvidence") {
        Some(value) => Some(decode_reuse_evidence(value)?),
        None => None,
    };
    let reused_from_execution_id = match root.get("reusedFromExecutionId") {
        Some(StrictJson::String(value)) => Some(
            ExecutionId::parse(value)
                .map_err(|_| invalid("reusedFromExecutionId must be a canonical UUID v4"))?,
        ),
        Some(_) => return Err(invalid("reusedFromExecutionId must be a string")),
        None => None,
    };
    if status == ExecutionStatus::Reused {
        if reuse_evidence.is_none() || reused_from_execution_id.is_none() {
            return Err(invalid(
                "reused execution requires source ID and reuse evidence",
            ));
        }
        if lake_exit_code.is_some()
            || termination_reason.is_some()
            || trigger_signal.is_some()
            || process_group_id.is_some()
            || termination_escalated.is_some()
            || process_group_reaped.is_some()
        {
            return Err(invalid(
                "reused execution must not carry Lake or process-group fields",
            ));
        }
    } else if reused_from_execution_id.is_some() {
        return Err(invalid(
            "non-reused execution must not reference a reused source",
        ));
    }

    Ok(ControlledBuildExecutionOutcomeV1 {
        build_execution: status,
        lake_exit_code,
        project_protected_records_stable,
        dependency_artifact_after,
        dependency_artifact_count,
        binding_stable,
        attestation_stable,
        inspection_stable,
        termination_reason,
        trigger_signal,
        process_group_id,
        termination_escalated,
        process_group_reaped,
        failure_stage,
        failure_message: failure_message.map(str::to_owned),
        reuse_evidence,
        reused_from_execution_id,
    })
}

fn decode_reuse_evidence(value: &StrictJson) -> Result<ProjectBuildReuseEvidenceV1, EvidenceError> {
    let root = object(value, "reuse evidence")?;
    reject_unknown_fields(root, REUSE_EVIDENCE_FIELDS, "reuse evidence")?;
    required_one(root, "schemaVersion", "reuse evidence")?;
    Ok(ProjectBuildReuseEvidenceV1 {
        project_input: decode_reuse_tree(
            required_object(root, "projectInput", "reuse evidence")?,
            "leanbun-project-input-tree-v1",
        )?,
        project_output: decode_reuse_tree(
            required_object(root, "projectOutput", "reuse evidence")?,
            "leanbun-project-output-tree-v1",
        )?,
    })
}

fn decode_reuse_tree(
    root: &BTreeMap<String, StrictJson>,
    expected_schema: &str,
) -> Result<ReuseTreeEvidenceV1, EvidenceError> {
    reject_unknown_fields(root, REUSE_TREE_FIELDS, "reuse tree")?;
    let schema = required_string(root, "schema", 64, "reuse tree")?;
    if schema != expected_schema {
        return Err(invalid("reuse tree schema is invalid"));
    }
    let entry_count = required_safe_integer(root, "entryCount", "reuse tree")?;
    let file_count = required_safe_integer(root, "fileCount", "reuse tree")?;
    if file_count > entry_count {
        return Err(invalid("reuse tree fileCount exceeds entryCount"));
    }
    Ok(ReuseTreeEvidenceV1 {
        schema: schema.to_owned(),
        tree_hash: required_sha256(root, "treeHash", "reuse tree")?,
        entry_count,
        file_count,
        byte_count: required_safe_integer(root, "byteCount", "reuse tree")?,
    })
}

pub(crate) fn lexically_canonical_absolute_path(value: &str) -> bool {
    if value == "/" {
        return true;
    }
    value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("//")
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn object<'a>(
    value: &'a StrictJson,
    label: &str,
) -> Result<&'a BTreeMap<String, StrictJson>, EvidenceError> {
    match value {
        StrictJson::Object(object) => Ok(object),
        _ => Err(invalid(format!("{label} must be an object"))),
    }
}

fn required_object<'a>(
    root: &'a BTreeMap<String, StrictJson>,
    field: &str,
    label: &str,
) -> Result<&'a BTreeMap<String, StrictJson>, EvidenceError> {
    match root.get(field) {
        Some(value) => object(value, field),
        None => Err(invalid(format!("{label} is missing {field}"))),
    }
}

fn reject_unknown_fields(
    root: &BTreeMap<String, StrictJson>,
    allowed: &[&str],
    label: &str,
) -> Result<(), EvidenceError> {
    for field in root.keys() {
        if allowed.binary_search(&field.as_str()).is_err() {
            return Err(invalid(format!("unknown {label} field: {field}")));
        }
    }
    Ok(())
}

fn required_one(
    root: &BTreeMap<String, StrictJson>,
    field: &str,
    label: &str,
) -> Result<(), EvidenceError> {
    match root.get(field) {
        Some(StrictJson::Number(number)) if number.as_str() == "1" => Ok(()),
        Some(_) => Err(invalid(format!("{label} {field} must be integer 1"))),
        None => Err(invalid(format!("{label} is missing {field}"))),
    }
}

fn required_string<'a>(
    root: &'a BTreeMap<String, StrictJson>,
    field: &str,
    maximum_bytes: usize,
    label: &str,
) -> Result<&'a str, EvidenceError> {
    match root.get(field) {
        Some(StrictJson::String(value)) if value.len() <= maximum_bytes => Ok(value),
        Some(StrictJson::String(_)) => Err(invalid(format!("{label} {field} exceeds byte limit"))),
        Some(_) => Err(invalid(format!("{label} {field} must be a string"))),
        None => Err(invalid(format!("{label} is missing {field}"))),
    }
}

fn required_nonempty_string<'a>(
    root: &'a BTreeMap<String, StrictJson>,
    field: &str,
    maximum_bytes: usize,
    label: &str,
) -> Result<&'a str, EvidenceError> {
    let value = required_string(root, field, maximum_bytes, label)?;
    if value.is_empty() {
        return Err(invalid(format!("{label} {field} must not be empty")));
    }
    Ok(value)
}

fn optional_string<'a>(
    root: &'a BTreeMap<String, StrictJson>,
    field: &str,
    label: &str,
) -> Result<Option<&'a str>, EvidenceError> {
    match root.get(field) {
        Some(StrictJson::String(value)) => Ok(Some(value)),
        Some(_) => Err(invalid(format!("{label} {field} must be a string"))),
        None => Ok(None),
    }
}

fn required_sha256(
    root: &BTreeMap<String, StrictJson>,
    field: &str,
    label: &str,
) -> Result<Sha256, EvidenceError> {
    Sha256::parse(required_string(root, field, 64, label)?)
        .map_err(|_| invalid(format!("{label} {field} must be a lowercase SHA-256 value")))
}

fn optional_sha256(
    root: &BTreeMap<String, StrictJson>,
    field: &str,
    label: &str,
) -> Result<Option<Sha256>, EvidenceError> {
    match root.get(field) {
        Some(StrictJson::String(value)) => Sha256::parse(value)
            .map(Some)
            .map_err(|_| invalid(format!("{label} {field} must be a lowercase SHA-256 value"))),
        Some(_) => Err(invalid(format!("{label} {field} must be a string"))),
        None => Ok(None),
    }
}

fn required_safe_integer(
    root: &BTreeMap<String, StrictJson>,
    field: &str,
    label: &str,
) -> Result<u64, EvidenceError> {
    optional_safe_integer(root, field, label)?
        .ok_or_else(|| invalid(format!("{label} is missing {field}")))
}

fn optional_safe_integer(
    root: &BTreeMap<String, StrictJson>,
    field: &str,
    label: &str,
) -> Result<Option<u64>, EvidenceError> {
    let Some(value) = root.get(field) else {
        return Ok(None);
    };
    let StrictJson::Number(number) = value else {
        return Err(invalid(format!("{label} {field} must be an integer")));
    };
    let lexical = number.as_str();
    if lexical.is_empty() || !lexical.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid(format!(
            "{label} {field} must be a nonnegative integer"
        )));
    }
    let parsed = lexical
        .parse::<u64>()
        .map_err(|_| invalid(format!("{label} {field} exceeds integer range")))?;
    if parsed > MAX_SAFE_JSON_INTEGER {
        return Err(invalid(format!(
            "{label} {field} exceeds JSON safe integer range"
        )));
    }
    Ok(Some(parsed))
}

fn optional_positive_safe_integer(
    root: &BTreeMap<String, StrictJson>,
    field: &str,
    label: &str,
) -> Result<Option<u64>, EvidenceError> {
    let value = optional_safe_integer(root, field, label)?;
    if value == Some(0) {
        return Err(invalid(format!("{label} {field} must be positive")));
    }
    Ok(value)
}

fn optional_signed_integer(
    root: &BTreeMap<String, StrictJson>,
    field: &str,
    label: &str,
) -> Result<Option<i64>, EvidenceError> {
    let Some(value) = root.get(field) else {
        return Ok(None);
    };
    let StrictJson::Number(number) = value else {
        return Err(invalid(format!("{label} {field} must be an integer")));
    };
    let lexical = number.as_str();
    if lexical.contains(['.', 'e', 'E']) {
        return Err(invalid(format!("{label} {field} must be an integer")));
    }
    let parsed = lexical
        .parse::<i64>()
        .map_err(|_| invalid(format!("{label} {field} exceeds integer range")))?;
    if parsed.unsigned_abs() > MAX_SAFE_JSON_INTEGER {
        return Err(invalid(format!(
            "{label} {field} exceeds JSON safe integer range"
        )));
    }
    Ok(Some(parsed))
}

fn optional_boolean(
    root: &BTreeMap<String, StrictJson>,
    field: &str,
    label: &str,
) -> Result<Option<bool>, EvidenceError> {
    match root.get(field) {
        Some(StrictJson::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(invalid(format!("{label} {field} must be a boolean"))),
        None => Ok(None),
    }
}

fn optional_enum<T>(
    root: &BTreeMap<String, StrictJson>,
    field: &str,
    parser: impl FnOnce(&str) -> Option<T>,
) -> Result<Option<T>, EvidenceError> {
    match root.get(field) {
        Some(StrictJson::String(value)) => parser(value)
            .map(Some)
            .ok_or_else(|| invalid(format!("execution outcome {field} is invalid"))),
        Some(_) => Err(invalid(format!(
            "execution outcome {field} must be a string"
        ))),
        None => Ok(None),
    }
}

fn require_null(
    root: &BTreeMap<String, StrictJson>,
    field: &str,
    label: &str,
) -> Result<(), EvidenceError> {
    match root.get(field) {
        Some(StrictJson::Null) => Ok(()),
        Some(_) => Err(invalid(format!("{label} {field} must be null"))),
        None => Err(invalid(format!("{label} is missing {field}"))),
    }
}

fn invalid(message: impl Into<String>) -> EvidenceError {
    EvidenceError::new(DiagnosticCode::EXECUTION_RECORD_FAILED, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonicalize_directory;
    use std::io;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const EXECUTION: &str = "12345678-1234-4123-8123-123456789abc";
    const PROJECT_ID: &str = "c32fe4e9adb318f7e52427c338c6b6c8079f12fa40b5f29423de8e7a7214e08b";
    static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> io::Result<Self> {
            let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "leanbun-execution-reader-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn running_json() -> String {
        format!(
            "{{\"schemaVersion\":1,\"recordType\":\"controlled-build-execution\",\"executionId\":\"{EXECUTION}\",\"status\":\"running\",\"projectId\":\"{PROJECT_ID}\",\"projectPath\":\"/fixture/project\",\"target\":\"Fixture\",\"imageId\":\"{}\",\"bindingSha256\":\"{}\",\"attestationSha256\":\"{}\",\"profileSha256\":\"{}\",\"dependencyArtifactBefore\":\"{}\",\"startedAt\":\"2026-07-24T00:00:00.000Z\",\"finishedAt\":null,\"outcome\":null}}",
            "1".repeat(64),
            "2".repeat(64),
            "3".repeat(64),
            "4".repeat(64),
            "5".repeat(64)
        )
    }

    #[test]
    fn stable_reader_binds_filename_and_running_state() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        fs::create_dir(fixture.0.join("executions"))?;
        fs::write(
            fixture.0.join(format!("executions/{EXECUTION}.json")),
            running_json(),
        )?;
        let root = canonicalize_directory(&fixture.0)?;
        let requested = ExecutionId::parse(EXECUTION)?;
        let observed = read_execution_record(&root, requested)?;
        assert_eq!(observed.record.status, ExecutionStatus::Running);
        assert_eq!(read_execution_record(&root, requested)?, observed);
        Ok(())
    }

    #[test]
    fn reader_rejects_symlinked_execution_store() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let outside = fixture.0.join("outside");
        fs::create_dir(&outside)?;
        symlink(&outside, fixture.0.join("executions"))?;
        let root = canonicalize_directory(&fixture.0)?;
        assert_eq!(
            read_execution_record(&root, ExecutionId::parse(EXECUTION)?)
                .map_err(|error| error.code),
            Err(DiagnosticCode::PATH_ESCAPES_ALLOWED_ROOT)
        );
        Ok(())
    }

    #[test]
    fn shared_execution_record_contract_cases_match() {
        for line in include_str!("../../../golden/execution-record-cases.tsv").lines() {
            let mut fields = line.splitn(4, '\t');
            let expected = fields.next();
            let label = fields.next();
            let requested = fields
                .next()
                .and_then(|value| ExecutionId::parse(value).ok());
            let json = fields.next();
            assert!(expected.is_some() && label.is_some() && requested.is_some() && json.is_some());
            let accepted = requested
                .zip(json)
                .and_then(|(execution, text)| parse_execution_record(text, execution).ok())
                .is_some();
            assert_eq!(accepted, expected == Some("true"), "{label:?}");
        }
    }
}
