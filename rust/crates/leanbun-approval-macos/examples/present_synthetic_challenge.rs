use leanbun_approval_macos::{
    prepare_lake_command_approval_presentation_v1,
    present_lake_command_approval_to_current_terminal_v1,
};
use leanbun_core::Sha256;
use leanbun_plan::{
    LakeCommandApprovalRequestV1, LakeCommandApprovalStateV1, LakeCommandPreflightDecisionV1,
    LakeCommandPreflightV1, PlanExecutionAuthorityV1, SUPPORTED_LAKE_VERSION,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let request_id =
        Sha256::parse("4d9d1e12c9daa6d20461d8c0dd2b8bb681dfe725593d9e0c4cc592f25e200d5c")?;
    let plan_report_sha256 =
        Sha256::parse("553843f557df3bdcd7e815688b6c7df3ce68317740b117f29e9470328589fa4a")?;
    let inventory_snapshot_sha256 =
        Sha256::parse("56207c2c37c4fc3085597c426c050a3c6202c2e81a2d9dc40ee8f762147389e2")?;
    let request = LakeCommandApprovalRequestV1 {
        schema_version: 1,
        request_type: "lake-command-approval-request".to_owned(),
        request_id,
        approval_state: LakeCommandApprovalStateV1::Pending,
        plan_report_sha256,
        inventory_snapshot_sha256,
        project_id: "synthetic-example-only".to_owned(),
        project_path: "/synthetic/not-executable".to_owned(),
        packages: vec!["mathlib".to_owned()],
        lake_version: SUPPORTED_LAKE_VERSION.to_owned(),
        network_required: true,
        nonce: "123e4567-e89b-42d3-a456-426614174000".to_owned(),
        issued_at_unix_ms: now.saturating_sub(1_000),
        expires_at_unix_ms: now.saturating_add(300_000),
        execution_authority: PlanExecutionAuthorityV1::Withheld,
    };
    let preflight = LakeCommandPreflightV1 {
        schema_version: 1,
        decision: LakeCommandPreflightDecisionV1::ReadyForExplicitApproval,
        request_id,
        plan_report_sha256,
        inventory_snapshot_sha256,
        executable_sha256: Sha256::parse(
            "f16d05ec6b29248d2c61adb1e9263f78e4f7bace1b955014a2d17872cfe4064d",
        )?,
        observed_at_unix_ms: now.saturating_sub(500),
        execution_authority: PlanExecutionAuthorityV1::Withheld,
    };
    let mut presentation = prepare_lake_command_approval_presentation_v1(&request, &preflight)?;
    present_lake_command_approval_to_current_terminal_v1(&mut presentation)?;
    Ok(())
}
