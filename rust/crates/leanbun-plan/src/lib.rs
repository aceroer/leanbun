#![forbid(unsafe_code)]

use core::fmt;
use leanbun_core::{DiagnosticCode, Sha256};
use leanbun_evidence::{CanonicalDirectory, CanonicalPath};
use leanbun_inventory_legacy::{
    DeclaredPackageSourceV1, DependencyDriftReportV1, DependencyDriftSummaryV1, PackageInventoryV1,
    package_inventory_snapshot_digest_v1,
};
use std::collections::BTreeSet;

mod approval_grant;
mod approval_request;
mod plan_report;
mod preflight;
mod trusted_ingress;
mod update_contract;

pub use approval_grant::{
    LakeCommandApprovalGrantError, LakeCommandApprovalGrantV1, LakeCommandGrantClaimDecisionV1,
    LakeCommandGrantClaimVerificationV1, decode_lake_command_approval_grant_v1,
    parse_lake_command_approval_grant_v1, verify_lake_command_approval_grant_v1,
};
pub use approval_request::{
    LakeCommandApprovalRequestError, LakeCommandApprovalRequestV1, LakeCommandApprovalStateV1,
    lake_command_approval_request_v1, verify_lake_command_approval_request_v1,
};
pub use plan_report::{
    LakeCommandPlanReportSourceV1, LakeCommandPlanReportV1, lake_command_plan_report_v1,
};
pub use preflight::{
    LakeCommandPreflightDecisionV1, LakeCommandPreflightError, LakeCommandPreflightRejectionV1,
    LakeCommandPreflightV1, lake_command_preflight_v1,
};
pub use trusted_ingress::{
    FORBIDDEN_APPROVAL_SOURCES_V1, LakeCommandTrustedApprovalChallengeV1,
    TRUSTED_INGRESS_REQUIREMENTS_V1, TrustedApprovalIngressContractV1,
    TrustedApprovalIngressDecisionV1, TrustedApprovalIngressError,
    lake_command_trusted_approval_challenge_v1, trusted_approval_ingress_contract_v1,
};
pub use update_contract::{
    LakeUpdateContractError, LakeUpdateContractFactV1, LakeUpdateContractSourceV1,
    LakeUpdateContractV1, LakeUpdateMitigationV1, LakeUpdateRequirementV1, lake_update_contract_v1,
    verify_lake_update_plan_contract_v1,
};

pub const SUPPORTED_LAKE_VERSION: &str = "5.0.0-src+8c9756b";

const ENVIRONMENT_ALLOWLIST_V1: &[&str] = &[
    "ELAN_HOME",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_TERMINAL_PROMPT",
    "HOME",
    "PATH",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LakeCommandFamilyV1 {
    Update,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandPermissionClassV1 {
    ExplicitExternalUpdate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandNetworkPolicyV1 {
    Required,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PlannedEffectV1 {
    LoadAndExecuteProjectConfiguration,
    ReadPackageOverrides,
    RewriteManifest,
    CreateOrModifyLakeDirectory,
    FetchRemotePackageContent,
    CreateOrModifyPackageCheckouts,
    ExecutePostUpdateHooks,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PlanRiskV1 {
    UntrustedProjectConfigurationExecution,
    NetworkAndRemoteContent,
    ManifestRewrite,
    CheckoutMutation,
    LakeInternalStateMutation,
    PostUpdateHookExecution,
    CheckoutEvidenceIncomplete,
    ObservedDependencyDrift,
    ExecutablePropertiesRequireGateRecheck,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanExecutionAuthorityV1 {
    Withheld,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeExecutableObservationV1 {
    pub schema_version: u8,
    pub canonical_path: CanonicalPath,
    pub lake_version: String,
    pub sha256: Sha256,
    pub byte_length: u64,
    pub unix_mode: u32,
    pub regular_file: bool,
    pub symlink_free: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeCommandPlanV1 {
    pub schema_version: u8,
    pub family: LakeCommandFamilyV1,
    pub lake_version: String,
    pub inventory_snapshot_sha256: Sha256,
    pub executable: CanonicalPath,
    pub executable_sha256: Sha256,
    pub executable_byte_length: u64,
    pub executable_unix_mode: u32,
    pub executable_regular_file: bool,
    pub executable_symlink_free: bool,
    pub arguments: Vec<String>,
    pub cwd: CanonicalDirectory,
    pub environment_allowlist: Vec<String>,
    pub permission_class: CommandPermissionClassV1,
    pub network_policy: CommandNetworkPolicyV1,
    pub expected_effects: Vec<PlannedEffectV1>,
    pub risks: Vec<PlanRiskV1>,
    pub execution_authority: PlanExecutionAuthorityV1,
}

#[derive(Clone, Debug)]
pub struct LakeUpdatePlanRequestV1<'a> {
    pub managed_toolchain_root: &'a CanonicalDirectory,
    pub executable_observation: &'a LakeExecutableObservationV1,
    pub project_root: &'a CanonicalDirectory,
    pub inventory: &'a PackageInventoryV1,
    pub drift_report: &'a DependencyDriftReportV1,
    pub packages: &'a [String],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeCommandPlanError {
    pub code: DiagnosticCode,
    pub message: String,
}

impl LakeCommandPlanError {
    fn new(code: DiagnosticCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for LakeCommandPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for LakeCommandPlanError {}

pub fn plan_lake_update(
    request: LakeUpdatePlanRequestV1<'_>,
) -> Result<LakeCommandPlanV1, LakeCommandPlanError> {
    if request.executable_observation.schema_version != 1
        || request.executable_observation.lake_version != SUPPORTED_LAKE_VERSION
    {
        return Err(LakeCommandPlanError::new(
            DiagnosticCode::TOOLCHAIN_MISMATCH,
            format!(
                "Lake version is not supported by the update plan contract: expected={} observed={}",
                SUPPORTED_LAKE_VERSION, request.executable_observation.lake_version
            ),
        ));
    }
    if request.inventory.project_id != request.drift_report.project_id {
        return Err(LakeCommandPlanError::new(
            DiagnosticCode::BUILD_INSPECTION_FAILED,
            "inventory and drift report project identities differ",
        ));
    }
    if request.inventory.project_path != request.project_root.as_path().to_string_lossy() {
        return Err(LakeCommandPlanError::new(
            DiagnosticCode::BUILD_INSPECTION_FAILED,
            "inventory project path differs from the canonical project root supplied to plan",
        ));
    }
    let inventory_snapshot =
        package_inventory_snapshot_digest_v1(request.inventory, request.drift_report).map_err(
            |error| {
                LakeCommandPlanError::new(
                    DiagnosticCode::BUILD_INSPECTION_FAILED,
                    format!("package inventory snapshot is invalid: {}", error.message),
                )
            },
        )?;
    let executable = request.executable_observation.canonical_path.as_path();
    if !executable.starts_with(request.managed_toolchain_root.as_path())
        || executable.file_name().and_then(|value| value.to_str()) != Some("lake")
    {
        return Err(LakeCommandPlanError::new(
            DiagnosticCode::PATH_ESCAPES_ALLOWED_ROOT,
            "Lake executable is not the canonical lake path inside the managed toolchain root",
        ));
    }
    if !request.executable_observation.regular_file
        || !request.executable_observation.symlink_free
        || request.executable_observation.byte_length == 0
        || request.executable_observation.unix_mode & 0o111 == 0
    {
        return Err(LakeCommandPlanError::new(
            DiagnosticCode::BUILD_NOT_AUTHORIZED,
            "Lake executable observation is not a non-empty, regular, symlink-free executable",
        ));
    }
    if request.packages.is_empty() {
        return Err(LakeCommandPlanError::new(
            DiagnosticCode::BUILD_NOT_AUTHORIZED,
            "bare lake update is outside the M0 plan contract; explicit packages are required",
        ));
    }

    let inventory_by_name = request
        .inventory
        .packages
        .iter()
        .map(|package| (package.name.as_str(), package))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut selected = BTreeSet::new();
    for package in request.packages {
        if !valid_package_selector(package) {
            return Err(LakeCommandPlanError::new(
                DiagnosticCode::MANIFEST_SHAPE_INVALID,
                format!("invalid Lake update package selector: {package}"),
            ));
        }
        if !selected.insert(package.as_str()) {
            return Err(LakeCommandPlanError::new(
                DiagnosticCode::MANIFEST_SHAPE_INVALID,
                format!("duplicate Lake update package selector: {package}"),
            ));
        }
        let Some(inventory_package) = inventory_by_name.get(package.as_str()) else {
            return Err(LakeCommandPlanError::new(
                DiagnosticCode::PROVIDER_PACKAGE_MISSING,
                format!("Lake update package is absent from inventory: {package}"),
            ));
        };
        if !matches!(
            inventory_package.declaration,
            Some(DeclaredPackageSourceV1::Git { .. })
        ) {
            return Err(LakeCommandPlanError::new(
                DiagnosticCode::BUILD_NOT_AUTHORIZED,
                format!("M0 update plans only support declared Git packages: {package}"),
            ));
        }
    }

    let mut arguments = vec!["--keep-toolchain".to_owned(), "update".to_owned()];
    arguments.extend(selected.into_iter().map(str::to_owned));
    let mut risks = vec![
        PlanRiskV1::UntrustedProjectConfigurationExecution,
        PlanRiskV1::NetworkAndRemoteContent,
        PlanRiskV1::ManifestRewrite,
        PlanRiskV1::CheckoutMutation,
        PlanRiskV1::LakeInternalStateMutation,
        PlanRiskV1::PostUpdateHookExecution,
        PlanRiskV1::ExecutablePropertiesRequireGateRecheck,
    ];
    match request.drift_report.summary {
        DependencyDriftSummaryV1::Matched => {}
        DependencyDriftSummaryV1::Drifted => risks.push(PlanRiskV1::ObservedDependencyDrift),
        DependencyDriftSummaryV1::Unobserved => {
            risks.push(PlanRiskV1::CheckoutEvidenceIncomplete);
        }
    }
    risks.sort();

    Ok(LakeCommandPlanV1 {
        schema_version: 1,
        family: LakeCommandFamilyV1::Update,
        lake_version: request.executable_observation.lake_version.clone(),
        inventory_snapshot_sha256: inventory_snapshot.sha256,
        executable: request.executable_observation.canonical_path.clone(),
        executable_sha256: request.executable_observation.sha256,
        executable_byte_length: request.executable_observation.byte_length,
        executable_unix_mode: request.executable_observation.unix_mode,
        executable_regular_file: request.executable_observation.regular_file,
        executable_symlink_free: request.executable_observation.symlink_free,
        arguments,
        cwd: request.project_root.clone(),
        environment_allowlist: ENVIRONMENT_ALLOWLIST_V1
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        permission_class: CommandPermissionClassV1::ExplicitExternalUpdate,
        network_policy: CommandNetworkPolicyV1::Required,
        expected_effects: vec![
            PlannedEffectV1::LoadAndExecuteProjectConfiguration,
            PlannedEffectV1::ReadPackageOverrides,
            PlannedEffectV1::RewriteManifest,
            PlannedEffectV1::CreateOrModifyLakeDirectory,
            PlannedEffectV1::FetchRemotePackageContent,
            PlannedEffectV1::CreateOrModifyPackageCheckouts,
            PlannedEffectV1::ExecutePostUpdateHooks,
        ],
        risks,
        execution_authority: PlanExecutionAuthorityV1::Withheld,
    })
}

fn valid_package_selector(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('-')
        && !value.chars().any(|character| {
            character.is_control() || character.is_whitespace() || matches!(character, '/' | '\\')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use leanbun_core::{Sha256, project_id};
    use leanbun_evidence::{canonicalize_contained, canonicalize_directory};
    use leanbun_inventory_legacy::{
        CheckoutObservationStateV1, DependencyDriftReportV1, GitRevision, PackageInventoryEntryV1,
        report_dependency_drift,
    };
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        toolchain: CanonicalDirectory,
        lake: CanonicalPath,
        project: CanonicalDirectory,
    }

    impl Fixture {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("leanbun-lake-plan-{}-{id}", std::process::id()));
            fs::create_dir_all(root.join("toolchain/bin"))?;
            fs::create_dir(root.join("project"))?;
            fs::write(root.join("toolchain/bin/lake"), b"fixture")?;
            fs::set_permissions(
                root.join("toolchain/bin/lake"),
                fs::Permissions::from_mode(0o755),
            )?;
            let canonical_root = canonicalize_directory(&root)?;
            let toolchain =
                leanbun_evidence::canonicalize_contained_directory(&canonical_root, "toolchain")?;
            let lake = canonicalize_contained(&canonical_root, "toolchain/bin/lake")?;
            let project =
                leanbun_evidence::canonicalize_contained_directory(&canonical_root, "project")?;
            Ok(Self {
                root,
                toolchain,
                lake,
                project,
            })
        }

        fn executable(&self, version: &str) -> LakeExecutableObservationV1 {
            LakeExecutableObservationV1 {
                schema_version: 1,
                canonical_path: self.lake.clone(),
                lake_version: version.to_owned(),
                sha256: Sha256::parse(
                    "f16d05ec6b29248d2c61adb1e9263f78e4f7bace1b955014a2d17872cfe4064d",
                )
                .unwrap_or_else(|error| panic!("fixture SHA must be valid: {error}")),
                byte_length: 7,
                unix_mode: 0o755,
                regular_file: true,
                symlink_free: true,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn csv(value: &str) -> Vec<&str> {
        if value == "<empty>" {
            Vec::new()
        } else {
            value.split(',').collect()
        }
    }

    fn inventory(
        fixture: &Fixture,
        names: &[&str],
        git_names: &[&str],
    ) -> Result<PackageInventoryV1, Box<dyn std::error::Error>> {
        let git_names = git_names.iter().copied().collect::<BTreeSet<_>>();
        let project_path = fixture.project.as_path().to_string_lossy().into_owned();
        Ok(PackageInventoryV1 {
            schema_version: 1,
            project_id: project_id(&project_path),
            project_path,
            toolchain: "leanprover/lean4:v4.32.0".to_owned(),
            manifest_sha256: Sha256::parse(&"0".repeat(64))?,
            override_sha256: None,
            provider_registry_sha256: None,
            provider_override_sha256: None,
            packages: names
                .iter()
                .map(|name| PackageInventoryEntryV1 {
                    name: (*name).to_owned(),
                    declaration: Some(if git_names.contains(name) {
                        DeclaredPackageSourceV1::Git {
                            revision: GitRevision::parse(&"1".repeat(40))
                                .unwrap_or_else(|error| panic!("valid fixture revision: {error}")),
                        }
                    } else {
                        DeclaredPackageSourceV1::Path {
                            declared_directory: format!("packages/{name}"),
                        }
                    }),
                    project_override_directory: None,
                    resolved_path_directory: None,
                    provider: None,
                    checkout: CheckoutObservationStateV1::Unobserved,
                })
                .collect(),
        })
    }

    fn report(inventory: &PackageInventoryV1) -> DependencyDriftReportV1 {
        report_dependency_drift(inventory)
    }

    fn request<'a>(
        fixture: &'a Fixture,
        executable_observation: &'a LakeExecutableObservationV1,
        inventory: &'a PackageInventoryV1,
        report: &'a DependencyDriftReportV1,
        packages: &'a [String],
    ) -> LakeUpdatePlanRequestV1<'a> {
        LakeUpdatePlanRequestV1 {
            managed_toolchain_root: &fixture.toolchain,
            executable_observation,
            project_root: &fixture.project,
            inventory,
            drift_report: report,
            packages,
        }
    }

    #[test]
    fn targeted_update_plan_is_non_executable_and_effect_complete()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let executable = fixture.executable(SUPPORTED_LAKE_VERSION);
        let inventory = inventory(&fixture, &["mathlib"], &["mathlib"])?;
        let report = report(&inventory);
        let packages = vec!["mathlib".to_owned()];
        let plan = plan_lake_update(request(
            &fixture,
            &executable,
            &inventory,
            &report,
            &packages,
        ))?;
        assert_eq!(plan.arguments, ["--keep-toolchain", "update", "mathlib"]);
        assert_eq!(plan.execution_authority, PlanExecutionAuthorityV1::Withheld);
        assert!(
            plan.expected_effects
                .contains(&PlannedEffectV1::ExecutePostUpdateHooks)
        );
        assert!(plan.risks.contains(&PlanRiskV1::CheckoutEvidenceIncomplete));
        verify_lake_update_plan_contract_v1(&plan)?;
        Ok(())
    }

    #[test]
    fn update_contract_rejects_omitted_effect_risk_and_mitigation()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let executable = fixture.executable(SUPPORTED_LAKE_VERSION);
        let inventory = inventory(&fixture, &["mathlib"], &["mathlib"])?;
        let report = report(&inventory);
        let packages = vec!["mathlib".to_owned()];
        let plan = plan_lake_update(request(
            &fixture,
            &executable,
            &inventory,
            &report,
            &packages,
        ))?;

        let contract = lake_update_contract_v1()?;
        assert_eq!(contract.schema_version, 1);
        assert_eq!(contract.sources.len(), 6);
        assert_eq!(contract.facts.len(), 13);

        let mut missing_effect = plan.clone();
        missing_effect
            .expected_effects
            .retain(|effect| *effect != PlannedEffectV1::RewriteManifest);
        assert!(verify_lake_update_plan_contract_v1(&missing_effect).is_err());

        let mut missing_risk = plan.clone();
        missing_risk
            .risks
            .retain(|risk| *risk != PlanRiskV1::PostUpdateHookExecution);
        assert!(verify_lake_update_plan_contract_v1(&missing_risk).is_err());

        let mut missing_mitigation = plan;
        missing_mitigation.arguments.remove(0);
        assert!(verify_lake_update_plan_contract_v1(&missing_mitigation).is_err());

        let mut alias = missing_mitigation;
        alias.arguments = vec![
            "--keep-toolchain".to_owned(),
            "upgrade".to_owned(),
            "mathlib".to_owned(),
        ];
        assert!(verify_lake_update_plan_contract_v1(&alias).is_err());
        Ok(())
    }

    #[test]
    fn command_plan_report_matches_bun_canonical_json() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let executable = fixture.executable(SUPPORTED_LAKE_VERSION);
        let inventory = inventory(&fixture, &["mathlib"], &["mathlib"])?;
        let report = report(&inventory);
        let packages = vec!["mathlib".to_owned()];
        let plan = plan_lake_update(request(
            &fixture,
            &executable,
            &inventory,
            &report,
            &packages,
        ))?;
        let report = lake_command_plan_report_v1(&plan)?;
        let normalized = report
            .to_canonical_json()
            .replace(
                &report.inventory_snapshot_sha256,
                "56207c2c37c4fc3085597c426c050a3c6202c2e81a2d9dc40ee8f762147389e2",
            )
            .replace(&report.executable, "/fixture/toolchain/bin/lake")
            .replace(&report.cwd, "/fixture/project");
        assert_eq!(
            normalized,
            include_str!("../../../golden/lake-command-plan-report.json").trim_end()
        );
        assert_eq!(report.execution_authority, "withheld");
        Ok(())
    }

    #[test]
    fn approval_request_is_pending_bounded_and_non_executable()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let executable = fixture.executable(SUPPORTED_LAKE_VERSION);
        let inventory = inventory(&fixture, &["mathlib"], &["mathlib"])?;
        let drift = report(&inventory);
        let packages = vec!["mathlib".to_owned()];
        let plan = plan_lake_update(request(
            &fixture,
            &executable,
            &inventory,
            &drift,
            &packages,
        ))?;
        let nonce = "123e4567-e89b-42d3-a456-426614174000";
        let approval =
            lake_command_approval_request_v1(&plan, nonce, 1_800_000_000_000, 1_800_000_600_000)?;
        let plan_report = lake_command_plan_report_v1(&plan)?;
        let mut hasher = leanbun_core::Sha256Hasher::new();
        hasher.update(plan_report.to_canonical_json().as_bytes());
        assert_eq!(approval.plan_report_sha256, hasher.finalize());
        assert_eq!(approval.approval_state, LakeCommandApprovalStateV1::Pending);
        assert_eq!(approval.packages, ["mathlib"]);
        assert_eq!(
            approval.execution_authority,
            PlanExecutionAuthorityV1::Withheld
        );
        verify_lake_command_approval_request_v1(&approval, &plan, 1_800_000_300_000)?;
        let preflight = lake_command_preflight_v1(
            &approval,
            &plan,
            &executable,
            1_800_000_299_000,
            1_800_000_300_000,
        )?;
        assert_eq!(
            preflight.decision,
            LakeCommandPreflightDecisionV1::ReadyForExplicitApproval
        );
        assert_eq!(
            preflight.execution_authority,
            PlanExecutionAuthorityV1::Withheld
        );
        let normalized_preflight = preflight
            .to_canonical_json()
            .replace(
                &preflight.request_id.to_string(),
                "4d9d1e12c9daa6d20461d8c0dd2b8bb681dfe725593d9e0c4cc592f25e200d5c",
            )
            .replace(
                &preflight.plan_report_sha256.to_string(),
                "553843f557df3bdcd7e815688b6c7df3ce68317740b117f29e9470328589fa4a",
            )
            .replace(
                &preflight.inventory_snapshot_sha256.to_string(),
                "56207c2c37c4fc3085597c426c050a3c6202c2e81a2d9dc40ee8f762147389e2",
            );
        assert_eq!(
            normalized_preflight,
            include_str!("../../../golden/lake-command-preflight.json").trim_end()
        );

        let mut executable_drift = executable.clone();
        executable_drift.sha256 = Sha256::parse(&"2".repeat(64))?;
        assert_eq!(
            lake_command_preflight_v1(
                &approval,
                &plan,
                &executable_drift,
                1_800_000_299_000,
                1_800_000_300_000,
            )
            .map_err(|error| error.rejection),
            Err(LakeCommandPreflightRejectionV1::ExecutableMismatch)
        );
        assert_eq!(
            lake_command_preflight_v1(
                &approval,
                &plan,
                &executable,
                1_800_000_290_000,
                1_800_000_300_000,
            )
            .map_err(|error| error.rejection),
            Err(LakeCommandPreflightRejectionV1::ObservationTimeInvalid)
        );

        let mut changed = approval.clone();
        changed.packages.push("plausible".to_owned());
        assert!(
            verify_lake_command_approval_request_v1(&changed, &plan, 1_800_000_300_000).is_err()
        );
        assert!(
            verify_lake_command_approval_request_v1(&approval, &plan, 1_800_000_600_000).is_err()
        );

        let mut changed_inventory = inventory.clone();
        changed_inventory.packages[0].checkout = CheckoutObservationStateV1::Missing;
        let changed_drift = report_dependency_drift(&changed_inventory);
        let changed_plan = plan_lake_update(request(
            &fixture,
            &executable,
            &changed_inventory,
            &changed_drift,
            &packages,
        ))?;
        assert_ne!(
            changed_plan.inventory_snapshot_sha256,
            plan.inventory_snapshot_sha256
        );
        assert!(
            verify_lake_command_approval_request_v1(&approval, &changed_plan, 1_800_000_300_000,)
                .is_err()
        );

        assert!(lake_command_approval_request_v1(&plan, "not-a-nonce", 10, 20).is_err());
        assert!(lake_command_approval_request_v1(&plan, nonce, 10, 10).is_err());
        assert!(lake_command_approval_request_v1(&plan, nonce, 10, 900_011).is_err());
        Ok(())
    }

    #[test]
    fn approval_request_identity_and_json_match_bun_golden()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan_report_sha256 =
            Sha256::parse("553843f557df3bdcd7e815688b6c7df3ce68317740b117f29e9470328589fa4a")?;
        let project_id = "c32fe4e9adb318f7e52427c338c6b6c8079f12fa40b5f29423de8e7a7214e08b";
        let nonce = "123e4567-e89b-42d3-a456-426614174000";
        let request_id = crate::approval_request::approval_request_id_v1(
            plan_report_sha256,
            project_id,
            nonce,
            1_800_000_000_000,
            1_800_000_600_000,
        );
        let request = LakeCommandApprovalRequestV1 {
            schema_version: 1,
            request_type: "lake-command-approval-request".to_owned(),
            request_id,
            approval_state: LakeCommandApprovalStateV1::Pending,
            plan_report_sha256,
            inventory_snapshot_sha256: Sha256::parse(
                "56207c2c37c4fc3085597c426c050a3c6202c2e81a2d9dc40ee8f762147389e2",
            )?,
            project_id: project_id.to_owned(),
            project_path: "/fixture/project".to_owned(),
            packages: vec!["mathlib".to_owned()],
            lake_version: SUPPORTED_LAKE_VERSION.to_owned(),
            network_required: true,
            nonce: nonce.to_owned(),
            issued_at_unix_ms: 1_800_000_000_000,
            expires_at_unix_ms: 1_800_000_600_000,
            execution_authority: PlanExecutionAuthorityV1::Withheld,
        };
        assert_eq!(
            request.to_canonical_json(),
            include_str!("../../../golden/lake-command-approval-request.json").trim_end()
        );
        Ok(())
    }

    #[test]
    fn external_grant_claim_is_strict_but_keeps_authority_withheld()
    -> Result<(), Box<dyn std::error::Error>> {
        let request_id =
            Sha256::parse("4d9d1e12c9daa6d20461d8c0dd2b8bb681dfe725593d9e0c4cc592f25e200d5c")?;
        let plan_report_sha256 =
            Sha256::parse("553843f557df3bdcd7e815688b6c7df3ce68317740b117f29e9470328589fa4a")?;
        let inventory_snapshot_sha256 =
            Sha256::parse("56207c2c37c4fc3085597c426c050a3c6202c2e81a2d9dc40ee8f762147389e2")?;
        let executable_sha256 =
            Sha256::parse("f16d05ec6b29248d2c61adb1e9263f78e4f7bace1b955014a2d17872cfe4064d")?;
        let request = LakeCommandApprovalRequestV1 {
            schema_version: 1,
            request_type: "lake-command-approval-request".to_owned(),
            request_id,
            approval_state: LakeCommandApprovalStateV1::Pending,
            plan_report_sha256,
            inventory_snapshot_sha256,
            project_id: "c32fe4e9adb318f7e52427c338c6b6c8079f12fa40b5f29423de8e7a7214e08b"
                .to_owned(),
            project_path: "/fixture/project".to_owned(),
            packages: vec!["mathlib".to_owned()],
            lake_version: SUPPORTED_LAKE_VERSION.to_owned(),
            network_required: true,
            nonce: "123e4567-e89b-42d3-a456-426614174000".to_owned(),
            issued_at_unix_ms: 1_800_000_000_000,
            expires_at_unix_ms: 1_800_000_600_000,
            execution_authority: PlanExecutionAuthorityV1::Withheld,
        };
        let preflight = LakeCommandPreflightV1 {
            schema_version: 1,
            decision: LakeCommandPreflightDecisionV1::ReadyForExplicitApproval,
            request_id,
            plan_report_sha256,
            inventory_snapshot_sha256,
            executable_sha256,
            observed_at_unix_ms: 1_800_000_299_000,
            execution_authority: PlanExecutionAuthorityV1::Withheld,
        };
        let text = include_str!("../../../golden/lake-command-approval-grant.json").trim_end();
        let grant = parse_lake_command_approval_grant_v1(text)?;
        let verified =
            verify_lake_command_approval_grant_v1(&grant, &preflight, &request, 1_800_000_350_000)?;
        assert_eq!(
            verified.decision,
            LakeCommandGrantClaimDecisionV1::StructurallyValidExternalClaim
        );
        assert_eq!(
            verified.execution_authority,
            PlanExecutionAuthorityV1::Withheld
        );

        assert!(parse_lake_command_approval_grant_v1(&format!("{text} trailing")).is_err());
        assert!(
            parse_lake_command_approval_grant_v1(
                &text.replace("explicit-request-id-confirmation", "implicit-confirmation")
            )
            .is_err()
        );
        assert!(
            verify_lake_command_approval_grant_v1(&grant, &preflight, &request, 1_800_000_400_000,)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn trusted_ingress_challenge_binds_session_but_still_withholds_authority()
    -> Result<(), Box<dyn std::error::Error>> {
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
            project_id: "c32fe4e9adb318f7e52427c338c6b6c8079f12fa40b5f29423de8e7a7214e08b"
                .to_owned(),
            project_path: "/fixture/project".to_owned(),
            packages: vec!["mathlib".to_owned()],
            lake_version: SUPPORTED_LAKE_VERSION.to_owned(),
            network_required: true,
            nonce: "123e4567-e89b-42d3-a456-426614174000".to_owned(),
            issued_at_unix_ms: 1_800_000_000_000,
            expires_at_unix_ms: 1_800_000_600_000,
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
            observed_at_unix_ms: 1_800_000_299_000,
            execution_authority: PlanExecutionAuthorityV1::Withheld,
        };
        let session_nonce_sha256 =
            Sha256::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?;
        let challenge = lake_command_trusted_approval_challenge_v1(
            &request,
            &preflight,
            session_nonce_sha256,
            1_800_000_300_000,
            1_800_000_360_000,
        )?;
        assert_eq!(
            challenge.to_canonical_json(),
            include_str!("../../../golden/lake-command-trusted-approval-challenge.json").trim_end()
        );
        assert_eq!(
            challenge.execution_authority,
            PlanExecutionAuthorityV1::Withheld
        );
        let contract = trusted_approval_ingress_contract_v1();
        assert_eq!(
            contract.decision,
            TrustedApprovalIngressDecisionV1::RequiresDedicatedMacOsAdapter
        );
        assert_eq!(
            contract.to_canonical_json(),
            include_str!("../../../golden/trusted-approval-ingress-contract.json").trim_end()
        );
        assert_eq!(
            contract.execution_authority,
            PlanExecutionAuthorityV1::Withheld
        );

        let zero = Sha256::from_bytes([0; 32]);
        assert!(
            lake_command_trusted_approval_challenge_v1(
                &request,
                &preflight,
                zero,
                1_800_000_300_000,
                1_800_000_360_000,
            )
            .is_err()
        );
        assert!(
            lake_command_trusted_approval_challenge_v1(
                &request,
                &preflight,
                session_nonce_sha256,
                1_800_000_300_000,
                1_800_000_360_001,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn executable_must_be_inside_managed_toolchain() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        fs::write(fixture.project.as_path().join("lake"), b"outside")?;
        let outside = canonicalize_contained(&fixture.project, "lake")?;
        let mut executable = fixture.executable(SUPPORTED_LAKE_VERSION);
        executable.canonical_path = outside;
        let inventory = inventory(&fixture, &["mathlib"], &["mathlib"])?;
        let report = report(&inventory);
        let packages = vec!["mathlib".to_owned()];
        let request = request(&fixture, &executable, &inventory, &report, &packages);
        assert_eq!(
            plan_lake_update(request).map_err(|error| error.code),
            Err(DiagnosticCode::PATH_ESCAPES_ALLOWED_ROOT)
        );
        Ok(())
    }

    #[test]
    fn shared_update_plan_cases_match_bun_oracle() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        for line in include_str!("../../../golden/lake-update-plan-cases.tsv").lines() {
            let fields = line.split('\t').collect::<Vec<_>>();
            assert_eq!(fields.len(), 7, "{line}");
            let package_values = csv(fields[3])
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let inventory_names = csv(fields[4]);
            let git_names = csv(fields[5]);
            let inventory = inventory(&fixture, &inventory_names, &git_names)?;
            let report = report(&inventory);
            let executable = fixture.executable(fields[2]);
            let result = plan_lake_update(request(
                &fixture,
                &executable,
                &inventory,
                &report,
                &package_values,
            ));
            assert_eq!(result.is_ok(), fields[0] == "true", "{}", fields[1]);
            if let Ok(plan) = result {
                assert_eq!(plan.arguments.join(","), fields[6], "{}", fields[1]);
            }
        }
        Ok(())
    }
}
