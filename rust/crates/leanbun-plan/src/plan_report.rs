use super::{
    CommandNetworkPolicyV1, CommandPermissionClassV1, LakeCommandFamilyV1, LakeCommandPlanV1,
    LakeUpdateContractError, LakeUpdateMitigationV1, PlanExecutionAuthorityV1, PlanRiskV1,
    PlannedEffectV1, lake_update_contract_v1, verify_lake_update_plan_contract_v1,
};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeCommandPlanReportSourceV1 {
    pub id: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeCommandPlanReportV1 {
    pub schema_version: u8,
    pub report_type: String,
    pub contract_schema_version: u8,
    pub contract_sources: Vec<LakeCommandPlanReportSourceV1>,
    pub family: String,
    pub lake_version: String,
    pub inventory_snapshot_sha256: String,
    pub executable: String,
    pub executable_sha256: String,
    pub executable_byte_length: u64,
    pub executable_unix_mode: u32,
    pub executable_regular_file: bool,
    pub executable_symlink_free: bool,
    pub arguments: Vec<String>,
    pub cwd: String,
    pub environment_keys: Vec<String>,
    pub permission_class: String,
    pub network_policy: String,
    pub expected_effects: Vec<String>,
    pub risks: Vec<String>,
    pub mitigations: Vec<String>,
    pub execution_authority: String,
}

pub fn lake_command_plan_report_v1(
    plan: &LakeCommandPlanV1,
) -> Result<LakeCommandPlanReportV1, LakeUpdateContractError> {
    verify_lake_update_plan_contract_v1(plan)?;
    let executable = plan
        .executable
        .as_path()
        .to_str()
        .ok_or_else(|| report_error("Lake executable path is not valid UTF-8"))?;
    let cwd = plan
        .cwd
        .as_path()
        .to_str()
        .ok_or_else(|| report_error("Lake working directory is not valid UTF-8"))?;
    let contract = lake_update_contract_v1()?;
    let mut environment_keys = plan.environment_allowlist.clone();
    environment_keys.sort();
    let mut expected_effects = plan
        .expected_effects
        .iter()
        .map(|effect| effect_name(*effect).to_owned())
        .collect::<Vec<_>>();
    expected_effects.sort();
    let mut risks = plan
        .risks
        .iter()
        .map(|risk| risk_name(*risk).to_owned())
        .collect::<Vec<_>>();
    risks.sort();
    let mitigations = contract
        .facts
        .iter()
        .filter_map(|fact| fact.mitigation)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|mitigation| mitigation_name(mitigation).to_owned())
        .collect();

    Ok(LakeCommandPlanReportV1 {
        schema_version: 1,
        report_type: "lake-command-plan".to_owned(),
        contract_schema_version: contract.schema_version,
        contract_sources: contract
            .sources
            .into_iter()
            .map(|source| LakeCommandPlanReportSourceV1 {
                id: source.id,
                sha256: source.sha256,
            })
            .collect(),
        family: family_name(plan.family).to_owned(),
        lake_version: plan.lake_version.clone(),
        inventory_snapshot_sha256: plan.inventory_snapshot_sha256.to_string(),
        executable: executable.to_owned(),
        executable_sha256: plan.executable_sha256.to_string(),
        executable_byte_length: plan.executable_byte_length,
        executable_unix_mode: plan.executable_unix_mode,
        executable_regular_file: plan.executable_regular_file,
        executable_symlink_free: plan.executable_symlink_free,
        arguments: plan.arguments.clone(),
        cwd: cwd.to_owned(),
        environment_keys,
        permission_class: permission_class_name(plan.permission_class).to_owned(),
        network_policy: network_policy_name(plan.network_policy).to_owned(),
        expected_effects,
        risks,
        mitigations,
        execution_authority: execution_authority_name(plan.execution_authority).to_owned(),
    })
}

impl LakeCommandPlanReportV1 {
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut output = String::from("{\"schemaVersion\":");
        output.push_str(&self.schema_version.to_string());
        output.push_str(",\"reportType\":");
        push_json_string(&mut output, &self.report_type);
        output.push_str(",\"contract\":{\"schemaVersion\":");
        output.push_str(&self.contract_schema_version.to_string());
        output.push_str(",\"sources\":[");
        for (index, source) in self.contract_sources.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            output.push_str("{\"id\":");
            push_json_string(&mut output, &source.id);
            output.push_str(",\"sha256\":");
            push_json_string(&mut output, &source.sha256);
            output.push('}');
        }
        output.push_str("]},\"family\":");
        push_json_string(&mut output, &self.family);
        output.push_str(",\"lakeVersion\":");
        push_json_string(&mut output, &self.lake_version);
        output.push_str(",\"inventorySnapshotSha256\":");
        push_json_string(&mut output, &self.inventory_snapshot_sha256);
        output.push_str(",\"executable\":");
        push_json_string(&mut output, &self.executable);
        output.push_str(",\"executableSha256\":");
        push_json_string(&mut output, &self.executable_sha256);
        output.push_str(",\"executableByteLength\":");
        output.push_str(&self.executable_byte_length.to_string());
        output.push_str(",\"executableUnixMode\":");
        output.push_str(&self.executable_unix_mode.to_string());
        output.push_str(",\"executableRegularFile\":");
        output.push_str(if self.executable_regular_file {
            "true"
        } else {
            "false"
        });
        output.push_str(",\"executableSymlinkFree\":");
        output.push_str(if self.executable_symlink_free {
            "true"
        } else {
            "false"
        });
        output.push_str(",\"arguments\":");
        push_json_array(&mut output, &self.arguments);
        output.push_str(",\"cwd\":");
        push_json_string(&mut output, &self.cwd);
        output.push_str(",\"environmentKeys\":");
        push_json_array(&mut output, &self.environment_keys);
        output.push_str(",\"permissionClass\":");
        push_json_string(&mut output, &self.permission_class);
        output.push_str(",\"networkPolicy\":");
        push_json_string(&mut output, &self.network_policy);
        output.push_str(",\"expectedEffects\":");
        push_json_array(&mut output, &self.expected_effects);
        output.push_str(",\"risks\":");
        push_json_array(&mut output, &self.risks);
        output.push_str(",\"mitigations\":");
        push_json_array(&mut output, &self.mitigations);
        output.push_str(",\"executionAuthority\":");
        push_json_string(&mut output, &self.execution_authority);
        output.push('}');
        output
    }
}

fn family_name(value: LakeCommandFamilyV1) -> &'static str {
    match value {
        LakeCommandFamilyV1::Update => "update",
    }
}

fn permission_class_name(value: CommandPermissionClassV1) -> &'static str {
    match value {
        CommandPermissionClassV1::ExplicitExternalUpdate => "explicit-external-update",
    }
}

fn network_policy_name(value: CommandNetworkPolicyV1) -> &'static str {
    match value {
        CommandNetworkPolicyV1::Required => "required",
    }
}

fn execution_authority_name(value: PlanExecutionAuthorityV1) -> &'static str {
    match value {
        PlanExecutionAuthorityV1::Withheld => "withheld",
    }
}

fn mitigation_name(value: LakeUpdateMitigationV1) -> &'static str {
    match value {
        LakeUpdateMitigationV1::RequireExplicitPackages => "require-explicit-packages",
        LakeUpdateMitigationV1::RejectBareUpdate => "reject-bare-update",
        LakeUpdateMitigationV1::UseCanonicalUpdateCommand => "use-canonical-update-command",
        LakeUpdateMitigationV1::IncludeKeepToolchain => "include-keep-toolchain",
    }
}

fn effect_name(value: PlannedEffectV1) -> &'static str {
    match value {
        PlannedEffectV1::LoadAndExecuteProjectConfiguration => {
            "load-and-execute-project-configuration"
        }
        PlannedEffectV1::ReadPackageOverrides => "read-package-overrides",
        PlannedEffectV1::RewriteManifest => "rewrite-manifest",
        PlannedEffectV1::CreateOrModifyLakeDirectory => "create-or-modify-lake-directory",
        PlannedEffectV1::FetchRemotePackageContent => "fetch-remote-package-content",
        PlannedEffectV1::CreateOrModifyPackageCheckouts => "create-or-modify-package-checkouts",
        PlannedEffectV1::ExecutePostUpdateHooks => "execute-post-update-hooks",
    }
}

fn risk_name(value: PlanRiskV1) -> &'static str {
    match value {
        PlanRiskV1::UntrustedProjectConfigurationExecution => {
            "untrusted-project-configuration-execution"
        }
        PlanRiskV1::NetworkAndRemoteContent => "network-and-remote-content",
        PlanRiskV1::ManifestRewrite => "manifest-rewrite",
        PlanRiskV1::CheckoutMutation => "checkout-mutation",
        PlanRiskV1::LakeInternalStateMutation => "lake-internal-state-mutation",
        PlanRiskV1::PostUpdateHookExecution => "post-update-hook-execution",
        PlanRiskV1::CheckoutEvidenceIncomplete => "checkout-evidence-incomplete",
        PlanRiskV1::ObservedDependencyDrift => "observed-dependency-drift",
        PlanRiskV1::ExecutablePropertiesRequireGateRecheck => {
            "executable-properties-require-gate-recheck"
        }
    }
}

fn report_error(message: &str) -> LakeUpdateContractError {
    LakeUpdateContractError {
        message: message.to_owned(),
    }
}

pub(super) fn push_json_array(output: &mut String, values: &[String]) {
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(output, value);
    }
    output.push(']');
}

pub(super) fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{0000}'..='\u{001f}' => {
                use core::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", u32::from(character));
            }
            _ => output.push(character),
        }
    }
    output.push('"');
}
