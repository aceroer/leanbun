use super::{
    LakeCommandFamilyV1, LakeCommandPlanV1, PlanExecutionAuthorityV1, PlanRiskV1, PlannedEffectV1,
    SUPPORTED_LAKE_VERSION,
};
use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

const SOURCES_V1: &str = include_str!("../../../../config/lake-update-contract-sources-v1.tsv");
const FACTS_V1: &str = include_str!("../../../../config/lake-update-contract-v1.tsv");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeUpdateContractSourceV1 {
    pub id: String,
    pub kind: String,
    pub version_relative_path: String,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LakeUpdateRequirementV1 {
    ExplicitPackages,
    CanonicalUpdateCommand,
    KeepToolchain,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LakeUpdateMitigationV1 {
    RequireExplicitPackages,
    RejectBareUpdate,
    UseCanonicalUpdateCommand,
    IncludeKeepToolchain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeUpdateContractFactV1 {
    pub id: String,
    pub source_id: String,
    pub line_start: u32,
    pub line_end: u32,
    pub requirement: Option<LakeUpdateRequirementV1>,
    pub effect: Option<PlannedEffectV1>,
    pub risk: Option<PlanRiskV1>,
    pub mitigation: Option<LakeUpdateMitigationV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeUpdateContractV1 {
    pub schema_version: u8,
    pub lake_version: &'static str,
    pub sources: Vec<LakeUpdateContractSourceV1>,
    pub facts: Vec<LakeUpdateContractFactV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeUpdateContractError {
    pub message: String,
}

impl LakeUpdateContractError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for LakeUpdateContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for LakeUpdateContractError {}

pub fn lake_update_contract_v1() -> Result<LakeUpdateContractV1, LakeUpdateContractError> {
    let mut source_ids = BTreeSet::new();
    let mut sources = Vec::new();
    for (index, line) in SOURCES_V1.lines().enumerate() {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 4 {
            return Err(LakeUpdateContractError::new(format!(
                "source fixture line {} must contain four fields",
                index + 1
            )));
        }
        if !valid_token(fields[0]) || !source_ids.insert(fields[0]) {
            return Err(LakeUpdateContractError::new(format!(
                "invalid or duplicate source id at line {}",
                index + 1
            )));
        }
        if !matches!(fields[1], "lean-source" | "html-reference")
            || fields[2].is_empty()
            || fields[2].starts_with('/')
            || fields[2]
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
            || !valid_sha256(fields[3])
        {
            return Err(LakeUpdateContractError::new(format!(
                "invalid source metadata at line {}",
                index + 1
            )));
        }
        sources.push(LakeUpdateContractSourceV1 {
            id: fields[0].to_owned(),
            kind: fields[1].to_owned(),
            version_relative_path: fields[2].to_owned(),
            sha256: fields[3].to_owned(),
        });
    }

    let mut fact_ids = BTreeSet::new();
    let mut facts = Vec::new();
    for (index, line) in FACTS_V1.lines().enumerate() {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 8 {
            return Err(LakeUpdateContractError::new(format!(
                "contract fixture line {} must contain eight fields",
                index + 1
            )));
        }
        if !valid_token(fields[0]) || !fact_ids.insert(fields[0]) {
            return Err(LakeUpdateContractError::new(format!(
                "invalid or duplicate fact id at line {}",
                index + 1
            )));
        }
        if !source_ids.contains(fields[1]) {
            return Err(LakeUpdateContractError::new(format!(
                "unknown source id at contract line {}",
                index + 1
            )));
        }
        let line_start = parse_line_number(fields[2], index)?;
        let line_end = parse_line_number(fields[3], index)?;
        if line_start > line_end {
            return Err(LakeUpdateContractError::new(format!(
                "reversed source range at contract line {}",
                index + 1
            )));
        }
        facts.push(LakeUpdateContractFactV1 {
            id: fields[0].to_owned(),
            source_id: fields[1].to_owned(),
            line_start,
            line_end,
            requirement: parse_requirement(fields[4], index)?,
            effect: parse_effect(fields[5], index)?,
            risk: parse_risk(fields[6], index)?,
            mitigation: parse_mitigation(fields[7], index)?,
        });
    }
    if sources.is_empty() || facts.is_empty() {
        return Err(LakeUpdateContractError::new(
            "Lake update contract fixtures must not be empty",
        ));
    }
    Ok(LakeUpdateContractV1 {
        schema_version: 1,
        lake_version: SUPPORTED_LAKE_VERSION,
        sources,
        facts,
    })
}

pub fn verify_lake_update_plan_contract_v1(
    plan: &LakeCommandPlanV1,
) -> Result<(), LakeUpdateContractError> {
    let contract = lake_update_contract_v1()?;
    if plan.schema_version != 1
        || plan.family != LakeCommandFamilyV1::Update
        || plan.lake_version != contract.lake_version
    {
        return Err(LakeUpdateContractError::new(
            "plan identity does not match Lake update contract v1",
        ));
    }
    if plan.execution_authority != PlanExecutionAuthorityV1::Withheld {
        return Err(LakeUpdateContractError::new(
            "Lake update execution authority must remain withheld",
        ));
    }
    if !plan.executable_regular_file
        || !plan.executable_symlink_free
        || plan.executable_byte_length == 0
        || plan.executable_unix_mode & 0o111 == 0
    {
        return Err(LakeUpdateContractError::new(
            "plan executable identity is not safe",
        ));
    }

    let effects = plan
        .expected_effects
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let required_effects = contract
        .facts
        .iter()
        .filter_map(|fact| fact.effect)
        .collect::<BTreeSet<_>>();
    if effects.len() != plan.expected_effects.len() || effects != required_effects {
        return Err(LakeUpdateContractError::new(
            "plan effects do not exactly cover the fixed Lake contract",
        ));
    }
    let risks = plan.risks.iter().copied().collect::<BTreeSet<_>>();
    let required_risks = contract
        .facts
        .iter()
        .filter_map(|fact| fact.risk)
        .collect::<BTreeSet<_>>();
    if risks.len() != plan.risks.len() || !required_risks.is_subset(&risks) {
        return Err(LakeUpdateContractError::new(
            "plan risks omit a fixed Lake contract risk",
        ));
    }

    let update_position = plan
        .arguments
        .iter()
        .position(|argument| argument == "update");
    let packages = update_position
        .and_then(|position| plan.arguments.get(position + 1..))
        .unwrap_or_default();
    let requirements = contract
        .facts
        .iter()
        .filter_map(|fact| fact.requirement)
        .collect::<BTreeSet<_>>();
    for requirement in requirements {
        let satisfied = match requirement {
            LakeUpdateRequirementV1::ExplicitPackages => !packages.is_empty(),
            LakeUpdateRequirementV1::CanonicalUpdateCommand => {
                update_position == Some(1)
                    && !plan.arguments.iter().any(|argument| argument == "upgrade")
            }
            LakeUpdateRequirementV1::KeepToolchain => {
                plan.arguments.first().map(String::as_str) == Some("--keep-toolchain")
            }
        };
        if !satisfied {
            return Err(LakeUpdateContractError::new(format!(
                "plan does not satisfy requirement {requirement:?}"
            )));
        }
    }
    let mitigations = contract
        .facts
        .iter()
        .filter_map(|fact| fact.mitigation)
        .collect::<BTreeSet<_>>();
    for mitigation in mitigations {
        let satisfied = match mitigation {
            LakeUpdateMitigationV1::RequireExplicitPackages
            | LakeUpdateMitigationV1::RejectBareUpdate => !packages.is_empty(),
            LakeUpdateMitigationV1::UseCanonicalUpdateCommand => {
                update_position.is_some()
                    && !plan.arguments.iter().any(|argument| argument == "upgrade")
            }
            LakeUpdateMitigationV1::IncludeKeepToolchain => {
                plan.arguments.first().map(String::as_str) == Some("--keep-toolchain")
                    && update_position == Some(1)
            }
        };
        if !satisfied {
            return Err(LakeUpdateContractError::new(format!(
                "plan does not satisfy mitigation {mitigation:?}"
            )));
        }
    }
    Ok(())
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_line_number(value: &str, index: usize) -> Result<u32, LakeUpdateContractError> {
    value
        .parse::<u32>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            LakeUpdateContractError::new(format!(
                "invalid source line at contract line {}",
                index + 1
            ))
        })
}

fn parse_requirement(
    value: &str,
    index: usize,
) -> Result<Option<LakeUpdateRequirementV1>, LakeUpdateContractError> {
    match value {
        "none" => Ok(None),
        "explicit-packages" => Ok(Some(LakeUpdateRequirementV1::ExplicitPackages)),
        "canonical-update-command" => Ok(Some(LakeUpdateRequirementV1::CanonicalUpdateCommand)),
        "keep-toolchain" => Ok(Some(LakeUpdateRequirementV1::KeepToolchain)),
        _ => Err(invalid_enum("requirement", index)),
    }
}

fn parse_effect(
    value: &str,
    index: usize,
) -> Result<Option<PlannedEffectV1>, LakeUpdateContractError> {
    let values = BTreeMap::from([
        (
            "LoadAndExecuteProjectConfiguration",
            PlannedEffectV1::LoadAndExecuteProjectConfiguration,
        ),
        (
            "ReadPackageOverrides",
            PlannedEffectV1::ReadPackageOverrides,
        ),
        ("RewriteManifest", PlannedEffectV1::RewriteManifest),
        (
            "CreateOrModifyLakeDirectory",
            PlannedEffectV1::CreateOrModifyLakeDirectory,
        ),
        (
            "FetchRemotePackageContent",
            PlannedEffectV1::FetchRemotePackageContent,
        ),
        (
            "CreateOrModifyPackageCheckouts",
            PlannedEffectV1::CreateOrModifyPackageCheckouts,
        ),
        (
            "ExecutePostUpdateHooks",
            PlannedEffectV1::ExecutePostUpdateHooks,
        ),
    ]);
    if value == "none" {
        Ok(None)
    } else {
        values
            .get(value)
            .copied()
            .map(Some)
            .ok_or_else(|| invalid_enum("effect", index))
    }
}

fn parse_risk(value: &str, index: usize) -> Result<Option<PlanRiskV1>, LakeUpdateContractError> {
    let values = BTreeMap::from([
        (
            "UntrustedProjectConfigurationExecution",
            PlanRiskV1::UntrustedProjectConfigurationExecution,
        ),
        (
            "NetworkAndRemoteContent",
            PlanRiskV1::NetworkAndRemoteContent,
        ),
        ("ManifestRewrite", PlanRiskV1::ManifestRewrite),
        ("CheckoutMutation", PlanRiskV1::CheckoutMutation),
        (
            "LakeInternalStateMutation",
            PlanRiskV1::LakeInternalStateMutation,
        ),
        (
            "PostUpdateHookExecution",
            PlanRiskV1::PostUpdateHookExecution,
        ),
    ]);
    if value == "none" {
        Ok(None)
    } else {
        values
            .get(value)
            .copied()
            .map(Some)
            .ok_or_else(|| invalid_enum("risk", index))
    }
}

fn parse_mitigation(
    value: &str,
    index: usize,
) -> Result<Option<LakeUpdateMitigationV1>, LakeUpdateContractError> {
    match value {
        "none" => Ok(None),
        "require-explicit-packages" => Ok(Some(LakeUpdateMitigationV1::RequireExplicitPackages)),
        "reject-bare-update" => Ok(Some(LakeUpdateMitigationV1::RejectBareUpdate)),
        "use-canonical-update-command" => {
            Ok(Some(LakeUpdateMitigationV1::UseCanonicalUpdateCommand))
        }
        "include-keep-toolchain" => Ok(Some(LakeUpdateMitigationV1::IncludeKeepToolchain)),
        _ => Err(invalid_enum("mitigation", index)),
    }
}

fn invalid_enum(kind: &str, index: usize) -> LakeUpdateContractError {
    LakeUpdateContractError::new(format!("invalid {kind} at contract line {}", index + 1))
}
