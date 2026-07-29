use crate::TrustedLakeExecutableObservationV1;
use core::fmt;
use leanbun_evidence::{canonicalize_directory, read_project_input, read_provider_pair};
use leanbun_inventory_legacy::{build_package_inventory, report_dependency_drift};
use leanbun_plan::{
    LakeCommandApprovalRequestV1, LakeCommandPlanV1, LakeUpdatePlanRequestV1, plan_lake_update,
};
use std::path::Path;

pub struct LakeProviderEvidenceLocationV1<'a> {
    pub isolation_root: &'a Path,
    pub registry: &'a Path,
    pub overrides: &'a Path,
    pub package_root: &'a Path,
}

pub struct TrustedFreshLakeUpdatePlanV1 {
    pub(crate) plan: LakeCommandPlanV1,
    pub(crate) executable: TrustedLakeExecutableObservationV1,
}

impl TrustedFreshLakeUpdatePlanV1 {
    #[must_use]
    pub fn plan(&self) -> &LakeCommandPlanV1 {
        &self.plan
    }

    #[must_use]
    pub fn executable(&self) -> &TrustedLakeExecutableObservationV1 {
        &self.executable
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsFreshLakePlanRejectionV1 {
    ProjectEvidenceInvalid,
    ProviderEvidenceInvalid,
    ProjectRequestMismatch,
    InventoryInvalid,
    PlanRejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacOsFreshLakePlanError {
    pub rejection: MacOsFreshLakePlanRejectionV1,
    pub message: String,
}

impl fmt::Display for MacOsFreshLakePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for MacOsFreshLakePlanError {}

pub fn derive_trusted_fresh_lake_update_plan_v1(
    request: &LakeCommandApprovalRequestV1,
    managed_toolchain_root: &Path,
    project_root: &Path,
    provider_location: Option<LakeProviderEvidenceLocationV1<'_>>,
    executable: TrustedLakeExecutableObservationV1,
) -> Result<TrustedFreshLakeUpdatePlanV1, MacOsFreshLakePlanError> {
    let managed_toolchain_root =
        canonicalize_directory(managed_toolchain_root).map_err(|error| {
            fresh_error(
                MacOsFreshLakePlanRejectionV1::ProjectEvidenceInvalid,
                format!("managed toolchain root is invalid: {}", error.message),
            )
        })?;
    let project_root = canonicalize_directory(project_root).map_err(|error| {
        fresh_error(
            MacOsFreshLakePlanRejectionV1::ProjectEvidenceInvalid,
            format!("project root is invalid: {}", error.message),
        )
    })?;
    if project_root.as_path().to_string_lossy() != request.project_path {
        return Err(fresh_error(
            MacOsFreshLakePlanRejectionV1::ProjectRequestMismatch,
            "fresh canonical project root differs from the approval request",
        ));
    }

    let provider = provider_location
        .map(|location| {
            let isolation_root =
                canonicalize_directory(location.isolation_root).map_err(|error| {
                    fresh_error(
                        MacOsFreshLakePlanRejectionV1::ProviderEvidenceInvalid,
                        format!("provider isolation root is invalid: {}", error.message),
                    )
                })?;
            read_provider_pair(
                &isolation_root,
                location.registry,
                location.overrides,
                location.package_root,
            )
            .map_err(|error| {
                fresh_error(
                    MacOsFreshLakePlanRejectionV1::ProviderEvidenceInvalid,
                    format!("provider evidence is invalid: {}", error.message),
                )
            })
        })
        .transpose()?;
    let project = read_project_input(&project_root, provider.as_ref()).map_err(|error| {
        fresh_error(
            MacOsFreshLakePlanRejectionV1::ProjectEvidenceInvalid,
            format!("project input evidence is invalid: {}", error.message),
        )
    })?;
    let inventory = build_package_inventory(&project, provider.as_ref(), &[]).map_err(|error| {
        fresh_error(
            MacOsFreshLakePlanRejectionV1::InventoryInvalid,
            format!(
                "fresh unobserved checkout inventory is invalid: {}",
                error.message
            ),
        )
    })?;
    let drift = report_dependency_drift(&inventory);
    let plan = plan_lake_update(LakeUpdatePlanRequestV1 {
        managed_toolchain_root: &managed_toolchain_root,
        executable_observation: &executable.observation,
        project_root: &project_root,
        inventory: &inventory,
        drift_report: &drift,
        packages: &request.packages,
    })
    .map_err(|error| {
        fresh_error(
            MacOsFreshLakePlanRejectionV1::PlanRejected,
            format!("fresh Lake update plan was rejected: {}", error.message),
        )
    })?;
    Ok(TrustedFreshLakeUpdatePlanV1 { plan, executable })
}

fn fresh_error(
    rejection: MacOsFreshLakePlanRejectionV1,
    message: impl Into<String>,
) -> MacOsFreshLakePlanError {
    MacOsFreshLakePlanError {
        rejection,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        LakeCommandApprovalConsumptionDecisionV1, LakeCommandApprovalConsumptionRecordV1,
        LakeCommandTrustedApprovalProofDecisionV1, MacOsReservationBoundPathEligibilityDecisionV1,
        TrustedLakeExecutionAuthorityV1, TrustedLakeExecutionCandidateDecisionV1,
        TrustedLakeExecutionGrantDecisionV1, TrustedLakeExecutionGrantRejectionV1,
        TrustedLakeLaunchAuthorityV1, TrustedLakeLaunchIntentDecisionV1,
        TrustedLakeLaunchIntentRejectionV1, TrustedLakeLaunchReservationAuthorityV1,
        TrustedLakeLaunchReservationDecisionV1, TrustedLakeLaunchReservationRejectionV1,
        TrustedTerminalBindingV1, assess_reservation_bound_path_eligibility_v1,
        execution_grant::grant_at_v1, grant_trusted_lake_execution_once_v1,
        observe_reviewed_lake_executable_v1, open_trusted_lake_launch_reservation_registry_v1,
        prepare_trusted_lake_launch_intent_v1, reverify_consumed_lake_command_approval_v1,
        seal_trusted_lake_execution_candidate_v1,
    };
    use leanbun_core::{Sha256, Sha256Hasher};
    use leanbun_evidence::{
        canonicalize_contained, canonicalize_contained_directory, read_project_input,
        read_provider_pair,
    };
    use leanbun_inventory_legacy::{build_package_inventory, report_dependency_drift};
    use leanbun_plan::{
        LakeExecutableObservationV1, PlanExecutionAuthorityV1, SUPPORTED_LAKE_VERSION,
        lake_command_approval_request_v1, verify_lake_command_approval_request_v1,
    };
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    const REVISION: &str = "81a5d257c8e410db227a6665ed08f64fea08e997";
    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        toolchain: PathBuf,
        project: PathBuf,
        provider: PathBuf,
        plan: LakeCommandPlanV1,
        request: LakeCommandApprovalRequestV1,
    }

    impl Fixture {
        fn new(
            issued_at_unix_ms: u64,
            expires_at_unix_ms: u64,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = PathBuf::from(format!(
                "/private/tmp/leanbun-fresh-plan-{}-{sequence}",
                std::process::id()
            ));
            let toolchain = root.join("toolchain");
            let project = root.join("project");
            let provider = root.join("provider");
            let package = provider.join("packages/mathlib");
            fs::create_dir_all(toolchain.join("bin"))?;
            fs::create_dir_all(project.join(".lake"))?;
            fs::create_dir_all(&package)?;
            let lake = toolchain.join("bin/lake");
            fs::write(&lake, b"reviewed-lake-binary")?;
            fs::set_permissions(&lake, fs::Permissions::from_mode(0o755))?;
            fs::write(project.join("lean-toolchain"), "leanprover/lean4:v4.32.0\n")?;
            let manifest = format!(
                r#"{{"version":"1.2.0","packagesDir":".lake/packages","packages":[{{"name":"mathlib","type":"git","rev":"{REVISION}"}}],"name":"fixture","lakeDir":".lake","fixedToolchain":false}}"#
            );
            let registry = format!(
                r#"{{"version":"1.2.0","packagesDir":".lake/packages","packages":[{{"name":"mathlib","type":"git","rev":"{REVISION}"}}]}}"#
            );
            let overrides = format!(
                r#"{{"version":"1.2.0","packages":[{{"name":"mathlib","type":"path","dir":"{}"}}]}}"#,
                package.display()
            );
            fs::write(project.join("lake-manifest.json"), manifest)?;
            fs::write(project.join(".lake/package-overrides.json"), &overrides)?;
            fs::write(provider.join("registry.json"), registry)?;
            fs::write(provider.join("overrides.json"), overrides)?;

            let canonical_root = canonicalize_directory(&root)?;
            let canonical_toolchain =
                canonicalize_contained_directory(&canonical_root, "toolchain")?;
            let canonical_project = canonicalize_contained_directory(&canonical_root, "project")?;
            let canonical_provider = canonicalize_contained_directory(&canonical_root, "provider")?;
            let provider_pair = read_provider_pair(
                &canonical_provider,
                "registry.json",
                "overrides.json",
                "packages",
            )?;
            let project_input = read_project_input(&canonical_project, Some(&provider_pair))?;
            let inventory = build_package_inventory(&project_input, Some(&provider_pair), &[])?;
            let drift = report_dependency_drift(&inventory);
            let executable_sha256 = bytes_sha256(b"reviewed-lake-binary");
            let executable = LakeExecutableObservationV1 {
                schema_version: 1,
                canonical_path: canonicalize_contained(&canonical_root, "toolchain/bin/lake")?,
                lake_version: SUPPORTED_LAKE_VERSION.to_owned(),
                sha256: executable_sha256,
                byte_length: 20,
                unix_mode: 0o755,
                regular_file: true,
                symlink_free: true,
            };
            let packages = vec!["mathlib".to_owned()];
            let plan = plan_lake_update(LakeUpdatePlanRequestV1 {
                managed_toolchain_root: &canonical_toolchain,
                executable_observation: &executable,
                project_root: &canonical_project,
                inventory: &inventory,
                drift_report: &drift,
                packages: &packages,
            })?;
            let request = lake_command_approval_request_v1(
                &plan,
                "123e4567-e89b-42d3-a456-426614174000",
                issued_at_unix_ms,
                expires_at_unix_ms,
            )?;
            Ok(Self {
                root,
                toolchain,
                project,
                provider,
                plan,
                request,
            })
        }

        fn provider_location(&self) -> LakeProviderEvidenceLocationV1<'_> {
            LakeProviderEvidenceLocationV1 {
                isolation_root: &self.provider,
                registry: Path::new("registry.json"),
                overrides: Path::new("overrides.json"),
                package_root: Path::new("packages"),
            }
        }

        fn derive(&self) -> Result<TrustedFreshLakeUpdatePlanV1, Box<dyn std::error::Error>> {
            let executable = observe_reviewed_lake_executable_v1(&self.toolchain, &self.plan)?;
            Ok(derive_trusted_fresh_lake_update_plan_v1(
                &self.request,
                &self.toolchain,
                &self.project,
                Some(self.provider_location()),
                executable,
            )?)
        }

        fn candidate(
            &self,
            now: u64,
            expiry: u64,
        ) -> Result<crate::TrustedLakeExecutionCandidateV1, Box<dyn std::error::Error>> {
            let consumption = LakeCommandApprovalConsumptionRecordV1 {
                schema_version: 1,
                decision: LakeCommandApprovalConsumptionDecisionV1::ConsumedOnce,
                challenge_id: Sha256::parse(&"9".repeat(64))?,
                request_id: self.request.request_id,
                preflight_sha256: Sha256::parse(&"3".repeat(64))?,
                response_sha256: Sha256::parse(&"6".repeat(64))?,
                terminal_binding: TrustedTerminalBindingV1 {
                    device: 10,
                    inode: 20,
                    raw_device: 30,
                    owner_uid: rustix::process::geteuid().as_raw(),
                    effective_user_id: rustix::process::geteuid().as_raw(),
                    process_group_id: 40,
                    process_session_id: 50,
                },
                responded_at_unix_ms: now.saturating_sub(500),
                consumed_at_unix_ms: now.saturating_sub(100),
                challenge_expires_at_unix_ms: expiry,
                record_sha256: Sha256::parse(&"4".repeat(64))?,
                execution_authority: PlanExecutionAuthorityV1::Withheld,
            };
            Ok(seal_trusted_lake_execution_candidate_v1(
                consumption,
                &self.request,
                self.derive()?,
            )?)
        }

        fn launch_intent(
            &self,
            now: u64,
            expiry: u64,
        ) -> Result<crate::TrustedLakeLaunchIntentV1, Box<dyn std::error::Error>> {
            for directory in [
                "environment/elan-home",
                "environment/home",
                "environment/path-a",
                "environment/path-b",
            ] {
                fs::create_dir_all(self.root.join(directory))?;
            }
            let path_entries = vec![
                PathBuf::from("environment/path-a"),
                PathBuf::from("environment/path-b"),
            ];
            let grant = grant_trusted_lake_execution_once_v1(self.candidate(now, expiry)?)?;
            Ok(prepare_trusted_lake_launch_intent_v1(
                grant,
                &self.toolchain,
                crate::LakeLaunchEnvironmentLocationV1 {
                    isolation_root: &self.root,
                    elan_home: Path::new("environment/elan-home"),
                    home: Path::new("environment/home"),
                    path_entries: &path_entries,
                },
            )?)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn bytes_sha256(bytes: &[u8]) -> Sha256 {
        let mut hasher = Sha256Hasher::new();
        hasher.update(bytes);
        hasher.finalize()
    }

    fn now_unix_ms() -> Result<u64, Box<dyn std::error::Error>> {
        Ok(u64::try_from(
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
        )?)
    }

    #[test]
    fn provider_bound_evidence_rederives_the_reviewed_unobserved_plan()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(1_800_000_000_000, 1_800_000_600_000)?;
        let fresh = fixture.derive()?;
        assert_eq!(fresh.plan, fixture.plan);
        assert!(
            fresh
                .plan
                .risks
                .contains(&leanbun_plan::PlanRiskV1::CheckoutEvidenceIncomplete)
        );
        verify_lake_command_approval_request_v1(&fixture.request, &fresh.plan, 1_800_000_300_000)?;
        Ok(())
    }

    #[test]
    fn changed_project_evidence_is_rejected_before_a_fresh_plan()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new(1_800_000_000_000, 1_800_000_600_000)?;
        let changed = format!(
            r#"{{"version":"1.2.0","packagesDir":".lake/packages","packages":[{{"name":"mathlib","type":"git","rev":"{}"}}],"name":"fixture","lakeDir":".lake","fixedToolchain":false}}"#,
            "2".repeat(40)
        );
        fs::write(fixture.project.join("lake-manifest.json"), changed)?;
        let executable = observe_reviewed_lake_executable_v1(&fixture.toolchain, &fixture.plan)?;
        let error = match derive_trusted_fresh_lake_update_plan_v1(
            &fixture.request,
            &fixture.toolchain,
            &fixture.project,
            Some(fixture.provider_location()),
            executable,
        ) {
            Ok(_) => return Err("changed project evidence produced a trusted fresh plan".into()),
            Err(error) => error,
        };
        assert_eq!(
            error.rejection,
            MacOsFreshLakePlanRejectionV1::ProjectEvidenceInvalid
        );
        Ok(())
    }

    #[test]
    fn public_pipeline_forms_only_a_withheld_proof() -> Result<(), Box<dyn std::error::Error>> {
        let now = now_unix_ms()?;
        let fixture = Fixture::new(now.saturating_sub(1_000), now.saturating_add(60_000))?;
        let fresh = fixture.derive()?;
        let consumption = LakeCommandApprovalConsumptionRecordV1 {
            schema_version: 1,
            decision: LakeCommandApprovalConsumptionDecisionV1::ConsumedOnce,
            challenge_id: Sha256::parse(&"9".repeat(64))?,
            request_id: fixture.request.request_id,
            preflight_sha256: Sha256::parse(&"3".repeat(64))?,
            response_sha256: Sha256::parse(&"6".repeat(64))?,
            terminal_binding: TrustedTerminalBindingV1 {
                device: 10,
                inode: 20,
                raw_device: 30,
                owner_uid: rustix::process::geteuid().as_raw(),
                effective_user_id: rustix::process::geteuid().as_raw(),
                process_group_id: 40,
                process_session_id: 50,
            },
            responded_at_unix_ms: now.saturating_sub(500),
            consumed_at_unix_ms: now.saturating_sub(100),
            challenge_expires_at_unix_ms: now.saturating_add(30_000),
            record_sha256: Sha256::parse(&"4".repeat(64))?,
            execution_authority: PlanExecutionAuthorityV1::Withheld,
        };
        let proof =
            reverify_consumed_lake_command_approval_v1(consumption, &fixture.request, fresh)?;
        assert_eq!(
            proof.decision(),
            LakeCommandTrustedApprovalProofDecisionV1::FreshFactsReverified
        );
        assert_eq!(
            proof.execution_authority(),
            PlanExecutionAuthorityV1::Withheld
        );
        Ok(())
    }

    #[test]
    fn public_pipeline_seals_exact_plan_and_proof_without_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = now_unix_ms()?;
        let fixture = Fixture::new(now.saturating_sub(1_000), now.saturating_add(60_000))?;
        let fresh = fixture.derive()?;
        let consumption = LakeCommandApprovalConsumptionRecordV1 {
            schema_version: 1,
            decision: LakeCommandApprovalConsumptionDecisionV1::ConsumedOnce,
            challenge_id: Sha256::parse(&"9".repeat(64))?,
            request_id: fixture.request.request_id,
            preflight_sha256: Sha256::parse(&"3".repeat(64))?,
            response_sha256: Sha256::parse(&"6".repeat(64))?,
            terminal_binding: TrustedTerminalBindingV1 {
                device: 10,
                inode: 20,
                raw_device: 30,
                owner_uid: rustix::process::geteuid().as_raw(),
                effective_user_id: rustix::process::geteuid().as_raw(),
                process_group_id: 40,
                process_session_id: 50,
            },
            responded_at_unix_ms: now.saturating_sub(500),
            consumed_at_unix_ms: now.saturating_sub(100),
            challenge_expires_at_unix_ms: now.saturating_add(30_000),
            record_sha256: Sha256::parse(&"4".repeat(64))?,
            execution_authority: PlanExecutionAuthorityV1::Withheld,
        };
        let candidate =
            seal_trusted_lake_execution_candidate_v1(consumption, &fixture.request, fresh)?;
        assert_eq!(
            candidate.decision(),
            TrustedLakeExecutionCandidateDecisionV1::ExactPlanAndProofSealed
        );
        assert_eq!(candidate.plan(), &fixture.plan);
        assert_eq!(
            candidate.proof().decision(),
            LakeCommandTrustedApprovalProofDecisionV1::FreshFactsReverified
        );
        assert_eq!(
            candidate.proof().plan_report_sha256(),
            fixture.request.plan_report_sha256
        );
        assert_eq!(candidate.expires_at_unix_ms(), now.saturating_add(30_000));
        assert_eq!(
            candidate.execution_authority(),
            PlanExecutionAuthorityV1::Withheld
        );
        Ok(())
    }

    #[test]
    fn sealed_candidate_grants_exact_command_once_inside_its_window()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = now_unix_ms()?;
        let fixture = Fixture::new(now.saturating_sub(1_000), now.saturating_add(60_000))?;
        let fresh = fixture.derive()?;
        let consumption = LakeCommandApprovalConsumptionRecordV1 {
            schema_version: 1,
            decision: LakeCommandApprovalConsumptionDecisionV1::ConsumedOnce,
            challenge_id: Sha256::parse(&"9".repeat(64))?,
            request_id: fixture.request.request_id,
            preflight_sha256: Sha256::parse(&"3".repeat(64))?,
            response_sha256: Sha256::parse(&"6".repeat(64))?,
            terminal_binding: TrustedTerminalBindingV1 {
                device: 10,
                inode: 20,
                raw_device: 30,
                owner_uid: rustix::process::geteuid().as_raw(),
                effective_user_id: rustix::process::geteuid().as_raw(),
                process_group_id: 40,
                process_session_id: 50,
            },
            responded_at_unix_ms: now.saturating_sub(500),
            consumed_at_unix_ms: now.saturating_sub(100),
            challenge_expires_at_unix_ms: now.saturating_add(30_000),
            record_sha256: Sha256::parse(&"4".repeat(64))?,
            execution_authority: PlanExecutionAuthorityV1::Withheld,
        };
        let candidate =
            seal_trusted_lake_execution_candidate_v1(consumption, &fixture.request, fresh)?;
        let grant = grant_trusted_lake_execution_once_v1(candidate)?;
        assert_eq!(
            grant.decision(),
            TrustedLakeExecutionGrantDecisionV1::GrantedOnce
        );
        assert_eq!(grant.plan(), &fixture.plan);
        assert_eq!(
            grant.execution_authority(),
            TrustedLakeExecutionAuthorityV1::GrantedOnce
        );
        assert_eq!(grant.expires_at_unix_ms(), now.saturating_add(30_000));
        assert!(grant.granted_at_unix_ms() < grant.expires_at_unix_ms());
        Ok(())
    }

    #[test]
    fn sealed_candidate_rejects_clock_rollback_and_expiry() -> Result<(), Box<dyn std::error::Error>>
    {
        let now = now_unix_ms()?;
        let make_candidate = || -> Result<_, Box<dyn std::error::Error>> {
            let fixture = Fixture::new(now.saturating_sub(1_000), now.saturating_add(60_000))?;
            let fresh = fixture.derive()?;
            let expiry = now.saturating_add(30_000);
            let consumption = LakeCommandApprovalConsumptionRecordV1 {
                schema_version: 1,
                decision: LakeCommandApprovalConsumptionDecisionV1::ConsumedOnce,
                challenge_id: Sha256::parse(&"9".repeat(64))?,
                request_id: fixture.request.request_id,
                preflight_sha256: Sha256::parse(&"3".repeat(64))?,
                response_sha256: Sha256::parse(&"6".repeat(64))?,
                terminal_binding: TrustedTerminalBindingV1 {
                    device: 10,
                    inode: 20,
                    raw_device: 30,
                    owner_uid: rustix::process::geteuid().as_raw(),
                    effective_user_id: rustix::process::geteuid().as_raw(),
                    process_group_id: 40,
                    process_session_id: 50,
                },
                responded_at_unix_ms: now.saturating_sub(500),
                consumed_at_unix_ms: now.saturating_sub(100),
                challenge_expires_at_unix_ms: expiry,
                record_sha256: Sha256::parse(&"4".repeat(64))?,
                execution_authority: PlanExecutionAuthorityV1::Withheld,
            };
            let candidate =
                seal_trusted_lake_execution_candidate_v1(consumption, &fixture.request, fresh)?;
            Ok((candidate, expiry))
        };

        let (rollback_candidate, _) = make_candidate()?;
        let rollback_time = rollback_candidate
            .proof()
            .verified_at_unix_ms()
            .saturating_sub(1);
        assert_eq!(
            grant_at_v1(rollback_candidate, rollback_time).map_err(|error| error.rejection),
            Err(TrustedLakeExecutionGrantRejectionV1::ClockInvalid)
        );

        let (expired_candidate, expiry) = make_candidate()?;
        assert_eq!(
            grant_at_v1(expired_candidate, expiry).map_err(|error| error.rejection),
            Err(TrustedLakeExecutionGrantRejectionV1::CandidateExpired)
        );
        Ok(())
    }

    #[test]
    fn trusted_grant_prepares_exact_launch_intent_without_spawning()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = now_unix_ms()?;
        let fixture = Fixture::new(now.saturating_sub(1_000), now.saturating_add(60_000))?;
        let grant = grant_trusted_lake_execution_once_v1(
            fixture.candidate(now, now.saturating_add(30_000))?,
        )?;
        for directory in [
            "environment/elan-home",
            "environment/home",
            "environment/path-a",
            "environment/path-b",
        ] {
            fs::create_dir_all(fixture.root.join(directory))?;
        }
        let path_entries = vec![
            PathBuf::from("environment/path-a"),
            PathBuf::from("environment/path-b"),
        ];
        let intent = prepare_trusted_lake_launch_intent_v1(
            grant,
            &fixture.toolchain,
            crate::LakeLaunchEnvironmentLocationV1 {
                isolation_root: &fixture.root,
                elan_home: Path::new("environment/elan-home"),
                home: Path::new("environment/home"),
                path_entries: &path_entries,
            },
        )?;
        assert_eq!(
            intent.decision(),
            TrustedLakeLaunchIntentDecisionV1::PreparedOnce
        );
        assert_eq!(intent.executable(), fixture.plan.executable.as_path());
        assert_eq!(intent.arguments(), fixture.plan.arguments);
        assert_eq!(intent.cwd(), fixture.plan.cwd.as_path());
        assert_eq!(
            intent
                .environment()
                .iter()
                .map(|entry| entry.key())
                .collect::<Vec<_>>(),
            [
                "ELAN_HOME",
                "GIT_CONFIG_NOSYSTEM",
                "GIT_TERMINAL_PROMPT",
                "HOME",
                "PATH"
            ]
        );
        assert_eq!(intent.environment()[1].value(), "1");
        assert_eq!(intent.environment()[2].value(), "0");
        assert_eq!(
            intent.execution_authority(),
            TrustedLakeLaunchAuthorityV1::PreparedOnce
        );
        assert!(intent.executable_observed_at_unix_ms() <= intent.prepared_at_unix_ms());
        assert!(intent.prepared_at_unix_ms() < intent.expires_at_unix_ms());
        Ok(())
    }

    #[test]
    fn launch_intent_rejects_executable_drift_and_environment_escape()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = now_unix_ms()?;
        let drift_fixture = Fixture::new(now.saturating_sub(1_000), now.saturating_add(60_000))?;
        let drift_grant = grant_trusted_lake_execution_once_v1(
            drift_fixture.candidate(now, now.saturating_add(30_000))?,
        )?;
        fs::write(
            drift_fixture.toolchain.join("bin/lake"),
            b"changed-lake-binary!",
        )?;
        fs::create_dir_all(drift_fixture.root.join("environment/all"))?;
        let path_entries = vec![PathBuf::from("environment/all")];
        let drift_error = match prepare_trusted_lake_launch_intent_v1(
            drift_grant,
            &drift_fixture.toolchain,
            crate::LakeLaunchEnvironmentLocationV1 {
                isolation_root: &drift_fixture.root,
                elan_home: Path::new("environment/all"),
                home: Path::new("environment/all"),
                path_entries: &path_entries,
            },
        ) {
            Ok(_) => return Err("executable drift produced a trusted launch intent".into()),
            Err(error) => error.rejection,
        };
        assert_eq!(
            drift_error,
            TrustedLakeLaunchIntentRejectionV1::ExecutableInvalid
        );

        let escape_fixture = Fixture::new(now.saturating_sub(1_000), now.saturating_add(60_000))?;
        let escape_grant = grant_trusted_lake_execution_once_v1(
            escape_fixture.candidate(now, now.saturating_add(30_000))?,
        )?;
        fs::create_dir_all(escape_fixture.root.join("environment/all"))?;
        let escape_entries = vec![PathBuf::from("../outside")];
        let escape_error = match prepare_trusted_lake_launch_intent_v1(
            escape_grant,
            &escape_fixture.toolchain,
            crate::LakeLaunchEnvironmentLocationV1 {
                isolation_root: &escape_fixture.root,
                elan_home: Path::new("environment/all"),
                home: Path::new("environment/all"),
                path_entries: &escape_entries,
            },
        ) {
            Ok(_) => return Err("environment escape produced a trusted launch intent".into()),
            Err(error) => error.rejection,
        };
        assert_eq!(
            escape_error,
            TrustedLakeLaunchIntentRejectionV1::EnvironmentInvalid
        );
        Ok(())
    }

    #[test]
    fn launch_intent_is_durably_reserved_once_without_spawning()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = now_unix_ms()?;
        let fixture = Fixture::new(now.saturating_sub(1_000), now.saturating_add(60_000))?;
        let intent = fixture.launch_intent(now, now.saturating_add(30_000))?;
        let intent_sha256 = intent.intent_sha256();
        let registry_root = fixture.root.join("launch-registry");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&registry_root)?;
        let registry = open_trusted_lake_launch_reservation_registry_v1(&registry_root)?;
        let reservation = registry.reserve_launch_intent_v1(intent)?;
        assert_eq!(
            reservation.decision(),
            TrustedLakeLaunchReservationDecisionV1::ReservedOnce
        );
        assert_eq!(reservation.intent_sha256(), intent_sha256);
        assert_eq!(reservation.executable(), fixture.plan.executable.as_path());
        assert_eq!(reservation.arguments(), fixture.plan.arguments);
        assert_eq!(
            reservation.execution_authority(),
            TrustedLakeLaunchReservationAuthorityV1::ReservedOnce
        );
        let slot = registry_root.join(format!("{intent_sha256}.launch-reserved-v1"));
        let bytes = fs::read(&slot)?;
        assert!(!bytes.is_empty());
        assert_eq!(reservation.reservation_sha256(), bytes_sha256(&bytes));
        assert_eq!(fs::metadata(slot)?.permissions().mode() & 0o077, 0);
        Ok(())
    }

    #[test]
    fn reservation_bound_path_assessment_is_fresh_withheld_and_non_consuming()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = now_unix_ms()?;
        let fixture = Fixture::new(now.saturating_sub(1_000), now.saturating_add(60_000))?;
        let intent = fixture.launch_intent(now, now.saturating_add(30_000))?;
        let intent_sha256 = intent.intent_sha256();
        let registry_root = fixture.root.join("launch-registry");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&registry_root)?;
        let registry = open_trusted_lake_launch_reservation_registry_v1(&registry_root)?;
        let reservation = registry.reserve_launch_intent_v1(intent)?;
        let slot = registry_root.join(format!("{intent_sha256}.launch-reserved-v1"));
        let slot_before = fs::read(&slot)?;

        let assessment = assess_reservation_bound_path_eligibility_v1(&reservation)?;
        assert_eq!(
            assessment.decision,
            MacOsReservationBoundPathEligibilityDecisionV1::DeniedUserOwnedComponent
        );
        assert_eq!(
            assessment.reservation_sha256,
            reservation.reservation_sha256()
        );
        assert_eq!(assessment.intent_sha256, intent_sha256);
        assert_eq!(
            assessment.executable_sha256,
            reservation.executable_sha256()
        );
        assert_eq!(assessment.executable, reservation.executable());
        assert!(assessment.path_provenance.is_some());
        assert_eq!(
            assessment.execution_authority,
            PlanExecutionAuthorityV1::Withheld
        );
        assert_eq!(fs::read(&slot)?, slot_before);
        assert_eq!(fs::read_dir(&registry_root)?.count(), 1);
        Ok(())
    }

    #[test]
    fn reservation_bound_path_assessment_detects_fresh_executable_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = now_unix_ms()?;
        let fixture = Fixture::new(now.saturating_sub(1_000), now.saturating_add(60_000))?;
        let intent = fixture.launch_intent(now, now.saturating_add(30_000))?;
        let registry_root = fixture.root.join("launch-registry");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&registry_root)?;
        let registry = open_trusted_lake_launch_reservation_registry_v1(&registry_root)?;
        let reservation = registry.reserve_launch_intent_v1(intent)?;
        fs::write(fixture.toolchain.join("bin/lake"), b"changed-lake-binary!!")?;

        let assessment = assess_reservation_bound_path_eligibility_v1(&reservation)?;
        assert_eq!(
            assessment.decision,
            MacOsReservationBoundPathEligibilityDecisionV1::DeniedExecutableIdentityDrift
        );
        assert!(assessment.path_provenance.is_none());
        assert_eq!(
            assessment.execution_authority,
            PlanExecutionAuthorityV1::Withheld
        );
        assert_eq!(fs::read_dir(&registry_root)?.count(), 1);
        Ok(())
    }

    #[test]
    fn reservation_bound_path_assessment_rejects_expiry_before_observation()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = now_unix_ms()?;
        let expiry = now.saturating_add(30_000);
        let fixture = Fixture::new(now.saturating_sub(1_000), now.saturating_add(60_000))?;
        let intent = fixture.launch_intent(now, expiry)?;
        let registry_root = fixture.root.join("launch-registry");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&registry_root)?;
        let registry = open_trusted_lake_launch_reservation_registry_v1(&registry_root)?;
        let reservation = registry.reserve_launch_intent_v1(intent)?;

        let assessment =
            crate::path_eligibility::assess_with_clock_v1(&reservation, || Ok(expiry))?;
        assert_eq!(
            assessment.decision,
            MacOsReservationBoundPathEligibilityDecisionV1::DeniedReservationExpired
        );
        assert!(assessment.path_provenance.is_none());
        assert_eq!(fs::read_dir(&registry_root)?.count(), 1);
        Ok(())
    }

    #[test]
    fn crash_slot_and_expiry_after_sync_remain_reserved() -> Result<(), Box<dyn std::error::Error>>
    {
        let now = now_unix_ms()?;
        let crash_fixture = Fixture::new(now.saturating_sub(1_000), now.saturating_add(60_000))?;
        let crash_intent = crash_fixture.launch_intent(now, now.saturating_add(30_000))?;
        let crash_root = crash_fixture.root.join("launch-registry");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&crash_root)?;
        let crash_slot = crash_root.join(format!(
            "{}.launch-reserved-v1",
            crash_intent.intent_sha256()
        ));
        fs::File::create(&crash_slot)?.sync_all()?;
        let crash_registry = open_trusted_lake_launch_reservation_registry_v1(&crash_root)?;
        let crash_error = match crash_registry.reserve_launch_intent_v1(crash_intent) {
            Ok(_) => return Err("crash-shaped launch slot was reused".into()),
            Err(error) => error.rejection,
        };
        assert_eq!(
            crash_error,
            TrustedLakeLaunchReservationRejectionV1::AlreadyReserved
        );

        let expiry_fixture = Fixture::new(now.saturating_sub(1_000), now.saturating_add(60_000))?;
        let expiry = now.saturating_add(30_000);
        let expiry_intent = expiry_fixture.launch_intent(now, expiry)?;
        let reserved_at = expiry_intent.prepared_at_unix_ms();
        let expiry_root = expiry_fixture.root.join("launch-registry");
        let mut expiry_builder = fs::DirBuilder::new();
        expiry_builder.mode(0o700).create(&expiry_root)?;
        let expiry_registry = open_trusted_lake_launch_reservation_registry_v1(&expiry_root)?;
        let expiry_error = match expiry_registry.reserve_launch_intent_with_clock_v1(
            expiry_intent,
            reserved_at,
            || Ok(expiry),
        ) {
            Ok(_) => return Err("expired durable reservation produced a capability".into()),
            Err(error) => error.rejection,
        };
        assert_eq!(
            expiry_error,
            TrustedLakeLaunchReservationRejectionV1::LaunchIntentExpired
        );
        assert_eq!(fs::read_dir(expiry_root)?.count(), 1);
        Ok(())
    }
}
