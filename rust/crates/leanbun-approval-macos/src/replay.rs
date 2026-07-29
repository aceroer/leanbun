use crate::{
    LakeCommandApprovalResponseClaimV1, LakeCommandApprovalResponseDecisionV1,
    TrustedTerminalBindingV1,
};
use core::fmt;
use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_plan::PlanExecutionAuthorityV1;
use rustix::fs::{FileType, Mode, OFlags};
use std::fs::File;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LakeCommandApprovalConsumptionDecisionV1 {
    ConsumedOnce,
}

#[derive(Debug, Eq, PartialEq)]
pub struct LakeCommandApprovalConsumptionRecordV1 {
    pub(crate) schema_version: u8,
    pub(crate) decision: LakeCommandApprovalConsumptionDecisionV1,
    pub(crate) challenge_id: Sha256,
    pub(crate) request_id: Sha256,
    pub(crate) preflight_sha256: Sha256,
    pub(crate) response_sha256: Sha256,
    pub(crate) terminal_binding: TrustedTerminalBindingV1,
    pub(crate) responded_at_unix_ms: u64,
    pub(crate) consumed_at_unix_ms: u64,
    pub(crate) challenge_expires_at_unix_ms: u64,
    pub(crate) record_sha256: Sha256,
    pub(crate) execution_authority: PlanExecutionAuthorityV1,
}

impl LakeCommandApprovalConsumptionRecordV1 {
    #[must_use]
    pub fn decision(&self) -> LakeCommandApprovalConsumptionDecisionV1 {
        self.decision
    }

    #[must_use]
    pub fn challenge_id(&self) -> Sha256 {
        self.challenge_id
    }

    #[must_use]
    pub fn request_id(&self) -> Sha256 {
        self.request_id
    }

    #[must_use]
    pub fn preflight_sha256(&self) -> Sha256 {
        self.preflight_sha256
    }

    #[must_use]
    pub fn response_sha256(&self) -> Sha256 {
        self.response_sha256
    }

    #[must_use]
    pub fn terminal_binding(&self) -> TrustedTerminalBindingV1 {
        self.terminal_binding
    }

    #[must_use]
    pub fn responded_at_unix_ms(&self) -> u64 {
        self.responded_at_unix_ms
    }

    #[must_use]
    pub fn consumed_at_unix_ms(&self) -> u64 {
        self.consumed_at_unix_ms
    }

    #[must_use]
    pub fn challenge_expires_at_unix_ms(&self) -> u64 {
        self.challenge_expires_at_unix_ms
    }

    #[must_use]
    pub fn record_sha256(&self) -> Sha256 {
        self.record_sha256
    }

    #[must_use]
    pub fn execution_authority(&self) -> PlanExecutionAuthorityV1 {
        self.execution_authority
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsApprovalReplayRejectionV1 {
    InvalidRegistryRoot,
    InvalidResponseClaim,
    ResponseExpired,
    AlreadyConsumed,
    PersistenceUncertain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacOsApprovalReplayError {
    pub rejection: MacOsApprovalReplayRejectionV1,
    pub message: String,
}

impl fmt::Display for MacOsApprovalReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for MacOsApprovalReplayError {}

pub struct LakeCommandApprovalReplayRegistryV1 {
    root: OwnedFd,
}

pub fn open_lake_command_approval_replay_registry_v1(
    root: &Path,
) -> Result<LakeCommandApprovalReplayRegistryV1, MacOsApprovalReplayError> {
    if !root.is_absolute() {
        return Err(replay_error(
            MacOsApprovalReplayRejectionV1::InvalidRegistryRoot,
            "approval replay registry root must be absolute",
        ));
    }
    let root = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        replay_error(
            MacOsApprovalReplayRejectionV1::InvalidRegistryRoot,
            format!("cannot open approval replay registry root: {error}"),
        )
    })?;
    let stat = rustix::fs::fstat(&root).map_err(|error| {
        replay_error(
            MacOsApprovalReplayRejectionV1::InvalidRegistryRoot,
            format!("cannot inspect approval replay registry root: {error}"),
        )
    })?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || Mode::from_raw_mode(stat.st_mode) != Mode::RWXU
    {
        return Err(replay_error(
            MacOsApprovalReplayRejectionV1::InvalidRegistryRoot,
            "approval replay registry must be a private 0700 directory owned by the effective user",
        ));
    }
    Ok(LakeCommandApprovalReplayRegistryV1 { root })
}

impl LakeCommandApprovalReplayRegistryV1 {
    pub fn consume_response_claim_v1(
        &self,
        claim: LakeCommandApprovalResponseClaimV1,
    ) -> Result<LakeCommandApprovalConsumptionRecordV1, MacOsApprovalReplayError> {
        let consumed_at_unix_ms = current_unix_ms()?;
        self.consume_response_claim_at_v1(claim, consumed_at_unix_ms)
    }

    fn consume_response_claim_at_v1(
        &self,
        claim: LakeCommandApprovalResponseClaimV1,
        consumed_at_unix_ms: u64,
    ) -> Result<LakeCommandApprovalConsumptionRecordV1, MacOsApprovalReplayError> {
        validate_claim(&claim, consumed_at_unix_ms)?;
        let bytes = canonical_consumption_bytes(&claim, consumed_at_unix_ms);
        let record_sha256 = sha256(&bytes);
        let filename = consumption_filename(claim.challenge_id);
        let slot = match rustix::fs::openat(
            &self.root,
            filename.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(slot) => slot,
            Err(error) if error == rustix::io::Errno::EXIST => {
                return Err(replay_error(
                    MacOsApprovalReplayRejectionV1::AlreadyConsumed,
                    "approval response claim already has a consumption slot",
                ));
            }
            Err(error) => {
                return Err(replay_error(
                    MacOsApprovalReplayRejectionV1::PersistenceUncertain,
                    format!("cannot atomically reserve approval consumption slot: {error}"),
                ));
            }
        };

        let mut slot: File = slot.into();
        slot.write_all(&bytes)
            .and_then(|()| slot.sync_all())
            .map_err(|error| {
                replay_error(
                    MacOsApprovalReplayRejectionV1::PersistenceUncertain,
                    format!(
                        "approval slot exists but its durable record is uncertain; it must remain consumed: {error}"
                    ),
                )
            })?;
        rustix::fs::fsync(&self.root).map_err(|error| {
            replay_error(
                MacOsApprovalReplayRejectionV1::PersistenceUncertain,
                format!(
                    "approval slot exists but directory durability is uncertain; execution remains withheld: {error}"
                ),
            )
        })?;

        Ok(LakeCommandApprovalConsumptionRecordV1 {
            schema_version: 1,
            decision: LakeCommandApprovalConsumptionDecisionV1::ConsumedOnce,
            challenge_id: claim.challenge_id,
            request_id: claim.request_id,
            preflight_sha256: claim.preflight_sha256,
            response_sha256: claim.response_sha256,
            terminal_binding: claim.terminal_binding,
            responded_at_unix_ms: claim.responded_at_unix_ms,
            consumed_at_unix_ms,
            challenge_expires_at_unix_ms: claim.challenge_expires_at_unix_ms,
            record_sha256,
            execution_authority: PlanExecutionAuthorityV1::Withheld,
        })
    }
}

fn validate_claim(
    claim: &LakeCommandApprovalResponseClaimV1,
    consumed_at_unix_ms: u64,
) -> Result<(), MacOsApprovalReplayError> {
    if claim.schema_version != 1
        || claim.decision != LakeCommandApprovalResponseDecisionV1::ExactTerminalResponseClaim
        || claim.execution_authority != PlanExecutionAuthorityV1::Withheld
        || claim.responded_at_unix_ms >= claim.challenge_expires_at_unix_ms
    {
        return Err(replay_error(
            MacOsApprovalReplayRejectionV1::InvalidResponseClaim,
            "approval response claim violates the exact-response contract",
        ));
    }
    if consumed_at_unix_ms < claim.responded_at_unix_ms
        || consumed_at_unix_ms >= claim.challenge_expires_at_unix_ms
    {
        return Err(replay_error(
            MacOsApprovalReplayRejectionV1::ResponseExpired,
            "approval response claim is outside its consumption window",
        ));
    }
    Ok(())
}

fn canonical_consumption_bytes(
    claim: &LakeCommandApprovalResponseClaimV1,
    consumed_at_unix_ms: u64,
) -> Vec<u8> {
    format!(
        "{{\"schemaVersion\":1,\"decision\":\"consumed-once\",\"challengeId\":\"{}\",\"requestId\":\"{}\",\"preflightSha256\":\"{}\",\"responseSha256\":\"{}\",\"terminalDevice\":{},\"terminalInode\":{},\"terminalRawDevice\":{},\"ownerUid\":{},\"effectiveUserId\":{},\"processGroupId\":{},\"processSessionId\":{},\"respondedAtUnixMs\":{},\"consumedAtUnixMs\":{},\"challengeExpiresAtUnixMs\":{},\"executionAuthority\":\"withheld\"}}\n",
        claim.challenge_id,
        claim.request_id,
        claim.preflight_sha256,
        claim.response_sha256,
        claim.terminal_binding.device,
        claim.terminal_binding.inode,
        claim.terminal_binding.raw_device,
        claim.terminal_binding.owner_uid,
        claim.terminal_binding.effective_user_id,
        claim.terminal_binding.process_group_id,
        claim.terminal_binding.process_session_id,
        claim.responded_at_unix_ms,
        consumed_at_unix_ms,
        claim.challenge_expires_at_unix_ms,
    )
    .into_bytes()
}

fn consumption_filename(challenge_id: Sha256) -> String {
    format!("{challenge_id}.consumed-v1")
}

fn sha256(bytes: &[u8]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn current_unix_ms() -> Result<u64, MacOsApprovalReplayError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        replay_error(
            MacOsApprovalReplayRejectionV1::ResponseExpired,
            "system clock is before Unix epoch",
        )
    })?;
    u64::try_from(duration.as_millis()).map_err(|_| {
        replay_error(
            MacOsApprovalReplayRejectionV1::ResponseExpired,
            "system clock is out of range",
        )
    })
}

fn replay_error(
    rejection: MacOsApprovalReplayRejectionV1,
    message: impl Into<String>,
) -> MacOsApprovalReplayError {
    MacOsApprovalReplayError {
        rejection,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
            let root = PathBuf::from(format!(
                "/tmp/leanbun-replay-{}-{sequence}",
                std::process::id()
            ));
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700).create(&root)?;
            Ok(Self(root))
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn response_claim() -> Result<LakeCommandApprovalResponseClaimV1, Box<dyn std::error::Error>> {
        Ok(LakeCommandApprovalResponseClaimV1 {
            schema_version: 1,
            decision: LakeCommandApprovalResponseDecisionV1::ExactTerminalResponseClaim,
            challenge_id: Sha256::parse(
                "905b7cadc6b96de0468b0833883dc41f6126ae9260de971532a1d4e5d943e260",
            )?,
            request_id: Sha256::parse(
                "4d9d1e12c9daa6d20461d8c0dd2b8bb681dfe725593d9e0c4cc592f25e200d5c",
            )?,
            preflight_sha256: Sha256::parse(
                "3a3be2ae3e43dc3534d9f1e81f6caecf7851202f9cafd4c1b95af75ff598a6e8",
            )?,
            response_sha256: Sha256::parse(
                "9667e61009b97e347b7186bc55ea573a6ee4c1d1d82861d7613b40c81e54681d",
            )?,
            terminal_binding: TrustedTerminalBindingV1 {
                device: 10,
                inode: 20,
                raw_device: 30,
                owner_uid: rustix::process::geteuid().as_raw(),
                effective_user_id: rustix::process::geteuid().as_raw(),
                process_group_id: 40,
                process_session_id: 50,
            },
            responded_at_unix_ms: 1_800_000_300_000,
            challenge_expires_at_unix_ms: 1_800_000_360_000,
            execution_authority: PlanExecutionAuthorityV1::Withheld,
        })
    }

    #[test]
    fn durable_slot_consumes_once_and_preserves_withheld_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = TestRoot::new()?;
        let registry = open_lake_command_approval_replay_registry_v1(&root.0)?;
        let claim = response_claim()?;
        let duplicate_claim = response_claim()?;
        let challenge_id = claim.challenge_id;
        let consumed_at = 1_800_000_300_100;
        let record = registry.consume_response_claim_at_v1(claim, consumed_at)?;
        assert_eq!(
            record.decision,
            LakeCommandApprovalConsumptionDecisionV1::ConsumedOnce
        );
        assert_eq!(
            record.execution_authority,
            PlanExecutionAuthorityV1::Withheld
        );

        let slot = root.0.join(consumption_filename(challenge_id));
        let bytes = fs::read(&slot)?;
        assert_eq!(
            bytes,
            canonical_consumption_bytes(&duplicate_claim, consumed_at)
        );
        assert_eq!(record.record_sha256, sha256(&bytes));
        assert_eq!(fs::metadata(&slot)?.permissions().mode() & 0o077, 0);

        let duplicate =
            match registry.consume_response_claim_at_v1(duplicate_claim, consumed_at + 1) {
                Ok(_) => return Err("duplicate response claim was consumed".into()),
                Err(error) => error,
            };
        assert_eq!(
            duplicate.rejection,
            MacOsApprovalReplayRejectionV1::AlreadyConsumed
        );
        Ok(())
    }

    #[test]
    fn concurrent_consumers_cannot_both_reserve_the_slot() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = TestRoot::new()?;
        let registry = open_lake_command_approval_replay_registry_v1(&root.0)?;
        let first_claim = response_claim()?;
        let second_claim = response_claim()?;
        let (first, second) = std::thread::scope(|scope| {
            let first = scope
                .spawn(|| registry.consume_response_claim_at_v1(first_claim, 1_800_000_300_100));
            let second = scope
                .spawn(|| registry.consume_response_claim_at_v1(second_claim, 1_800_000_300_100));
            let first = first
                .join()
                .map_err(|_| std::io::Error::other("first consumer panicked"))?;
            let second = second
                .join()
                .map_err(|_| std::io::Error::other("second consumer panicked"))?;
            Ok::<_, std::io::Error>((first, second))
        })?;
        let outcomes = [first, second];
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| matches!(
                    result,
                    Err(error)
                        if error.rejection == MacOsApprovalReplayRejectionV1::AlreadyConsumed
                ))
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn crash_shaped_empty_slot_remains_consumed() -> Result<(), Box<dyn std::error::Error>> {
        let root = TestRoot::new()?;
        let claim = response_claim()?;
        let retry_claim = response_claim()?;
        let slot = root.0.join(consumption_filename(claim.challenge_id));
        File::create(&slot)?.sync_all()?;
        let registry = open_lake_command_approval_replay_registry_v1(&root.0)?;
        let error = match registry.consume_response_claim_at_v1(retry_claim, 1_800_000_300_100) {
            Ok(_) => return Err("pre-existing crash slot was reused".into()),
            Err(error) => error,
        };
        assert_eq!(
            error.rejection,
            MacOsApprovalReplayRejectionV1::AlreadyConsumed
        );
        assert_eq!(fs::metadata(slot)?.len(), 0);
        Ok(())
    }

    #[test]
    fn registry_rejects_broad_permissions_and_expired_claims()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = TestRoot::new()?;
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o755))?;
        let error = match open_lake_command_approval_replay_registry_v1(&root.0) {
            Ok(_) => return Err("broad registry permissions were accepted".into()),
            Err(error) => error,
        };
        assert_eq!(
            error.rejection,
            MacOsApprovalReplayRejectionV1::InvalidRegistryRoot
        );
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700))?;

        let actual = root.0.join("actual");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&actual)?;
        let linked = root.0.join("linked");
        symlink(&actual, &linked)?;
        let linked_error = match open_lake_command_approval_replay_registry_v1(&linked) {
            Ok(_) => return Err("symlinked registry root was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(
            linked_error.rejection,
            MacOsApprovalReplayRejectionV1::InvalidRegistryRoot
        );

        let registry = open_lake_command_approval_replay_registry_v1(&root.0)?;
        let claim = response_claim()?;
        let expiry = claim.challenge_expires_at_unix_ms;
        let challenge_id = claim.challenge_id;
        let expired = match registry.consume_response_claim_at_v1(claim, expiry) {
            Ok(_) => return Err("expired response claim was consumed".into()),
            Err(error) => error,
        };
        assert_eq!(
            expired.rejection,
            MacOsApprovalReplayRejectionV1::ResponseExpired
        );
        assert!(!root.0.join(consumption_filename(challenge_id)).exists());
        Ok(())
    }
}
