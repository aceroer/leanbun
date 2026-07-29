use crate::{
    CurrentProcessTerminalObservationV1, MacOsTerminalIngressDecisionV1, PlatformProofV1,
    TerminalDeviceIdentityV1, observe_current_process_terminal_v1,
};
use core::fmt;
use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_plan::{
    LakeCommandApprovalRequestV1, LakeCommandPreflightV1, LakeCommandTrustedApprovalChallengeV1,
    PlanExecutionAuthorityV1, lake_command_trusted_approval_challenge_v1,
};
use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

const CHALLENGE_WINDOW_MS: u64 = 60_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedTerminalBindingV1 {
    pub device: u64,
    pub inode: u64,
    pub raw_device: u64,
    pub owner_uid: u32,
    pub effective_user_id: u32,
    pub process_group_id: i32,
    pub process_session_id: i32,
}

pub struct LakeCommandApprovalPresentationV1 {
    pub schema_version: u8,
    pub terminal_binding: TrustedTerminalBindingV1,
    pub session_nonce_sha256: Sha256,
    pub challenge: LakeCommandTrustedApprovalChallengeV1,
    pub display_text: String,
    pub execution_authority: PlanExecutionAuthorityV1,
    presented: bool,
    _session_nonce: OsSessionNonceV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LakeCommandApprovalResponseDecisionV1 {
    ExactTerminalResponseClaim,
}

#[derive(Debug, Eq, PartialEq)]
pub struct LakeCommandApprovalResponseClaimV1 {
    pub(crate) schema_version: u8,
    pub(crate) decision: LakeCommandApprovalResponseDecisionV1,
    pub(crate) challenge_id: Sha256,
    pub(crate) request_id: Sha256,
    pub(crate) preflight_sha256: Sha256,
    pub(crate) response_sha256: Sha256,
    pub(crate) terminal_binding: TrustedTerminalBindingV1,
    pub(crate) responded_at_unix_ms: u64,
    pub(crate) challenge_expires_at_unix_ms: u64,
    pub(crate) execution_authority: PlanExecutionAuthorityV1,
}

impl LakeCommandApprovalResponseClaimV1 {
    #[must_use]
    pub fn decision(&self) -> LakeCommandApprovalResponseDecisionV1 {
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
    pub fn challenge_expires_at_unix_ms(&self) -> u64 {
        self.challenge_expires_at_unix_ms
    }

    #[must_use]
    pub fn execution_authority(&self) -> PlanExecutionAuthorityV1 {
        self.execution_authority
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsApprovalResponseRejectionV1 {
    ChallengeNotPresented,
    ChallengeExpired,
    TerminalChanged,
    InputFailed,
    EndOfFile,
    ResponseTooLong,
    MissingNewline,
    InvalidUtf8,
    ResponseMismatch,
    ExtraInput,
    QueueInspectionFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacOsApprovalResponseError {
    pub rejection: MacOsApprovalResponseRejectionV1,
    pub message: String,
}

impl fmt::Display for MacOsApprovalResponseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for MacOsApprovalResponseError {}

struct OsSessionNonceV1([u8; 32]);

impl Drop for OsSessionNonceV1 {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacOsApprovalPresentationError {
    pub message: String,
}

impl fmt::Display for MacOsApprovalPresentationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for MacOsApprovalPresentationError {}

pub fn prepare_lake_command_approval_presentation_v1(
    request: &LakeCommandApprovalRequestV1,
    preflight: &LakeCommandPreflightV1,
) -> Result<LakeCommandApprovalPresentationV1, MacOsApprovalPresentationError> {
    let observation = observe_current_process_terminal_v1();
    let terminal_binding = trusted_terminal_binding_v1(&observation)?;
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|error| invalid(format!("OS CSPRNG failed: {error}")))?;
    let now = current_unix_ms()?;
    prepare_with_nonce_v1(request, preflight, terminal_binding, nonce, now)
}

pub fn present_lake_command_approval_to_current_terminal_v1(
    presentation: &mut LakeCommandApprovalPresentationV1,
) -> Result<(), MacOsApprovalPresentationError> {
    if presentation.presented {
        return Err(invalid("approval challenge was already presented"));
    }
    let observation = observe_current_process_terminal_v1();
    let current_binding = trusted_terminal_binding_v1(&observation)?;
    if current_binding != presentation.terminal_binding {
        return Err(invalid(
            "terminal identity changed before challenge presentation",
        ));
    }
    let now = current_unix_ms()?;
    if now < presentation.challenge.issued_at_unix_ms
        || now >= presentation.challenge.expires_at_unix_ms
    {
        return Err(invalid(
            "approval challenge expired before terminal presentation",
        ));
    }
    let mut stderr = io::stderr().lock();
    stderr
        .write_all(presentation.display_text.as_bytes())
        .and_then(|()| stderr.flush())
        .map_err(|error| invalid(format!("cannot present challenge on stderr: {error}")))?;
    presentation.presented = true;
    Ok(())
}

pub fn read_bounded_exact_response_from_current_terminal_v1(
    presentation: LakeCommandApprovalPresentationV1,
) -> Result<LakeCommandApprovalResponseClaimV1, MacOsApprovalResponseError> {
    if !presentation.presented {
        return Err(response_error(
            MacOsApprovalResponseRejectionV1::ChallengeNotPresented,
            "approval response cannot be read before challenge presentation",
        ));
    }
    let now = response_time_v1()?;
    if now < presentation.challenge.issued_at_unix_ms
        || now >= presentation.challenge.expires_at_unix_ms
    {
        return Err(response_error(
            MacOsApprovalResponseRejectionV1::ChallengeExpired,
            "approval challenge is outside its response window",
        ));
    }
    verify_current_binding_for_response(&presentation)?;

    let expected = presentation.challenge.confirmation.as_bytes();
    if expected.is_empty() || expected.len() > 256 {
        return Err(response_error(
            MacOsApprovalResponseRejectionV1::ResponseTooLong,
            "approval confirmation exceeds the bounded reader contract",
        ));
    }
    let mut stdin = io::stdin().lock();
    let mut buffer = vec![0_u8; expected.len() + 2];
    let mut used = 0_usize;
    loop {
        if used == buffer.len() {
            return Err(response_error(
                MacOsApprovalResponseRejectionV1::ResponseTooLong,
                "approval response exceeded the exact confirmation bound",
            ));
        }
        let count = stdin.read(&mut buffer[used..]).map_err(|error| {
            response_error(
                MacOsApprovalResponseRejectionV1::InputFailed,
                format!("cannot read approval response: {error}"),
            )
        })?;
        if count == 0 {
            return Err(response_error(
                MacOsApprovalResponseRejectionV1::EndOfFile,
                "approval response ended before a newline",
            ));
        }
        used += count;
        if buffer[..used].contains(&b'\n') {
            break;
        }
    }
    let queued = rustix::io::ioctl_fionread(&stdin).map_err(|error| {
        response_error(
            MacOsApprovalResponseRejectionV1::QueueInspectionFailed,
            format!("cannot inspect queued terminal input: {error}"),
        )
    })?;
    let response = validate_response_bytes_v1(&buffer[..used], expected, queued)?;
    let response_sha256 = {
        let mut hasher = Sha256Hasher::new();
        hasher.update(response.as_bytes());
        hasher.finalize()
    };
    drop(stdin);

    verify_current_binding_for_response(&presentation)?;
    let responded_at_unix_ms = response_time_v1()?;
    if responded_at_unix_ms < presentation.challenge.issued_at_unix_ms
        || responded_at_unix_ms >= presentation.challenge.expires_at_unix_ms
    {
        return Err(response_error(
            MacOsApprovalResponseRejectionV1::ChallengeExpired,
            "approval challenge expired while reading the response",
        ));
    }
    Ok(LakeCommandApprovalResponseClaimV1 {
        schema_version: 1,
        decision: LakeCommandApprovalResponseDecisionV1::ExactTerminalResponseClaim,
        challenge_id: presentation.challenge.challenge_id,
        request_id: presentation.challenge.request_id,
        preflight_sha256: presentation.challenge.preflight_sha256,
        response_sha256,
        terminal_binding: presentation.terminal_binding,
        responded_at_unix_ms,
        challenge_expires_at_unix_ms: presentation.challenge.expires_at_unix_ms,
        execution_authority: PlanExecutionAuthorityV1::Withheld,
    })
}

fn verify_current_binding_for_response(
    presentation: &LakeCommandApprovalPresentationV1,
) -> Result<(), MacOsApprovalResponseError> {
    let observation = observe_current_process_terminal_v1();
    let current = trusted_terminal_binding_v1(&observation).map_err(|error| {
        response_error(
            MacOsApprovalResponseRejectionV1::TerminalChanged,
            error.message,
        )
    })?;
    if current != presentation.terminal_binding {
        return Err(response_error(
            MacOsApprovalResponseRejectionV1::TerminalChanged,
            "terminal identity changed before or during response input",
        ));
    }
    Ok(())
}

fn validate_response_bytes_v1<'a>(
    bytes: &'a [u8],
    expected: &[u8],
    queued_bytes: u64,
) -> Result<&'a str, MacOsApprovalResponseError> {
    let Some(newline) = bytes.iter().position(|byte| *byte == b'\n') else {
        return Err(response_error(
            MacOsApprovalResponseRejectionV1::MissingNewline,
            "approval response must end with one newline",
        ));
    };
    if newline + 1 != bytes.len() || queued_bytes != 0 {
        return Err(response_error(
            MacOsApprovalResponseRejectionV1::ExtraInput,
            "approval response contains or queues input after the first newline",
        ));
    }
    let response = std::str::from_utf8(&bytes[..newline]).map_err(|_| {
        response_error(
            MacOsApprovalResponseRejectionV1::InvalidUtf8,
            "approval response is not valid UTF-8",
        )
    })?;
    if response.as_bytes() != expected {
        return Err(response_error(
            MacOsApprovalResponseRejectionV1::ResponseMismatch,
            "approval response does not exactly equal the presented confirmation",
        ));
    }
    Ok(response)
}

fn trusted_terminal_binding_v1(
    observation: &CurrentProcessTerminalObservationV1,
) -> Result<TrustedTerminalBindingV1, MacOsApprovalPresentationError> {
    if observation.decision != MacOsTerminalIngressDecisionV1::ReadyForChallengeResponse
        || observation.effective_user_ownership != PlatformProofV1::Verified
        || observation.foreground_process_group != PlatformProofV1::Verified
        || observation.controlling_terminal_session != PlatformProofV1::Verified
        || observation.execution_authority != PlanExecutionAuthorityV1::Withheld
    {
        return Err(invalid(
            "current process does not hold complete trusted terminal proof",
        ));
    }
    let TerminalDeviceIdentityV1 {
        device,
        inode,
        raw_device,
        owner_uid,
    } = observation
        .terminal_device
        .ok_or_else(|| invalid("trusted terminal device identity is absent"))?;
    let effective_user_id = observation
        .effective_user_id
        .ok_or_else(|| invalid("effective user identity is absent"))?;
    let process_group_id = observation
        .process_group_id
        .ok_or_else(|| invalid("foreground process group identity is absent"))?;
    let process_session_id = observation
        .process_session_id
        .ok_or_else(|| invalid("controlling terminal session identity is absent"))?;
    Ok(TrustedTerminalBindingV1 {
        device,
        inode,
        raw_device,
        owner_uid,
        effective_user_id,
        process_group_id,
        process_session_id,
    })
}

fn prepare_with_nonce_v1(
    request: &LakeCommandApprovalRequestV1,
    preflight: &LakeCommandPreflightV1,
    terminal_binding: TrustedTerminalBindingV1,
    nonce: [u8; 32],
    issued_at_unix_ms: u64,
) -> Result<LakeCommandApprovalPresentationV1, MacOsApprovalPresentationError> {
    let expires_at_unix_ms = issued_at_unix_ms
        .checked_add(CHALLENGE_WINDOW_MS)
        .map(|expiry| expiry.min(request.expires_at_unix_ms))
        .ok_or_else(|| invalid("approval challenge time overflow"))?;
    let session_nonce_sha256 = session_nonce_sha256_v1(&nonce, terminal_binding);
    let challenge = lake_command_trusted_approval_challenge_v1(
        request,
        preflight,
        session_nonce_sha256,
        issued_at_unix_ms,
        expires_at_unix_ms,
    )
    .map_err(|error| invalid(error.message))?;
    let display_text = format!(
        "LeanBun external Lake command approval challenge\nrequestId: {}\npreflightSha256: {}\nchallengeId: {}\nexpiresAtUnixMs: {}\nfuture response must exactly equal:\n{}\nThis step does not read a response or grant execution authority.\n",
        challenge.request_id,
        challenge.preflight_sha256,
        challenge.challenge_id,
        challenge.expires_at_unix_ms,
        challenge.confirmation,
    );
    Ok(LakeCommandApprovalPresentationV1 {
        schema_version: 1,
        terminal_binding,
        session_nonce_sha256,
        challenge,
        display_text,
        execution_authority: PlanExecutionAuthorityV1::Withheld,
        presented: false,
        _session_nonce: OsSessionNonceV1(nonce),
    })
}

fn session_nonce_sha256_v1(nonce: &[u8; 32], terminal: TrustedTerminalBindingV1) -> Sha256 {
    let mut random_hasher = Sha256Hasher::new();
    random_hasher.update(nonce);
    let random_sha256 = random_hasher.finalize();
    let identity = format!(
        "{{\"schema\":\"leanbun-macos-session-nonce-v1\",\"randomSha256\":\"{random_sha256}\",\"device\":{},\"inode\":{},\"rawDevice\":{},\"ownerUid\":{},\"effectiveUserId\":{},\"processGroupId\":{},\"processSessionId\":{}}}",
        terminal.device,
        terminal.inode,
        terminal.raw_device,
        terminal.owner_uid,
        terminal.effective_user_id,
        terminal.process_group_id,
        terminal.process_session_id,
    );
    let mut hasher = Sha256Hasher::new();
    hasher.update(identity.as_bytes());
    hasher.finalize()
}

fn current_unix_ms() -> Result<u64, MacOsApprovalPresentationError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("system clock is before Unix epoch"))?;
    u64::try_from(duration.as_millis()).map_err(|_| invalid("system clock is out of range"))
}

fn response_time_v1() -> Result<u64, MacOsApprovalResponseError> {
    current_unix_ms().map_err(|error| {
        response_error(
            MacOsApprovalResponseRejectionV1::ChallengeExpired,
            error.message,
        )
    })
}

fn invalid(message: impl Into<String>) -> MacOsApprovalPresentationError {
    MacOsApprovalPresentationError {
        message: message.into(),
    }
}

fn response_error(
    rejection: MacOsApprovalResponseRejectionV1,
    message: impl Into<String>,
) -> MacOsApprovalResponseError {
    MacOsApprovalResponseError {
        rejection,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leanbun_plan::{
        LakeCommandApprovalStateV1, LakeCommandPreflightDecisionV1, SUPPORTED_LAKE_VERSION,
    };

    const TERMINAL: TrustedTerminalBindingV1 = TrustedTerminalBindingV1 {
        device: 10,
        inode: 20,
        raw_device: 30,
        owner_uid: 501,
        effective_user_id: 501,
        process_group_id: 40,
        process_session_id: 50,
    };

    fn fixture()
    -> Result<(LakeCommandApprovalRequestV1, LakeCommandPreflightV1), Box<dyn std::error::Error>>
    {
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
            project_id: "fixture-project".to_owned(),
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
        Ok((request, preflight))
    }

    #[test]
    fn nonce_is_bound_to_terminal_and_never_rendered() -> Result<(), Box<dyn std::error::Error>> {
        let (request, preflight) = fixture()?;
        let first =
            prepare_with_nonce_v1(&request, &preflight, TERMINAL, [7; 32], 1_800_000_300_000)?;
        let second =
            prepare_with_nonce_v1(&request, &preflight, TERMINAL, [8; 32], 1_800_000_300_000)?;
        let moved = prepare_with_nonce_v1(
            &request,
            &preflight,
            TrustedTerminalBindingV1 {
                inode: 21,
                ..TERMINAL
            },
            [7; 32],
            1_800_000_300_000,
        )?;
        assert_ne!(first.session_nonce_sha256, second.session_nonce_sha256);
        assert_ne!(first.session_nonce_sha256, moved.session_nonce_sha256);
        assert!(first.display_text.contains(&first.challenge.confirmation));
        assert!(!first.display_text.contains(&"07".repeat(32)));
        assert_eq!(
            first.execution_authority,
            PlanExecutionAuthorityV1::Withheld
        );
        assert_eq!(first._session_nonce.0, [7; 32]);
        Ok(())
    }

    #[test]
    fn challenge_window_is_capped_by_request_expiry() -> Result<(), Box<dyn std::error::Error>> {
        let (request, preflight) = fixture()?;
        let presentation =
            prepare_with_nonce_v1(&request, &preflight, TERMINAL, [9; 32], 1_800_000_550_000)?;
        assert_eq!(
            presentation.challenge.expires_at_unix_ms,
            request.expires_at_unix_ms
        );
        Ok(())
    }

    #[test]
    fn exact_response_parser_rejects_every_non_exact_shape()
    -> Result<(), Box<dyn std::error::Error>> {
        let expected = b"approve:fixture";
        assert_eq!(
            validate_response_bytes_v1(b"approve:fixture\n", expected, 0)?,
            "approve:fixture"
        );
        for (bytes, queued, rejection) in [
            (
                b"approve:fixture".as_slice(),
                0,
                MacOsApprovalResponseRejectionV1::MissingNewline,
            ),
            (
                b"approve:fixture\r\n".as_slice(),
                0,
                MacOsApprovalResponseRejectionV1::ResponseMismatch,
            ),
            (
                b"approve:fixture\nextra".as_slice(),
                0,
                MacOsApprovalResponseRejectionV1::ExtraInput,
            ),
            (
                b"approve:fixture\n".as_slice(),
                1,
                MacOsApprovalResponseRejectionV1::ExtraInput,
            ),
            (
                b"approve:other\n".as_slice(),
                0,
                MacOsApprovalResponseRejectionV1::ResponseMismatch,
            ),
            (
                [0xff, b'\n'].as_slice(),
                0,
                MacOsApprovalResponseRejectionV1::InvalidUtf8,
            ),
        ] {
            let error = match validate_response_bytes_v1(bytes, expected, queued) {
                Ok(_) => return Err("non-exact response was accepted".into()),
                Err(error) => error,
            };
            assert_eq!(error.rejection, rejection);
        }
        Ok(())
    }

    #[test]
    fn unpresented_capability_cannot_be_read() -> Result<(), Box<dyn std::error::Error>> {
        let (request, preflight) = fixture()?;
        let presentation =
            prepare_with_nonce_v1(&request, &preflight, TERMINAL, [10; 32], 1_800_000_300_000)?;
        let error = match read_bounded_exact_response_from_current_terminal_v1(presentation) {
            Ok(_) => return Err("unpresented capability was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(
            error.rejection,
            MacOsApprovalResponseRejectionV1::ChallengeNotPresented
        );
        Ok(())
    }
}
