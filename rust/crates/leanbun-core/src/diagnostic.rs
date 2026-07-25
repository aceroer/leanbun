macro_rules! define_diagnostic_codes {
    ($($code:ident),+ $(,)?) => {
        #[allow(non_camel_case_types)]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub enum DiagnosticCode {
            $($code),+
        }

        impl DiagnosticCode {
            pub const ALL: &'static [Self] = &[$(Self::$code),+];

            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$code => stringify!($code)),+
                }
            }
        }
    };
}

define_diagnostic_codes!(
    BUN_RUNTIME_UNSUPPORTED,
    PROJECT_NOT_FOUND,
    PROJECT_NOT_DIRECTORY,
    PATH_ESCAPES_ALLOWED_ROOT,
    EVIDENCE_MISSING,
    EVIDENCE_NOT_REGULAR_FILE,
    EVIDENCE_READ_FAILED,
    EVIDENCE_TOO_LARGE,
    EVIDENCE_CHANGED_DURING_READ,
    JSON_MALFORMED,
    MANIFEST_SCHEMA_UNSUPPORTED,
    MANIFEST_SHAPE_INVALID,
    TOOLCHAIN_INVALID,
    PROVIDER_UNAVAILABLE,
    PROVIDER_SCHEMA_INVALID,
    PROVIDER_PACKAGE_MISSING,
    GIT_EVIDENCE_FAILED,
    COMMAND_TIMEOUT,
    COMMAND_OUTPUT_LIMIT,
    ARTIFACT_SYMLINK_SKIPPED,
    ARTIFACT_LIMIT_EXCEEDED,
    BINDING_MISSING,
    BINDING_INVALID,
    BINDING_DRIFTED,
    BINDING_POLICY_REJECTED,
    BINDING_WRITE_BUSY,
    BINDING_WRITE_CONFLICT,
    BINDING_WRITE_FAILED,
    PROJECT_BOUND,
    TARGET_NOT_APPROVED,
    TARGET_INVALID,
    ATTESTATION_MISSING,
    ATTESTATION_INVALID,
    ATTESTATION_UNVERIFIED,
    ATTESTATION_REVERIFICATION_FAILED,
    ATTESTATION_REVERIFIED,
    ATTESTATION_POLICY_REJECTED,
    ATTESTATION_SEAL_BUSY,
    ATTESTATION_SEAL_CONFLICT,
    ATTESTATION_SEAL_FAILED,
    ATTESTATION_SEALED,
    BUILD_INSPECTION_FAILED,
    BUILD_NOT_AUTHORIZED,
    BUILD_SANDBOX_INVALID,
    BUILD_SANDBOX_FAILED,
    BUILD_SANDBOX_PROBE_PASSED,
    LAKE_BUILD_NOT_ATTEMPTED,
    LAKE_SANDBOX_BUILD_PASSED,
    LAKE_EXECUTION_FAILED,
    LAKE_EXECUTION_TIMED_OUT,
    LAKE_EXECUTION_CANCELLED,
    PROCESS_GROUP_NOT_REAPED,
    DEPENDENCY_ROOT_DRIFTED,
    CONTROLLED_BUILD_PASSED,
    CONTROLLED_BUILD_FAILED,
    EXECUTION_RECORD_STARTED,
    EXECUTION_RECORD_FINALIZED,
    EXECUTION_RECORD_FAILED,
    BUILD_LOCK_ACQUIRED,
    BUILD_LOCK_BUSY,
    BUILD_LOCK_RELEASED,
    BUILD_LOCK_CONFLICT,
    BUILD_LOCK_FAILED,
    PROJECT_INPUT_DRIFTED,
    PROJECT_OUTPUT_MISSING,
    REUSE_EVIDENCE_RECORDED,
    REUSE_CANDIDATE_NOT_FOUND,
    REUSE_CANDIDATE_ELIGIBLE,
    REUSE_INPUT_MISMATCH,
    REUSE_OUTPUT_MISMATCH,
    REUSE_TRANSACTION_STARTED,
    REUSE_TRANSACTION_COMPLETED,
    REUSE_TRANSACTION_FAILED,
    REUSE_TRANSACTION_CANCELLED,
    REUSE_EXECUTION_RECOVERED,
    EXECUTION_COORDINATOR_ACTIVE,
    EXECUTION_PROJECT_PROCESS_ACTIVE,
    EXECUTION_RECOVERY_BLOCKED,
    EXECUTION_RECOVERY_EVIDENCE_DRIFTED,
    EXECUTION_RECOVERED,
    IMAGE_EVIDENCE_BLOCKED,
    TREE_HASH_LIMIT_EXCEEDED,
    TOOLCHAIN_MISMATCH,
    MANIFEST_PROVIDER_MISMATCH,
    PACKAGE_REVISION_MISMATCH,
    PACKAGE_DIRTY,
    OVERRIDE_MISSING,
    OVERRIDE_DRIFTED,
    DEPENDENCY_ARTIFACT_MISSING,
    TRACE_MISSING,
    HASH_FILE_UNVERIFIED,
    LAKE_EXECUTION_NOT_ATTEMPTED,
);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

impl DiagnosticSeverity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    pub code: DiagnosticCode,
    pub severity: DiagnosticSeverity,
    pub message: String,
    pub evidence: Vec<String>,
}

impl Diagnostic {
    #[must_use]
    pub fn new(
        code: DiagnosticCode,
        severity: DiagnosticSeverity,
        message: impl Into<String>,
        evidence: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            code,
            severity,
            message: message.into(),
            evidence: evidence.into_iter().map(Into::into).collect(),
        }
    }

    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut output = String::from("{\"code\":");
        push_json_string(&mut output, self.code.as_str());
        output.push_str(",\"severity\":");
        push_json_string(&mut output, self.severity.as_str());
        output.push_str(",\"message\":");
        push_json_string(&mut output, &self.message);
        output.push_str(",\"evidence\":[");
        for (index, evidence) in self.evidence.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            push_json_string(&mut output, evidence);
        }
        output.push_str("]}");
        output
    }
}

fn push_json_string(output: &mut String, value: &str) {
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
