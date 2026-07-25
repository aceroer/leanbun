#![forbid(unsafe_code)]

pub mod diagnostic;
pub mod identity;
mod sha256;

pub use diagnostic::{Diagnostic, DiagnosticCode, DiagnosticSeverity};
pub use identity::{
    BuildTarget, ExecutionId, ImageId, ProjectId, Sha256, ValidationError, project_id,
};
pub use sha256::Sha256Hasher;
