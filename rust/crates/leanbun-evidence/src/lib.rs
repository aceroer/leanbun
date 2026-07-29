#![forbid(unsafe_code)]

#[cfg(not(unix))]
compile_error!("leanbun-evidence M1 currently requires Unix file identity semantics");

mod build_lock;
mod execution_record;
mod image_attestation;
mod path;
mod project_binding;
mod project_identity;
mod project_input;
mod project_manifest;
mod provider_override;
mod provider_registry;
mod stable_file;
mod strict_json;
mod tree_hash;

pub use build_lock::{
    BUILD_LOCK_MAX_BYTES, BuildExecutionLockV1, StableBuildExecutionLockFile, build_lock_key,
    decode_build_execution_lock, parse_build_execution_lock, read_build_execution_lock,
};
pub use execution_record::{
    ControlledBuildExecutionOutcomeV1, ControlledBuildExecutionRecordV1,
    EXECUTION_RECORD_MAX_BYTES, ExecutionPolicyIdentity, ExecutionRecoveryIdentity,
    ExecutionStatus, FailureStage, ProjectBuildReuseEvidenceV1, ReuseTreeEvidenceV1,
    StableExecutionRecordFile, TerminationReason, TriggerSignal, decode_execution_record,
    parse_execution_record, read_execution_record,
};
pub use image_attestation::{
    ArtifactPolicyV1, AttestationProviderV1, IMAGE_ATTESTATION_MAX_BYTES, ImageAttestationV1,
    ImageIdentityV1, MAX_MISSING_ARTIFACT_ROOTS, MAX_SAFE_JSON_INTEGER, StableImageAttestationFile,
    decode_image_attestation, image_id, parse_image_attestation, read_image_attestation,
};
pub use path::{
    CanonicalDirectory, CanonicalPath, canonicalize_contained, canonicalize_contained_directory,
    canonicalize_directory,
};
pub use project_binding::{
    MAX_ALLOWED_TARGETS, PROJECT_BINDING_MAX_BYTES, ProjectBindingV1, StableProjectBindingFile,
    decode_project_binding, parse_project_binding, read_project_binding,
};
pub use project_identity::{
    PROJECT_INPUT_IDENTITY_SCHEMA, ProjectInputIdentityMaterial, ProjectInputIdentityPackage,
    ProjectInputIdentityPackageKind, ProjectInputIdentityV1, canonical_project_input_identity,
    derive_project_input_identity,
};
pub use project_input::{
    ProjectInputState, ProjectPathPackage, StableProjectInput, read_project_input,
};
pub use project_manifest::{
    ProjectManifest, ProjectManifestPackage, ProjectPackageSource, ProjectProviderComparison,
    ProjectProviderMatchState, ProjectProviderMismatch, StableProjectManifestFile,
    compare_project_manifest_to_provider, decode_project_manifest, parse_project_manifest,
    read_project_manifest,
};
pub use provider_override::{
    ProviderOverride, ProviderOverridePackage, StableProviderOverrideFile, StableProviderPair,
    VerifiedProviderPackage, decode_provider_override, parse_provider_override,
    read_provider_override, read_provider_pair,
};
pub use provider_registry::{
    MAX_PROVIDER_PACKAGES, PROVIDER_REGISTRY_MAX_BYTES, ProviderRegistry, ProviderRegistryPackage,
    StableProviderRegistryFile, decode_provider_registry, parse_provider_registry,
    read_provider_registry,
};
pub use stable_file::{EvidenceError, MAX_STABLE_TEXT_BYTES, StableTextFile, read_stable_text};
pub use strict_json::{
    JsonNumber, MAX_JSON_DEPTH, MAX_JSON_NODES, StableJsonFile, StrictJson, StrictJsonError,
    parse_strict_json, read_strict_json,
};
pub use tree_hash::{
    MAX_PROJECT_TREE_BYTES, MAX_PROJECT_TREE_ENTRIES, MAX_PROJECT_TREE_FILE_BYTES,
    PROJECT_INPUT_TREE_SCHEMA, ProjectInputTreeHash, hash_project_input_tree,
};
