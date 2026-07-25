#![forbid(unsafe_code)]

mod model;
mod probe;

pub use model::{
    LakeBridgeError, LakeBridgeErrorKind, LakeDependencySourceV1, LakeManifestProjectionV1,
    LakeObservedPackagePathV1, LakePackageProjectionMetadataV1, LakeRootDeclarationV1,
    LakeRootDependencyV1, LakeRuntimePackagesProjectionV1, LakeWorkspacePathObservationV1,
    parse_root_declaration_probe_v1, validate_managed_runtime_package_files_v1,
};
pub use probe::{
    LakeRootProbeRequestV1, run_lake_root_probe_v1, verify_lake_source_compatibility_v1,
};
