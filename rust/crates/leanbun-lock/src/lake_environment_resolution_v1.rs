use crate::LeanBunLockV1;
use leanbun_core::{Sha256, Sha256Hasher};

/// Identity of the dependency resolution selected for one Lake environment.
///
/// Two isolated Lake environments may have the same resolution key when their
/// exact toolchain and canonical dependency graph agree. The key deliberately
/// excludes root package inputs and machine paths. Equality describes the
/// resolution result; it does not identify a shared Store object, authorize
/// publication, or prove that compiled artifacts are compatible.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LakeEnvironmentResolutionKeyV1(Sha256);

impl LakeEnvironmentResolutionKeyV1 {
    #[must_use]
    pub fn from_lock(lock: &LeanBunLockV1) -> Self {
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"leanbun-lake-environment-resolution-v1\0");
        hash_string(&mut hasher, lock.lean_toolchain());
        hash_string(&mut hasher, lock.lean_compiler_githash());
        hash_string(&mut hasher, lock.lake_version());
        hasher.update(lock.graph_sha256().as_bytes());
        Self(hasher.finalize())
    }

    #[must_use]
    pub const fn digest(self) -> Sha256 {
        self.0
    }
}

fn hash_string(hasher: &mut Sha256Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CanonicalSourceUrlV1, LockedLeanPackageV1, PackageKeyV1, RequestedPackageSourceV1,
        ResolvedPackageSourceV1,
    };

    fn sha(byte: u8) -> Sha256 {
        Sha256::from_bytes([byte; 32])
    }

    fn lock(
        toolchain: &str,
        root_config: Sha256,
        root_declaration: Sha256,
        source_tree: Sha256,
    ) -> LeanBunLockV1 {
        let url = CanonicalSourceUrlV1::parse("https://github.com/example/package")
            .unwrap_or_else(|error| panic!("fixture URL failed: {error}"));
        let package = LockedLeanPackageV1::new(
            PackageKeyV1::new("", "mathlib")
                .unwrap_or_else(|error| panic!("fixture key failed: {error}")),
            RequestedPackageSourceV1::git(url.clone(), Some("v4.32.0".to_owned()))
                .unwrap_or_else(|error| panic!("requested source failed: {error}")),
            ResolvedPackageSourceV1::git(url, "1111111111111111111111111111111111111111", None)
                .unwrap_or_else(|error| panic!("resolved source failed: {error}")),
            Some(sha(1)),
            source_tree,
            sha(3),
            Some(sha(4)),
            Vec::new(),
            vec![sha(5)],
            sha(6),
        )
        .unwrap_or_else(|error| panic!("fixture package failed: {error}"));
        LeanBunLockV1::new(
            toolchain,
            "1111111111111111111111111111111111111111",
            "5.0.0-src+8c9756b",
            root_config,
            root_declaration,
            vec![package],
        )
        .unwrap_or_else(|error| panic!("fixture lock failed: {error}"))
    }

    #[test]
    fn equivalent_environments_share_resolution_but_not_lock_identity() {
        let first = lock("leanprover/lean4:v4.32.0", sha(8), sha(9), sha(2));
        let another_root = lock("leanprover/lean4:v4.32.0", sha(20), sha(21), sha(2));
        assert_ne!(first.identity(), another_root.identity());
        assert_eq!(
            LakeEnvironmentResolutionKeyV1::from_lock(&first),
            LakeEnvironmentResolutionKeyV1::from_lock(&another_root)
        );
    }

    #[test]
    fn resolution_changes_with_toolchain_or_graph() {
        let first = lock("leanprover/lean4:v4.32.0", sha(8), sha(9), sha(2));
        let another_toolchain = lock("leanprover/lean4:v4.33.0", sha(20), sha(21), sha(2));
        assert_ne!(
            LakeEnvironmentResolutionKeyV1::from_lock(&first),
            LakeEnvironmentResolutionKeyV1::from_lock(&another_toolchain)
        );

        let changed_graph = lock("leanprover/lean4:v4.32.0", sha(20), sha(21), sha(22));
        assert_ne!(
            LakeEnvironmentResolutionKeyV1::from_lock(&first),
            LakeEnvironmentResolutionKeyV1::from_lock(&changed_graph)
        );
    }
}
