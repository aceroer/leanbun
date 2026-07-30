use crate::{
    CanonicalSourceUrlV1, LeanBunLockV1Error, LockedLeanPackageV1, ResolvedPackageSourceV1,
};
use leanbun_core::{Sha256, Sha256Hasher};

/// Provenance-preserving identity of one immutable Git package source.
///
/// Package names and environment identities are deliberately excluded. Two
/// environments may reuse a source only when this exact identity agrees.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackageSourceKeyV1(Sha256);

impl PackageSourceKeyV1 {
    pub fn from_git(
        url: &CanonicalSourceUrlV1,
        exact_revision: &str,
        subdir: Option<&str>,
        source_tree_sha256: Sha256,
    ) -> Result<Self, LeanBunLockV1Error> {
        ResolvedPackageSourceV1::git(
            url.clone(),
            exact_revision.to_owned(),
            subdir.map(str::to_owned),
        )?;
        Ok(Self(hash_git(
            url,
            exact_revision,
            subdir,
            source_tree_sha256,
        )))
    }

    #[must_use]
    pub fn from_resolved_source(
        source: &ResolvedPackageSourceV1,
        source_tree_sha256: Sha256,
    ) -> Option<Self> {
        match source {
            ResolvedPackageSourceV1::Git {
                url,
                exact_revision,
                subdir,
            } => Some(Self(hash_git(
                url,
                exact_revision,
                subdir.as_deref(),
                source_tree_sha256,
            ))),
            ResolvedPackageSourceV1::PathSnapshot { .. } => None,
        }
    }

    #[must_use]
    pub fn from_locked_package(package: &LockedLeanPackageV1) -> Option<Self> {
        Self::from_resolved_source(package.resolved_source(), package.source_tree_sha256())
    }

    #[must_use]
    pub const fn digest(self) -> Sha256 {
        self.0
    }
}

fn hash_git(
    url: &CanonicalSourceUrlV1,
    exact_revision: &str,
    subdir: Option<&str>,
    source_tree_sha256: Sha256,
) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-package-source-v1\0");
    hash_string(&mut hasher, url.as_str());
    hash_string(&mut hasher, exact_revision);
    match subdir {
        Some(value) => {
            hasher.update(&[1]);
            hash_string(&mut hasher, value);
        }
        None => hasher.update(&[0]),
    }
    hasher.update(source_tree_sha256.as_bytes());
    hasher.finalize()
}

fn hash_string(hasher: &mut Sha256Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PackageKeyV1, RequestedPackageSourceV1};

    fn sha(byte: u8) -> Sha256 {
        Sha256::from_bytes([byte; 32])
    }

    fn url(value: &str) -> CanonicalSourceUrlV1 {
        CanonicalSourceUrlV1::parse(value)
            .unwrap_or_else(|error| panic!("fixture URL failed: {error}"))
    }

    #[test]
    fn binds_url_commit_subdir_and_tree_but_not_package_name() {
        let source_url = url("https://github.com/example/package");
        let first = PackageSourceKeyV1::from_git(
            &source_url,
            "1111111111111111111111111111111111111111",
            Some("lean"),
            sha(1),
        )
        .unwrap_or_else(|error| panic!("source key failed: {error}"));
        for changed in [
            PackageSourceKeyV1::from_git(
                &url("https://github.com/example/other"),
                "1111111111111111111111111111111111111111",
                Some("lean"),
                sha(1),
            ),
            PackageSourceKeyV1::from_git(
                &source_url,
                "2222222222222222222222222222222222222222",
                Some("lean"),
                sha(1),
            ),
            PackageSourceKeyV1::from_git(
                &source_url,
                "1111111111111111111111111111111111111111",
                Some("other"),
                sha(1),
            ),
            PackageSourceKeyV1::from_git(
                &source_url,
                "1111111111111111111111111111111111111111",
                Some("lean"),
                sha(2),
            ),
        ] {
            let changed = changed.unwrap_or_else(|error| panic!("changed key failed: {error}"));
            assert_ne!(first, changed);
        }

        let package = LockedLeanPackageV1::new(
            PackageKeyV1::new("", "renamed")
                .unwrap_or_else(|error| panic!("package key failed: {error}")),
            RequestedPackageSourceV1::git(source_url.clone(), None)
                .unwrap_or_else(|error| panic!("requested source failed: {error}")),
            ResolvedPackageSourceV1::git(
                source_url,
                "1111111111111111111111111111111111111111",
                Some("lean".to_owned()),
            )
            .unwrap_or_else(|error| panic!("resolved source failed: {error}")),
            Some(sha(3)),
            sha(1),
            sha(4),
            None,
            Vec::new(),
            vec![sha(5)],
            sha(6),
        )
        .unwrap_or_else(|error| panic!("locked package failed: {error}"));
        assert_eq!(
            PackageSourceKeyV1::from_locked_package(&package),
            Some(first)
        );
    }

    #[test]
    fn path_snapshots_are_not_global_package_source_keys() {
        let source = ResolvedPackageSourceV1::path_snapshot("vendor/local")
            .unwrap_or_else(|error| panic!("path source failed: {error}"));
        assert_eq!(
            PackageSourceKeyV1::from_resolved_source(&source, sha(1)),
            None
        );
    }
}
