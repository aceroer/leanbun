use leanbun_core::Sha256;
use leanbun_lock::{
    CanonicalSourceUrlV1, LeanBunLockV1, LockedLeanPackageV1, PackageKeyV1,
    RequestedPackageSourceV1, ReservoirBindingDocumentV1, ReservoirBindingV1,
    ReservoirBindingV1ErrorKind, ReservoirRegistryIdentityV1, ResolvedPackageSourceV1,
};
use std::collections::BTreeSet;

#[derive(Clone)]
struct Facts {
    registry: Sha256,
    scope: String,
    name: String,
    version: String,
    metadata: Sha256,
    url: String,
    commit: String,
    download: Sha256,
    tree: Sha256,
    selected: Sha256,
}

fn sha(byte: u8) -> Sha256 {
    Sha256::parse(&format!("{:02x}", byte).repeat(32))
        .unwrap_or_else(|error| panic!("test SHA failed: {error}"))
}

fn revision(byte: u8) -> String {
    format!("{:02x}", byte).repeat(20)
}

fn facts() -> Facts {
    Facts {
        registry: sha(1),
        scope: String::new(),
        name: "mathlib".to_owned(),
        version: "v4.32.0".to_owned(),
        metadata: sha(2),
        url: "https://github.com/leanprover-community/mathlib4".to_owned(),
        commit: revision(3),
        download: sha(4),
        tree: sha(5),
        selected: sha(6),
    }
}

fn binding(facts: &Facts) -> ReservoirBindingV1 {
    ReservoirBindingV1::new(
        ReservoirRegistryIdentityV1::new(facts.registry),
        PackageKeyV1::new(facts.scope.clone(), facts.name.clone())
            .unwrap_or_else(|error| panic!("package key failed: {error}")),
        facts.version.clone(),
        facts.metadata,
        CanonicalSourceUrlV1::parse(facts.url.clone())
            .unwrap_or_else(|error| panic!("URL failed: {error}")),
        facts.commit.clone(),
        facts.download,
        facts.tree,
        facts.selected,
    )
    .unwrap_or_else(|error| panic!("binding failed: {error}"))
}

fn lock(facts: &Facts, root_config: Sha256) -> LeanBunLockV1 {
    let key = PackageKeyV1::new(facts.scope.clone(), facts.name.clone())
        .unwrap_or_else(|error| panic!("package key failed: {error}"));
    let url = CanonicalSourceUrlV1::parse(facts.url.clone())
        .unwrap_or_else(|error| panic!("URL failed: {error}"));
    let package = LockedLeanPackageV1::new(
        key,
        RequestedPackageSourceV1::git(url.clone(), Some(facts.version.clone()))
            .unwrap_or_else(|error| panic!("request failed: {error}")),
        ResolvedPackageSourceV1::git(url, facts.commit.clone(), None)
            .unwrap_or_else(|error| panic!("resolution failed: {error}")),
        Some(facts.download),
        facts.tree,
        sha(7),
        Some(sha(8)),
        Vec::new(),
        vec![sha(9)],
        facts.selected,
    )
    .unwrap_or_else(|error| panic!("package failed: {error}"));
    LeanBunLockV1::new(
        "leanprover/lean4:v4.32.0",
        revision(10),
        "5.0.0",
        root_config,
        sha(11),
        vec![package],
    )
    .unwrap_or_else(|error| panic!("lock failed: {error}"))
}

#[test]
fn companion_round_trips_and_binds_the_exact_v1_lock_without_rewriting_it() {
    let facts = facts();
    let lock = lock(&facts, sha(12));
    let lock_text = lock.to_canonical_text();
    let document = ReservoirBindingDocumentV1::new(&lock, vec![binding(&facts)])
        .unwrap_or_else(|error| panic!("document failed: {error}"));
    let text = document.to_canonical_text();
    let decoded = ReservoirBindingDocumentV1::from_canonical_text(&text, &lock)
        .unwrap_or_else(|error| panic!("decode failed: {error}"));

    assert_eq!(decoded, document);
    assert_eq!(document.lock_v1_identity(), lock.identity());
    assert_eq!(lock.to_canonical_text(), lock_text);
    assert!(text.starts_with("leanbun-reservoir-bindings-v1\t1\n"));
}

#[test]
fn every_binding_authority_field_changes_the_binding_identity() {
    let base = facts();
    let mut variants = Vec::new();
    variants.push(base.clone());
    for changed in [1_u8, 2, 3, 4, 5] {
        let mut value = base.clone();
        match changed {
            1 => value.registry = sha(21),
            2 => value.metadata = sha(22),
            3 => value.download = sha(23),
            4 => value.tree = sha(24),
            _ => value.selected = sha(25),
        }
        variants.push(value);
    }
    let mut version = base.clone();
    version.version = "v4.32.1".to_owned();
    variants.push(version);
    let mut package = base.clone();
    package.name = "mathlib-alt".to_owned();
    variants.push(package);
    let mut url = base.clone();
    url.url = "https://github.com/leanprover-community/mathlib4-mirror".to_owned();
    variants.push(url);
    let mut commit = base;
    commit.commit = revision(26);
    variants.push(commit);

    let identities = variants
        .iter()
        .map(|value| binding(value).identity())
        .collect::<BTreeSet<_>>();
    assert_eq!(identities.len(), variants.len());
}

#[test]
fn companion_rejects_duplicate_missing_and_exact_lock_fact_drift() {
    let base = facts();
    let lock = lock(&base, sha(12));
    let valid = binding(&base);
    assert_eq!(
        ReservoirBindingDocumentV1::new(&lock, vec![valid.clone(), valid])
            .map_err(|error| error.kind),
        Err(ReservoirBindingV1ErrorKind::DuplicatePackage)
    );

    let mut missing = base.clone();
    missing.name = "absent".to_owned();
    assert_eq!(
        ReservoirBindingDocumentV1::new(&lock, vec![binding(&missing)]).map_err(|error| error.kind),
        Err(ReservoirBindingV1ErrorKind::MissingPackage)
    );

    let mut drifted = Vec::new();
    for changed in [1_u8, 2, 3, 4, 5] {
        let mut value = base.clone();
        match changed {
            1 => value.url = "https://github.com/leanbun/other".to_owned(),
            2 => value.commit = revision(31),
            3 => value.download = sha(32),
            4 => value.tree = sha(33),
            _ => value.selected = sha(34),
        }
        drifted.push(value);
    }
    for value in drifted {
        assert_eq!(
            ReservoirBindingDocumentV1::new(&lock, vec![binding(&value)])
                .map_err(|error| error.kind),
            Err(ReservoirBindingV1ErrorKind::IncompatibleLock)
        );
    }
}

#[test]
fn strict_reader_rejects_digest_drift_wrong_lock_and_trailing_content() {
    let facts = facts();
    let active_lock = lock(&facts, sha(12));
    let document = ReservoirBindingDocumentV1::new(&active_lock, vec![binding(&facts)])
        .unwrap_or_else(|error| panic!("document failed: {error}"));
    let text = document.to_canonical_text();
    let metadata_drift = text.replace(
        &format!("metadata-sha256\t{}", facts.metadata),
        &format!("metadata-sha256\t{}", sha(40)),
    );
    assert_eq!(
        ReservoirBindingDocumentV1::from_canonical_text(&metadata_drift, &active_lock)
            .map_err(|error| error.kind),
        Err(ReservoirBindingV1ErrorKind::DigestMismatch)
    );

    let other_lock = lock(&facts, sha(41));
    assert_eq!(
        ReservoirBindingDocumentV1::from_canonical_text(&text, &other_lock)
            .map_err(|error| error.kind),
        Err(ReservoirBindingV1ErrorKind::IncompatibleLock)
    );
    assert_eq!(
        ReservoirBindingDocumentV1::from_canonical_text(
            &format!("{text}trailing\n"),
            &active_lock,
        )
            .map_err(|error| error.kind),
        Err(ReservoirBindingV1ErrorKind::NonCanonicalText)
    );
}
