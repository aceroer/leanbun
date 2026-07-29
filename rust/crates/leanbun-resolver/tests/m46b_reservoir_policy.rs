use leanbun_core::Sha256;
use leanbun_lock::{
    CanonicalSourceUrlV1, PackageKeyV1, ReservoirBindingV1, ReservoirRegistryIdentityV1,
};
use leanbun_resolver::{
    ReservoirBindingOutcomeV1, ReservoirPolicyErrorKindV1, ReservoirRebindAuthorizationV1,
    evaluate_reservoir_binding_v1,
};

#[derive(Clone)]
struct Facts {
    registry: Sha256,
    package: String,
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
        .unwrap_or_else(|error| panic!("SHA failed: {error}"))
}

fn revision(byte: u8) -> String {
    format!("{:02x}", byte).repeat(20)
}

fn facts() -> Facts {
    Facts {
        registry: sha(1),
        package: "mathlib".to_owned(),
        version: "v4.32.0".to_owned(),
        metadata: sha(2),
        url: "https://github.com/leanprover-community/mathlib4".to_owned(),
        commit: revision(3),
        download: sha(4),
        tree: sha(5),
        selected: sha(6),
    }
}

fn binding(value: &Facts) -> ReservoirBindingV1 {
    ReservoirBindingV1::new(
        ReservoirRegistryIdentityV1::new(value.registry),
        PackageKeyV1::new("", value.package.clone())
            .unwrap_or_else(|error| panic!("key failed: {error}")),
        value.version.clone(),
        value.metadata,
        CanonicalSourceUrlV1::parse(value.url.clone())
            .unwrap_or_else(|error| panic!("URL failed: {error}")),
        value.commit.clone(),
        value.download,
        value.tree,
        value.selected,
    )
    .unwrap_or_else(|error| panic!("binding failed: {error}"))
}

#[test]
fn first_resolution_is_pending_and_never_accepted_by_rebind_authority() {
    let candidate = binding(&facts());
    assert_eq!(
        evaluate_reservoir_binding_v1(None, std::slice::from_ref(&candidate), None)
            .unwrap_or_else(|error| panic!("evaluation failed: {error}")),
        ReservoirBindingOutcomeV1::FirstResolutionPending {
            proposed_binding_identity: candidate.identity(),
        }
    );
    assert!(matches!(
        evaluate_reservoir_binding_v1(None, &[], None)
            .unwrap_or_else(|error| panic!("evaluation failed: {error}")),
        ReservoirBindingOutcomeV1::DisappearedBinding {
            active_binding_identity: None
        }
    ));
}

#[test]
fn stable_metadata_content_rebound_disappeared_and_ambiguous_are_distinct() {
    let base_facts = facts();
    let active = binding(&base_facts);
    assert!(matches!(
        evaluate_reservoir_binding_v1(Some(&active), std::slice::from_ref(&active), None)
            .unwrap_or_else(|error| panic!("stable failed: {error}")),
        ReservoirBindingOutcomeV1::StableBinding { .. }
    ));

    let mut metadata = base_facts.clone();
    metadata.metadata = sha(10);
    assert!(matches!(
        evaluate_reservoir_binding_v1(Some(&active), &[binding(&metadata)], None)
            .unwrap_or_else(|error| panic!("metadata failed: {error}")),
        ReservoirBindingOutcomeV1::MetadataDrift { .. }
    ));

    let mut content = base_facts.clone();
    content.tree = sha(11);
    assert!(matches!(
        evaluate_reservoir_binding_v1(Some(&active), &[binding(&content)], None)
            .unwrap_or_else(|error| panic!("content failed: {error}")),
        ReservoirBindingOutcomeV1::ContentMismatch { .. }
    ));

    let mut rebound = base_facts;
    rebound.commit = revision(12);
    assert!(matches!(
        evaluate_reservoir_binding_v1(Some(&active), &[binding(&rebound)], None)
            .unwrap_or_else(|error| panic!("rebound failed: {error}")),
        ReservoirBindingOutcomeV1::VersionRebound { .. }
    ));
    assert!(matches!(
        evaluate_reservoir_binding_v1(Some(&active), &[], None)
            .unwrap_or_else(|error| panic!("disappeared failed: {error}")),
        ReservoirBindingOutcomeV1::DisappearedBinding { .. }
    ));
    assert_eq!(
        evaluate_reservoir_binding_v1(Some(&active), &[active.clone(), active.clone()], None)
            .unwrap_or_else(|error| panic!("ambiguous failed: {error}")),
        ReservoirBindingOutcomeV1::AmbiguousCandidates {
            observation_count: 2
        }
    );
}

#[test]
fn ordinary_update_cannot_accept_rebound_but_exact_authorization_can() {
    let base = facts();
    let active = binding(&base);
    let mut changed = base;
    changed.commit = revision(20);
    changed.metadata = sha(21);
    changed.download = sha(22);
    changed.tree = sha(23);
    changed.selected = sha(24);
    let proposed = binding(&changed);
    assert!(matches!(
        evaluate_reservoir_binding_v1(Some(&active), std::slice::from_ref(&proposed), None)
            .unwrap_or_else(|error| panic!("ordinary update failed: {error}")),
        ReservoirBindingOutcomeV1::VersionRebound { .. }
    ));
    let authorization = ReservoirRebindAuthorizationV1::new(&active, &proposed)
        .unwrap_or_else(|error| panic!("authorization failed: {error}"));
    assert_eq!(
        evaluate_reservoir_binding_v1(
            Some(&active),
            std::slice::from_ref(&proposed),
            Some(&authorization),
        )
        .unwrap_or_else(|error| panic!("authorized evaluation failed: {error}")),
        ReservoirBindingOutcomeV1::ExplicitRebindAccepted {
            authorization_identity: authorization.identity(),
            proposed_binding_identity: proposed.identity(),
        }
    );
}

#[test]
fn stale_authorization_and_cross_scope_observation_fail_closed() {
    let base = facts();
    let active = binding(&base);
    let mut changed = base.clone();
    changed.commit = revision(30);
    let proposed = binding(&changed);
    let authorization = ReservoirRebindAuthorizationV1::new(&active, &proposed)
        .unwrap_or_else(|error| panic!("authorization failed: {error}"));
    changed.metadata = sha(31);
    let later = binding(&changed);
    assert_eq!(
        evaluate_reservoir_binding_v1(Some(&active), &[later], Some(&authorization))
            .map_err(|error| error.kind),
        Err(ReservoirPolicyErrorKindV1::InvalidAuthorization)
    );

    let mut other_scope = base;
    other_scope.version = "v4.33.0".to_owned();
    assert_eq!(
        evaluate_reservoir_binding_v1(Some(&active), &[binding(&other_scope)], None)
            .map_err(|error| error.kind),
        Err(ReservoirPolicyErrorKindV1::InvalidScope)
    );
}
