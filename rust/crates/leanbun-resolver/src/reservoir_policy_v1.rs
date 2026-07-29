use core::fmt;
use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_lock::{PackageKeyV1, ReservoirBindingV1, ReservoirRegistryIdentityV1};

pub const MAX_RESERVOIR_OBSERVATIONS_V1: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservoirPolicyErrorKindV1 {
    InvalidScope,
    InvalidAuthorization,
    LimitExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservoirPolicyErrorV1 {
    pub kind: ReservoirPolicyErrorKindV1,
    pub message: String,
}

impl ReservoirPolicyErrorV1 {
    fn new(kind: ReservoirPolicyErrorKindV1, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for ReservoirPolicyErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ReservoirPolicyErrorV1 {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservoirRebindAuthorizationV1 {
    registry: ReservoirRegistryIdentityV1,
    package: PackageKeyV1,
    requested_version: String,
    old_commit: String,
    new_commit: String,
    observed_metadata_sha256: Sha256,
    active_binding_identity: Sha256,
    proposed_binding_identity: Sha256,
    identity: Sha256,
}

impl ReservoirRebindAuthorizationV1 {
    pub fn new(
        active: &ReservoirBindingV1,
        proposed: &ReservoirBindingV1,
    ) -> Result<Self, ReservoirPolicyErrorV1> {
        require_same_scope(active, proposed)?;
        if active.exact_commit() == proposed.exact_commit() {
            return Err(ReservoirPolicyErrorV1::new(
                ReservoirPolicyErrorKindV1::InvalidAuthorization,
                "explicit Reservoir rebind requires a changed exact commit",
            ));
        }
        let identity = authorization_identity(active, proposed);
        Ok(Self {
            registry: active.registry(),
            package: active.package().clone(),
            requested_version: active.requested_version().to_owned(),
            old_commit: active.exact_commit().to_owned(),
            new_commit: proposed.exact_commit().to_owned(),
            observed_metadata_sha256: proposed.metadata_sha256(),
            active_binding_identity: active.identity(),
            proposed_binding_identity: proposed.identity(),
            identity,
        })
    }

    #[must_use]
    pub const fn identity(&self) -> Sha256 {
        self.identity
    }

    fn matches(&self, active: &ReservoirBindingV1, proposed: &ReservoirBindingV1) -> bool {
        self.registry == active.registry()
            && self.registry == proposed.registry()
            && self.package == *active.package()
            && self.package == *proposed.package()
            && self.requested_version == active.requested_version()
            && self.requested_version == proposed.requested_version()
            && self.old_commit == active.exact_commit()
            && self.new_commit == proposed.exact_commit()
            && self.observed_metadata_sha256 == proposed.metadata_sha256()
            && self.active_binding_identity == active.identity()
            && self.proposed_binding_identity == proposed.identity()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReservoirBindingOutcomeV1 {
    FirstResolutionPending {
        proposed_binding_identity: Sha256,
    },
    StableBinding {
        active_binding_identity: Sha256,
    },
    AmbiguousCandidates {
        observation_count: usize,
    },
    MetadataDrift {
        active_binding_identity: Sha256,
        observed_metadata_sha256: Sha256,
    },
    VersionRebound {
        active_binding_identity: Sha256,
        proposed_binding_identity: Sha256,
    },
    DisappearedBinding {
        active_binding_identity: Option<Sha256>,
    },
    ContentMismatch {
        active_binding_identity: Sha256,
        proposed_binding_identity: Sha256,
    },
    ExplicitRebindAccepted {
        authorization_identity: Sha256,
        proposed_binding_identity: Sha256,
    },
}

pub fn evaluate_reservoir_binding_v1(
    active: Option<&ReservoirBindingV1>,
    observations: &[ReservoirBindingV1],
    authorization: Option<&ReservoirRebindAuthorizationV1>,
) -> Result<ReservoirBindingOutcomeV1, ReservoirPolicyErrorV1> {
    if observations.len() > MAX_RESERVOIR_OBSERVATIONS_V1 {
        return Err(ReservoirPolicyErrorV1::new(
            ReservoirPolicyErrorKindV1::LimitExceeded,
            "Reservoir observation count exceeds limit",
        ));
    }
    let Some(active) = active else {
        if authorization.is_some() {
            return Err(ReservoirPolicyErrorV1::new(
                ReservoirPolicyErrorKindV1::InvalidAuthorization,
                "explicit rebind authorization cannot create a first binding",
            ));
        }
        return Ok(match observations {
            [] => ReservoirBindingOutcomeV1::DisappearedBinding {
                active_binding_identity: None,
            },
            [proposed] => ReservoirBindingOutcomeV1::FirstResolutionPending {
                proposed_binding_identity: proposed.identity(),
            },
            _ => ReservoirBindingOutcomeV1::AmbiguousCandidates {
                observation_count: observations.len(),
            },
        });
    };

    for observation in observations {
        require_same_scope(active, observation)?;
    }
    let [proposed] = observations else {
        if authorization.is_some() {
            return Err(ReservoirPolicyErrorV1::new(
                ReservoirPolicyErrorKindV1::InvalidAuthorization,
                "explicit rebind authorization requires one unambiguous observation",
            ));
        }
        return Ok(if observations.is_empty() {
            ReservoirBindingOutcomeV1::DisappearedBinding {
                active_binding_identity: Some(active.identity()),
            }
        } else {
            ReservoirBindingOutcomeV1::AmbiguousCandidates {
                observation_count: observations.len(),
            }
        });
    };

    if proposed.identity() == active.identity() {
        if authorization.is_some() {
            return Err(ReservoirPolicyErrorV1::new(
                ReservoirPolicyErrorKindV1::InvalidAuthorization,
                "explicit rebind authorization cannot be applied to a stable binding",
            ));
        }
        return Ok(ReservoirBindingOutcomeV1::StableBinding {
            active_binding_identity: active.identity(),
        });
    }
    if let Some(authorization) = authorization {
        if !authorization.matches(active, proposed) {
            return Err(ReservoirPolicyErrorV1::new(
                ReservoirPolicyErrorKindV1::InvalidAuthorization,
                "explicit rebind authorization does not match active and proposed bindings",
            ));
        }
        return Ok(ReservoirBindingOutcomeV1::ExplicitRebindAccepted {
            authorization_identity: authorization.identity(),
            proposed_binding_identity: proposed.identity(),
        });
    }
    if active.exact_commit() != proposed.exact_commit() {
        return Ok(ReservoirBindingOutcomeV1::VersionRebound {
            active_binding_identity: active.identity(),
            proposed_binding_identity: proposed.identity(),
        });
    }
    if active.resolved_url() != proposed.resolved_url()
        || active.download_integrity() != proposed.download_integrity()
        || active.source_tree_sha256() != proposed.source_tree_sha256()
        || active.selected_source_identity() != proposed.selected_source_identity()
    {
        return Ok(ReservoirBindingOutcomeV1::ContentMismatch {
            active_binding_identity: active.identity(),
            proposed_binding_identity: proposed.identity(),
        });
    }
    Ok(ReservoirBindingOutcomeV1::MetadataDrift {
        active_binding_identity: active.identity(),
        observed_metadata_sha256: proposed.metadata_sha256(),
    })
}

fn require_same_scope(
    active: &ReservoirBindingV1,
    proposed: &ReservoirBindingV1,
) -> Result<(), ReservoirPolicyErrorV1> {
    if active.registry() != proposed.registry()
        || active.package() != proposed.package()
        || active.requested_version() != proposed.requested_version()
    {
        return Err(ReservoirPolicyErrorV1::new(
            ReservoirPolicyErrorKindV1::InvalidScope,
            "Reservoir observation differs in registry, package or requested version scope",
        ));
    }
    Ok(())
}

fn authorization_identity(active: &ReservoirBindingV1, proposed: &ReservoirBindingV1) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-reservoir-rebind-authorization-v1\0");
    hasher.update(active.registry().sha256().as_bytes());
    hash_string(&mut hasher, active.package().scope());
    hash_string(&mut hasher, active.package().name());
    hash_string(&mut hasher, active.requested_version());
    hash_string(&mut hasher, active.exact_commit());
    hash_string(&mut hasher, proposed.exact_commit());
    hasher.update(proposed.metadata_sha256().as_bytes());
    hasher.update(active.identity().as_bytes());
    hasher.update(proposed.identity().as_bytes());
    hasher.finalize()
}

fn hash_string(hasher: &mut Sha256Hasher, value: &str) {
    hasher.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value.as_bytes());
}
