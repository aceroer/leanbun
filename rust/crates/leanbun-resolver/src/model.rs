use core::fmt;
use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_lake_bridge::{LakeDependencySourceV1, LakeRootDeclarationV1, LakeRootDependencyV1};
use leanbun_lock::{
    CanonicalSourceUrlV1, LeanBunLockV1, LockedLeanPackageV1, PackageKeyV1,
    RequestedPackageSourceV1, ResolvedPackageSourceV1,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_PACKAGES_V1: usize = 4_096;
const MAX_DEPENDENCIES_V1: usize = 4_096;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_GRAPH_DEPTH_V1: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeanResolutionErrorKind {
    InvalidField,
    LimitExceeded,
    ActiveLockRequired,
    ActiveLockMismatch,
    DuplicateCandidateIdentity,
    DuplicateUpdateTarget,
    UnknownUpdateTarget,
    MissingTransitiveDeclaration,
    AmbiguousCandidate,
    SourceKindConflict,
    SourceValueConflict,
    ToolchainCandidateConflict,
    DependencyCycle,
    GraphTooDeep,
    FrozenGraphDrift,
    UpdateEscapesImpactClosure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeanResolutionError {
    pub kind: LeanResolutionErrorKind,
    pub message: String,
    pub conflict: Option<Box<LeanResolutionConflictV1>>,
}

impl LeanResolutionError {
    fn new(kind: LeanResolutionErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            conflict: None,
        }
    }

    fn with_conflict(
        kind: LeanResolutionErrorKind,
        message: impl Into<String>,
        conflict: LeanResolutionConflictV1,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            conflict: Some(Box::new(conflict)),
        }
    }
}

impl fmt::Display for LeanResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for LeanResolutionError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeanToolchainIdentityV1 {
    lean_toolchain: String,
    compiler_githash: String,
    lake_version: String,
}

impl LeanToolchainIdentityV1 {
    pub fn new(
        lean_toolchain: impl Into<String>,
        compiler_githash: impl Into<String>,
        lake_version: impl Into<String>,
    ) -> Result<Self, LeanResolutionError> {
        let lean_toolchain = lean_toolchain.into();
        let compiler_githash = compiler_githash.into();
        let lake_version = lake_version.into();
        validate_text(&lean_toolchain, "Lean toolchain")?;
        validate_exact_revision(&compiler_githash)?;
        validate_text(&lake_version, "Lake version")?;
        Ok(Self {
            lean_toolchain,
            compiler_githash,
            lake_version,
        })
    }

    #[must_use]
    pub fn lean_toolchain(&self) -> &str {
        &self.lean_toolchain
    }
    #[must_use]
    pub fn compiler_githash(&self) -> &str {
        &self.compiler_githash
    }
    #[must_use]
    pub fn lake_version(&self) -> &str {
        &self.lake_version
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeanSourceRequestV1 {
    Git {
        url: CanonicalSourceUrlV1,
        revision: Option<String>,
        subdir: Option<String>,
    },
    Reservoir {
        version: Option<String>,
    },
    Path {
        portable_path_token: String,
    },
}

impl LeanSourceRequestV1 {
    pub fn git(
        url: CanonicalSourceUrlV1,
        revision: Option<String>,
        subdir: Option<String>,
    ) -> Result<Self, LeanResolutionError> {
        if let Some(value) = revision.as_deref() {
            validate_text(value, "requested Git revision")?;
        }
        if let Some(value) = subdir.as_deref() {
            validate_relative_path(value, "requested Git subdirectory")?;
        }
        Ok(Self::Git {
            url,
            revision,
            subdir,
        })
    }

    pub fn reservoir(version: Option<String>) -> Result<Self, LeanResolutionError> {
        if let Some(value) = version.as_deref() {
            validate_text(value, "Reservoir version")?;
        }
        Ok(Self::Reservoir { version })
    }

    pub fn path(token: impl Into<String>) -> Result<Self, LeanResolutionError> {
        let portable_path_token = token.into();
        validate_relative_path(&portable_path_token, "path source token")?;
        Ok(Self::Path {
            portable_path_token,
        })
    }

    fn from_root(dependency: &LakeRootDependencyV1) -> Result<Self, LeanResolutionError> {
        match dependency.source() {
            LakeDependencySourceV1::Git {
                url,
                revision,
                subdir,
            } => Self::git(
                CanonicalSourceUrlV1::parse(url.clone())
                    .map_err(|error| invalid(error.to_string()))?,
                revision.clone(),
                subdir.clone(),
            ),
            LakeDependencySourceV1::Path { directory } => Self::path(directory.clone()),
            LakeDependencySourceV1::Reservoir => {
                Self::reservoir(dependency.version().map(str::to_owned))
            }
        }
    }

    fn kind_tag(&self) -> u8 {
        match self {
            Self::Git { .. } => 1,
            Self::Reservoir { .. } => 2,
            Self::Path { .. } => 3,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeanExactSourceV1 {
    Git {
        url: CanonicalSourceUrlV1,
        exact_revision: String,
        subdir: Option<String>,
    },
    Path {
        portable_path_token: String,
        source_identity: Sha256,
    },
}

impl LeanExactSourceV1 {
    pub fn git(
        url: CanonicalSourceUrlV1,
        exact_revision: impl Into<String>,
        subdir: Option<String>,
    ) -> Result<Self, LeanResolutionError> {
        let exact_revision = exact_revision.into();
        validate_exact_revision(&exact_revision)?;
        if let Some(value) = subdir.as_deref() {
            validate_relative_path(value, "resolved Git subdirectory")?;
        }
        Ok(Self::Git {
            url,
            exact_revision,
            subdir,
        })
    }

    pub fn path(
        token: impl Into<String>,
        source_identity: Sha256,
    ) -> Result<Self, LeanResolutionError> {
        let portable_path_token = token.into();
        validate_relative_path(&portable_path_token, "resolved path source token")?;
        Ok(Self::Path {
            portable_path_token,
            source_identity,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeanDependencyRequirementV1 {
    key: PackageKeyV1,
    source: LeanSourceRequestV1,
}

impl LeanDependencyRequirementV1 {
    #[must_use]
    pub fn new(key: PackageKeyV1, source: LeanSourceRequestV1) -> Self {
        Self { key, source }
    }
    #[must_use]
    pub fn key(&self) -> &PackageKeyV1 {
        &self.key
    }
    #[must_use]
    pub const fn source(&self) -> &LeanSourceRequestV1 {
        &self.source
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeanPackageCandidateV1 {
    key: PackageKeyV1,
    requested: LeanSourceRequestV1,
    resolved: LeanExactSourceV1,
    dependencies: Vec<LeanDependencyRequirementV1>,
    toolchain_candidate: Option<LeanToolchainIdentityV1>,
    download_integrity: Option<Sha256>,
    source_tree_sha256: Sha256,
    config_sha256: Sha256,
    manifest_sha256: Option<Sha256>,
    selected_source_identity: Sha256,
    identity: Sha256,
}

impl LeanPackageCandidateV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: PackageKeyV1,
        requested: LeanSourceRequestV1,
        resolved: LeanExactSourceV1,
        dependencies: Vec<LeanDependencyRequirementV1>,
        toolchain_candidate: Option<LeanToolchainIdentityV1>,
        download_integrity: Option<Sha256>,
        source_tree_sha256: Sha256,
        config_sha256: Sha256,
        manifest_sha256: Option<Sha256>,
        selected_source_identity: Sha256,
    ) -> Result<Self, LeanResolutionError> {
        if dependencies.len() > MAX_DEPENDENCIES_V1 {
            return Err(limit("candidate dependency count exceeds limit"));
        }
        validate_source_pair(
            &requested,
            &resolved,
            download_integrity,
            selected_source_identity,
        )?;
        let identity = candidate_identity(
            &key,
            &requested,
            &resolved,
            &dependencies,
            toolchain_candidate.as_ref(),
            download_integrity,
            source_tree_sha256,
            config_sha256,
            manifest_sha256,
            selected_source_identity,
        );
        Ok(Self {
            key,
            requested,
            resolved,
            dependencies,
            toolchain_candidate,
            download_integrity,
            source_tree_sha256,
            config_sha256,
            manifest_sha256,
            selected_source_identity,
            identity,
        })
    }

    #[must_use]
    pub fn key(&self) -> &PackageKeyV1 {
        &self.key
    }
    #[must_use]
    pub const fn requested_source(&self) -> &LeanSourceRequestV1 {
        &self.requested
    }
    #[must_use]
    pub const fn resolved_source(&self) -> &LeanExactSourceV1 {
        &self.resolved
    }
    #[must_use]
    pub fn dependencies(&self) -> &[LeanDependencyRequirementV1] {
        &self.dependencies
    }
    #[must_use]
    pub const fn identity(&self) -> Sha256 {
        self.identity
    }
    #[must_use]
    pub const fn selected_source_identity(&self) -> Sha256 {
        self.selected_source_identity
    }
    #[must_use]
    pub const fn toolchain_candidate(&self) -> Option<&LeanToolchainIdentityV1> {
        self.toolchain_candidate.as_ref()
    }
    #[must_use]
    pub const fn download_integrity(&self) -> Option<Sha256> {
        self.download_integrity
    }
    #[must_use]
    pub const fn source_tree_sha256(&self) -> Sha256 {
        self.source_tree_sha256
    }
    #[must_use]
    pub const fn config_sha256(&self) -> Sha256 {
        self.config_sha256
    }
    #[must_use]
    pub const fn manifest_sha256(&self) -> Option<Sha256> {
        self.manifest_sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeanResolutionModeV1 {
    Frozen,
    Update { packages: Vec<PackageKeyV1> },
}

impl LeanResolutionModeV1 {
    pub fn update(mut packages: Vec<PackageKeyV1>) -> Result<Self, LeanResolutionError> {
        packages.sort();
        if packages.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(LeanResolutionError::new(
                LeanResolutionErrorKind::DuplicateUpdateTarget,
                "update set contains a duplicate package",
            ));
        }
        if packages.len() > MAX_PACKAGES_V1 {
            return Err(limit("update set exceeds package limit"));
        }
        Ok(Self::Update { packages })
    }

    fn update_set(&self) -> BTreeSet<&PackageKeyV1> {
        match self {
            Self::Frozen => BTreeSet::new(),
            Self::Update { packages } => packages.iter().collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeanResolutionRequestV1 {
    root: LakeRootDeclarationV1,
    active_lock: Option<LeanBunLockV1>,
    mode: LeanResolutionModeV1,
    toolchain: LeanToolchainIdentityV1,
}

impl LeanResolutionRequestV1 {
    pub fn new(
        root: LakeRootDeclarationV1,
        active_lock: Option<LeanBunLockV1>,
        mode: LeanResolutionModeV1,
        toolchain: LeanToolchainIdentityV1,
    ) -> Result<Self, LeanResolutionError> {
        if matches!(mode, LeanResolutionModeV1::Frozen) && active_lock.is_none() {
            return Err(LeanResolutionError::new(
                LeanResolutionErrorKind::ActiveLockRequired,
                "frozen resolution requires an active lock",
            ));
        }
        if let Some(lock) = active_lock.as_ref()
            && (lock.lean_toolchain() != toolchain.lean_toolchain()
                || lock.lean_compiler_githash() != toolchain.compiler_githash()
                || lock.lake_version() != toolchain.lake_version()
                || lock.root_declaration_sha256() != root.identity())
        {
            return Err(LeanResolutionError::new(
                LeanResolutionErrorKind::ActiveLockMismatch,
                "active lock differs from the requested root or toolchain identity",
            ));
        }
        Ok(Self {
            root,
            active_lock,
            mode,
            toolchain,
        })
    }

    #[must_use]
    pub const fn root(&self) -> &LakeRootDeclarationV1 {
        &self.root
    }
    #[must_use]
    pub const fn active_lock(&self) -> Option<&LeanBunLockV1> {
        self.active_lock.as_ref()
    }
    #[must_use]
    pub const fn mode(&self) -> &LeanResolutionModeV1 {
        &self.mode
    }
    #[must_use]
    pub const fn toolchain(&self) -> &LeanToolchainIdentityV1 {
        &self.toolchain
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LeanResolutionOriginV1 {
    Root {
        declaration_index: usize,
    },
    Package {
        package: PackageKeyV1,
        declaration_index: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeanShadowDecisionV1 {
    package: PackageKeyV1,
    selected_candidate: Sha256,
    winner: LeanResolutionOriginV1,
    shadowed: LeanResolutionOriginV1,
}

impl LeanShadowDecisionV1 {
    #[must_use]
    pub fn package(&self) -> &PackageKeyV1 {
        &self.package
    }
    #[must_use]
    pub const fn winner(&self) -> &LeanResolutionOriginV1 {
        &self.winner
    }
    #[must_use]
    pub const fn shadowed(&self) -> &LeanResolutionOriginV1 {
        &self.shadowed
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeanResolutionConflictV1 {
    pub package: PackageKeyV1,
    pub winner: LeanResolutionOriginV1,
    pub conflicting: LeanResolutionOriginV1,
    pub selected_candidate: Sha256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeanResolvedPackageV1 {
    candidate: LeanPackageCandidateV1,
    dependencies: Vec<PackageKeyV1>,
}

impl LeanResolvedPackageV1 {
    #[must_use]
    pub fn key(&self) -> &PackageKeyV1 {
        self.candidate.key()
    }
    #[must_use]
    pub const fn source(&self) -> &LeanExactSourceV1 {
        self.candidate.resolved_source()
    }
    #[must_use]
    pub fn dependencies(&self) -> &[PackageKeyV1] {
        &self.dependencies
    }
    #[must_use]
    pub const fn candidate_identity(&self) -> Sha256 {
        self.candidate.identity()
    }
    #[must_use]
    pub const fn candidate(&self) -> &LeanPackageCandidateV1 {
        &self.candidate
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeanResolutionGraphV1 {
    toolchain: LeanToolchainIdentityV1,
    root_declaration_identity: Sha256,
    packages: Vec<LeanResolvedPackageV1>,
    root_packages: Vec<PackageKeyV1>,
    resolution_order: Vec<PackageKeyV1>,
    shadows: Vec<LeanShadowDecisionV1>,
    impact_closure: Vec<PackageKeyV1>,
    identity: Sha256,
}

impl LeanResolutionGraphV1 {
    #[must_use]
    pub const fn toolchain(&self) -> &LeanToolchainIdentityV1 {
        &self.toolchain
    }
    #[must_use]
    pub const fn root_declaration_identity(&self) -> Sha256 {
        self.root_declaration_identity
    }
    #[must_use]
    pub fn packages(&self) -> &[LeanResolvedPackageV1] {
        &self.packages
    }
    #[must_use]
    pub fn root_packages(&self) -> &[PackageKeyV1] {
        &self.root_packages
    }
    #[must_use]
    pub fn resolution_order(&self) -> &[PackageKeyV1] {
        &self.resolution_order
    }
    #[must_use]
    pub fn shadows(&self) -> &[LeanShadowDecisionV1] {
        &self.shadows
    }
    #[must_use]
    pub fn impact_closure(&self) -> &[PackageKeyV1] {
        &self.impact_closure
    }
    #[must_use]
    pub const fn identity(&self) -> Sha256 {
        self.identity
    }
}

struct SelectedCandidate {
    candidate: LeanPackageCandidateV1,
    winner: LeanResolutionOriginV1,
}

pub fn resolve_lean_dependencies_v1(
    request: &LeanResolutionRequestV1,
    mut candidates: Vec<LeanPackageCandidateV1>,
) -> Result<LeanResolutionGraphV1, LeanResolutionError> {
    if candidates.len() > MAX_PACKAGES_V1 * 4 {
        return Err(limit("candidate registry exceeds limit"));
    }
    candidates.sort_by(|left, right| {
        left.key
            .cmp(&right.key)
            .then(left.identity.cmp(&right.identity))
    });
    if candidates
        .windows(2)
        .any(|pair| pair[0].identity == pair[1].identity)
    {
        return Err(LeanResolutionError::new(
            LeanResolutionErrorKind::DuplicateCandidateIdentity,
            "candidate registry contains a duplicate identity",
        ));
    }
    let mut registry = BTreeMap::<PackageKeyV1, Vec<LeanPackageCandidateV1>>::new();
    for candidate in candidates {
        registry
            .entry(candidate.key.clone())
            .or_default()
            .push(candidate);
    }
    let active = request.active_lock.as_ref().map(lock_map);
    let update_set = request.mode.update_set();
    let mut selected = BTreeMap::<PackageKeyV1, SelectedCandidate>::new();
    let mut queue = VecDeque::<PackageKeyV1>::new();
    let mut resolution_order = Vec::new();
    let mut root_packages = Vec::new();
    let mut shadows = Vec::new();

    let root_requirements = request
        .root
        .dependencies()
        .iter()
        .enumerate()
        .map(|(index, dependency)| {
            Ok((
                LeanDependencyRequirementV1::new(
                    dependency.key().clone(),
                    LeanSourceRequestV1::from_root(dependency)?,
                ),
                LeanResolutionOriginV1::Root {
                    declaration_index: index,
                },
            ))
        })
        .collect::<Result<Vec<_>, LeanResolutionError>>()?;
    for (requirement, origin) in root_requirements.into_iter().rev() {
        select_requirement(
            &requirement,
            origin,
            request,
            &registry,
            active.as_ref(),
            &update_set,
            &mut selected,
            &mut queue,
            &mut resolution_order,
            &mut shadows,
        )?;
        root_packages.push(requirement.key.clone());
    }

    while let Some(parent_key) = queue.pop_front() {
        let dependencies = selected
            .get(&parent_key)
            .ok_or_else(|| invalid("selected queue entry disappeared"))?
            .candidate
            .dependencies
            .clone();
        for (index, requirement) in dependencies.iter().enumerate().rev() {
            select_requirement(
                requirement,
                LeanResolutionOriginV1::Package {
                    package: parent_key.clone(),
                    declaration_index: index,
                },
                request,
                &registry,
                active.as_ref(),
                &update_set,
                &mut selected,
                &mut queue,
                &mut resolution_order,
                &mut shadows,
            )?;
        }
    }

    if selected.len() > MAX_PACKAGES_V1 {
        return Err(limit("resolved package closure exceeds limit"));
    }
    let mut packages = selected
        .into_values()
        .map(|selected| {
            let mut dependencies = selected
                .candidate
                .dependencies
                .iter()
                .map(|dependency| dependency.key.clone())
                .collect::<Vec<_>>();
            dependencies.sort();
            dependencies.dedup();
            LeanResolvedPackageV1 {
                candidate: selected.candidate,
                dependencies,
            }
        })
        .collect::<Vec<_>>();
    packages.sort_by(|left, right| left.key().cmp(right.key()));
    validate_cycles_and_depth(&packages)?;
    root_packages.sort();
    root_packages.dedup();
    shadows.sort_by(|left, right| {
        left.package
            .cmp(&right.package)
            .then(left.winner.cmp(&right.winner))
            .then(left.shadowed.cmp(&right.shadowed))
    });
    let impact_closure = validate_mode_result(request, &packages, &update_set)?;
    let identity = graph_identity(
        &request.toolchain,
        request.root.identity(),
        &packages,
        &root_packages,
        &resolution_order,
        &shadows,
        &impact_closure,
    );
    Ok(LeanResolutionGraphV1 {
        toolchain: request.toolchain.clone(),
        root_declaration_identity: request.root.identity(),
        packages,
        root_packages,
        resolution_order,
        shadows,
        impact_closure,
        identity,
    })
}

#[allow(clippy::too_many_arguments)]
fn select_requirement(
    requirement: &LeanDependencyRequirementV1,
    origin: LeanResolutionOriginV1,
    request: &LeanResolutionRequestV1,
    registry: &BTreeMap<PackageKeyV1, Vec<LeanPackageCandidateV1>>,
    active: Option<&BTreeMap<PackageKeyV1, &LockedLeanPackageV1>>,
    update_set: &BTreeSet<&PackageKeyV1>,
    selected: &mut BTreeMap<PackageKeyV1, SelectedCandidate>,
    queue: &mut VecDeque<PackageKeyV1>,
    resolution_order: &mut Vec<PackageKeyV1>,
    shadows: &mut Vec<LeanShadowDecisionV1>,
) -> Result<(), LeanResolutionError> {
    if let Some(existing) = selected.get(requirement.key()) {
        if !request_matches_candidate(requirement.source(), &existing.candidate) {
            let conflict = LeanResolutionConflictV1 {
                package: requirement.key.clone(),
                winner: existing.winner.clone(),
                conflicting: origin,
                selected_candidate: existing.candidate.identity,
            };
            return Err(LeanResolutionError::with_conflict(
                LeanResolutionErrorKind::SourceValueConflict,
                "shadowed dependency requirement is incompatible with the selected source",
                conflict,
            ));
        }
        shadows.push(LeanShadowDecisionV1 {
            package: requirement.key.clone(),
            selected_candidate: existing.candidate.identity,
            winner: existing.winner.clone(),
            shadowed: origin,
        });
        return Ok(());
    }
    let available = registry.get(requirement.key()).ok_or_else(|| {
        LeanResolutionError::new(
            LeanResolutionErrorKind::MissingTransitiveDeclaration,
            format!(
                "no supplied metadata for {}/{}",
                requirement.key.scope(),
                requirement.key.name()
            ),
        )
    })?;
    let pinned = active
        .and_then(|packages| packages.get(requirement.key()).copied())
        .filter(|_| !update_set.contains(requirement.key()));
    let matching = available
        .iter()
        .filter(|candidate| {
            request_matches_candidate(requirement.source(), candidate)
                && pinned.is_none_or(|package| candidate_matches_lock(candidate, package))
        })
        .collect::<Vec<_>>();
    if matching.is_empty() {
        let kind_match = available
            .iter()
            .any(|candidate| candidate.requested.kind_tag() == requirement.source.kind_tag());
        return Err(LeanResolutionError::new(
            if kind_match {
                LeanResolutionErrorKind::SourceValueConflict
            } else {
                LeanResolutionErrorKind::SourceKindConflict
            },
            format!(
                "supplied metadata cannot satisfy {}/{}{}",
                requirement.key.scope(),
                requirement.key.name(),
                if pinned.is_some() {
                    " at the active lock pin"
                } else {
                    ""
                }
            ),
        ));
    }
    if matching.len() != 1 {
        return Err(LeanResolutionError::new(
            LeanResolutionErrorKind::AmbiguousCandidate,
            format!(
                "multiple exact candidates satisfy {}/{}",
                requirement.key.scope(),
                requirement.key.name()
            ),
        ));
    }
    let candidate = matching[0].clone();
    if candidate
        .toolchain_candidate
        .as_ref()
        .is_some_and(|toolchain| toolchain != &request.toolchain)
    {
        return Err(LeanResolutionError::new(
            LeanResolutionErrorKind::ToolchainCandidateConflict,
            format!(
                "package {}/{} proposes a different toolchain",
                candidate.key.scope(),
                candidate.key.name()
            ),
        ));
    }
    resolution_order.push(candidate.key.clone());
    queue.push_back(candidate.key.clone());
    selected.insert(
        candidate.key.clone(),
        SelectedCandidate {
            candidate,
            winner: origin,
        },
    );
    Ok(())
}

fn validate_mode_result(
    request: &LeanResolutionRequestV1,
    packages: &[LeanResolvedPackageV1],
    update_set: &BTreeSet<&PackageKeyV1>,
) -> Result<Vec<PackageKeyV1>, LeanResolutionError> {
    let Some(lock) = request.active_lock.as_ref() else {
        if let LeanResolutionModeV1::Update { packages: targets } = &request.mode {
            let selected = packages
                .iter()
                .map(LeanResolvedPackageV1::key)
                .collect::<BTreeSet<_>>();
            if let Some(target) = targets.iter().find(|target| !selected.contains(target)) {
                return Err(LeanResolutionError::new(
                    LeanResolutionErrorKind::UnknownUpdateTarget,
                    format!(
                        "update target is absent: {}/{}",
                        target.scope(),
                        target.name()
                    ),
                ));
            }
        }
        return Ok(Vec::new());
    };
    let active = lock_map(lock);
    let selected = packages
        .iter()
        .map(|package| (package.key(), package))
        .collect::<BTreeMap<_, _>>();
    if matches!(request.mode, LeanResolutionModeV1::Frozen) {
        if active.len() != selected.len()
            || active.iter().any(|(key, package)| {
                selected
                    .get(key)
                    .is_none_or(|resolved| !candidate_matches_lock(&resolved.candidate, package))
            })
        {
            return Err(LeanResolutionError::new(
                LeanResolutionErrorKind::FrozenGraphDrift,
                "frozen resolution differs from the complete active lock",
            ));
        }
        return Ok(Vec::new());
    }
    for target in update_set {
        if !active.contains_key(*target) && !selected.contains_key(*target) {
            return Err(LeanResolutionError::new(
                LeanResolutionErrorKind::UnknownUpdateTarget,
                format!(
                    "unknown update target: {}/{}",
                    target.scope(),
                    target.name()
                ),
            ));
        }
    }
    let mut impact = active_impact_closure(&active, update_set);
    impact.extend(selected_impact_closure(&selected, update_set));
    for (key, package) in &selected {
        if let Some(old) = active.get(key)
            && !impact.contains(key)
            && !candidate_matches_lock(&package.candidate, old)
        {
            return Err(LeanResolutionError::new(
                LeanResolutionErrorKind::UpdateEscapesImpactClosure,
                format!(
                    "package changed outside update impact closure: {}/{}",
                    key.scope(),
                    key.name()
                ),
            ));
        }
    }
    for key in active.keys() {
        if !selected.contains_key(key) && !impact.contains(key) {
            return Err(LeanResolutionError::new(
                LeanResolutionErrorKind::UpdateEscapesImpactClosure,
                format!(
                    "package disappeared outside update impact closure: {}/{}",
                    key.scope(),
                    key.name()
                ),
            ));
        }
    }
    Ok(impact.into_iter().cloned().collect())
}

fn active_impact_closure<'a>(
    active: &'a BTreeMap<PackageKeyV1, &'a LockedLeanPackageV1>,
    update_set: &BTreeSet<&PackageKeyV1>,
) -> BTreeSet<&'a PackageKeyV1> {
    let mut impact = BTreeSet::new();
    let mut queue = update_set
        .iter()
        .filter_map(|key| active.get(*key).map(|package| package.key()))
        .collect::<VecDeque<_>>();
    while let Some(key) = queue.pop_front() {
        if !impact.insert(key) {
            continue;
        }
        if let Some(package) = active.get(key) {
            for dependency in package.dependencies() {
                if let Some(child) = active.get(dependency.package()) {
                    queue.push_back(child.key());
                }
            }
        }
    }
    impact
}

fn selected_impact_closure<'a>(
    selected: &'a BTreeMap<&'a PackageKeyV1, &'a LeanResolvedPackageV1>,
    update_set: &BTreeSet<&PackageKeyV1>,
) -> BTreeSet<&'a PackageKeyV1> {
    let mut impact = BTreeSet::new();
    let mut queue = update_set
        .iter()
        .filter_map(|key| selected.get(*key).map(|package| package.key()))
        .collect::<VecDeque<_>>();
    while let Some(key) = queue.pop_front() {
        if !impact.insert(key) {
            continue;
        }
        if let Some(package) = selected.get(key) {
            for dependency in package.dependencies() {
                if let Some(child) = selected.get(dependency) {
                    queue.push_back(child.key());
                }
            }
        }
    }
    impact
}

fn lock_map(lock: &LeanBunLockV1) -> BTreeMap<PackageKeyV1, &LockedLeanPackageV1> {
    lock.packages()
        .iter()
        .map(|package| (package.key().clone(), package))
        .collect()
}

fn request_matches_candidate(
    requirement: &LeanSourceRequestV1,
    candidate: &LeanPackageCandidateV1,
) -> bool {
    match (requirement, &candidate.requested, &candidate.resolved) {
        (
            LeanSourceRequestV1::Git {
                url,
                revision,
                subdir,
            },
            LeanSourceRequestV1::Git {
                url: candidate_url,
                revision: candidate_revision,
                subdir: candidate_subdir,
            },
            LeanExactSourceV1::Git {
                url: resolved_url,
                subdir: resolved_subdir,
                ..
            },
        ) => {
            url == candidate_url
                && url == resolved_url
                && revision == candidate_revision
                && subdir == candidate_subdir
                && subdir == resolved_subdir
        }
        (
            LeanSourceRequestV1::Reservoir { version },
            LeanSourceRequestV1::Reservoir {
                version: candidate_version,
            },
            LeanExactSourceV1::Git { .. },
        ) => version == candidate_version,
        (
            LeanSourceRequestV1::Path {
                portable_path_token,
            },
            LeanSourceRequestV1::Path {
                portable_path_token: candidate_token,
            },
            LeanExactSourceV1::Path {
                portable_path_token: resolved_token,
                ..
            },
        ) => portable_path_token == candidate_token && portable_path_token == resolved_token,
        _ => false,
    }
}

fn candidate_matches_lock(
    candidate: &LeanPackageCandidateV1,
    package: &LockedLeanPackageV1,
) -> bool {
    let mut candidate_dependencies = candidate
        .dependencies
        .iter()
        .map(|dependency| dependency.key())
        .collect::<Vec<_>>();
    candidate_dependencies.sort();
    candidate_dependencies.dedup();
    let locked_dependencies = package
        .dependencies()
        .iter()
        .map(|dependency| dependency.package())
        .collect::<Vec<_>>();
    if candidate.key() != package.key()
        || candidate.download_integrity != package.download_integrity()
        || candidate.source_tree_sha256 != package.source_tree_sha256()
        || candidate.config_sha256 != package.config_sha256()
        || candidate.manifest_sha256 != package.manifest_sha256()
        || candidate.selected_source_identity != package.selected_source_identity()
        || candidate_dependencies != locked_dependencies
    {
        return false;
    }
    let requested_matches = match (&candidate.requested, package.requested_source()) {
        (
            LeanSourceRequestV1::Git { url, revision, .. },
            RequestedPackageSourceV1::Git {
                url: locked_url,
                requested_revision,
            },
        ) => url == locked_url && revision == requested_revision,
        (
            LeanSourceRequestV1::Path {
                portable_path_token,
            },
            RequestedPackageSourceV1::PathSnapshot {
                portable_path_token: locked_token,
            },
        ) => portable_path_token == locked_token,
        (LeanSourceRequestV1::Reservoir { .. }, RequestedPackageSourceV1::Git { .. }) => true,
        _ => false,
    };
    if !requested_matches {
        return false;
    }
    match (&candidate.resolved, package.resolved_source()) {
        (
            LeanExactSourceV1::Git {
                url,
                exact_revision,
                subdir,
            },
            ResolvedPackageSourceV1::Git {
                url: locked_url,
                exact_revision: locked_revision,
                subdir: locked_subdir,
            },
        ) => url == locked_url && exact_revision == locked_revision && subdir == locked_subdir,
        (
            LeanExactSourceV1::Path {
                portable_path_token,
                source_identity,
            },
            ResolvedPackageSourceV1::PathSnapshot {
                portable_path_token: locked_token,
            },
        ) => {
            portable_path_token == locked_token
                && *source_identity == package.selected_source_identity()
        }
        _ => false,
    }
}

fn validate_cycles_and_depth(
    packages: &[LeanResolvedPackageV1],
) -> Result<(), LeanResolutionError> {
    let map = packages
        .iter()
        .map(|package| (package.key(), package))
        .collect::<BTreeMap<_, _>>();
    let mut states = BTreeMap::<&PackageKeyV1, u8>::new();
    fn visit<'a>(
        key: &'a PackageKeyV1,
        depth: usize,
        map: &BTreeMap<&'a PackageKeyV1, &'a LeanResolvedPackageV1>,
        states: &mut BTreeMap<&'a PackageKeyV1, u8>,
    ) -> Result<(), LeanResolutionError> {
        if depth > MAX_GRAPH_DEPTH_V1 {
            return Err(LeanResolutionError::new(
                LeanResolutionErrorKind::GraphTooDeep,
                "resolved graph exceeds depth limit",
            ));
        }
        match states.get(key) {
            Some(1) => {
                return Err(LeanResolutionError::new(
                    LeanResolutionErrorKind::DependencyCycle,
                    format!("dependency cycle reaches {}/{}", key.scope(), key.name()),
                ));
            }
            Some(2) => return Ok(()),
            _ => {}
        }
        states.insert(key, 1);
        let package = map.get(key).ok_or_else(|| {
            LeanResolutionError::new(
                LeanResolutionErrorKind::MissingTransitiveDeclaration,
                "selected dependency edge has no package",
            )
        })?;
        for dependency in package.dependencies() {
            visit(dependency, depth + 1, map, states)?;
        }
        states.insert(key, 2);
        Ok(())
    }
    for key in map.keys() {
        visit(key, 1, &map, &mut states)?;
    }
    Ok(())
}

fn validate_source_pair(
    requested: &LeanSourceRequestV1,
    resolved: &LeanExactSourceV1,
    download_integrity: Option<Sha256>,
    selected_source_identity: Sha256,
) -> Result<(), LeanResolutionError> {
    match (requested, resolved) {
        (
            LeanSourceRequestV1::Git { url, subdir, .. },
            LeanExactSourceV1::Git {
                url: resolved_url,
                subdir: resolved_subdir,
                ..
            },
        ) if url == resolved_url && subdir == resolved_subdir && download_integrity.is_some() => {
            Ok(())
        }
        (LeanSourceRequestV1::Reservoir { .. }, LeanExactSourceV1::Git { .. })
            if download_integrity.is_some() =>
        {
            Ok(())
        }
        (
            LeanSourceRequestV1::Path {
                portable_path_token,
            },
            LeanExactSourceV1::Path {
                portable_path_token: resolved_token,
                source_identity,
            },
        ) if portable_path_token == resolved_token
            && download_integrity.is_none()
            && *source_identity == selected_source_identity =>
        {
            Ok(())
        }
        _ => Err(LeanResolutionError::new(
            LeanResolutionErrorKind::SourceKindConflict,
            "requested and exact candidate sources are incompatible",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn candidate_identity(
    key: &PackageKeyV1,
    requested: &LeanSourceRequestV1,
    resolved: &LeanExactSourceV1,
    dependencies: &[LeanDependencyRequirementV1],
    toolchain: Option<&LeanToolchainIdentityV1>,
    download_integrity: Option<Sha256>,
    source_tree_sha256: Sha256,
    config_sha256: Sha256,
    manifest_sha256: Option<Sha256>,
    selected_source_identity: Sha256,
) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-resolution-candidate-v1\0");
    hash_key(&mut hasher, key);
    hash_request(&mut hasher, requested);
    hash_exact_source(&mut hasher, resolved);
    hash_optional_sha(&mut hasher, download_integrity);
    hasher.update(source_tree_sha256.as_bytes());
    hasher.update(config_sha256.as_bytes());
    hash_optional_sha(&mut hasher, manifest_sha256);
    hasher.update(selected_source_identity.as_bytes());
    hash_optional_toolchain(&mut hasher, toolchain);
    hash_usize(&mut hasher, dependencies.len());
    for dependency in dependencies {
        hash_key(&mut hasher, dependency.key());
        hash_request(&mut hasher, dependency.source());
    }
    hasher.finalize()
}

fn graph_identity(
    toolchain: &LeanToolchainIdentityV1,
    root_identity: Sha256,
    packages: &[LeanResolvedPackageV1],
    root_packages: &[PackageKeyV1],
    resolution_order: &[PackageKeyV1],
    shadows: &[LeanShadowDecisionV1],
    impact_closure: &[PackageKeyV1],
) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-resolution-graph-v1\0");
    hash_toolchain(&mut hasher, toolchain);
    hasher.update(root_identity.as_bytes());
    hash_usize(&mut hasher, packages.len());
    for package in packages {
        hash_key(&mut hasher, package.key());
        hasher.update(package.candidate_identity().as_bytes());
        hash_usize(&mut hasher, package.dependencies.len());
        for dependency in &package.dependencies {
            hash_key(&mut hasher, dependency);
        }
    }
    for keys in [root_packages, resolution_order, impact_closure] {
        hash_usize(&mut hasher, keys.len());
        for key in keys {
            hash_key(&mut hasher, key);
        }
    }
    hash_usize(&mut hasher, shadows.len());
    for shadow in shadows {
        hash_key(&mut hasher, &shadow.package);
        hasher.update(shadow.selected_candidate.as_bytes());
        hash_origin(&mut hasher, &shadow.winner);
        hash_origin(&mut hasher, &shadow.shadowed);
    }
    hasher.finalize()
}

fn hash_request(hasher: &mut Sha256Hasher, source: &LeanSourceRequestV1) {
    match source {
        LeanSourceRequestV1::Git {
            url,
            revision,
            subdir,
        } => {
            hasher.update(&[1]);
            hash_string(hasher, url.as_str());
            hash_optional_string(hasher, revision.as_deref());
            hash_optional_string(hasher, subdir.as_deref());
        }
        LeanSourceRequestV1::Reservoir { version } => {
            hasher.update(&[2]);
            hash_optional_string(hasher, version.as_deref());
        }
        LeanSourceRequestV1::Path {
            portable_path_token,
        } => {
            hasher.update(&[3]);
            hash_string(hasher, portable_path_token);
        }
    }
}

fn hash_exact_source(hasher: &mut Sha256Hasher, source: &LeanExactSourceV1) {
    match source {
        LeanExactSourceV1::Git {
            url,
            exact_revision,
            subdir,
        } => {
            hasher.update(&[1]);
            hash_string(hasher, url.as_str());
            hash_string(hasher, exact_revision);
            hash_optional_string(hasher, subdir.as_deref());
        }
        LeanExactSourceV1::Path {
            portable_path_token,
            source_identity,
        } => {
            hasher.update(&[2]);
            hash_string(hasher, portable_path_token);
            hasher.update(source_identity.as_bytes());
        }
    }
}

fn hash_optional_toolchain(hasher: &mut Sha256Hasher, toolchain: Option<&LeanToolchainIdentityV1>) {
    match toolchain {
        Some(value) => {
            hasher.update(&[1]);
            hash_toolchain(hasher, value);
        }
        None => hasher.update(&[0]),
    }
}

fn hash_toolchain(hasher: &mut Sha256Hasher, toolchain: &LeanToolchainIdentityV1) {
    hash_string(hasher, toolchain.lean_toolchain());
    hash_string(hasher, toolchain.compiler_githash());
    hash_string(hasher, toolchain.lake_version());
}

fn hash_origin(hasher: &mut Sha256Hasher, origin: &LeanResolutionOriginV1) {
    match origin {
        LeanResolutionOriginV1::Root { declaration_index } => {
            hasher.update(&[1]);
            hash_usize(hasher, *declaration_index);
        }
        LeanResolutionOriginV1::Package {
            package,
            declaration_index,
        } => {
            hasher.update(&[2]);
            hash_key(hasher, package);
            hash_usize(hasher, *declaration_index);
        }
    }
}

fn hash_key(hasher: &mut Sha256Hasher, key: &PackageKeyV1) {
    hash_string(hasher, key.scope());
    hash_string(hasher, key.name());
}

fn hash_optional_sha(hasher: &mut Sha256Hasher, value: Option<Sha256>) {
    match value {
        Some(value) => {
            hasher.update(&[1]);
            hasher.update(value.as_bytes());
        }
        None => hasher.update(&[0]),
    }
}

fn hash_optional_string(hasher: &mut Sha256Hasher, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update(&[1]);
            hash_string(hasher, value);
        }
        None => hasher.update(&[0]),
    }
}

fn hash_string(hasher: &mut Sha256Hasher, value: &str) {
    hash_usize(hasher, value.len());
    hasher.update(value.as_bytes());
}

fn hash_usize(hasher: &mut Sha256Hasher, value: usize) {
    hasher.update(&(value as u64).to_be_bytes());
}

fn validate_text(value: &str, label: &str) -> Result<(), LeanResolutionError> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(invalid(format!("{label} is invalid")));
    }
    Ok(())
}

fn validate_exact_revision(value: &str) -> Result<(), LeanResolutionError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            "exact revision must be 40 lowercase hexadecimal bytes",
        ));
    }
    Ok(())
}

fn validate_relative_path(value: &str, label: &str) -> Result<(), LeanResolutionError> {
    validate_text(value, label)?;
    if value.starts_with('/')
        || value.starts_with('\\')
        || value.contains('\\')
        || value
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        || (value.len() >= 2 && value.as_bytes()[1] == b':')
    {
        return Err(invalid(format!(
            "{label} must be a normalized relative path"
        )));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> LeanResolutionError {
    LeanResolutionError::new(LeanResolutionErrorKind::InvalidField, message)
}

fn limit(message: impl Into<String>) -> LeanResolutionError {
    LeanResolutionError::new(LeanResolutionErrorKind::LimitExceeded, message)
}
