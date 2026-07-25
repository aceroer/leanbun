use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_lake_bridge::{LakeDependencySourceV1, LakeRootDeclarationV1, LakeRootDependencyV1};
use leanbun_package::{
    CanonicalSourceUrlV1, LeanBunLockV1, LockedLeanPackageV1, PackageDependencyV1, PackageKeyV1,
    RequestedPackageSourceV1, ResolvedPackageSourceV1,
};
use leanbun_resolver::{
    LeanDependencyRequirementV1, LeanExactSourceV1, LeanPackageCandidateV1,
    LeanResolutionErrorKind, LeanResolutionModeV1, LeanResolutionOriginV1, LeanResolutionRequestV1,
    LeanSourceRequestV1, LeanToolchainIdentityV1, resolve_lean_dependencies_v1,
};
use std::fs;
use std::path::{Path, PathBuf};

const TOOLCHAIN: &str = "leanprover/lean4:v4.32.0";
const COMPILER: &str = "8c9756b28d64dab099da31a4c09229a9e6a2ef35";
const LAKE: &str = "5.0.0-src+8c9756b";

fn sha(byte: u8) -> Sha256 {
    Sha256::from_bytes([byte; 32])
}

fn key(name: &str) -> PackageKeyV1 {
    PackageKeyV1::new("", name).unwrap_or_else(|error| panic!("key failed: {error}"))
}

fn revision(value: u64) -> String {
    format!("{value:040x}")
}

fn url(name: &str) -> CanonicalSourceUrlV1 {
    CanonicalSourceUrlV1::parse(format!("https://github.com/leanbun/{name}"))
        .unwrap_or_else(|error| panic!("URL failed: {error}"))
}

fn toolchain() -> LeanToolchainIdentityV1 {
    LeanToolchainIdentityV1::new(TOOLCHAIN, COMPILER, LAKE)
        .unwrap_or_else(|error| panic!("toolchain failed: {error}"))
}

fn git_request(name: &str, branch: &str) -> LeanSourceRequestV1 {
    LeanSourceRequestV1::git(url(name), Some(branch.to_owned()), None)
        .unwrap_or_else(|error| panic!("request failed: {error}"))
}

fn requirement(name: &str, branch: &str) -> LeanDependencyRequirementV1 {
    LeanDependencyRequirementV1::new(key(name), git_request(name, branch))
}

fn root_git_dependency(name: &str, branch: &str) -> LakeRootDependencyV1 {
    LakeRootDependencyV1::new(
        key(name),
        Some(format!("git#{branch}")),
        LakeDependencySourceV1::Git {
            url: url(name).as_str().to_owned(),
            revision: Some(branch.to_owned()),
            subdir: None,
        },
    )
    .unwrap_or_else(|error| panic!("root dependency failed: {error}"))
}

fn root(dependencies: Vec<LakeRootDependencyV1>) -> LakeRootDeclarationV1 {
    LakeRootDeclarationV1::new("resolver_fixture", "lakefile.toml", dependencies)
        .unwrap_or_else(|error| panic!("root failed: {error}"))
}

#[derive(Clone)]
struct GitFixture {
    candidate: LeanPackageCandidateV1,
    locked: LockedLeanPackageV1,
}

fn git_fixture(
    name: &str,
    branch: &str,
    exact: u64,
    dependencies: Vec<LeanDependencyRequirementV1>,
    marker: u8,
) -> GitFixture {
    let package_key = key(name);
    let source_url = url(name);
    let exact_revision = revision(exact);
    let selected = sha(marker.wrapping_add(4));
    let candidate = LeanPackageCandidateV1::new(
        package_key.clone(),
        LeanSourceRequestV1::git(source_url.clone(), Some(branch.to_owned()), None)
            .unwrap_or_else(|error| panic!("request failed: {error}")),
        LeanExactSourceV1::git(source_url.clone(), exact_revision.clone(), None)
            .unwrap_or_else(|error| panic!("exact source failed: {error}")),
        dependencies.clone(),
        None,
        Some(sha(marker)),
        sha(marker.wrapping_add(1)),
        sha(marker.wrapping_add(2)),
        Some(sha(marker.wrapping_add(3))),
        selected,
    )
    .unwrap_or_else(|error| panic!("candidate failed: {error}"));
    let mut locked_dependencies = dependencies
        .into_iter()
        .map(|dependency| PackageDependencyV1::new(dependency.key().clone()))
        .collect::<Vec<_>>();
    locked_dependencies.sort();
    locked_dependencies.dedup();
    let locked = LockedLeanPackageV1::new(
        package_key,
        RequestedPackageSourceV1::git(source_url.clone(), Some(branch.to_owned()))
            .unwrap_or_else(|error| panic!("locked request failed: {error}")),
        ResolvedPackageSourceV1::git(source_url, exact_revision, None)
            .unwrap_or_else(|error| panic!("locked source failed: {error}")),
        Some(sha(marker)),
        sha(marker.wrapping_add(1)),
        sha(marker.wrapping_add(2)),
        Some(sha(marker.wrapping_add(3))),
        locked_dependencies,
        vec![sha(240)],
        selected,
    )
    .unwrap_or_else(|error| panic!("locked package failed: {error}"));
    GitFixture { candidate, locked }
}

fn lock(root: &LakeRootDeclarationV1, packages: Vec<LockedLeanPackageV1>) -> LeanBunLockV1 {
    LeanBunLockV1::new(
        TOOLCHAIN,
        COMPILER,
        LAKE,
        sha(250),
        root.identity(),
        packages,
    )
    .unwrap_or_else(|error| panic!("lock failed: {error}"))
}

fn fresh_request(root: LakeRootDeclarationV1) -> LeanResolutionRequestV1 {
    LeanResolutionRequestV1::new(
        root,
        None,
        LeanResolutionModeV1::update(Vec::new())
            .unwrap_or_else(|error| panic!("mode failed: {error}")),
        toolchain(),
    )
    .unwrap_or_else(|error| panic!("request failed: {error}"))
}

fn names<'a>(keys: impl IntoIterator<Item = &'a PackageKeyV1>) -> Vec<&'a str> {
    keys.into_iter().map(PackageKeyV1::name).collect()
}

fn permutations<T: Clone>(values: &[T]) -> Vec<Vec<T>> {
    if values.is_empty() {
        return vec![Vec::new()];
    }
    let mut output = Vec::new();
    for index in 0..values.len() {
        let mut rest = values.to_vec();
        let head = rest.remove(index);
        for mut tail in permutations(&rest) {
            let mut permutation = Vec::with_capacity(values.len());
            permutation.push(head.clone());
            permutation.append(&mut tail);
            output.push(permutation);
        }
    }
    output
}

#[test]
fn lake_reverse_breadth_first_order_is_deterministic_under_registry_permutation() {
    let root = root(vec![
        root_git_dependency("a", "main"),
        root_git_dependency("b", "main"),
        root_git_dependency("c", "main"),
    ]);
    let fixtures = [
        git_fixture("a", "main", 1, Vec::new(), 10),
        git_fixture(
            "b",
            "main",
            2,
            vec![requirement("x", "main"), requirement("y", "main")],
            20,
        ),
        git_fixture("c", "main", 3, Vec::new(), 30),
        git_fixture("x", "main", 4, Vec::new(), 40),
        git_fixture("y", "main", 5, Vec::new(), 50),
    ];
    let request = fresh_request(root);
    let forward = fixtures
        .iter()
        .map(|fixture| fixture.candidate.clone())
        .collect::<Vec<_>>();
    let first = resolve_lean_dependencies_v1(&request, forward.clone())
        .unwrap_or_else(|error| panic!("resolution failed: {error}"));
    for permutation in permutations(&forward) {
        let graph = resolve_lean_dependencies_v1(&request, permutation)
            .unwrap_or_else(|error| panic!("permuted resolution failed: {error}"));
        assert_eq!(first.identity(), graph.identity());
    }
    assert_eq!(
        names(first.resolution_order()),
        vec!["c", "b", "a", "y", "x"]
    );
    assert_eq!(
        names(first.packages().iter().map(|package| package.key())),
        vec!["a", "b", "c", "x", "y"]
    );
}

#[test]
fn frozen_mode_reuses_every_active_pin_and_rejects_incomplete_closure() {
    let root = root(vec![root_git_dependency("mathlib", "main")]);
    let dependency = git_fixture("a", "main", 10, Vec::new(), 10);
    let mathlib = git_fixture("mathlib", "main", 11, vec![requirement("a", "main")], 20);
    let newer = git_fixture("mathlib", "next", 12, vec![requirement("a", "main")], 30);
    let active = lock(
        &root,
        vec![mathlib.locked.clone(), dependency.locked.clone()],
    );
    let request = LeanResolutionRequestV1::new(
        root.clone(),
        Some(active),
        LeanResolutionModeV1::Frozen,
        toolchain(),
    )
    .unwrap_or_else(|error| panic!("request failed: {error}"));
    let graph = resolve_lean_dependencies_v1(
        &request,
        vec![
            newer.candidate,
            dependency.candidate.clone(),
            mathlib.candidate.clone(),
        ],
    )
    .unwrap_or_else(|error| panic!("frozen resolution failed: {error}"));
    let resolved_mathlib = graph
        .packages()
        .iter()
        .find(|package| package.key().name() == "mathlib")
        .unwrap_or_else(|| panic!("mathlib missing"));
    assert!(matches!(
        resolved_mathlib.source(),
        LeanExactSourceV1::Git { exact_revision, .. } if exact_revision == &revision(11)
    ));

    let orphan = git_fixture("orphan", "main", 13, Vec::new(), 40);
    let active_with_orphan = lock(
        &root,
        vec![mathlib.locked, dependency.locked, orphan.locked],
    );
    let incomplete = LeanResolutionRequestV1::new(
        root,
        Some(active_with_orphan),
        LeanResolutionModeV1::Frozen,
        toolchain(),
    )
    .unwrap_or_else(|error| panic!("request failed: {error}"));
    assert!(matches!(
        resolve_lean_dependencies_v1(
            &incomplete,
            vec![mathlib.candidate, dependency.candidate, orphan.candidate]
        ),
        Err(error) if error.kind == LeanResolutionErrorKind::FrozenGraphDrift
    ));
}

#[test]
fn targeted_update_changes_mathlib_and_pins_every_existing_non_target() {
    let root = root(vec![
        root_git_dependency("b", "main"),
        root_git_dependency("mathlib", "main"),
    ]);
    let a = git_fixture("a", "main", 20, Vec::new(), 10);
    let b = git_fixture("b", "main", 21, Vec::new(), 20);
    let newer_b = git_fixture("b", "main", 121, Vec::new(), 25);
    let old_mathlib = git_fixture("mathlib", "main", 22, vec![requirement("a", "main")], 30);
    let new_mathlib = git_fixture(
        "mathlib",
        "main",
        23,
        vec![requirement("a", "main"), requirement("newdep", "main")],
        40,
    );
    let newdep = git_fixture("newdep", "main", 24, Vec::new(), 50);
    let active = lock(
        &root,
        vec![old_mathlib.locked, a.locked.clone(), b.locked.clone()],
    );
    let request = LeanResolutionRequestV1::new(
        root,
        Some(active),
        LeanResolutionModeV1::update(vec![key("mathlib")])
            .unwrap_or_else(|error| panic!("mode failed: {error}")),
        toolchain(),
    )
    .unwrap_or_else(|error| panic!("request failed: {error}"));
    let graph = resolve_lean_dependencies_v1(
        &request,
        vec![
            newdep.candidate,
            newer_b.candidate,
            b.candidate.clone(),
            new_mathlib.candidate,
            a.candidate.clone(),
        ],
    )
    .unwrap_or_else(|error| panic!("update failed: {error}"));
    assert_eq!(
        names(graph.impact_closure()),
        vec!["a", "mathlib", "newdep"]
    );
    let resolved_b = graph
        .packages()
        .iter()
        .find(|package| package.key().name() == "b")
        .unwrap_or_else(|| panic!("b missing"));
    assert_eq!(resolved_b.candidate_identity(), b.candidate.identity());
    let resolved_a = graph
        .packages()
        .iter()
        .find(|package| package.key().name() == "a")
        .unwrap_or_else(|| panic!("a missing"));
    assert_eq!(resolved_a.candidate_identity(), a.candidate.identity());
}

#[test]
fn root_priority_and_later_require_shadow_are_explicit() {
    let root_declaration = root(vec![
        root_git_dependency("a", "main"),
        root_git_dependency("x", "main"),
    ]);
    let a = git_fixture("a", "main", 30, vec![requirement("x", "main")], 10);
    let x = git_fixture("x", "main", 31, Vec::new(), 20);
    let graph = resolve_lean_dependencies_v1(
        &fresh_request(root_declaration),
        vec![a.candidate, x.candidate],
    )
    .unwrap_or_else(|error| panic!("resolution failed: {error}"));
    assert_eq!(graph.shadows().len(), 1);
    assert!(matches!(
        graph.shadows()[0].winner(),
        LeanResolutionOriginV1::Root { .. }
    ));

    let duplicate_root = root(vec![root_git_dependency("b", "main")]);
    let b = git_fixture(
        "b",
        "main",
        32,
        vec![requirement("x", "main"), requirement("x", "main")],
        30,
    );
    let x = git_fixture("x", "main", 33, Vec::new(), 40);
    let graph = resolve_lean_dependencies_v1(
        &fresh_request(duplicate_root),
        vec![b.candidate, x.candidate],
    )
    .unwrap_or_else(|error| panic!("resolution failed: {error}"));
    assert!(matches!(
        graph.shadows()[0].winner(),
        LeanResolutionOriginV1::Package {
            declaration_index: 1,
            ..
        }
    ));
}

#[test]
fn incompatible_later_shadow_returns_conflict_provenance() {
    let root = root(vec![root_git_dependency("b", "main")]);
    let b = git_fixture(
        "b",
        "main",
        40,
        vec![requirement("x", "main"), requirement("x", "next")],
        10,
    );
    let x = git_fixture("x", "next", 41, Vec::new(), 20);
    let error = resolve_lean_dependencies_v1(&fresh_request(root), vec![b.candidate, x.candidate])
        .err()
        .unwrap_or_else(|| panic!("conflicting shadow unexpectedly resolved"));
    assert_eq!(error.kind, LeanResolutionErrorKind::SourceValueConflict);
    let conflict = error
        .conflict
        .unwrap_or_else(|| panic!("conflict provenance missing"));
    assert_eq!(conflict.package.name(), "x");
    assert!(matches!(
        conflict.winner,
        LeanResolutionOriginV1::Package {
            declaration_index: 1,
            ..
        }
    ));
    assert!(matches!(
        conflict.conflicting,
        LeanResolutionOriginV1::Package {
            declaration_index: 0,
            ..
        }
    ));
}

#[test]
fn reservoir_and_path_metadata_normalize_to_exact_sources() {
    let reservoir_key = key("reservoirpkg");
    let path_key = key("pathpkg");
    let root = root(vec![
        LakeRootDependencyV1::new(
            reservoir_key.clone(),
            Some("v1.2.3".to_owned()),
            LakeDependencySourceV1::Reservoir,
        )
        .unwrap_or_else(|error| panic!("root reservoir failed: {error}")),
        LakeRootDependencyV1::new(
            path_key.clone(),
            None,
            LakeDependencySourceV1::Path {
                directory: "vendor/pathpkg".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("root path failed: {error}")),
    ]);
    let reservoir = LeanPackageCandidateV1::new(
        reservoir_key,
        LeanSourceRequestV1::reservoir(Some("v1.2.3".to_owned()))
            .unwrap_or_else(|error| panic!("reservoir request failed: {error}")),
        LeanExactSourceV1::git(url("reservoirpkg"), revision(50), None)
            .unwrap_or_else(|error| panic!("reservoir exact failed: {error}")),
        Vec::new(),
        None,
        Some(sha(10)),
        sha(11),
        sha(12),
        Some(sha(13)),
        sha(14),
    )
    .unwrap_or_else(|error| panic!("reservoir candidate failed: {error}"));
    let path_identity = sha(60);
    let path = LeanPackageCandidateV1::new(
        path_key,
        LeanSourceRequestV1::path("vendor/pathpkg")
            .unwrap_or_else(|error| panic!("path request failed: {error}")),
        LeanExactSourceV1::path("vendor/pathpkg", path_identity)
            .unwrap_or_else(|error| panic!("path exact failed: {error}")),
        Vec::new(),
        None,
        None,
        sha(61),
        sha(62),
        None,
        path_identity,
    )
    .unwrap_or_else(|error| panic!("path candidate failed: {error}"));
    let graph = resolve_lean_dependencies_v1(&fresh_request(root), vec![path, reservoir])
        .unwrap_or_else(|error| panic!("resolution failed: {error}"));
    assert!(graph.packages().iter().any(|package| matches!(
        package.source(),
        LeanExactSourceV1::Git { exact_revision, .. } if exact_revision == &revision(50)
    )));
    assert!(graph.packages().iter().any(|package| matches!(
        package.source(),
        LeanExactSourceV1::Path { source_identity, .. } if *source_identity == path_identity
    )));
}

#[test]
fn cycle_missing_transitive_and_source_kind_conflict_fail_closed() {
    let root_declaration = root(vec![root_git_dependency("a", "main")]);
    let a = git_fixture("a", "main", 60, vec![requirement("b", "main")], 10);
    let b = git_fixture("b", "main", 61, vec![requirement("a", "main")], 20);
    assert!(matches!(
        resolve_lean_dependencies_v1(
            &fresh_request(root_declaration.clone()),
            vec![a.candidate.clone(), b.candidate]
        ),
        Err(error) if error.kind == LeanResolutionErrorKind::DependencyCycle
    ));
    assert!(matches!(
        resolve_lean_dependencies_v1(
            &fresh_request(root_declaration.clone()),
            vec![a.candidate]
        ),
        Err(error) if error.kind == LeanResolutionErrorKind::MissingTransitiveDeclaration
    ));
    let path_identity = sha(70);
    let path_candidate = LeanPackageCandidateV1::new(
        key("a"),
        LeanSourceRequestV1::path("vendor/a")
            .unwrap_or_else(|error| panic!("path request failed: {error}")),
        LeanExactSourceV1::path("vendor/a", path_identity)
            .unwrap_or_else(|error| panic!("path exact failed: {error}")),
        Vec::new(),
        None,
        None,
        sha(71),
        sha(72),
        None,
        path_identity,
    )
    .unwrap_or_else(|error| panic!("path candidate failed: {error}"));
    assert!(matches!(
        resolve_lean_dependencies_v1(&fresh_request(root_declaration), vec![path_candidate]),
        Err(error) if error.kind == LeanResolutionErrorKind::SourceKindConflict
    ));

    let deep_root = root(vec![root_git_dependency("p000", "main")]);
    let deep_candidates = (0..129)
        .map(|index| {
            let name = format!("p{index:03}");
            let dependencies = if index < 128 {
                vec![requirement(&format!("p{:03}", index + 1), "main")]
            } else {
                Vec::new()
            };
            git_fixture(
                &name,
                "main",
                1_000 + index,
                dependencies,
                u8::try_from(index).unwrap_or_else(|error| panic!("marker failed: {error}")),
            )
            .candidate
        })
        .collect();
    assert!(matches!(
        resolve_lean_dependencies_v1(&fresh_request(deep_root), deep_candidates),
        Err(error) if error.kind == LeanResolutionErrorKind::GraphTooDeep
    ));
}

#[test]
fn duplicate_ambiguous_and_toolchain_candidate_conflicts_fail_closed() {
    let root = root(vec![root_git_dependency("a", "main")]);
    let a = git_fixture("a", "main", 70, Vec::new(), 10);
    assert!(matches!(
        LeanResolutionModeV1::update(vec![key("a"), key("a")]),
        Err(error) if error.kind == LeanResolutionErrorKind::DuplicateUpdateTarget
    ));
    assert!(matches!(
        resolve_lean_dependencies_v1(
            &fresh_request(root.clone()),
            vec![a.candidate.clone(), a.candidate.clone()]
        ),
        Err(error) if error.kind == LeanResolutionErrorKind::DuplicateCandidateIdentity
    ));
    let other = git_fixture("a", "main", 71, Vec::new(), 20);
    assert!(matches!(
        resolve_lean_dependencies_v1(
            &fresh_request(root.clone()),
            vec![a.candidate, other.candidate]
        ),
        Err(error) if error.kind == LeanResolutionErrorKind::AmbiguousCandidate
    ));
    let wrong_toolchain = LeanToolchainIdentityV1::new(
        "leanprover/lean4:v4.31.0",
        "1111111111111111111111111111111111111111",
        "5.0.0-src+1111111",
    )
    .unwrap_or_else(|error| panic!("wrong toolchain failed: {error}"));
    let candidate = LeanPackageCandidateV1::new(
        key("a"),
        git_request("a", "main"),
        LeanExactSourceV1::git(url("a"), revision(72), None)
            .unwrap_or_else(|error| panic!("exact failed: {error}")),
        Vec::new(),
        Some(wrong_toolchain),
        Some(sha(30)),
        sha(31),
        sha(32),
        Some(sha(33)),
        sha(34),
    )
    .unwrap_or_else(|error| panic!("candidate failed: {error}"));
    assert!(matches!(
        resolve_lean_dependencies_v1(&fresh_request(root), vec![candidate]),
        Err(error) if error.kind == LeanResolutionErrorKind::ToolchainCandidateConflict
    ));
}

#[test]
fn lake_432_resolve_source_hash_and_ordering_facts_are_locked() {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| panic!("repository root missing"));
    let source = repository.join(
        ".leanbun-dev/lean/elan-home/toolchains/leanprover--lean4---v4.32.0/src/lean/lake/Lake/Load/Resolve.lean",
    );
    let bytes =
        fs::read(&source).unwrap_or_else(|error| panic!("Resolve.lean read failed: {error}"));
    let mut hasher = Sha256Hasher::new();
    hasher.update(&bytes);
    assert_eq!(
        hasher.finalize().to_string(),
        "b1cce0ebebbcd620906750760a1c6b5ff50b26e18caba946888f48b391390516"
    );
    let text = String::from_utf8(bytes)
        .unwrap_or_else(|error| panic!("Resolve.lean UTF-8 failed: {error}"));
    for fact in [
        "Recursion occurs breadth-first.",
        "pkg.depConfigs.foldrM",
        "let deps : Vector _ numDeps := Vector.mk ws.root.depConfigs.reverse",
        "later requires should shadow earlier definitions",
        "Requires written by a user should take priority",
    ] {
        assert!(text.contains(fact), "locked Lake rule missing: {fact}");
    }
}
