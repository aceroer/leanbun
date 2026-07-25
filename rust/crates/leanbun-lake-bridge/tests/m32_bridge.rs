use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_evidence::{StrictJson, parse_strict_json};
use leanbun_lake_bridge::{
    LakeBridgeErrorKind, LakeDependencySourceV1, LakeManifestProjectionV1,
    LakeObservedPackagePathV1, LakePackageProjectionMetadataV1, LakeRootDeclarationV1,
    LakeRootDependencyV1, LakeRootProbeRequestV1, LakeRuntimePackagesProjectionV1,
    LakeWorkspacePathObservationV1, parse_root_declaration_probe_v1, run_lake_root_probe_v1,
    validate_managed_runtime_package_files_v1,
};
use leanbun_package::{
    CanonicalSourceUrlV1, LeanBunLockV1, LockedLeanPackageV1, PackageDependencyV1, PackageKeyV1,
    PackagePathDecisionSetV1, PackagePathDecisionV1, PackagePathProvenanceSetV1,
    PackagePathProvenanceV1, RequestedPackageSourceV1, ResolvedPackageSourceV1,
};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{collections::BTreeMap, fs};

fn sha(byte: u8) -> Sha256 {
    Sha256::from_bytes([byte; 32])
}

fn git_package(
    key: PackageKeyV1,
    url: &str,
    revision: &str,
    subdir: Option<String>,
    dependencies: Vec<PackageDependencyV1>,
    selected: Sha256,
) -> LockedLeanPackageV1 {
    let url =
        CanonicalSourceUrlV1::parse(url).unwrap_or_else(|error| panic!("URL failed: {error}"));
    LockedLeanPackageV1::new(
        key,
        RequestedPackageSourceV1::git(url.clone(), Some(revision.to_owned()))
            .unwrap_or_else(|error| panic!("request failed: {error}")),
        ResolvedPackageSourceV1::git(url, revision, subdir)
            .unwrap_or_else(|error| panic!("resolution failed: {error}")),
        Some(sha(1)),
        sha(2),
        sha(3),
        Some(sha(4)),
        dependencies,
        vec![sha(5)],
        selected,
    )
    .unwrap_or_else(|error| panic!("package failed: {error}"))
}

struct FixtureModel {
    lock: LeanBunLockV1,
    declaration: LakeRootDeclarationV1,
    metadata: Vec<LakePackageProjectionMetadataV1>,
    decisions: PackagePathDecisionSetV1,
}

fn fixture_model() -> FixtureModel {
    let alpha =
        PackageKeyV1::new("", "alpha").unwrap_or_else(|error| panic!("key failed: {error}"));
    let beta =
        PackageKeyV1::new("scope", "beta").unwrap_or_else(|error| panic!("key failed: {error}"));
    let alpha_url = "https://github.com/example/alpha";
    let alpha_revision = "1111111111111111111111111111111111111111";
    let lock = LeanBunLockV1::new(
        "leanprover/lean4:v4.32.0",
        "1111111111111111111111111111111111111111",
        "5.0.0-src+8c9756b",
        sha(8),
        sha(9),
        vec![
            git_package(
                alpha.clone(),
                alpha_url,
                alpha_revision,
                Some("src".to_owned()),
                vec![PackageDependencyV1::new(beta.clone())],
                sha(21),
            ),
            git_package(
                beta.clone(),
                "https://github.com/example/beta",
                "2222222222222222222222222222222222222222",
                None,
                Vec::new(),
                sha(22),
            ),
        ],
    )
    .unwrap_or_else(|error| panic!("lock failed: {error}"));
    let declaration = LakeRootDeclarationV1::new(
        "root",
        "lakefile.toml",
        vec![
            LakeRootDependencyV1::new(
                alpha.clone(),
                Some(format!("git#{alpha_revision}")),
                LakeDependencySourceV1::Git {
                    url: alpha_url.to_owned(),
                    revision: Some(alpha_revision.to_owned()),
                    subdir: Some("src".to_owned()),
                },
            )
            .unwrap_or_else(|error| panic!("declaration failed: {error}")),
        ],
    )
    .unwrap_or_else(|error| panic!("root declaration failed: {error}"));
    let metadata = vec![
        LakePackageProjectionMetadataV1::new(
            alpha.clone(),
            false,
            "lakefile.toml",
            Some("lake-manifest.json".to_owned()),
            Some("main".to_owned()),
        )
        .unwrap_or_else(|error| panic!("metadata failed: {error}")),
        LakePackageProjectionMetadataV1::new(
            beta.clone(),
            true,
            "lakefile.toml",
            Some("lake-manifest.json".to_owned()),
            Some("v1".to_owned()),
        )
        .unwrap_or_else(|error| panic!("metadata failed: {error}")),
    ];
    let provenance = PackagePathProvenanceSetV1::new(vec![
        PackagePathProvenanceV1::manifest(alpha.clone(), sha(20)),
        PackagePathProvenanceV1::workspace_override(alpha.clone(), sha(21)),
        PackagePathProvenanceV1::manifest(beta.clone(), sha(22)),
    ])
    .unwrap_or_else(|error| panic!("provenance failed: {error}"));
    let decisions = PackagePathDecisionSetV1::new(
        &lock,
        vec![
            PackagePathDecisionV1::new(
                alpha,
                &provenance,
                sha(21),
                "/isolated/generation",
                "/isolated/generation/packages/alpha",
                sha(31),
                sha(2),
                sha(40),
            )
            .unwrap_or_else(|error| panic!("decision failed: {error}")),
            PackagePathDecisionV1::new(
                beta,
                &provenance,
                sha(22),
                "/isolated/generation",
                "/isolated/generation/packages/beta",
                sha(32),
                sha(2),
                sha(40),
            )
            .unwrap_or_else(|error| panic!("decision failed: {error}")),
        ],
    )
    .unwrap_or_else(|error| panic!("decision set failed: {error}"));
    FixtureModel {
        lock,
        declaration,
        metadata,
        decisions,
    }
}

#[test]
fn root_probe_decoder_is_strict_bounded_and_canonical() {
    let json = r#"{"configFile":"lakefile.toml","dependencies":[{"name":"mathlib","scope":"","source":{"kind":"git","revision":"81a5d257c8e410db227a6665ed08f64fea08e997","subDir":null,"url":"https://github.com/leanprover-community/mathlib4"},"version":"git#81a5d257c8e410db227a6665ed08f64fea08e997"}],"rootName":"fixture","schemaVersion":1}"#;
    let declaration = parse_root_declaration_probe_v1(json)
        .unwrap_or_else(|error| panic!("probe decode failed: {error}"));
    assert_eq!(declaration.dependencies().len(), 1);
    assert_eq!(declaration.dependencies()[0].key().name(), "mathlib");
    assert!(
        parse_root_declaration_probe_v1(
            &json.replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"unknown\":0")
        )
        .is_err()
    );
    assert!(
        parse_root_declaration_probe_v1(&json.replace(
            "\"name\":\"mathlib\"",
            "\"name\":\"mathlib\",\"name\":\"other\""
        ))
        .is_err()
    );
}

#[test]
fn projections_are_complete_sorted_and_lake_json_compatible() {
    let fixture = fixture_model();
    let manifest = LakeManifestProjectionV1::new(
        &fixture.declaration,
        &fixture.lock,
        fixture.metadata.clone(),
    )
    .unwrap_or_else(|error| panic!("manifest projection failed: {error}"));
    let runtime = LakeRuntimePackagesProjectionV1::from_bun_decisions(
        &fixture.lock,
        &fixture.decisions,
        fixture.metadata.clone(),
    )
    .unwrap_or_else(|error| panic!("runtime projection failed: {error}"));
    assert!(parse_strict_json(manifest.as_str()).is_ok());
    assert!(parse_strict_json(runtime.as_str()).is_ok());
    assert_eq!(runtime.package_count(), 2);
    assert!(
        manifest.as_str().find("alpha").unwrap_or(usize::MAX)
            < manifest.as_str().find("beta").unwrap_or(0)
    );
    assert!(manifest.as_str().contains("\"subDir\":\"src\""));
    assert!(
        runtime
            .as_str()
            .contains("\"dir\":\"/isolated/generation/packages/alpha\"")
    );
    assert!(!runtime.as_str().contains("\"type\":\"git\""));
    assert_ne!(manifest.sha256(), runtime.sha256());
}

#[test]
fn managed_runtime_rejects_duplicate_files_and_workspace_path_drift() {
    let fixture = fixture_model();
    assert!(validate_managed_runtime_package_files_v1(1, 1).is_ok());
    assert!(
        matches!(validate_managed_runtime_package_files_v1(2, 1), Err(error) if error.kind == LakeBridgeErrorKind::NonBunRuntimeOverride)
    );
    let paths = fixture
        .decisions
        .decisions()
        .iter()
        .map(|decision| {
            LakeObservedPackagePathV1::new(decision.package().clone(), decision.final_path())
                .unwrap_or_else(|error| panic!("path failed: {error}"))
        })
        .collect();
    assert!(LakeWorkspacePathObservationV1::compare(&fixture.decisions, paths).is_ok());
    let drift = vec![
        LakeObservedPackagePathV1::new(
            PackageKeyV1::new("", "alpha").unwrap_or_else(|error| panic!("key failed: {error}")),
            "/isolated/generation/packages/wrong",
        )
        .unwrap_or_else(|error| panic!("path failed: {error}")),
        LakeObservedPackagePathV1::new(
            PackageKeyV1::new("scope", "beta")
                .unwrap_or_else(|error| panic!("key failed: {error}")),
            "/isolated/generation/packages/beta",
        )
        .unwrap_or_else(|error| panic!("path failed: {error}")),
    ];
    assert!(
        matches!(LakeWorkspacePathObservationV1::compare(&fixture.decisions, drift), Err(error) if error.kind == LakeBridgeErrorKind::WorkspacePathMismatch)
    );
}

#[test]
fn source_kind_drift_missing_metadata_and_manifest_fallback_fail_closed() {
    let fixture = fixture_model();
    let path_declaration = LakeRootDeclarationV1::new(
        "root",
        "lakefile.toml",
        vec![
            LakeRootDependencyV1::new(
                PackageKeyV1::new("", "alpha")
                    .unwrap_or_else(|error| panic!("key failed: {error}")),
                None,
                LakeDependencySourceV1::Path {
                    directory: "vendor/alpha".to_owned(),
                },
            )
            .unwrap_or_else(|error| panic!("dependency failed: {error}")),
        ],
    )
    .unwrap_or_else(|error| panic!("declaration failed: {error}"));
    assert!(
        matches!(LakeManifestProjectionV1::new(&path_declaration, &fixture.lock, fixture.metadata.clone()), Err(error) if error.kind == LakeBridgeErrorKind::SourceKindDrift)
    );
    assert!(
        matches!(LakeManifestProjectionV1::new(&fixture.declaration, &fixture.lock, vec![fixture.metadata[0].clone()]), Err(error) if error.kind == LakeBridgeErrorKind::MissingPackage)
    );
    assert!(validate_managed_runtime_package_files_v1(0, 0).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn exact_lake_432_load_workspace_root_probe_reads_only_staged_fixtures() {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| panic!("repository root missing"));
    let development_root = repository.join(".leanbun-dev");
    let toolchain = development_root.join("lean/elan-home/toolchains/leanprover--lean4---v4.32.0");
    for (label, expected_dependencies) in [
        ("lake-basic", 0),
        ("lake-lean-config", 0),
        ("mathlib-project", 1),
    ] {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("clock failed: {error}"))
            .as_nanos();
        let staging =
            development_root.join(format!("tmp/m32-rust-probe-{}-{nonce}", std::process::id()));
        let request = LakeRootProbeRequestV1 {
            source_fixture_root: repository.join("test/fixtures"),
            source_project: repository.join("test/fixtures").join(label),
            development_root: development_root.clone(),
            staging_directory: staging.clone(),
            lean_executable: toolchain.join("bin/lean"),
            elan_home: development_root.join("lean/elan-home"),
            sandbox_executable: PathBuf::from("/usr/bin/sandbox-exec"),
            sandbox_profile: repository.join("config/leanbun-dev.sb"),
            probe_source: repository.join("lean/probes/M32RootDeclarations.lean"),
            lake_source_root: toolchain.join("src/lean/lake"),
        };
        let declaration = run_lake_root_probe_v1(&request)
            .unwrap_or_else(|error| panic!("{label} probe failed: {error}"));
        assert_eq!(declaration.dependencies().len(), expected_dependencies);
        assert!(!staging.join("lake-manifest.json").exists());
        assert!(!staging.join(".lake/packages").exists());
        std::fs::remove_dir_all(&staging)
            .unwrap_or_else(|error| panic!("staging cleanup failed: {error}"));
    }
}

#[test]
fn declaration_identity_uses_bun_compatible_sha256_domain() {
    let fixture = fixture_model();
    let mut hasher = Sha256Hasher::new();
    hasher.update(fixture.declaration.identity().as_bytes());
    assert_ne!(hasher.finalize(), sha(0));
}

#[cfg(target_os = "macos")]
#[test]
fn exact_lake_manifest_parse_entries_accepts_both_rust_projections_field_for_field() {
    let fixture = fixture_model();
    let manifest = LakeManifestProjectionV1::new(
        &fixture.declaration,
        &fixture.lock,
        fixture.metadata.clone(),
    )
    .unwrap_or_else(|error| panic!("manifest projection failed: {error}"));
    let runtime = LakeRuntimePackagesProjectionV1::from_bun_decisions(
        &fixture.lock,
        &fixture.decisions,
        fixture.metadata,
    )
    .unwrap_or_else(|error| panic!("runtime projection failed: {error}"));
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| panic!("repository root missing"));
    let development_root = repository.join(".leanbun-dev");
    let toolchain = development_root.join("lean/elan-home/toolchains/leanprover--lean4---v4.32.0");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("clock failed: {error}"))
        .as_nanos();
    let staging = development_root.join(format!(
        "tmp/m32-parse-oracle-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&staging).unwrap_or_else(|error| panic!("staging failed: {error}"));
    for (name, projection, expected_kind) in [
        ("manifest.json", manifest.as_str(), "git"),
        ("runtime.json", runtime.as_str(), "path"),
    ] {
        let projection_file = staging.join(name);
        fs::write(&projection_file, projection)
            .unwrap_or_else(|error| panic!("projection write failed: {error}"));
        let output = Command::new("/usr/bin/sandbox-exec")
            .args(["-f"])
            .arg(repository.join("config/leanbun-dev.sb"))
            .arg(toolchain.join("bin/lean"))
            .arg("--run")
            .arg(repository.join("lean/probes/M32ParseEntries.lean"))
            .arg(&projection_file)
            .current_dir(&staging)
            .env_clear()
            .env(
                "PATH",
                format!(
                    "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                    toolchain.join("bin").display()
                ),
            )
            .env("ELAN_HOME", development_root.join("lean/elan-home"))
            .env("TMPDIR", &staging)
            .env("HOME", &staging)
            .env("LC_ALL", "C.UTF-8")
            .env("LANG", "C.UTF-8")
            .output()
            .unwrap_or_else(|error| panic!("Lake parse oracle failed to run: {error}"));
        assert!(
            output.status.success(),
            "Lake parse oracle failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let parsed = parse_strict_json(
            &String::from_utf8(output.stdout)
                .unwrap_or_else(|error| panic!("oracle UTF-8 failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("oracle JSON failed: {error}"));
        let root = json_object(&parsed);
        let entries = json_array(
            root.get("entries")
                .unwrap_or_else(|| panic!("oracle entries missing")),
        );
        assert_eq!(entries.len(), 2);
        for (entry, decision) in entries.iter().zip(fixture.decisions.decisions()) {
            let entry = json_object(entry);
            assert_eq!(json_string(entry, "name"), decision.package().name());
            let source = json_object(
                entry
                    .get("source")
                    .unwrap_or_else(|| panic!("source missing")),
            );
            assert_eq!(json_string(source, "kind"), expected_kind);
            if expected_kind == "path" {
                assert_eq!(json_string(source, "directory"), decision.final_path());
            }
        }
    }
    fs::remove_dir_all(&staging).unwrap_or_else(|error| panic!("staging cleanup failed: {error}"));
}

#[test]
fn mathlib_nine_package_runtime_projection_matches_every_bun_final_path() {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| panic!("repository root missing"));
    let manifest_text =
        fs::read_to_string(repository.join("test/fixtures/mathlib-project/lake-manifest.json"))
            .unwrap_or_else(|error| panic!("manifest read failed: {error}"));
    let override_text =
        fs::read_to_string(repository.join(".leanbun-dev/lean/overrides/package-overrides.json"))
            .unwrap_or_else(|error| panic!("override read failed: {error}"));
    let manifest_json = parse_strict_json(&manifest_text)
        .unwrap_or_else(|error| panic!("manifest parse failed: {error}"));
    let override_json = parse_strict_json(&override_text)
        .unwrap_or_else(|error| panic!("override parse failed: {error}"));
    let manifest = json_object(&manifest_json);
    let overrides = json_object(&override_json);
    let manifest_packages = json_array(
        manifest
            .get("packages")
            .unwrap_or_else(|| panic!("manifest packages missing")),
    );
    let override_packages = json_array(
        overrides
            .get("packages")
            .unwrap_or_else(|| panic!("override packages missing")),
    );
    assert_eq!(manifest_packages.len(), 9);
    assert_eq!(override_packages.len(), 9);
    let override_paths = override_packages
        .iter()
        .map(|value| {
            let item = json_object(value);
            (
                json_string(item, "name").to_owned(),
                json_string(item, "dir").to_owned(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut locked = Vec::new();
    let mut metadata = Vec::new();
    let mut provenance = Vec::new();
    let mut source_trees = BTreeMap::new();
    let mut selected_sources = BTreeMap::new();
    for (index, value) in manifest_packages.iter().enumerate() {
        let item = json_object(value);
        let name = json_string(item, "name");
        let scope = json_string(item, "scope");
        let key = PackageKeyV1::new(scope, name)
            .unwrap_or_else(|error| panic!("package key failed: {error}"));
        let url = json_string(item, "url");
        let revision = json_string(item, "rev");
        let subdir = json_nullable_string(item, "subDir");
        let input_revision = json_nullable_string(item, "inputRev");
        let selected = sha(u8::try_from(50 + index)
            .unwrap_or_else(|error| panic!("selected byte failed: {error}")));
        let tree =
            sha(u8::try_from(70 + index)
                .unwrap_or_else(|error| panic!("tree byte failed: {error}")));
        let canonical_url =
            CanonicalSourceUrlV1::parse(url).unwrap_or_else(|error| panic!("URL failed: {error}"));
        locked.push(
            LockedLeanPackageV1::new(
                key.clone(),
                RequestedPackageSourceV1::git(canonical_url.clone(), input_revision.clone())
                    .unwrap_or_else(|error| panic!("request failed: {error}")),
                ResolvedPackageSourceV1::git(canonical_url, revision, subdir)
                    .unwrap_or_else(|error| panic!("resolution failed: {error}")),
                Some(sha(1)),
                tree,
                sha(3),
                Some(sha(4)),
                Vec::new(),
                vec![sha(5)],
                selected,
            )
            .unwrap_or_else(|error| panic!("locked package failed: {error}")),
        );
        metadata.push(
            LakePackageProjectionMetadataV1::new(
                key.clone(),
                json_bool(item, "inherited"),
                json_string(item, "configFile"),
                json_nullable_string(item, "manifestFile"),
                input_revision,
            )
            .unwrap_or_else(|error| panic!("metadata failed: {error}")),
        );
        provenance.push(PackagePathProvenanceV1::manifest(key.clone(), selected));
        source_trees.insert(key.clone(), tree);
        selected_sources.insert(key, selected);
    }
    let lock = LeanBunLockV1::new(
        "leanprover/lean4:v4.32.0",
        "1111111111111111111111111111111111111111",
        "5.0.0-src+8c9756b",
        sha(8),
        sha(9),
        locked,
    )
    .unwrap_or_else(|error| panic!("lock failed: {error}"));
    let mathlib = manifest_packages
        .iter()
        .map(json_object)
        .find(|item| json_string(item, "name") == "mathlib")
        .unwrap_or_else(|| panic!("mathlib missing"));
    let declaration = LakeRootDeclarationV1::new(
        "leanbun_mathlib_fixture",
        "lakefile.toml",
        vec![
            LakeRootDependencyV1::new(
                PackageKeyV1::new("", "mathlib")
                    .unwrap_or_else(|error| panic!("mathlib key failed: {error}")),
                Some(format!("git#{}", json_string(mathlib, "rev"))),
                LakeDependencySourceV1::Git {
                    url: json_string(mathlib, "url").to_owned(),
                    revision: Some(json_string(mathlib, "rev").to_owned()),
                    subdir: None,
                },
            )
            .unwrap_or_else(|error| panic!("root dependency failed: {error}")),
        ],
    )
    .unwrap_or_else(|error| panic!("declaration failed: {error}"));
    let provenance = PackagePathProvenanceSetV1::new(provenance)
        .unwrap_or_else(|error| panic!("provenance failed: {error}"));
    let generation_root = repository
        .join(".leanbun-dev/lean/package-set/packages")
        .to_string_lossy()
        .into_owned();
    let decisions = lock
        .packages()
        .iter()
        .map(|package| {
            let final_path = override_paths
                .get(package.key().name())
                .unwrap_or_else(|| panic!("override path missing for {}", package.key().name()));
            PackagePathDecisionV1::new(
                package.key().clone(),
                &provenance,
                *selected_sources
                    .get(package.key())
                    .unwrap_or_else(|| panic!("selected source missing")),
                &generation_root,
                final_path,
                sha(31),
                *source_trees
                    .get(package.key())
                    .unwrap_or_else(|| panic!("source tree missing")),
                sha(40),
            )
            .unwrap_or_else(|error| panic!("decision failed: {error}"))
        })
        .collect::<Vec<_>>();
    let decisions = PackagePathDecisionSetV1::new(&lock, decisions)
        .unwrap_or_else(|error| panic!("decision set failed: {error}"));
    let manifest_projection = LakeManifestProjectionV1::new(&declaration, &lock, metadata.clone())
        .unwrap_or_else(|error| panic!("manifest projection failed: {error}"));
    let runtime = LakeRuntimePackagesProjectionV1::from_bun_decisions(&lock, &decisions, metadata)
        .unwrap_or_else(|error| panic!("runtime projection failed: {error}"));
    assert_eq!(runtime.package_count(), 9);
    assert!(
        manifest_projection
            .as_str()
            .contains("\"name\":\"mathlib\"")
    );
    for decision in decisions.decisions() {
        assert!(
            runtime.as_str().contains(decision.final_path()),
            "runtime projection omitted {}",
            decision.package().name()
        );
    }
    let observations = decisions
        .decisions()
        .iter()
        .map(|decision| {
            LakeObservedPackagePathV1::new(decision.package().clone(), decision.final_path())
                .unwrap_or_else(|error| panic!("observation failed: {error}"))
        })
        .collect();
    assert_eq!(
        LakeWorkspacePathObservationV1::compare(&decisions, observations)
            .unwrap_or_else(|error| panic!("path comparison failed: {error}"))
            .paths()
            .len(),
        9
    );
}

fn json_object(value: &StrictJson) -> &BTreeMap<String, StrictJson> {
    match value {
        StrictJson::Object(value) => value,
        _ => panic!("expected JSON object"),
    }
}

fn json_array(value: &StrictJson) -> &[StrictJson] {
    match value {
        StrictJson::Array(value) => value,
        _ => panic!("expected JSON array"),
    }
}

fn json_string<'a>(value: &'a BTreeMap<String, StrictJson>, field: &str) -> &'a str {
    match value.get(field) {
        Some(StrictJson::String(value)) => value,
        _ => panic!("expected string field {field}"),
    }
}

fn json_nullable_string(value: &BTreeMap<String, StrictJson>, field: &str) -> Option<String> {
    match value.get(field) {
        Some(StrictJson::String(value)) => Some(value.clone()),
        Some(StrictJson::Null) | None => None,
        _ => panic!("expected nullable string field {field}"),
    }
}

fn json_bool(value: &BTreeMap<String, StrictJson>, field: &str) -> bool {
    match value.get(field) {
        Some(StrictJson::Bool(value)) => *value,
        _ => panic!("expected bool field {field}"),
    }
}
