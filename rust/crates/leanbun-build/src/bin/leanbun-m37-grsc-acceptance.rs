#![forbid(unsafe_code)]

use leanbun_build::{
    BuildErrorKind, BuildImageV1, BuildInputsV1, SupervisedLakeBuildV1, project_artifact_sha256_v1,
    run_supervised_lake_build_v1, verify_lake_workspace_paths_v1,
};
use leanbun_core::{Sha256, Sha256Hasher};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

const TOOLCHAIN: &str = "leanprover/lean4:v4.32.0";
const COMPILER: &str = "8c9756b28d64dab099da31a4c09229a9e6a2ef35";
const TARGET: &str = "GRSC";
const FAILURE_TARGET: &str = "LeanBunIntentionalMissingTarget";
const EXPECTED_LAKE: &str = "58261a1a2fa1a362376c71e02ca854a093e71cc5e6ea64b287a931cb2565273d";
const EXPECTED_MANIFEST: &str = "41c9dbc1f83d4418b242b5b296628b7533558060ba195ffe28a6ad8ad7a91f49";
const EXPECTED_TOOLCHAIN: &str = "2773c517aa90b66ea8a2c52bddddf84393157797f8341be0df45294fff7fd32e";
const EXPECTED_CONFIG: &str = "c1d86bb4f548fadcad806d8a62f0f295c1dbfd6e92cf9520dfb9eb7cc026edaa";
const EXPECTED_LEGACY_OVERRIDE: &str =
    "4b6b0a278d135b9da81301faab4989308b43a5eb20840487b3ee9f91c185d6af";
const EXPECTED_RUNTIME: &str = "d3f503435675166710c94a50f948ff72b9c7a484579686dbe4f26715f80265ea";
const SOURCE_ATTESTATION: &str = "4c131d0a6d516b775d169317feb9d60cd08b7116f31707b7669b21710b027c2a";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let repository_argument = arguments
        .next()
        .ok_or("usage: leanbun-m37-grsc-acceptance REPOSITORY PROJECT")?;
    let project_argument = arguments
        .next()
        .ok_or("usage: leanbun-m37-grsc-acceptance REPOSITORY PROJECT")?;
    if arguments.next().is_some() {
        return Err("usage: leanbun-m37-grsc-acceptance REPOSITORY PROJECT".into());
    }
    let repository = canonical_directory(Path::new(&repository_argument))?;
    let project = canonical_directory(Path::new(&project_argument))?;
    let project_identity = project.to_string_lossy();
    require_hash(&project.join("lakefile.lean"), EXPECTED_CONFIG)?;
    require_hash(&project.join("lean-toolchain"), EXPECTED_TOOLCHAIN)?;
    require_hash(&project.join("lake-manifest.json"), EXPECTED_MANIFEST)?;
    require_hash(
        &project.join(".lake/package-overrides.json"),
        EXPECTED_LEGACY_OVERRIDE,
    )?;

    let development = repository.join(".leanbun-dev/lean");
    let runtime = development.join("overrides/package-overrides.json");
    let registry = development.join("registry/manifest.json");
    let attestation = repository.join(
        ".leanbun-dev/state/attestations/f96a870796339f594c527940b43b4a7c1941e8180e9b6f449a917d2f5aff5ff1.json",
    );
    require_hash(&runtime, EXPECTED_RUNTIME)?;
    require_hash(&attestation, SOURCE_ATTESTATION)?;
    let lake = development
        .join("elan-home/toolchains/leanprover--lean4---v4.32.0/bin/lake")
        .canonicalize()?;
    require_hash(&lake, EXPECTED_LAKE)?;
    let package_paths = runtime_paths(&runtime, &development.join("package-set/packages"))?;
    if package_paths.len() != 9 {
        return Err("M37 requires exactly nine Bun-decided package paths".into());
    }

    let control = project.join(".leanbun/m37");
    if control.exists() {
        if fs::read_dir(&control)?.next().is_some() {
            return Err(
                "M37 control directory already contains state; refusing an ambiguous rerun".into(),
            );
        }
    } else {
        fs::create_dir_all(&control)?;
    }
    fs::set_permissions(project.join(".leanbun"), fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(&control, fs::Permissions::from_mode(0o700))?;

    let protected_before = protected_source_digest(&project)?;
    let artifact_root = project.join(".lake/build");
    let project_artifact_before = project_artifact_sha256_v1(&artifact_root)?;
    let dependency_before = dependency_image_digest(&package_paths)?;
    let runtime_sha = hash_file(&runtime)?;
    let registry_sha = hash_file(&registry)?;
    let decision_sha = decision_digest(&package_paths);
    let generation_sha = combine(
        b"leanbun-m37-imported-generation-v1\0",
        &[runtime_sha, registry_sha, hash_file(&attestation)?],
    );
    let build_image = BuildImageV1::new(
        BuildInputsV1 {
            lock_sha256: hash_file(&project.join("lake-manifest.json"))?,
            graph_sha256: registry_sha,
            decision_set_sha256: decision_sha,
            generation_sha256: generation_sha,
            lean_toolchain: TOOLCHAIN.to_owned(),
            compiler_githash: COMPILER.to_owned(),
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            build_config_sha256: hash_file(&project.join("lakefile.lean"))?,
            target: TARGET.to_owned(),
        },
        dependency_before,
    )?;

    let legacy = fs::read(project.join(".lake/package-overrides.json"))?;
    create_synced(&control.join("retained-package-overrides.json"), &legacy)?;
    let baseline = format!(
        "leanbun-m37-generation-v1\t1\nkind\tbaseline\nproject\t{}\noverride-sha256\t{}\nproject-input-sha256\t{}\nproject-artifact-sha256\t{}\n",
        hex(project_identity.as_bytes()),
        EXPECTED_LEGACY_OVERRIDE,
        protected_before,
        project_artifact_before,
    );
    create_synced(&control.join("baseline.record"), baseline.as_bytes())?;
    replace_synced(&control.join("active.record"), baseline.as_bytes())?;

    let profile = control.join("build.sb");
    let profile_text = sandbox_profile(&project, &control)?;
    create_synced(&profile, profile_text.as_bytes())?;
    let supervisor = std::env::current_exe()?
        .parent()
        .ok_or("M37 binary has no parent")?
        .join("leanbun-process-supervisor")
        .canonicalize()?;
    let request = build_request(&supervisor, &lake, &project, &runtime, &profile, TARGET)?;

    verify_lake_workspace_paths_v1(&request, &package_paths)?;
    let mut failure = request.clone();
    failure.target = FAILURE_TARGET.to_owned();
    failure.allowed_targets.insert(FAILURE_TARGET.to_owned());
    let failure_error = run_supervised_lake_build_v1(&failure)
        .err()
        .ok_or("intentional M37 failure unexpectedly succeeded")?;
    if failure_error.kind != BuildErrorKind::LakeNonzero {
        return Err(
            format!("intentional M37 failure had wrong terminal kind: {failure_error}").into(),
        );
    }
    if fs::read_to_string(control.join("active.record"))? != baseline {
        return Err("failed candidate changed the baseline active record".into());
    }
    let failure_record = format!(
        "leanbun-m37-failure-v1\t1\ntarget\t{}\nterminal\tlake-nonzero\nactive-preserved\ttrue\n",
        FAILURE_TARGET
    );
    create_synced(&control.join("failure.record"), failure_record.as_bytes())?;

    let first = run_supervised_lake_build_v1(&request)?;
    let artifact_after_first = project_artifact_sha256_v1(&artifact_root)?;
    let second = run_supervised_lake_build_v1(&request)?;
    let artifact_after_second = project_artifact_sha256_v1(&artifact_root)?;
    if artifact_after_first != artifact_after_second {
        return Err("same M37 build image did not produce stable project output".into());
    }
    let protected_after = protected_source_digest(&project)?;
    if protected_before != protected_after {
        return Err("M37 changed protected project source or declarations".into());
    }
    let dependency_after = dependency_image_digest(&package_paths)?;
    if dependency_before != dependency_after {
        return Err("M37 changed the frozen dependency image".into());
    }
    require_hash(
        &project.join(".lake/package-overrides.json"),
        EXPECTED_LEGACY_OVERRIDE,
    )?;

    let candidate = format!(
        "leanbun-m37-generation-v1\t1\nkind\tcandidate\nbuild-image\t{}\ngeneration\t{}\ndecisions\t{}\nruntime-sha256\t{}\nproject-input-sha256\t{}\nproject-artifact-sha256\t{}\ndependency-artifact-sha256\t{}\npackage-count\t9\ntarget\t{}\n",
        build_image.key(),
        generation_sha,
        decision_sha,
        runtime_sha,
        protected_after,
        artifact_after_second,
        dependency_after,
        TARGET,
    );
    create_synced(&control.join("candidate.record"), candidate.as_bytes())?;
    replace_synced(&control.join("active.record"), candidate.as_bytes())?;
    if fs::read_to_string(control.join("active.record"))? != candidate {
        return Err("candidate active publication did not read back exactly".into());
    }

    replace_synced(&control.join("active.record"), baseline.as_bytes())?;
    if fs::read_to_string(control.join("active.record"))? != baseline {
        return Err("M37 rollback did not restore the retained baseline".into());
    }
    let acceptance = format!(
        "leanbun-m37-acceptance-v1\t1\nstatus\trolled-back\nproject\t{}\ntarget\t{}\nbuild-image\t{}\ngeneration\t{}\ndecisions\t{}\nprotected-before\t{}\nprotected-after\t{}\nproject-artifact-before\t{}\nproject-artifact-after\t{}\ndependency-artifact-before\t{}\ndependency-artifact-after\t{}\nfirst-process-group\t{}\nsecond-process-group\t{}\nintentional-failure\tlake-nonzero\npackage-count\t9\nlegacy-override-preserved\ttrue\nsource-attestation-sha256\t{}\n",
        hex(project_identity.as_bytes()),
        TARGET,
        build_image.key(),
        generation_sha,
        decision_sha,
        protected_before,
        protected_after,
        project_artifact_before,
        artifact_after_second,
        dependency_before,
        dependency_after,
        first.process_group_id,
        second.process_group_id,
        SOURCE_ATTESTATION,
    );
    create_synced(&control.join("acceptance.record"), acceptance.as_bytes())?;
    println!("status=rolled-back");
    println!("build-image={}", build_image.key());
    println!("generation={generation_sha}");
    println!("decisions={decision_sha}");
    println!("project-input={protected_after}");
    println!("project-artifact={artifact_after_second}");
    println!("dependency-artifact={dependency_after}");
    Ok(())
}

fn build_request(
    supervisor: &Path,
    lake: &Path,
    project: &Path,
    runtime: &Path,
    profile: &Path,
    target: &str,
) -> Result<SupervisedLakeBuildV1, Box<dyn std::error::Error>> {
    let repository = runtime
        .ancestors()
        .nth(4)
        .ok_or("runtime path has no LeanBun repository ancestor")?;
    let toolchain = repository
        .join(".leanbun-dev/lean/elan-home/toolchains/leanprover--lean4---v4.32.0");
    let bin = toolchain.join("bin");
    Ok(SupervisedLakeBuildV1 {
        supervisor_executable: supervisor.to_path_buf(),
        sandbox_executable: PathBuf::from("/usr/bin/sandbox-exec"),
        sandbox_profile: profile.to_path_buf(),
        sandbox_profile_sha256: hash_file(profile)?,
        lake_executable: lake.to_path_buf(),
        lake_executable_sha256: hash_file(lake)?,
        cwd: project.to_path_buf(),
        runtime_packages: runtime.to_path_buf(),
        target: target.to_owned(),
        allowed_targets: BTreeSet::from([target.to_owned()]),
        environment: BTreeMap::from([
            (
                "PATH".to_owned(),
                format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", bin.display()),
            ),
            ("HOME".to_owned(), project.to_string_lossy().into_owned()),
            (
                "TMPDIR".to_owned(),
                project.join(".leanbun/m37").to_string_lossy().into_owned(),
            ),
            (
                "LEAN_SYSROOT".to_owned(),
                toolchain.to_string_lossy().into_owned(),
            ),
            (
                "DYLD_LIBRARY_PATH".to_owned(),
                toolchain.join("lib/lean").to_string_lossy().into_owned(),
            ),
            ("LC_ALL".to_owned(), "C.UTF-8".to_owned()),
            ("LANG".to_owned(), "C.UTF-8".to_owned()),
            ("DO_NOT_TRACK".to_owned(), "1".to_owned()),
            ("LAKE_NO_CACHE".to_owned(), "1".to_owned()),
            ("LAKE_ARTIFACT_CACHE".to_owned(), "0".to_owned()),
        ]),
        deadline: Duration::from_secs(300),
        termination_grace: Duration::from_secs(2),
        maximum_output_bytes: 16 * 1024 * 1024,
    })
}

fn sandbox_profile(project: &Path, control: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let build = project.join(".lake/build").canonicalize()?;
    let config = project.join(".lake/config").canonicalize()?;
    Ok(format!(
        "(version 1)\n(allow default)\n(deny network*)\n(deny file-write*)\n(allow file-write*\n  (subpath {})\n  (subpath {})\n  (subpath {})\n  (literal \"/dev/null\")\n  (literal \"/dev/stdin\")\n  (literal \"/dev/stdout\")\n  (literal \"/dev/stderr\"))\n",
        sbpl(&build),
        sbpl(&config),
        sbpl(control),
    ))
}

fn sbpl(path: &Path) -> String {
    format!("{:?}", path.to_string_lossy())
}

fn runtime_paths(
    runtime: &Path,
    allowed_root: &Path,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let allowed_root = allowed_root.canonicalize()?;
    let text = fs::read_to_string(runtime)?;
    let mut paths = Vec::new();
    for line in text.lines() {
        if let Some(value) = line
            .trim()
            .strip_prefix("\"dir\": \"")
            .and_then(|value| value.strip_suffix("\","))
        {
            let path = PathBuf::from(value).canonicalize()?;
            if !path.starts_with(&allowed_root) || !path.is_dir() {
                return Err(
                    "runtime package path escaped the frozen development package set".into(),
                );
            }
            paths.push(path);
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn protected_source_digest(project: &Path) -> Result<Sha256, Box<dyn std::error::Error>> {
    let mut entries = Vec::new();
    collect_source(project, project, &mut entries)?;
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-m37-protected-project-v1\0");
    for (relative, digest) in entries {
        hash_text(&mut hasher, &relative);
        hasher.update(digest.as_bytes());
    }
    Ok(hasher.finalize())
}

fn collect_source(
    root: &Path,
    current: &Path,
    output: &mut Vec<(String, Sha256)>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let name = entry.file_name();
        if kind.is_dir() && (name == ".lake" || name == ".leanbun" || name == ".git") {
            continue;
        }
        if kind.is_dir() {
            collect_source(root, &entry.path(), output)?;
        } else if kind.is_file() {
            let relative = entry
                .path()
                .strip_prefix(root)?
                .to_string_lossy()
                .into_owned();
            output.push((relative, hash_file(&entry.path())?));
        } else {
            return Err("protected project contains a symlink or special file".into());
        }
    }
    Ok(())
}

fn dependency_image_digest(paths: &[PathBuf]) -> Result<Sha256, Box<dyn std::error::Error>> {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-m37-dependency-artifacts-v1\0");
    for path in paths {
        hash_text(&mut hasher, &path.to_string_lossy());
        let build = path.join(".lake/build");
        if build.is_dir() {
            hasher.update(project_artifact_sha256_v1(&build)?.as_bytes());
        } else {
            hasher.update(&[0_u8; 32]);
        }
    }
    Ok(hasher.finalize())
}

fn decision_digest(paths: &[PathBuf]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-m37-path-decisions-v1\0");
    for path in paths {
        hash_text(&mut hasher, &path.to_string_lossy());
    }
    hasher.finalize()
}

fn combine(domain: &[u8], values: &[Sha256]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(domain);
    for value in values {
        hasher.update(value.as_bytes());
    }
    hasher.finalize()
}

fn hash_text(hasher: &mut Sha256Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn hash_file(path: &Path) -> Result<Sha256, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > 1024 * 1024 * 1024 {
        return Err(format!(
            "M37 input is not a bounded regular file: {}",
            path.display()
        )
        .into());
    }
    let mut file = File::open(path)?;
    let mut hasher = Sha256Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize())
}

fn require_hash(path: &Path, expected: &str) -> Result<(), Box<dyn std::error::Error>> {
    let expected = Sha256::parse(expected)?;
    let actual = hash_file(path)?;
    if actual != expected {
        return Err(format!(
            "M37 fixed input drifted: {} expected {expected}, got {actual}",
            path.display()
        )
        .into());
    }
    Ok(())
}

fn canonical_directory(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = path.canonicalize()?;
    if !path.is_dir() {
        return Err("M37 boundary is not a directory".into());
    }
    Ok(path)
}

fn create_synced(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn replace_synced(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = path.with_extension("next");
    create_synced(&temporary, bytes)?;
    fs::rename(temporary, path)?;
    let parent = File::open(path.parent().ok_or("record has no parent")?)?;
    parent.sync_all()?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}
