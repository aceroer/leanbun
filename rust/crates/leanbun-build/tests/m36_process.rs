#![cfg(target_os = "macos")]

use leanbun_build::{
    BuildErrorKind, ProgramTerminationReasonV1, SupervisedLakeBuildV1, SupervisedProgramRunV1,
    project_artifact_sha256_v1, protected_project_input_sha256_v1, run_supervised_lake_build_v1,
    run_supervised_program_v1, verify_lake_workspace_paths_v1,
};
use leanbun_core::{Sha256, Sha256Hasher};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(1);

fn hash_file(path: &Path) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(&fs::read(path).unwrap_or_else(|error| panic!("hash read failed: {error}")));
    hasher.finalize()
}

fn program_request(
    root: &Path,
    body: &str,
    arguments: Vec<String>,
    deadline: Duration,
    maximum: usize,
) -> SupervisedProgramRunV1 {
    let script = root.join("program");
    fs::write(&script, format!("#!/bin/sh\n{body}\n"))
        .unwrap_or_else(|error| panic!("program script failed: {error}"));
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("program chmod failed: {error}"));
    let profile = root.join("program.sb");
    fs::write(&profile, "(version 1)\n(allow default)\n(deny network*)\n")
        .unwrap_or_else(|error| panic!("program profile failed: {error}"));
    SupervisedProgramRunV1 {
        supervisor_executable: PathBuf::from(env!("CARGO_BIN_EXE_leanbun-process-supervisor")),
        sandbox_executable: PathBuf::from("/usr/bin/sandbox-exec"),
        sandbox_profile_sha256: hash_file(&profile),
        sandbox_profile: profile,
        executable_sha256: hash_file(&script),
        executable: script,
        cwd: root.to_path_buf(),
        arguments,
        environment: BTreeMap::from([
            ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
            ("HOME".to_owned(), root.to_string_lossy().into_owned()),
            ("TMPDIR".to_owned(), root.to_string_lossy().into_owned()),
            ("LC_ALL".to_owned(), "C.UTF-8".to_owned()),
            ("LANG".to_owned(), "C.UTF-8".to_owned()),
        ]),
        deadline,
        termination_grace: Duration::from_millis(100),
        maximum_output_bytes: maximum,
    }
}

#[test]
fn supervised_program_preserves_arguments_and_bounded_terminal_results() {
    let success_root = temporary();
    let success = program_request(
        &success_root,
        "printf '%s' \"$1\"",
        vec!["exact argument".to_owned()],
        Duration::from_secs(2),
        1024,
    );
    let result = run_supervised_program_v1(&success)
        .unwrap_or_else(|error| panic!("program success failed: {error}"));
    assert_eq!(
        result.exit_code,
        0,
        "program stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, b"exact argument");
    assert_eq!(result.termination, ProgramTerminationReasonV1::Exit);

    let nonzero_root = temporary();
    let nonzero = program_request(
        &nonzero_root,
        "exit 7",
        Vec::new(),
        Duration::from_secs(2),
        1024,
    );
    let result = run_supervised_program_v1(&nonzero)
        .unwrap_or_else(|error| panic!("program nonzero failed: {error}"));
    assert_eq!(result.exit_code, 7);
    assert_eq!(result.termination, ProgramTerminationReasonV1::Exit);

    let timeout_root = temporary();
    let timeout = program_request(
        &timeout_root,
        "sleep 5",
        Vec::new(),
        Duration::from_millis(100),
        1024,
    );
    let result = run_supervised_program_v1(&timeout)
        .unwrap_or_else(|error| panic!("program timeout failed: {error}"));
    assert_eq!(result.exit_code, 124);
    assert_eq!(result.termination, ProgramTerminationReasonV1::Timeout);

    let signal_root = temporary();
    let signal = program_request(
        &signal_root,
        "kill -TERM $$",
        Vec::new(),
        Duration::from_secs(2),
        1024,
    );
    let result = run_supervised_program_v1(&signal)
        .unwrap_or_else(|error| panic!("program signal failed: {error}"));
    assert_eq!(result.exit_code, 143);
    assert_eq!(result.termination, ProgramTerminationReasonV1::Signal);
    assert_eq!(result.signal, Some(15));

    let overflow_root = temporary();
    let overflow = program_request(
        &overflow_root,
        "yes x",
        Vec::new(),
        Duration::from_secs(2),
        1024,
    );
    let result = run_supervised_program_v1(&overflow)
        .unwrap_or_else(|error| panic!("program overflow failed: {error}"));
    assert_eq!(result.exit_code, 125);
    assert_eq!(
        result.termination,
        ProgramTerminationReasonV1::OutputOverflow
    );
    assert_eq!(result.stdout.len(), 1024);

    let mut too_many = success.clone();
    too_many.arguments = vec!["x".to_owned(); 65];
    assert_eq!(
        run_supervised_program_v1(&too_many).map_err(|error| error.kind),
        Err(BuildErrorKind::InvalidField)
    );
    for root in [
        success_root,
        nonzero_root,
        timeout_root,
        signal_root,
        overflow_root,
    ] {
        let _ = fs::remove_dir_all(root);
    }
}

fn temporary() -> PathBuf {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap_or_else(|| panic!("repository root missing"));
    let parent = repository.join(".leanbun-dev-rust/test-tmp");
    fs::create_dir_all(&parent).unwrap_or_else(|error| panic!("test-tmp failed: {error}"));
    let root = parent.join(format!(
        "leanbun-m36-process-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap_or_else(|error| panic!("temp failed: {error}"));
    root.canonicalize()
        .unwrap_or_else(|error| panic!("canonical temp failed: {error}"))
}

fn script_request(
    root: &Path,
    body: &str,
    deadline: Duration,
    maximum: usize,
) -> SupervisedLakeBuildV1 {
    let script = root.join("fake-lake");
    fs::write(&script, format!("#!/bin/sh\n{body}\n"))
        .unwrap_or_else(|error| panic!("script failed: {error}"));
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("chmod failed: {error}"));
    let packages = root.join("runtime-packages.json");
    fs::write(&packages, "{\"version\":\"1.2.0\",\"packages\":[]}")
        .unwrap_or_else(|error| panic!("packages failed: {error}"));
    let profile = root.join("sandbox.sb");
    fs::write(&profile, "(version 1)\n(allow default)\n(deny network*)\n")
        .unwrap_or_else(|error| panic!("profile failed: {error}"));
    SupervisedLakeBuildV1 {
        supervisor_executable: PathBuf::from(env!("CARGO_BIN_EXE_leanbun-process-supervisor")),
        sandbox_executable: PathBuf::from("/usr/bin/sandbox-exec"),
        sandbox_profile_sha256: hash_file(&profile),
        sandbox_profile: profile,
        lake_executable_sha256: hash_file(&script),
        lake_executable: script,
        cwd: root.to_path_buf(),
        runtime_packages: packages,
        target: "Fixture".to_owned(),
        allowed_targets: BTreeSet::from(["Fixture".to_owned()]),
        environment: BTreeMap::from([("PATH".to_owned(), "/usr/bin:/bin".to_owned())]),
        deadline,
        termination_grace: Duration::from_millis(100),
        maximum_output_bytes: maximum,
    }
}

#[test]
fn supervisor_accepts_success_and_rejects_nonzero_timeout_and_overflow() {
    let success_root = temporary();
    let success = script_request(&success_root, "printf ok", Duration::from_secs(2), 1024);
    let result = run_supervised_lake_build_v1(&success)
        .unwrap_or_else(|error| panic!("success failed: {error}"));
    assert_eq!(result.stdout, b"ok");
    let mut forbidden = success.clone();
    forbidden.target = "NotAllowed".to_owned();
    assert_eq!(
        run_supervised_lake_build_v1(&forbidden).map_err(|error| error.kind),
        Err(BuildErrorKind::InvalidField)
    );
    fs::write(&success.lake_executable, "#!/bin/sh\nprintf drift\n")
        .unwrap_or_else(|error| panic!("executable drift failed: {error}"));
    assert_eq!(
        run_supervised_lake_build_v1(&success).map_err(|error| error.kind),
        Err(BuildErrorKind::ExecutableDrift)
    );

    let nonzero_root = temporary();
    let nonzero = script_request(&nonzero_root, "exit 7", Duration::from_secs(2), 1024);
    assert_eq!(
        run_supervised_lake_build_v1(&nonzero).map_err(|error| error.kind),
        Err(BuildErrorKind::LakeNonzero)
    );

    let timeout_root = temporary();
    let timeout = script_request(&timeout_root, "sleep 5", Duration::from_millis(100), 1024);
    assert_eq!(
        run_supervised_lake_build_v1(&timeout).map_err(|error| error.kind),
        Err(BuildErrorKind::TimedOut)
    );

    let signal_root = temporary();
    let signal = script_request(&signal_root, "kill -TERM $$", Duration::from_secs(2), 1024);
    assert_eq!(
        run_supervised_lake_build_v1(&signal).map_err(|error| error.kind),
        Err(BuildErrorKind::Signalled)
    );

    let overflow_root = temporary();
    let overflow = script_request(
        &overflow_root,
        "yes x | head -c 4096",
        Duration::from_secs(2),
        1024,
    );
    assert_eq!(
        run_supervised_lake_build_v1(&overflow).map_err(|error| error.kind),
        Err(BuildErrorKind::OutputOverflow)
    );
    for root in [
        success_root,
        nonzero_root,
        timeout_root,
        signal_root,
        overflow_root,
    ] {
        let _ = fs::remove_dir_all(root);
    }
}

#[test]
fn build_artifact_hash_accepts_large_compiler_cache_without_weakening_source_limits() {
    let root = temporary();
    let cache = root.join("cache");
    fs::File::create(&cache)
        .and_then(|file| file.set_len(65 * 1024 * 1024))
        .unwrap_or_else(|error| panic!("large cache fixture failed: {error}"));
    let before = project_artifact_sha256_v1(&root)
        .unwrap_or_else(|error| panic!("large artifact hash failed: {error}"));
    fs::write(root.join("marker"), b"changed")
        .unwrap_or_else(|error| panic!("marker failed: {error}"));
    let after = project_artifact_sha256_v1(&root)
        .unwrap_or_else(|error| panic!("changed artifact hash failed: {error}"));
    assert_ne!(before, after);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn dependency_free_and_mathlib_build_offline_with_actual_paths() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap_or_else(|| panic!("repository root missing"));
    let toolchain =
        repository.join(".leanbun-dev/lean/elan-home/toolchains/leanprover--lean4---v4.32.0");
    let lake = toolchain
        .join("bin/lake")
        .canonicalize()
        .unwrap_or_else(|error| panic!("Lake missing: {error}"));
    let package_overrides = repository
        .join(".leanbun-dev/lean/overrides/package-overrides.json")
        .canonicalize()
        .unwrap_or_else(|error| panic!("overrides missing: {error}"));
    let cases = [
        (
            "lake-basic",
            "leanbun_lake_fixture",
            repository.join("test/fixtures/lake-basic/lake-manifest.json"),
            Vec::new(),
        ),
        (
            "mathlib-project",
            "LeanBunMathlibFixture",
            package_overrides.clone(),
            override_paths(&package_overrides),
        ),
    ];
    for (fixture, target, runtime, paths) in cases {
        let root = temporary();
        copy_tree(&repository.join("test/fixtures").join(fixture), &root);
        let runtime_copy = root.join("runtime-packages.json");
        fs::copy(runtime, &runtime_copy)
            .unwrap_or_else(|error| panic!("runtime copy failed: {error}"));
        let profile = root.join("sandbox.sb");
        fs::write(&profile, format!("(version 1)\n(allow default)\n(deny network*)\n(deny file-write*)\n(allow file-write* (subpath {:?}) (literal \"/dev/null\") (literal \"/dev/stdout\") (literal \"/dev/stderr\"))\n", root.to_string_lossy()))
            .unwrap_or_else(|error| panic!("profile failed: {error}"));
        let bin = toolchain.join("bin");
        let request = SupervisedLakeBuildV1 {
            supervisor_executable: PathBuf::from(env!("CARGO_BIN_EXE_leanbun-process-supervisor")),
            sandbox_executable: PathBuf::from("/usr/bin/sandbox-exec"),
            sandbox_profile_sha256: hash_file(&profile),
            sandbox_profile: profile,
            lake_executable_sha256: hash_file(&lake),
            lake_executable: lake.clone(),
            cwd: root.clone(),
            runtime_packages: runtime_copy,
            target: target.to_owned(),
            allowed_targets: BTreeSet::from([target.to_owned()]),
            environment: BTreeMap::from([
                (
                    "PATH".to_owned(),
                    format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", bin.display()),
                ),
                ("HOME".to_owned(), root.to_string_lossy().into_owned()),
                ("TMPDIR".to_owned(), root.to_string_lossy().into_owned()),
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
            deadline: Duration::from_secs(120),
            termination_grace: Duration::from_secs(1),
            maximum_output_bytes: 16 * 1024 * 1024,
        };
        let protected_before = protected_project_input_sha256_v1(&root)
            .unwrap_or_else(|error| panic!("protected pre-hash failed: {error}"));
        verify_lake_workspace_paths_v1(&request, &paths)
            .unwrap_or_else(|error| panic!("path verification failed for {fixture}: {error}"));
        run_supervised_lake_build_v1(&request)
            .unwrap_or_else(|error| panic!("build failed for {fixture}: {error}"));
        let protected_after = protected_project_input_sha256_v1(&root)
            .unwrap_or_else(|error| panic!("protected post-hash failed: {error}"));
        assert_eq!(
            protected_before, protected_after,
            "Lake changed protected input for {fixture}"
        );
        let artifact_root = root.join(".lake/build");
        let artifact_first = project_artifact_sha256_v1(&artifact_root)
            .unwrap_or_else(|error| panic!("artifact hash failed: {error}"));
        run_supervised_lake_build_v1(&request)
            .unwrap_or_else(|error| panic!("reuse build failed for {fixture}: {error}"));
        let artifact_second = project_artifact_sha256_v1(&artifact_root)
            .unwrap_or_else(|error| panic!("reuse artifact hash failed: {error}"));
        assert_eq!(
            artifact_first, artifact_second,
            "same build image was not reused for {fixture}"
        );
        if !paths.is_empty() {
            assert_eq!(
                verify_lake_workspace_paths_v1(&request, &paths[..paths.len() - 1])
                    .map_err(|error| error.kind),
                Err(BuildErrorKind::PathDrift)
            );
        }
        let _ = fs::remove_dir_all(root);
    }
}

fn copy_tree(source: &Path, destination: &Path) {
    for entry in fs::read_dir(source).unwrap_or_else(|error| panic!("read tree failed: {error}")) {
        let entry = entry.unwrap_or_else(|error| panic!("entry failed: {error}"));
        let target = destination.join(entry.file_name());
        if entry
            .file_type()
            .unwrap_or_else(|error| panic!("type failed: {error}"))
            .is_dir()
        {
            fs::create_dir(&target).unwrap_or_else(|error| panic!("mkdir failed: {error}"));
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap_or_else(|error| panic!("copy failed: {error}"));
        }
    }
}

fn override_paths(path: &Path) -> Vec<PathBuf> {
    let text =
        fs::read_to_string(path).unwrap_or_else(|error| panic!("override read failed: {error}"));
    text.lines()
        .filter_map(|line| line.trim().strip_prefix("\"dir\": \"")?.strip_suffix("\","))
        .map(PathBuf::from)
        .collect()
}
