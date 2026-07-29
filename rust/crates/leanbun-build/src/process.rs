use crate::model::{
    BuildError, BuildErrorKind, BuildResultV1, SupervisedLakeBuildV1, TerminationReasonV1,
    hash_file, io,
};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub fn run_supervised_lake_build_v1(
    request: &SupervisedLakeBuildV1,
) -> Result<BuildResultV1, BuildError> {
    execute(request, request.lake_arguments())
}

/// Loads the exact workspace through Lake and compares its effective package
/// search roots with Bun's final-path decisions.  The root package and Lean
/// sysroot entries are excluded; no package is inferred from the manifest.
pub fn verify_lake_workspace_paths_v1(
    request: &SupervisedLakeBuildV1,
    expected_package_paths: &[PathBuf],
) -> Result<(), BuildError> {
    let result = execute(
        request,
        vec![
            format!("--packages={}", request.runtime_packages.display()),
            "--no-cache".to_owned(),
            "--keep-toolchain".to_owned(),
            "--no-ansi".to_owned(),
            "env".to_owned(),
            "/usr/bin/env".to_owned(),
        ],
    )?;
    let output = String::from_utf8(result.stdout).map_err(|_| {
        BuildError::new(
            BuildErrorKind::PathDrift,
            "Lake environment output is not UTF-8",
        )
    })?;
    let lean_path = output
        .lines()
        .find_map(|line| line.strip_prefix("LEAN_PATH="))
        .ok_or_else(|| {
            BuildError::new(BuildErrorKind::PathDrift, "Lake did not report LEAN_PATH")
        })?;
    let suffix = PathBuf::from(".lake/build/lib/lean");
    let expected = expected_package_paths
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut observed = BTreeSet::new();
    for entry in lean_path.split(':') {
        let path = PathBuf::from(entry);
        if path.ends_with(&suffix)
            && let Some(package) = path
                .parent()
                .and_then(|path| path.parent())
                .and_then(|path| path.parent())
                .and_then(|path| path.parent())
        {
            let package = package.to_path_buf();
            if package != request.cwd {
                observed.insert(package);
            }
        }
    }
    if observed != expected {
        return Err(BuildError::new(
            BuildErrorKind::PathDrift,
            format!(
                "Lake actual package paths differ from Bun decisions: expected {expected:?}, observed {observed:?}"
            ),
        ));
    }
    Ok(())
}

fn execute(
    request: &SupervisedLakeBuildV1,
    lake_arguments: Vec<String>,
) -> Result<BuildResultV1, BuildError> {
    request.validate()?;
    if hash_file(&request.lake_executable, 128 * 1_024 * 1_024)? != request.lake_executable_sha256
        || hash_file(&request.sandbox_profile, 1024 * 1_024)? != request.sandbox_profile_sha256
    {
        return Err(BuildError::new(
            BuildErrorKind::ExecutableDrift,
            "Lake executable or sandbox profile differs from its fixed SHA",
        ));
    }

    let mut command = Command::new(&request.supervisor_executable);
    command
        .arg("__leanbun-supervise")
        .arg(&request.sandbox_executable)
        .arg("-D")
        .arg(format!(
            "LEANBUN_REPOSITORY={}",
            sandbox_repository(&request.sandbox_profile).display()
        ))
        .arg("-f")
        .arg(&request.sandbox_profile)
        .arg(&request.lake_executable)
        .args(lake_arguments)
        .current_dir(&request.cwd)
        .env_clear()
        .envs(&request.environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|error| {
        BuildError::new(
            BuildErrorKind::SpawnFailed,
            format!("cannot spawn M36 supervisor: {error}"),
        )
    })?;
    let process_group_id = child.id();
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io(std::io::Error::other("stdout pipe missing")))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io(std::io::Error::other("stderr pipe missing")))?;
    let maximum = request.maximum_output_bytes;
    let stdout_reader = thread::spawn(move || read_bounded(stdout, maximum));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, maximum));
    let started = Instant::now();
    let mut termination = TerminationReasonV1::Exit;
    let status = 'wait: loop {
        if let Some(status) = child.try_wait().map_err(io)? {
            break status;
        }
        if started.elapsed() >= request.deadline {
            termination = TerminationReasonV1::Timeout;
            signal_group(process_group_id, "-TERM")?;
            let grace_started = Instant::now();
            loop {
                if let Some(status) = child.try_wait().map_err(io)? {
                    break 'wait status;
                }
                if grace_started.elapsed() >= request.termination_grace {
                    signal_group(process_group_id, "-KILL")?;
                    break 'wait child.wait().map_err(io)?;
                }
                thread::sleep(Duration::from_millis(10));
            }
        } else {
            thread::sleep(Duration::from_millis(10));
            continue;
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| io(std::io::Error::other("stdout reader panicked")))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| io(std::io::Error::other("stderr reader panicked")))??;
    if termination == TerminationReasonV1::Exit && status.code().is_none() {
        termination = TerminationReasonV1::Signal;
    }
    let output_overflow = stdout.1 || stderr.1;
    let exit_code = status.code().unwrap_or(128);
    let result = BuildResultV1 {
        exit_code,
        stdout: stdout.0,
        stderr: stderr.0,
        termination,
        process_group_id,
        output_overflow,
    };
    if output_overflow {
        return Err(BuildError::new(
            BuildErrorKind::OutputOverflow,
            "Lake output exceeded its bound",
        ));
    }
    if termination == TerminationReasonV1::Timeout {
        return Err(BuildError::new(
            BuildErrorKind::TimedOut,
            "Lake process group exceeded its deadline",
        ));
    }
    if termination == TerminationReasonV1::Signal {
        return Err(BuildError::new(
            BuildErrorKind::Signalled,
            "Lake process group ended by signal",
        ));
    }
    if !status.success() {
        return Err(BuildError::new(
            BuildErrorKind::LakeNonzero,
            format!(
                "Lake exited nonzero ({exit_code}): {}",
                String::from_utf8_lossy(&result.stderr)
            ),
        ));
    }
    Ok(result)
}

fn sandbox_repository(profile: &Path) -> &Path {
    profile
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("/private/tmp/leanbun-unavailable-repository"))
}

fn read_bounded(mut reader: impl Read, maximum: usize) -> Result<(Vec<u8>, bool), BuildError> {
    let mut output = Vec::with_capacity(maximum.min(64 * 1024));
    let mut buffer = [0_u8; 8192];
    let mut overflow = false;
    loop {
        let count = reader.read(&mut buffer).map_err(io)?;
        if count == 0 {
            break;
        }
        let remaining = maximum.saturating_sub(output.len());
        output.extend_from_slice(&buffer[..count.min(remaining)]);
        overflow |= count > remaining;
    }
    Ok((output, overflow))
}

fn signal_group(process_group_id: u32, signal: &str) -> Result<(), BuildError> {
    let target = format!("-{process_group_id}");
    let status = Command::new("/bin/kill")
        .args([signal, "--", &target])
        .env_clear()
        .status()
        .map_err(io)?;
    if !status.success() {
        return Err(BuildError::new(
            BuildErrorKind::Signalled,
            "cannot signal Lake process group",
        ));
    }
    Ok(())
}
