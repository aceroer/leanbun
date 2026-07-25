#![forbid(unsafe_code)]

use leanbun_build::{run_lake_basic_regression_v1, run_repository_fixture_acceptance_v1};
use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_lake_bridge::verify_lake_source_compatibility_v1;
use leanbun_managed::{
    ManagedProjectControllerV1, ManagedProjectStatusV1, dry_run_external_adoption_v1,
    run_concurrent_history_regression_v1, run_external_fixture_acceptance_v1,
    run_managed_dependency_regression_v1, run_mathlib_regression_v1,
    run_negative_fixture_regression_v1,
};
use leanbun_store::run_loopback_update_acceptance_v1;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const RELEASE_VERSION: &str = "0.11.0-m42-dev";
const BUN_UPSTREAM_COMMIT: &str = "892b1dabc69e2a0a973244f772b84967c73ccad5";
const BUN_UPSTREAM_TREE: &str = "81a25490c3c5aeb4271a200a96943239b686404b";
const LEAN_TOOLCHAIN: &str = "leanprover/lean4:v4.32.0";
const LEAN_COMPILER_COMMIT: &str = "8c9756b28d64dab099da31a4c09229a9e6a2ef35";
const LAKE_VERSION: &str = "5.0.0-src+8c9756b";
const BUN_LOCK_FILE_SHA256: &str =
    "d2292d26c8200f23db4fc4fc89237117f0d90a25821fb65b8fe009f0e9134ae4";
const RELEASE_CONFIG: &str = "schemaVersion=1\nactiveGenerationReader=1\nmanagedProjectSchema=1\ndependencyClosure=registered-git-v1\nexternalProjectAdoption=fixture-acceptance-v1\nfixtureRegression=lake-basic-managed-dependency-mathlib-negative-concurrent-history-v1\n";

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    let Some(command) = arguments.next() else {
        print_usage();
        return ExitCode::from(64);
    };
    if command == OsStr::new("__leanbun-supervise") {
        return supervise(arguments);
    }
    let result = match command.to_str() {
        Some("version") => version(),
        Some("doctor") => repository_argument(arguments).and_then(|root| doctor(&root)),
        Some("fixture-accept") => {
            repository_argument(arguments).and_then(|root| fixture_accept(&root))
        }
        Some("fixture-regress") => fixture_regression_arguments(arguments)
            .and_then(|(root, fixture)| fixture_regress(&root, &fixture)),
        Some("fixture-network-update") => {
            repository_argument(arguments).and_then(|root| fixture_network_update(&root))
        }
        Some("fixture-install-accept") => {
            repository_argument(arguments).and_then(|root| fixture_install_accept(&root))
        }
        Some("fixture-managed-recovery") => two_path_arguments(arguments)
            .and_then(|(repository, project)| fixture_managed_recovery(&repository, &project)),
        Some("fixture-external-accept") => repository_argument(arguments)
            .and_then(|repository| fixture_external_accept(&repository)),
        Some("install") => two_path_arguments(arguments)
            .and_then(|(repository, root)| install_release(&repository, &root, false)),
        Some("adopt-dry-run") => {
            dry_run_arguments(arguments).and_then(|(repository, project, target)| {
                adoption_dry_run(&repository, &project, &target)
            })
        }
        Some("adopt") => adopt_arguments(arguments).and_then(|(repository, project, target)| {
            adopt_project(&repository, &project, &target)
        }),
        Some("update") => {
            update_arguments(arguments).and_then(|(repository, project, packages)| {
                update_project(&repository, &project, &packages)
            })
        }
        Some("build") => two_path_arguments(arguments)
            .and_then(|(repository, project)| build_project(&repository, &project)),
        Some("managed-status") => two_path_arguments(arguments)
            .and_then(|(repository, project)| managed_status(&repository, &project)),
        Some("recover") => two_path_arguments(arguments)
            .and_then(|(repository, target)| recover_dispatch(&repository, &target)),
        Some("rollback") => two_path_arguments(arguments)
            .and_then(|(repository, target)| rollback_dispatch(&repository, &target)),
        Some("inspect") => repository_argument(arguments).and_then(|root| inspect(&root)),
        Some("export-evidence") => {
            repository_argument(arguments).and_then(|root| export_evidence(&root))
        }
        _ => Err("unknown LeanBun command".to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("leanbun: {error}");
            ExitCode::from(1)
        }
    }
}

fn version() -> Result<(), String> {
    println!("leanbun {RELEASE_VERSION}");
    println!("bun-upstream-commit={BUN_UPSTREAM_COMMIT}");
    println!("bun-upstream-tree={BUN_UPSTREAM_TREE}");
    println!("lean-toolchain={LEAN_TOOLCHAIN}");
    println!("lean-compiler-commit={LEAN_COMPILER_COMMIT}");
    println!("lake-version={LAKE_VERSION}");
    println!("target={}-{}", env::consts::ARCH, env::consts::OS);
    Ok(())
}

fn doctor(repository: &Path) -> Result<(), String> {
    require_platform()?;
    let repository = canonical_repository(repository)?;
    require_hash(
        &repository.join("config/upstream-bun.lock.json"),
        BUN_LOCK_FILE_SHA256,
        "Bun source lock",
    )?;
    let lock = fs::read_to_string(repository.join("config/upstream-bun.lock.json"))
        .map_err(|error| format!("cannot read Bun source lock: {error}"))?;
    for required in [BUN_UPSTREAM_COMMIT, BUN_UPSTREAM_TREE] {
        if !lock.contains(required) {
            return Err("Bun source lock does not name the compiled upstream identity".to_owned());
        }
    }
    let toolchain =
        repository.join(".leanbun-dev/lean/elan-home/toolchains/leanprover--lean4---v4.32.0");
    verify_lake_source_compatibility_v1(&toolchain.join("src/lean/lake"))
        .map_err(|error| format!("Lake source compatibility rejected: {error}"))?;
    let fixture_toolchain =
        fs::read_to_string(repository.join("test/fixtures/lake-basic/lean-toolchain"))
            .map_err(|error| format!("cannot read registered fixture toolchain: {error}"))?;
    if fixture_toolchain.trim() != LEAN_TOOLCHAIN {
        return Err("registered fixture uses an unsupported Lean toolchain".to_owned());
    }
    println!("doctor-status=compatible");
    println!("repository={}", repository.display());
    println!("platform={}-{}", env::consts::ARCH, env::consts::OS);
    println!("bun-source=locked");
    println!("lake-source=locked");
    println!("fixture=lake-basic");
    Ok(())
}

fn fixture_accept(repository: &Path) -> Result<(), String> {
    doctor(repository)?;
    let repository = canonical_repository(repository)?;
    let executable = env::current_exe()
        .map_err(|error| format!("cannot identify release executable: {error}"))?;
    let report = run_repository_fixture_acceptance_v1(&repository, &executable)
        .map_err(|error| format!("fixture acceptance rejected: {error}"))?;
    println!("acceptance-status=passed-and-rolled-back");
    println!("baseline-generation={}", report.baseline_generation_sha256);
    println!(
        "candidate-generation={}",
        report.candidate_generation_sha256
    );
    println!("build-image={}", report.build_image_sha256);
    println!("project-artifact={}", report.project_artifact_sha256);
    Ok(())
}

fn fixture_regress(repository: &Path, fixture: &str) -> Result<(), String> {
    doctor(repository)?;
    let repository = canonical_repository(repository)?;
    let executable = env::current_exe()
        .map_err(|error| format!("cannot identify regression supervisor: {error}"))?;
    if fixture == "lake-basic" {
        let report = run_lake_basic_regression_v1(&repository, &executable)
            .map_err(|error| format!("fixture regression rejected: {error}"))?;
        println!("fixture-regression-status=passed");
        println!("run-id={}", report.run_id);
        println!("fixture={}", report.fixture);
        println!("record={}", report.record.display());
        println!("record-sha256={}", report.record_sha256);
        println!(
            "baseline-generation={}",
            report.acceptance.baseline_generation_sha256
        );
        println!(
            "candidate-generation={}",
            report.acceptance.candidate_generation_sha256
        );
        println!("build-image={}", report.acceptance.build_image_sha256);
        println!(
            "project-artifact={}",
            report.acceptance.project_artifact_sha256
        );
    } else if fixture == "lake-managed-dependency" {
        let report = run_managed_dependency_regression_v1(&repository, &executable)
            .map_err(managed_error)?;
        print_managed_fixture_regression(&report);
    } else if fixture == "mathlib-project" {
        let report = run_mathlib_regression_v1(&repository, &executable).map_err(managed_error)?;
        print_managed_fixture_regression(&report);
    } else if fixture == "negative-matrix" {
        let report = run_negative_fixture_regression_v1(&repository).map_err(managed_error)?;
        println!("negative-fixture-regression-status=passed");
        println!("run-id={}", report.run_id);
        println!("fixture=m42-negative");
        println!("record={}", report.record.display());
        println!("record-sha256={}", report.record_sha256);
        println!("matrix-tree-sha256={}", report.matrix_tree_sha256);
        println!("case-count={}", report.case_count);
        println!("positive-records=unchanged");
        println!("positive-latest=unchanged");
        println!("managed-project-state=none");
        println!("execution-copy=not-created");
        return Ok(());
    } else if fixture == "concurrent-history" {
        let report = run_concurrent_history_regression_v1(&repository).map_err(managed_error)?;
        println!("concurrent-history-regression-status=passed");
        println!("run-id={}", report.run_id);
        println!("concurrent-worker-count=2");
        for digest in report.worker_records {
            println!("worker-record-sha256={digest}");
        }
        println!(
            "failure-terminal-record={}",
            report.failure_terminal_record.display()
        );
        println!(
            "failure-terminal-record-sha256={}",
            report.failure_terminal_sha256
        );
        println!("audit-record={}", report.audit_record.display());
        println!("audit-record-sha256={}", report.audit_record_sha256);
        println!("inventory-sha256={}", report.inventory_sha256);
        println!("positive-record-count={}", report.positive_record_count);
        println!("negative-record-count={}", report.negative_record_count);
        println!("terminal-record-count={}", report.terminal_record_count);
        println!(
            "prior-audit-record-count={}",
            report.prior_audit_record_count
        );
        println!("retention-policy=retain-all-v1");
        println!("automatic-deletion=disabled");
        return Ok(());
    } else {
        return Err("fixture-regress names an unregistered fixture".to_owned());
    }
    println!("execution-copy=cleaned");
    Ok(())
}

fn print_managed_fixture_regression(report: &leanbun_managed::ManagedDependencyRegressionV1) {
    println!("fixture-regression-status=passed");
    println!("run-id={}", report.run_id);
    println!("fixture={}", report.fixture);
    println!("record={}", report.record.display());
    println!("record-sha256={}", report.record_sha256);
    println!("project-id={}", report.project_id);
    println!("package-count={}", report.package_count);
    println!("baseline-generation={}", report.baseline_generation_sha256);
    println!("updated-generation={}", report.updated_generation_sha256);
    println!("rollback-generation={}", report.rollback_generation_sha256);
    println!("project-artifact={}", report.project_artifact_sha256);
    println!("explicit-update-package={}", report.explicit_update_package);
    println!("fault-recovery=passed");
    println!("project-controller-state=cleaned");
}

fn fixture_network_update(repository: &Path) -> Result<(), String> {
    doctor(repository)?;
    let repository = canonical_repository(repository)?;
    let report = run_loopback_update_acceptance_v1(&repository)
        .map_err(|error| format!("explicit network fixture rejected: {error}"))?;
    println!("network-update-status=passed");
    println!("graph={}", report.graph_sha256);
    println!("store-object={}", report.store_object_sha256);
    println!("network-requests={}", report.network_request_count);
    Ok(())
}

fn fixture_managed_recovery(repository: &Path, project: &Path) -> Result<(), String> {
    doctor(repository)?;
    let repository = canonical_repository(repository)?;
    let project = project
        .canonicalize()
        .map_err(|error| format!("cannot canonicalize managed recovery fixture: {error}"))?;
    if !project.starts_with(repository.join(".leanbun-dev-rust/managed-fixture")) {
        return Err(
            "fault injection is restricted to the repository managed-fixture root".to_owned(),
        );
    }
    let controller = managed_controller(&repository, &project)?;
    let before = controller.status().map_err(managed_error)?;
    if controller
        .update_with_fault(leanbun_generation::LeanGenerationFaultV1::BeforeActiveRename)
        .is_ok()
    {
        return Err("managed update fault injection unexpectedly succeeded".to_owned());
    }
    let pending = controller.status().map_err(managed_error)?;
    if pending.pending_transaction.is_none()
        || pending.active_transaction != before.active_transaction
    {
        return Err(
            "failed managed update did not preserve active state with pending evidence".to_owned(),
        );
    }
    let recovered = controller.recover().map_err(managed_error)?;
    if recovered.active_transaction != before.active_transaction
        || recovered.pending_transaction.is_some()
    {
        return Err("managed recovery did not restore the prior active generation".to_owned());
    }
    print_managed_status("fault-recovered", &recovered)
}

fn fixture_external_accept(repository: &Path) -> Result<(), String> {
    doctor(repository)?;
    let repository = canonical_repository(repository)?;
    let executable = env::current_exe()
        .map_err(|error| format!("cannot identify M41 acceptance supervisor: {error}"))?;
    let report =
        run_external_fixture_acceptance_v1(&repository, &executable).map_err(managed_error)?;
    println!("external-acceptance-status=passed");
    println!("project-id={}", report.dry_run.project_id);
    println!("project={}", report.dry_run.project_root.display());
    println!("dry-run-record={}", report.dry_run_record.display());
    println!("acceptance-record={}", report.acceptance_record.display());
    println!("baseline-generation={}", report.baseline_generation_sha256);
    println!("updated-generation={}", report.updated_generation_sha256);
    println!("rollback-generation={}", report.rollback_generation_sha256);
    println!("project-artifact={}", report.project_artifact_sha256);
    Ok(())
}

fn adopt_project(repository: &Path, project: &Path, target: &str) -> Result<(), String> {
    doctor(repository)?;
    let controller = managed_controller(repository, project)?;
    print_managed_status("adopted", &controller.adopt(target).map_err(managed_error)?)
}

fn adoption_dry_run(repository: &Path, project: &Path, target: &str) -> Result<(), String> {
    doctor(repository)?;
    let repository = canonical_repository(repository)?;
    let project = project
        .canonicalize()
        .map_err(|error| format!("cannot canonicalize adoption dry-run candidate: {error}"))?;
    let authorized = repository.join("test/fixtures/lake-managed-dependency");
    let authorized = authorized
        .canonicalize()
        .map_err(|error| format!("cannot canonicalize M41 fixture: {error}"))?;
    if project != authorized {
        return Err(
            "M41 Phase A dry-run is restricted to test/fixtures/lake-managed-dependency".to_owned(),
        );
    }
    let report =
        dry_run_external_adoption_v1(&repository, &project, target).map_err(managed_error)?;
    let state = report.input_state_name();
    println!("adoption-dry-run-status=eligible-not-adopted");
    println!("project-id={}", report.project_id);
    println!("project={}", report.project_root.display());
    println!("target={}", report.target);
    println!("input-state={state}");
    println!("project-tree={}", report.project_tree_sha256);
    println!("entry-count={}", report.entry_count);
    println!("file-count={}", report.file_count);
    println!("byte-count={}", report.byte_count);
    println!("config-file={}", report.config_file);
    println!("config-sha256={}", report.config_sha256);
    println!("toolchain={}", report.toolchain);
    println!("toolchain-sha256={}", report.toolchain_sha256);
    println!("manifest-sha256={}", report.manifest_sha256);
    println!("root-declaration={}", report.root_declaration_sha256);
    println!("direct-dependency-count={}", report.direct_dependency_count);
    println!("manifest-package-count={}", report.manifest_package_count);
    println!("mutation=none");
    Ok(())
}

fn update_project(repository: &Path, project: &Path, packages: &[String]) -> Result<(), String> {
    doctor(repository)?;
    let controller = managed_controller(repository, project)?;
    print_managed_status(
        "updated",
        &controller
            .update_packages(packages)
            .map_err(managed_error)?,
    )
}

fn build_project(repository: &Path, project: &Path) -> Result<(), String> {
    doctor(repository)?;
    let controller = managed_controller(repository, project)?;
    let result = controller.build().map_err(managed_error)?;
    println!("managed-build-status=passed");
    println!("generation={}", result.generation_sha256);
    println!("project-artifact={}", result.project_artifact_sha256);
    Ok(())
}

fn managed_status(repository: &Path, project: &Path) -> Result<(), String> {
    doctor(repository)?;
    let controller = managed_controller(repository, project)?;
    print_managed_status("active", &controller.status().map_err(managed_error)?)
}

fn recover_dispatch(repository: &Path, target: &Path) -> Result<(), String> {
    if is_install_root(repository, target)? {
        recover_install(repository, target)
    } else {
        doctor(repository)?;
        let controller = managed_controller(repository, target)?;
        print_managed_status("recovered", &controller.recover().map_err(managed_error)?)
    }
}

fn rollback_dispatch(repository: &Path, target: &Path) -> Result<(), String> {
    if is_install_root(repository, target)? {
        rollback_install(repository, target)
    } else {
        doctor(repository)?;
        let controller = managed_controller(repository, target)?;
        print_managed_status(
            "rolled-back",
            &controller.rollback().map_err(managed_error)?,
        )
    }
}

fn managed_controller(
    repository: &Path,
    project: &Path,
) -> Result<ManagedProjectControllerV1, String> {
    let repository = canonical_repository(repository)?;
    let project = project
        .canonicalize()
        .map_err(|error| format!("cannot canonicalize managed project: {error}"))?;
    if !project.starts_with(repository.join(".leanbun-dev-rust/managed-fixture")) {
        return Err(
            "generic managed commands permit only repository managed-fixture copies; M41 external acceptance uses its dedicated fixture command"
                .to_owned(),
        );
    }
    let executable = env::current_exe()
        .map_err(|error| format!("cannot identify managed supervisor: {error}"))?;
    ManagedProjectControllerV1::open(&repository, &project, executable).map_err(managed_error)
}

fn print_managed_status(label: &str, status: &ManagedProjectStatusV1) -> Result<(), String> {
    println!("managed-project-status={label}");
    println!("project-id={}", status.project_id);
    println!("project={}", status.project_root.display());
    println!("target={}", status.target);
    println!("active-transaction={}", status.active_transaction);
    println!(
        "previous-transaction={}",
        status
            .previous_transaction
            .map_or("-".to_owned(), |value| value.to_string())
    );
    println!(
        "pending-transaction={}",
        status
            .pending_transaction
            .map_or("-".to_owned(), |value| value.to_string())
    );
    println!("generation={}", status.generation_sha256);
    println!("package-count={}", status.package_count);
    Ok(())
}

fn managed_error(error: leanbun_managed::ManagedProjectError) -> String {
    format!("managed project rejected: {error}")
}

fn is_install_root(repository: &Path, target: &Path) -> Result<bool, String> {
    let repository = canonical_repository(repository)?;
    let target = target
        .canonicalize()
        .map_err(|error| format!("cannot canonicalize recover/rollback target: {error}"))?;
    Ok(target.starts_with(repository.join(".leanbun-dev-rust/release-fixture")))
}

fn fixture_install_accept(repository: &Path) -> Result<(), String> {
    doctor(repository)?;
    let repository = canonical_repository(repository)?;
    let root = repository.join(".leanbun-dev-rust/release-fixture/m38-install-acceptance");
    if root.exists() {
        return Err("install acceptance root already exists".to_owned());
    }
    fs::create_dir_all(&root)
        .map_err(|error| format!("cannot create install acceptance root: {error}"))?;
    let cleanup = Cleanup(root.clone());

    let fresh = root.join("fresh");
    install_release(&repository, &fresh, false)?;
    if read_record(&fresh.join("active"))? != RELEASE_VERSION {
        return Err("fresh install did not activate the release".to_owned());
    }

    let upgrade = root.join("upgrade");
    seed_development_install(&repository, &upgrade)?;
    install_release(&repository, &upgrade, false)?;
    if read_record(&upgrade.join("active"))? != RELEASE_VERSION
        || read_record(&upgrade.join("previous"))? != "0.0.0-dev"
    {
        return Err("upgrade did not preserve the previous development version".to_owned());
    }
    rollback_install(&repository, &upgrade)?;
    if read_record(&upgrade.join("active"))? != "0.0.0-dev"
        || !upgrade
            .join(format!("versions/{RELEASE_VERSION}/leanbun"))
            .is_file()
    {
        return Err("install rollback did not retain and restore both versions".to_owned());
    }

    let crash = root.join("crash");
    seed_development_install(&repository, &crash)?;
    if install_release(&repository, &crash, true).is_ok()
        || read_record(&crash.join("active"))? != "0.0.0-dev"
    {
        return Err("injected install crash changed the active version".to_owned());
    }
    recover_install(&repository, &crash)?;
    if read_record(&crash.join("active"))? != RELEASE_VERSION {
        return Err("install recovery did not publish the verified release".to_owned());
    }
    rollback_install(&repository, &crash)?;
    if read_record(&crash.join("active"))? != "0.0.0-dev" {
        return Err("recovered install could not roll back".to_owned());
    }

    let unsupported = root.join("unsupported-source");
    fs::create_dir_all(unsupported.join("config"))
        .map_err(|error| format!("cannot create compatibility fixture: {error}"))?;
    fs::create_dir_all(unsupported.join("test/fixtures/lake-basic"))
        .map_err(|error| format!("cannot create compatibility fixture: {error}"))?;
    fs::copy(
        repository.join("TEST_PROJECT_BOUNDARY.adoc"),
        unsupported.join("TEST_PROJECT_BOUNDARY.adoc"),
    )
    .map_err(|error| format!("cannot copy compatibility boundary: {error}"))?;
    fs::write(
        unsupported.join("config/upstream-bun.lock.json"),
        b"unsupported-bun-source\n",
    )
    .map_err(|error| format!("cannot write incompatible source lock: {error}"))?;
    if doctor(&unsupported).is_ok() {
        return Err("doctor accepted an unsupported Bun source hash".to_owned());
    }
    println!("install-acceptance-status=passed");
    println!("fresh-install=passed");
    println!("development-upgrade=passed");
    println!("crash-recovery=passed");
    println!("install-rollback=passed");
    println!("unsupported-source-rejection=passed");
    drop(cleanup);
    Ok(())
}

fn install_release(repository: &Path, root: &Path, inject_fault: bool) -> Result<(), String> {
    doctor(repository)?;
    let repository = canonical_repository(repository)?;
    let root = checked_install_root(&repository, root, true)?;
    let executable = env::current_exe()
        .map_err(|error| format!("cannot identify release executable: {error}"))?;
    let version_root = root.join("versions").join(RELEASE_VERSION);
    fs::create_dir_all(root.join("versions"))
        .map_err(|error| format!("cannot create versions directory: {error}"))?;
    if !version_root.exists() {
        let staging = root.join(format!("installing-{}", std::process::id()));
        if staging.exists() {
            return Err("install staging path already exists".to_owned());
        }
        fs::create_dir(&staging)
            .map_err(|error| format!("cannot create install staging: {error}"))?;
        fs::copy(&executable, staging.join("leanbun"))
            .map_err(|error| format!("cannot copy release binary: {error}"))?;
        fs::write(staging.join("config.v1"), RELEASE_CONFIG)
            .map_err(|error| format!("cannot write release config: {error}"))?;
        sync_file(&staging.join("leanbun"))?;
        sync_file(&staging.join("config.v1"))?;
        sync_directory(&staging)?;
        fs::rename(&staging, &version_root)
            .map_err(|error| format!("cannot publish version directory: {error}"))?;
        sync_directory(&root.join("versions"))?;
    }
    if hash_file(&version_root.join("leanbun"))? != hash_file(&executable)?
        || fs::read_to_string(version_root.join("config.v1"))
            .map_err(|error| format!("cannot read installed config: {error}"))?
            != RELEASE_CONFIG
    {
        return Err("installed version bytes do not match this release".to_owned());
    }
    let old = optional_record(&root.join("active"))?;
    atomic_write(
        &root,
        "install-transaction",
        &format!(
            "old={}\nnew={RELEASE_VERSION}\n",
            old.as_deref().unwrap_or("")
        ),
    )?;
    if inject_fault {
        return Err("injected failure before active install publication".to_owned());
    }
    publish_install_records(&root, old.as_deref(), RELEASE_VERSION)?;
    fs::remove_file(root.join("install-transaction"))
        .map_err(|error| format!("cannot clear install transaction: {error}"))?;
    sync_directory(&root)?;
    println!("install-status=active");
    println!("install-root={}", root.display());
    println!("active-version={RELEASE_VERSION}");
    Ok(())
}

fn recover_install(repository: &Path, root: &Path) -> Result<(), String> {
    doctor(repository)?;
    let repository = canonical_repository(repository)?;
    let root = checked_install_root(&repository, root, false)?;
    let transaction = fs::read_to_string(root.join("install-transaction"))
        .map_err(|error| format!("cannot read install transaction: {error}"))?;
    let mut old = None;
    let mut new = None;
    for line in transaction.lines() {
        if let Some(value) = line.strip_prefix("old=") {
            old = if value.is_empty() {
                None
            } else {
                Some(validate_version(value)?)
            };
        } else if let Some(value) = line.strip_prefix("new=") {
            new = Some(validate_version(value)?);
        } else {
            return Err("install transaction contains an unknown field".to_owned());
        }
    }
    let new = new.ok_or_else(|| "install transaction lacks new version".to_owned())?;
    if !root.join("versions").join(&new).join("leanbun").is_file()
        || !root.join("versions").join(&new).join("config.v1").is_file()
    {
        return Err("install recovery version is incomplete".to_owned());
    }
    publish_install_records(&root, old.as_deref(), &new)?;
    fs::remove_file(root.join("install-transaction"))
        .map_err(|error| format!("cannot clear recovered transaction: {error}"))?;
    sync_directory(&root)?;
    println!("install-recovery-status=published");
    println!("active-version={new}");
    Ok(())
}

fn rollback_install(repository: &Path, root: &Path) -> Result<(), String> {
    doctor(repository)?;
    let repository = canonical_repository(repository)?;
    let root = checked_install_root(&repository, root, false)?;
    if root.join("install-transaction").exists() {
        return Err("cannot roll back while an install transaction is pending".to_owned());
    }
    let active = read_record(&root.join("active"))?;
    let previous = read_record(&root.join("previous"))?;
    if !root
        .join("versions")
        .join(&previous)
        .join("leanbun")
        .is_file()
    {
        return Err("previous release binary is missing".to_owned());
    }
    atomic_write(&root, "active", &format!("{previous}\n"))?;
    atomic_write(&root, "previous", &format!("{active}\n"))?;
    println!("install-rollback-status=active");
    println!("active-version={previous}");
    Ok(())
}

fn seed_development_install(repository: &Path, root: &Path) -> Result<(), String> {
    let root = checked_install_root(repository, root, true)?;
    let version = root.join("versions/0.0.0-dev");
    fs::create_dir_all(&version)
        .map_err(|error| format!("cannot seed development version: {error}"))?;
    fs::write(version.join("leanbun"), b"leanbun-development-fixture\n")
        .map_err(|error| format!("cannot seed development binary: {error}"))?;
    fs::write(version.join("config.v1"), RELEASE_CONFIG)
        .map_err(|error| format!("cannot seed development config: {error}"))?;
    atomic_write(&root, "active", "0.0.0-dev\n")
}

fn publish_install_records(root: &Path, old: Option<&str>, new: &str) -> Result<(), String> {
    if let Some(old) = old
        && old != new
    {
        validate_version(old)?;
        atomic_write(root, "previous", &format!("{old}\n"))?;
    }
    atomic_write(root, "active", &format!("{}\n", validate_version(new)?))
}

fn checked_install_root(repository: &Path, root: &Path, create: bool) -> Result<PathBuf, String> {
    let allowed = repository.join(".leanbun-dev-rust/release-fixture");
    fs::create_dir_all(&allowed)
        .map_err(|error| format!("cannot create release fixture root: {error}"))?;
    let allowed = allowed
        .canonicalize()
        .map_err(|error| format!("cannot canonicalize release fixture root: {error}"))?;
    if !root.is_absolute() || !root.starts_with(&allowed) || root == allowed {
        return Err(
            "install root must be a child of this repository's release-fixture root".to_owned(),
        );
    }
    if create {
        fs::create_dir_all(root).map_err(|error| format!("cannot create install root: {error}"))?;
    }
    let root = root
        .canonicalize()
        .map_err(|error| format!("cannot canonicalize install root: {error}"))?;
    if !root.starts_with(&allowed) || root == allowed {
        return Err("canonical install root escaped the release fixture root".to_owned());
    }
    Ok(root)
}

fn atomic_write(root: &Path, name: &str, contents: &str) -> Result<(), String> {
    let next = root.join(format!(".{name}.next"));
    if next.exists() {
        return Err(format!("pending atomic file already exists: {name}"));
    }
    let mut file =
        fs::File::create(&next).map_err(|error| format!("cannot create atomic {name}: {error}"))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| format!("cannot write atomic {name}: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("cannot sync atomic {name}: {error}"))?;
    fs::rename(&next, root.join(name))
        .map_err(|error| format!("cannot publish atomic {name}: {error}"))?;
    sync_directory(root)
}

fn optional_record(path: &Path) -> Result<Option<String>, String> {
    match fs::read_to_string(path) {
        Ok(value) => Ok(Some(validate_version(value.trim())?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot read {}: {error}", path.display())),
    }
}

fn read_record(path: &Path) -> Result<String, String> {
    optional_record(path)?.ok_or_else(|| format!("record is missing: {}", path.display()))
}

fn validate_version(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err("release version record is invalid".to_owned());
    }
    Ok(value.to_owned())
}

fn sync_file(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("cannot sync file {}: {error}", path.display()))
}

fn sync_directory(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync directory {}: {error}", path.display()))
}

fn inspect(repository: &Path) -> Result<(), String> {
    let repository = canonical_repository(repository)?;
    println!("repository={}", repository.display());
    println!(
        "registered-fixture={}",
        repository.join("test/fixtures/lake-basic").display()
    );
    println!("managed-external-projects=0");
    println!("mutation-authority=withheld");
    Ok(())
}

fn export_evidence(repository: &Path) -> Result<(), String> {
    let repository = canonical_repository(repository)?;
    let executable = env::current_exe()
        .map_err(|error| format!("cannot identify release executable: {error}"))?;
    println!("schemaVersion=1");
    println!("releaseVersion={RELEASE_VERSION}");
    println!("bunUpstreamCommit={BUN_UPSTREAM_COMMIT}");
    println!("bunUpstreamTree={BUN_UPSTREAM_TREE}");
    println!("leanCompilerCommit={LEAN_COMPILER_COMMIT}");
    println!("lakeVersion={LAKE_VERSION}");
    println!("target={}-{}", env::consts::ARCH, env::consts::OS);
    println!("binarySha256={}", hash_file(&executable)?);
    println!("repository={}", repository.display());
    println!("signatureStatus=unsigned-development");
    println!("notarizationStatus=not-submitted");
    Ok(())
}

fn supervise(mut arguments: impl Iterator<Item = std::ffi::OsString>) -> ExitCode {
    let Some(executable) = arguments.next() else {
        eprintln!("leanbun supervisor requires an executable");
        return ExitCode::from(64);
    };
    if rustix::process::setsid().is_err() {
        eprintln!("leanbun supervisor could not create a process group");
        return ExitCode::from(70);
    }
    let error = Command::new(executable).args(arguments).exec();
    eprintln!("leanbun supervisor exec failed: {error}");
    ExitCode::from(71)
}

fn repository_argument(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<PathBuf, String> {
    let value = arguments
        .next()
        .ok_or_else(|| "command requires one repository path".to_owned())?;
    if arguments.next().is_some() {
        return Err("command accepts exactly one repository path".to_owned());
    }
    Ok(PathBuf::from(value))
}

fn two_path_arguments(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(PathBuf, PathBuf), String> {
    let first = arguments
        .next()
        .ok_or_else(|| "command requires repository and install-root paths".to_owned())?;
    let second = arguments
        .next()
        .ok_or_else(|| "command requires repository and install-root paths".to_owned())?;
    if arguments.next().is_some() {
        return Err("command accepts exactly two paths".to_owned());
    }
    Ok((PathBuf::from(first), PathBuf::from(second)))
}

fn fixture_regression_arguments(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(PathBuf, String), String> {
    let repository = arguments
        .next()
        .ok_or_else(|| "fixture-regress requires one repository path".to_owned())?;
    let fixture = match arguments.next() {
        None => "lake-basic".to_owned(),
        Some(option) => option
            .into_string()
            .map_err(|_| "fixture-regress option is not UTF-8".to_owned())?
            .strip_prefix("--fixture=")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                "fixture-regress accepts only a nonempty --fixture=NAME option".to_owned()
            })?
            .to_owned(),
    };
    if arguments.next().is_some() {
        return Err("fixture-regress accepts at most one fixture option".to_owned());
    }
    Ok((PathBuf::from(repository), fixture))
}

fn adopt_arguments(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(PathBuf, PathBuf, String), String> {
    let repository = arguments
        .next()
        .ok_or_else(|| "adopt requires repository, project, target, and confirmation".to_owned())?;
    let project = arguments
        .next()
        .ok_or_else(|| "adopt requires repository, project, target, and confirmation".to_owned())?;
    let target = arguments
        .next()
        .ok_or_else(|| "adopt requires repository, project, target, and confirmation".to_owned())?;
    let confirmation = arguments
        .next()
        .ok_or_else(|| "adopt requires repository, project, target, and confirmation".to_owned())?;
    if arguments.next().is_some() || confirmation != OsStr::new("--explicit-managed-project") {
        return Err("adopt requires the exact --explicit-managed-project confirmation".to_owned());
    }
    let target = target
        .into_string()
        .map_err(|_| "managed target is not UTF-8".to_owned())?;
    Ok((PathBuf::from(repository), PathBuf::from(project), target))
}

fn dry_run_arguments(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(PathBuf, PathBuf, String), String> {
    let repository = arguments.next().ok_or_else(|| {
        "adopt-dry-run requires repository, project, target, and confirmation".to_owned()
    })?;
    let project = arguments.next().ok_or_else(|| {
        "adopt-dry-run requires repository, project, target, and confirmation".to_owned()
    })?;
    let target = arguments.next().ok_or_else(|| {
        "adopt-dry-run requires repository, project, target, and confirmation".to_owned()
    })?;
    let confirmation = arguments.next().ok_or_else(|| {
        "adopt-dry-run requires repository, project, target, and confirmation".to_owned()
    })?;
    if arguments.next().is_some() || confirmation != OsStr::new("--explicit-dry-run") {
        return Err("adopt-dry-run requires the exact --explicit-dry-run confirmation".to_owned());
    }
    let target = target
        .into_string()
        .map_err(|_| "dry-run target is not UTF-8".to_owned())?;
    Ok((PathBuf::from(repository), PathBuf::from(project), target))
}

fn update_arguments(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(PathBuf, PathBuf, Vec<String>), String> {
    let repository = arguments
        .next()
        .ok_or_else(|| "update requires repository and project paths".to_owned())?;
    let project = arguments
        .next()
        .ok_or_else(|| "update requires repository and project paths".to_owned())?;
    let mut packages = Vec::new();
    for argument in arguments {
        let argument = argument
            .into_string()
            .map_err(|_| "update package option is not UTF-8".to_owned())?;
        let package = argument
            .strip_prefix("--package=")
            .filter(|package| !package.is_empty())
            .ok_or_else(|| "update accepts only nonempty --package=NAME options".to_owned())?;
        packages.push(package.to_owned());
    }
    Ok((PathBuf::from(repository), PathBuf::from(project), packages))
}

fn canonical_repository(path: &Path) -> Result<PathBuf, String> {
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("cannot canonicalize repository: {error}"))?;
    if !canonical.join("TEST_PROJECT_BOUNDARY.adoc").is_file()
        || !canonical.join("test/fixtures/lake-basic").is_dir()
    {
        return Err("path is not the LeanBun repository with registered fixtures".to_owned());
    }
    Ok(canonical)
}

fn require_platform() -> Result<(), String> {
    if env::consts::OS != "macos" || env::consts::ARCH != "aarch64" {
        return Err("LeanBun v1 supports only macOS arm64".to_owned());
    }
    Ok(())
}

fn require_hash(path: &Path, expected: &str, label: &str) -> Result<(), String> {
    let actual = hash_file(path)?;
    if actual.to_string() != expected {
        return Err(format!("{label} hash is unsupported: {actual}"));
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<Sha256, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() > 128 * 1024 * 1024 {
        return Err(format!(
            "input is not a bounded regular file: {}",
            path.display()
        ));
    }
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut hasher = Sha256Hasher::new();
    hasher.update(&bytes);
    Ok(hasher.finalize())
}

fn print_usage() {
    eprintln!(
        "usage: leanbun <version|doctor|inspect|fixture-accept|fixture-regress|fixture-network-update|fixture-install-accept|fixture-managed-recovery|fixture-external-accept|export-evidence|adopt-dry-run|adopt|update|build|managed-status|recover|rollback> ..."
    );
}

struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        make_writable(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn make_writable(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_dir() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                make_writable(&entry.path());
            }
        }
    } else if metadata.file_type().is_file() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
}
