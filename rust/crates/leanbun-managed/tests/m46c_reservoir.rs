#![cfg(target_os = "macos")]

use leanbun_managed::run_reservoir_loopback_regression_v1;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[test]
fn registered_reservoir_loopback_closes_durable_rebind_and_offline_rollback() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap_or_else(|| panic!("repository root missing"))
        .canonicalize()
        .unwrap_or_else(|error| panic!("repository canonicalization failed: {error}"));
    let report = run_reservoir_loopback_regression_v1(&repository)
        .unwrap_or_else(|error| panic!("M46C regression failed: {error}"));

    assert!(report.result_record.starts_with(&report.run_root));
    assert_eq!(
        report.registry_read_count,
        report.frozen_replay_registry_reads
    );
    assert_eq!(report.audit_record_count, 10);
    assert_ne!(report.old_lock_identity, report.new_lock_identity);
    assert_ne!(report.old_binding_identity, report.new_binding_identity);
    let verification_records = fs::read_dir(report.run_root.join("records"))
        .unwrap_or_else(|error| panic!("record directory read failed: {error}"))
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .contains("-verification-")
        })
        .collect::<Vec<_>>();
    assert_eq!(verification_records.len(), 2);
    assert!(verification_records.iter().all(|entry| {
        entry
            .metadata()
            .map(|metadata| metadata.permissions().mode() & 0o777 == 0o400)
            .unwrap_or(false)
    }));
    assert_eq!(
        fs::symlink_metadata(&report.result_record)
            .unwrap_or_else(|error| panic!("result metadata failed: {error}"))
            .permissions()
            .mode()
            & 0o777,
        0o400
    );
    let result = fs::read_to_string(&report.result_record)
        .unwrap_or_else(|error| panic!("result read failed: {error}"));
    assert!(result.contains("ordinary-rebind\trejected\n"));
    assert!(result.contains("old-offline-after-disappearance\tpassed\n"));
    assert!(result.contains("network-access\tnone\n"));
    assert!(result.contains("public-discovery\tclosed\n"));
}
