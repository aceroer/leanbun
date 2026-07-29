use leanbun_approval_macos::observe_macos_path_provenance_v1;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let executable = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: observe_path_provenance <absolute-executable>")?;
    let observation = observe_macos_path_provenance_v1(&executable)?;

    println!("decision={:?}", observation.decision);
    println!("effective_uid={}", observation.effective_uid);
    println!("acl_coverage={:?}", observation.acl_coverage);
    println!("components={}", observation.components.len());
    for component in &observation.components {
        println!(
            "path={} uid={} gid={} mode={:04o} flags=0x{:08x} write={:?} acl={:?} acl_entries={} fsid={} statvfs_flags=0x{:x} native_mount_flags=0x{:x} read_only={} ignore_ownership={}",
            component.path.display(),
            component.owner_uid,
            component.owner_gid,
            component.unix_mode & 0o7777,
            component.darwin_flags,
            component.effective_uid_write_access,
            component.acl_decision,
            component.acl_entry_count,
            component.mount_fsid,
            component.mount_flags,
            component.native_mount_flags,
            component.native_mount_read_only,
            component.native_mount_ignores_ownership,
        );
    }
    println!("execution_authority={:?}", observation.execution_authority);
    Ok(())
}
