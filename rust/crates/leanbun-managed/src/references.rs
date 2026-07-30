use super::{ManagedProjectError, input_error, io_error};
use leanbun_build::PackageBuildKeyV1;
use leanbun_core::{ProjectId, Sha256};
use leanbun_lock::{PackageKeyV1, PackageSourceKeyV1};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_REFERENCE_RECORD_BYTES: u64 = 4 * 1024 * 1024;
static REFERENCE_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PackageReferenceV1 {
    pub package: PackageKeyV1,
    pub source: PackageSourceKeyV1,
    pub build: PackageBuildKeyV1,
    pub artifact: Sha256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GenerationReferenceReportV1 {
    pub generation: Sha256,
    pub source_references: usize,
    pub artifact_cache_hits: usize,
    pub artifact_publications: usize,
    pub artifact_reuses: usize,
    pub packages: Vec<PackageReferenceV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GenerationReferenceSummaryV1 {
    pub source_references: usize,
    pub artifact_references: usize,
    pub artifact_cache_hits: usize,
    pub artifact_publications: usize,
    pub artifact_reuses: usize,
    pub source_keys: Vec<Sha256>,
    pub build_keys: Vec<Sha256>,
}

pub(crate) fn publish_generation_references_v1(
    project_control: &Path,
    project: ProjectId,
    report: &GenerationReferenceReportV1,
) -> Result<PathBuf, ManagedProjectError> {
    if project_control.file_name().and_then(|name| name.to_str()) != Some(&project.to_string()) {
        return Err(input_error(
            "generation references do not match project control identity",
        ));
    }
    if report.source_references < report.packages.len()
        || report.artifact_reuses + report.artifact_publications != report.packages.len()
        || report.artifact_cache_hits > report.artifact_reuses
    {
        return Err(input_error("generation reference counts are inconsistent"));
    }
    let mut packages = report.packages.clone();
    packages.sort_by(|left, right| left.package.cmp(&right.package));
    if packages
        .windows(2)
        .any(|pair| pair[0].package == pair[1].package)
    {
        return Err(input_error(
            "generation reference contains duplicate package",
        ));
    }
    let report = GenerationReferenceReportV1 {
        packages,
        ..report.clone()
    };
    let bytes = encode(&report);
    let directory = project_control.join("package-references");
    ensure_private_directory(project_control, &directory)?;
    let path = directory.join(format!("{}.record", report.generation));
    if path.exists() {
        let existing = stable_read(&path)?;
        parse_summary(&existing, report.generation)?;
        if !same_reference_identity(&existing, &bytes) {
            return Err(input_error(
                "generation reference record conflicts with existing bytes",
            ));
        }
        return Ok(path);
    }
    let temporary = directory.join(format!(
        ".{}-{}-{}.tmp",
        report.generation,
        std::process::id(),
        REFERENCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(io_error)?;
    file.write_all(&bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o400)).map_err(io_error)?;
    match fs::rename(&temporary, &path) {
        Ok(()) => {}
        Err(error) if path.exists() => {
            let _ = fs::remove_file(&temporary);
            let existing = stable_read(&path)?;
            parse_summary(&existing, report.generation)?;
            if !same_reference_identity(&existing, &bytes) {
                return Err(input_error(
                    "concurrent generation reference record conflicts",
                ));
            }
            let _ = error;
        }
        Err(error) => return Err(io_error(error)),
    }
    fs::File::open(&directory)
        .and_then(|directory| directory.sync_all())
        .map_err(io_error)?;
    parse_summary(&stable_read(&path)?, report.generation)?;
    Ok(path)
}

fn same_reference_identity(left: &[u8], right: &[u8]) -> bool {
    fn stable_lines(bytes: &[u8]) -> Option<Vec<&str>> {
        let text = std::str::from_utf8(bytes).ok()?;
        Some(
            text.lines()
                .filter(|line| {
                    !line.starts_with("artifact-cache-hits\t")
                        && !line.starts_with("artifact-publications\t")
                        && !line.starts_with("artifact-reuses\t")
                })
                .collect(),
        )
    }
    stable_lines(left) == stable_lines(right)
}

pub(crate) fn read_generation_reference_summary_v1(
    project_control: &Path,
    generation: Sha256,
) -> Result<Option<GenerationReferenceSummaryV1>, ManagedProjectError> {
    let path = project_control
        .join("package-references")
        .join(format!("{generation}.record"));
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o777 != 0o400 {
                return Err(input_error(
                    "generation reference is not a sealed regular file",
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(error)),
    }
    parse_summary(&stable_read(&path)?, generation).map(Some)
}

fn encode(report: &GenerationReferenceReportV1) -> Vec<u8> {
    let mut output = format!(
        "leanbun-generation-package-references-v1\t1\ngeneration\t{}\nsource-references\t{}\nartifact-references\t{}\nartifact-cache-hits\t{}\nartifact-publications\t{}\nartifact-reuses\t{}\n",
        report.generation,
        report.source_references,
        report.packages.len(),
        report.artifact_cache_hits,
        report.artifact_publications,
        report.artifact_reuses
    );
    for package in &report.packages {
        output.push_str(&format!(
            "package\t{}\t{}\t{}\t{}\t{}\n",
            hex(package.package.scope().as_bytes()),
            hex(package.package.name().as_bytes()),
            package.source.digest(),
            package.build.digest(),
            package.artifact
        ));
    }
    output.push_str("end-generation-package-references\n");
    output.into_bytes()
}

fn parse_summary(
    bytes: &[u8],
    generation: Sha256,
) -> Result<GenerationReferenceSummaryV1, ManagedProjectError> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| input_error("generation reference is not UTF-8"))?;
    let mut lines = text.lines();
    if lines.next() != Some("leanbun-generation-package-references-v1\t1")
        || field(&mut lines, "generation")? != generation.to_string()
    {
        return Err(input_error(
            "generation reference header or identity drifted",
        ));
    }
    let source_references = number(field(&mut lines, "source-references")?)?;
    let artifact_references = number(field(&mut lines, "artifact-references")?)?;
    let artifact_cache_hits = number(field(&mut lines, "artifact-cache-hits")?)?;
    let artifact_publications = number(field(&mut lines, "artifact-publications")?)?;
    let artifact_reuses = number(field(&mut lines, "artifact-reuses")?)?;
    let remaining = lines.collect::<Vec<_>>();
    if remaining.len() != artifact_references + 1
        || remaining.last().copied() != Some("end-generation-package-references")
        || artifact_reuses + artifact_publications != artifact_references
        || artifact_cache_hits > artifact_reuses
        || source_references < artifact_references
        || remaining[..artifact_references]
            .iter()
            .any(|line| line.split('\t').count() != 6 || !line.starts_with("package\t"))
    {
        return Err(input_error("generation reference body is inconsistent"));
    }
    let mut source_keys = Vec::with_capacity(artifact_references);
    let mut build_keys = Vec::with_capacity(artifact_references);
    let mut previous_package = None;
    for line in &remaining[..artifact_references] {
        let fields = line.split('\t').collect::<Vec<_>>();
        let package = PackageKeyV1::new(decode_hex(fields[1])?, decode_hex(fields[2])?)
            .map_err(|_| input_error("generation package reference identity is invalid"))?;
        if previous_package
            .as_ref()
            .is_some_and(|prior| prior >= &package)
        {
            return Err(input_error(
                "generation package references are not strictly ordered",
            ));
        }
        previous_package = Some(package);
        source_keys.push(
            Sha256::parse(fields[3])
                .map_err(|_| input_error("generation source reference key is invalid"))?,
        );
        build_keys.push(
            Sha256::parse(fields[4])
                .map_err(|_| input_error("generation build reference key is invalid"))?,
        );
        Sha256::parse(fields[5])
            .map_err(|_| input_error("generation artifact reference digest is invalid"))?;
    }
    Ok(GenerationReferenceSummaryV1 {
        source_references,
        artifact_references,
        artifact_cache_hits,
        artifact_publications,
        artifact_reuses,
        source_keys,
        build_keys,
    })
}

fn field<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    expected: &str,
) -> Result<&'a str, ManagedProjectError> {
    let line = lines
        .next()
        .ok_or_else(|| input_error("generation reference field is missing"))?;
    let (name, value) = line
        .split_once('\t')
        .ok_or_else(|| input_error("generation reference field is malformed"))?;
    if name != expected || value.is_empty() {
        return Err(input_error(
            "generation reference field name or value drifted",
        ));
    }
    Ok(value)
}

fn number(value: &str) -> Result<usize, ManagedProjectError> {
    value
        .parse::<usize>()
        .map_err(|_| input_error("generation reference count is invalid"))
}

fn decode_hex(value: &str) -> Result<String, ManagedProjectError> {
    if !value.len().is_multiple_of(2) {
        return Err(input_error("generation package reference hex is invalid"));
    }
    let bytes = value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect::<Result<Vec<_>, ManagedProjectError>>()?;
    String::from_utf8(bytes)
        .map_err(|_| input_error("generation package reference text is not UTF-8"))
}

fn hex_digit(byte: u8) -> Result<u8, ManagedProjectError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(input_error(
            "generation package reference hex is not lowercase canonical",
        )),
    }
}

fn stable_read(path: &Path) -> Result<Vec<u8>, ManagedProjectError> {
    let before = fs::symlink_metadata(path).map_err(io_error)?;
    if !before.file_type().is_file() || before.len() > MAX_REFERENCE_RECORD_BYTES {
        return Err(input_error(
            "generation reference is not a bounded regular file",
        ));
    }
    let bytes = fs::read(path).map_err(io_error)?;
    let after = fs::symlink_metadata(path).map_err(io_error)?;
    if before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || bytes.len() as u64 != before.len()
    {
        return Err(input_error("generation reference changed while reading"));
    }
    Ok(bytes)
}

fn ensure_private_directory(base: &Path, path: &Path) -> Result<(), ManagedProjectError> {
    if !path.starts_with(base) {
        return Err(input_error(
            "generation reference directory escaped project control",
        ));
    }
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(io_error(error)),
    }
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.file_type().is_dir() {
        return Err(input_error("generation reference directory is not direct"));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(TABLE[(byte >> 4) as usize] as char);
        output.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::parse_summary;
    use leanbun_core::Sha256;

    fn sha(byte: char) -> Sha256 {
        Sha256::parse(&byte.to_string().repeat(64))
            .unwrap_or_else(|error| panic!("test digest failed: {error}"))
    }

    fn record(lines: &[&str]) -> Vec<u8> {
        format!(
            "leanbun-generation-package-references-v1\t1\ngeneration\t{}\nsource-references\t2\nartifact-references\t2\nartifact-cache-hits\t0\nartifact-publications\t1\nartifact-reuses\t1\n{}\nend-generation-package-references\n",
            sha('1'),
            lines.join("\n")
        )
        .into_bytes()
    }

    #[test]
    fn strict_reader_accepts_sorted_complete_reference_identities() {
        let bytes = record(&[
            &format!("package\t\t61\t{}\t{}\t{}", sha('2'), sha('3'), sha('4')),
            &format!("package\t78\t62\t{}\t{}\t{}", sha('5'), sha('6'), sha('7')),
        ]);
        let summary = parse_summary(&bytes, sha('1'))
            .unwrap_or_else(|error| panic!("reference parse failed: {error}"));
        assert_eq!(summary.source_references, 2);
        assert_eq!(summary.artifact_references, 2);
    }

    #[test]
    fn strict_reader_rejects_duplicate_package_and_invalid_artifact_digest() {
        let line = format!("package\t\t61\t{}\t{}\t{}", sha('2'), sha('3'), sha('4'));
        assert!(parse_summary(&record(&[&line, &line]), sha('1')).is_err());
        let bad = format!("package\t78\t62\t{}\t{}\tnot-a-digest", sha('5'), sha('6'));
        assert!(parse_summary(&record(&[&line, &bad]), sha('1')).is_err());
    }
}
