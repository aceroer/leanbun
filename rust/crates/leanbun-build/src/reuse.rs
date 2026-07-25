use crate::model::{BuildError, BuildErrorKind, BuildImageV1, hash_file, io};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReuseOutcomeV1 {
    Published,
    Reused,
    Aborted,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BuildImageFaultV1 {
    #[default]
    None,
    AfterLock,
    AfterArtifact,
    AfterMetadata,
    AfterRename,
}

#[derive(Clone, Debug)]
pub struct BuildImageStoreV1 {
    root: PathBuf,
}

impl BuildImageStoreV1 {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, BuildError> {
        let root = root.as_ref().canonicalize().map_err(io)?;
        if !root.is_dir() {
            return Err(BuildError::new(
                BuildErrorKind::BoundaryViolation,
                "image root is not a directory",
            ));
        }
        Ok(Self { root })
    }

    pub fn publish_or_reuse(
        &self,
        image: &BuildImageV1,
        artifact: &Path,
    ) -> Result<ReuseOutcomeV1, BuildError> {
        self.publish_or_reuse_with_fault(image, artifact, BuildImageFaultV1::None)
    }

    pub fn publish_or_reuse_with_fault(
        &self,
        image: &BuildImageV1,
        artifact: &Path,
        fault: BuildImageFaultV1,
    ) -> Result<ReuseOutcomeV1, BuildError> {
        let artifact = artifact.canonicalize().map_err(io)?;
        if !artifact.is_file() || (artifact != self.root && !artifact.starts_with(&self.root)) {
            return Err(BuildError::new(
                BuildErrorKind::BoundaryViolation,
                "build image artifact escapes image root",
            ));
        }
        let observed = hash_file(&artifact, 512 * 1_024 * 1_024)?;
        if observed != image.dependency_artifact_sha256() {
            return Err(BuildError::new(
                BuildErrorKind::ArtifactDrift,
                "candidate build image artifact drifted",
            ));
        }
        let key = image.key().to_string();
        let object = self.root.join("objects").join(&key);
        let record = object.join("image.meta");
        if object.exists() {
            verify_record(&record, image)?;
            return Ok(ReuseOutcomeV1::Reused);
        }
        fs::create_dir_all(self.root.join("objects")).map_err(io)?;
        let lock = self.root.join(format!("{key}.lock"));
        let mut lock_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    BuildError::new(
                        BuildErrorKind::LockBusy,
                        "build image key is already locked",
                    )
                } else {
                    io(error)
                }
            })?;
        lock_file
            .write_all(b"leanbun-build-image-lock-v1\n")
            .map_err(io)?;
        lock_file.sync_all().map_err(io)?;
        inject(fault, BuildImageFaultV1::AfterLock)?;
        let temporary = self.root.join("objects").join(format!(".{key}.tmp"));
        if temporary.exists() {
            return Err(BuildError::new(
                BuildErrorKind::RecordDrift,
                "unknown build image staging entry exists",
            ));
        }
        fs::create_dir(&temporary).map_err(io)?;
        fs::copy(&artifact, temporary.join("artifact.bin")).map_err(io)?;
        inject(fault, BuildImageFaultV1::AfterArtifact)?;
        let bytes = record_bytes(image);
        let mut metadata = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temporary.join("image.meta"))
            .map_err(io)?;
        metadata.write_all(bytes.as_bytes()).map_err(io)?;
        metadata.sync_all().map_err(io)?;
        inject(fault, BuildImageFaultV1::AfterMetadata)?;
        fs::rename(&temporary, &object).map_err(io)?;
        inject(fault, BuildImageFaultV1::AfterRename)?;
        fs::remove_file(&lock).map_err(io)?;
        verify_record(&record, image)?;
        Ok(ReuseOutcomeV1::Published)
    }

    /// Recovers only a named image transaction. Unknown or drifted staging is
    /// retained for diagnosis and is never guessed stale by age.
    pub fn recover(&self, image: &BuildImageV1) -> Result<ReuseOutcomeV1, BuildError> {
        let key = image.key().to_string();
        let object = self.root.join("objects").join(&key);
        let temporary = self.root.join("objects").join(format!(".{key}.tmp"));
        let lock = self.root.join(format!("{key}.lock"));
        if object.exists() {
            self.verify(image)?;
            if lock.exists() {
                fs::remove_file(lock).map_err(io)?;
            }
            return Ok(ReuseOutcomeV1::Reused);
        }
        if !lock.is_file() {
            return Err(BuildError::new(
                BuildErrorKind::RecordDrift,
                "build image recovery lock is missing",
            ));
        }
        if !temporary.exists() {
            fs::remove_file(lock).map_err(io)?;
            return Ok(ReuseOutcomeV1::Aborted);
        }
        let actual = hash_file(&temporary.join("artifact.bin"), 512 * 1_024 * 1_024)?;
        if actual != image.dependency_artifact_sha256() {
            return Err(BuildError::new(
                BuildErrorKind::ArtifactDrift,
                "staged build image artifact drifted",
            ));
        }
        let metadata_path = temporary.join("image.meta");
        if metadata_path.exists() {
            verify_record(&metadata_path, image)?;
        } else {
            let mut metadata = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&metadata_path)
                .map_err(io)?;
            metadata
                .write_all(record_bytes(image).as_bytes())
                .map_err(io)?;
            metadata.sync_all().map_err(io)?;
        }
        fs::rename(&temporary, &object).map_err(io)?;
        fs::remove_file(lock).map_err(io)?;
        self.verify(image)?;
        Ok(ReuseOutcomeV1::Published)
    }

    pub fn verify(&self, image: &BuildImageV1) -> Result<(), BuildError> {
        let object = self.root.join("objects").join(image.key().to_string());
        verify_record(&object.join("image.meta"), image)?;
        let actual = hash_file(&object.join("artifact.bin"), 512 * 1_024 * 1_024)?;
        if actual != image.dependency_artifact_sha256() {
            return Err(BuildError::new(
                BuildErrorKind::ArtifactDrift,
                "stored build image artifact drifted",
            ));
        }
        Ok(())
    }
}

fn inject(actual: BuildImageFaultV1, expected: BuildImageFaultV1) -> Result<(), BuildError> {
    if actual == expected {
        Err(BuildError::new(
            BuildErrorKind::Io,
            format!("M36 coordinator crash injected at {expected:?}"),
        ))
    } else {
        Ok(())
    }
}

fn record_bytes(image: &BuildImageV1) -> String {
    format!(
        "leanbun-build-image-v1\t1\nkey\t{}\nartifact\t{}\n",
        image.key(),
        image.dependency_artifact_sha256()
    )
}

fn verify_record(path: &Path, image: &BuildImageV1) -> Result<(), BuildError> {
    let actual = fs::read_to_string(path).map_err(io)?;
    if actual != record_bytes(image) {
        return Err(BuildError::new(
            BuildErrorKind::RecordDrift,
            "build image metadata drifted",
        ));
    }
    Ok(())
}
