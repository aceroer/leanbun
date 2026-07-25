use leanbun_build::{
    BuildErrorKind, BuildImageFaultV1, BuildImageStoreV1, BuildImageV1, BuildInputsV1,
    ReuseOutcomeV1,
};
use leanbun_core::{Sha256, Sha256Hasher};
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);

fn digest(label: &str) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(label.as_bytes());
    hasher.finalize()
}

fn image(artifact: Sha256) -> BuildImageV1 {
    BuildImageV1::new(
        BuildInputsV1 {
            lock_sha256: digest("lock"),
            graph_sha256: digest("graph"),
            decision_set_sha256: digest("decisions"),
            generation_sha256: digest("generation"),
            lean_toolchain: "leanprover/lean4:v4.32.0".to_owned(),
            compiler_githash: "0123456789abcdef".repeat(2),
            platform: "darwin-arm64".to_owned(),
            build_config_sha256: digest("config"),
            target: "LeanBunFixture".to_owned(),
        },
        artifact,
    )
    .unwrap_or_else(|error| panic!("image failed: {error}"))
}

fn temporary() -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "leanbun-m36-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap_or_else(|error| panic!("temp failed: {error}"));
    root
}

#[test]
fn image_key_excludes_artifact_but_reuse_reverifies_it() {
    let root = temporary();
    let artifact = root.join("candidate.bin");
    fs::write(&artifact, b"artifact-v1").unwrap_or_else(|error| panic!("write failed: {error}"));
    let expected = digest("artifact-v1");
    let first = image(expected);
    let second = image(expected);
    assert_eq!(first.key(), second.key());
    let store =
        BuildImageStoreV1::open(&root).unwrap_or_else(|error| panic!("store failed: {error}"));
    assert_eq!(
        store.publish_or_reuse(&first, &artifact),
        Ok(ReuseOutcomeV1::Published)
    );
    assert_eq!(
        store.publish_or_reuse(&second, &artifact),
        Ok(ReuseOutcomeV1::Reused)
    );
    store
        .verify(&first)
        .unwrap_or_else(|error| panic!("verify failed: {error}"));
    fs::write(
        root.join("objects")
            .join(first.key().to_string())
            .join("artifact.bin"),
        b"drift",
    )
    .unwrap_or_else(|error| panic!("drift failed: {error}"));
    assert_eq!(
        store.verify(&first).map_err(|error| error.kind),
        Err(BuildErrorKind::ArtifactDrift)
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn image_key_rejects_every_build_input_drift() {
    let base = image(digest("artifact"));
    let mut inputs = base.inputs().clone();
    inputs.target = "Other".to_owned();
    let changed = BuildImageV1::new(inputs, digest("artifact"))
        .unwrap_or_else(|error| panic!("changed image failed: {error}"));
    assert_ne!(base.key(), changed.key());
}

#[test]
fn every_coordinator_crash_point_has_an_exact_recovery() {
    for fault in [
        BuildImageFaultV1::AfterLock,
        BuildImageFaultV1::AfterArtifact,
        BuildImageFaultV1::AfterMetadata,
        BuildImageFaultV1::AfterRename,
    ] {
        let root = temporary();
        let artifact = root.join("candidate.bin");
        fs::write(&artifact, b"recoverable")
            .unwrap_or_else(|error| panic!("write failed: {error}"));
        let expected = image(digest("recoverable"));
        let store =
            BuildImageStoreV1::open(&root).unwrap_or_else(|error| panic!("store failed: {error}"));
        assert!(
            store
                .publish_or_reuse_with_fault(&expected, &artifact, fault)
                .is_err()
        );
        let recovered = store
            .recover(&expected)
            .unwrap_or_else(|error| panic!("recovery failed at {fault:?}: {error}"));
        if fault == BuildImageFaultV1::AfterLock {
            assert_eq!(recovered, ReuseOutcomeV1::Aborted);
            assert_eq!(
                store.publish_or_reuse(&expected, &artifact),
                Ok(ReuseOutcomeV1::Published)
            );
        } else {
            assert!(matches!(
                recovered,
                ReuseOutcomeV1::Published | ReuseOutcomeV1::Reused
            ));
        }
        store
            .verify(&expected)
            .unwrap_or_else(|error| panic!("post-recovery verify failed: {error}"));
        let _ = fs::remove_dir_all(root);
    }
}
