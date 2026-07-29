//! Emits the M31 canonical lock identities for the shared Bun/Rust golden fixture.

use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_lock::{
    CanonicalSourceUrlV1, LeanBunLockV1, LockedLeanPackageV1, PackageDependencyV1, PackageKeyV1,
    RequestedPackageSourceV1, ResolvedPackageSourceV1,
};

fn sha(byte: u8) -> Sha256 {
    Sha256::from_bytes([byte; 32])
}

fn package(
    key: PackageKeyV1,
    dependencies: Vec<PackageDependencyV1>,
    selected: Sha256,
) -> Result<LockedLeanPackageV1, Box<dyn std::error::Error>> {
    let url = CanonicalSourceUrlV1::parse("https://github.com/example/package")?;
    Ok(LockedLeanPackageV1::new(
        key,
        RequestedPackageSourceV1::git(url.clone(), Some("main".to_owned()))?,
        ResolvedPackageSourceV1::git(
            url,
            "1111111111111111111111111111111111111111",
            Some("src".to_owned()),
        )?,
        Some(sha(1)),
        sha(2),
        sha(3),
        Some(sha(4)),
        dependencies,
        vec![sha(5)],
        selected,
    )?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let alpha = PackageKeyV1::new("", "alpha")?;
    let beta = PackageKeyV1::new("scope", "beta")?;
    let lock = LeanBunLockV1::new(
        "leanprover/lean4:v4.32.0",
        "1111111111111111111111111111111111111111",
        "5.0.0-src+8c9756b",
        sha(8),
        sha(9),
        vec![
            package(alpha, vec![PackageDependencyV1::new(beta.clone())], sha(6))?,
            package(beta, Vec::new(), sha(7))?,
        ],
    )?;
    let text = lock.to_canonical_text();
    let mut hasher = Sha256Hasher::new();
    hasher.update(text.as_bytes());
    println!("graph\t{}", lock.graph_sha256());
    println!("identity\t{}", lock.identity());
    println!("text-sha256\t{}", hasher.finalize());
    println!("text-hex\t{}", encode_hex(text.as_bytes()));
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
