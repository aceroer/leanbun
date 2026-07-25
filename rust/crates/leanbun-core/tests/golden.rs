use leanbun_core::identity::valid_build_target;
use leanbun_core::{Diagnostic, DiagnosticCode, DiagnosticSeverity, Sha256Hasher};

#[test]
fn diagnostic_vocabulary_matches_bun_oracle() {
    let expected = include_str!("../../../golden/diagnostic-codes.txt")
        .lines()
        .collect::<Vec<_>>();
    let actual = DiagnosticCode::ALL
        .iter()
        .map(|code| code.as_str())
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

#[test]
fn diagnostic_json_matches_bun_oracle() {
    let diagnostic = Diagnostic::new(
        DiagnosticCode::EVIDENCE_READ_FAILED,
        DiagnosticSeverity::Error,
        "cannot read \"fixture\"\nnext",
        ["fixture", "路径"],
    );
    assert_eq!(
        diagnostic.to_canonical_json(),
        include_str!("../../../golden/diagnostic.json").trim_end()
    );
}

#[test]
fn target_validation_matches_shared_cases() {
    for line in include_str!("../../../golden/target-cases.txt").lines() {
        let mut fields = line.splitn(3, '\t');
        let expected = fields.next() == Some("true");
        let encoding = fields.next().unwrap_or("");
        let payload = fields.next().unwrap_or("");
        let value = match encoding {
            "text" => payload.to_owned(),
            "hex" => decode_hex(payload),
            "repeat-a" => "a".repeat(payload.parse::<usize>().unwrap_or(0)),
            "repeat-grin" => "😀".repeat(payload.parse::<usize>().unwrap_or(0)),
            _ => String::new(),
        };
        assert_eq!(valid_build_target(&value), expected, "case: {line}");
    }
}

#[test]
fn sha256_matches_bun_and_system_golden_cases() {
    for line in include_str!("../../../golden/sha256-cases.txt").lines() {
        let mut fields = line.splitn(3, '\t');
        let encoding = fields.next().unwrap_or("");
        let payload = fields.next().unwrap_or("");
        let expected = fields.next().unwrap_or("");
        let input = match encoding {
            "hex" => decode_hex_bytes(payload),
            "repeat-a" => vec![b'a'; payload.parse::<usize>().unwrap_or(0)],
            _ => Vec::new(),
        };
        let mut hasher = Sha256Hasher::new();
        for chunk in input.chunks(7) {
            hasher.update(chunk);
        }
        assert_eq!(hasher.finalize().to_string(), expected, "case: {line}");
    }
}

fn decode_hex(value: &str) -> String {
    String::from_utf8(decode_hex_bytes(value)).unwrap_or_default()
}

fn decode_hex_bytes(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect::<Vec<_>>()
}

const fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}
