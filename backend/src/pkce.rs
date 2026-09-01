const MIN_CODE_CHALLENGE_LENGTH: usize = 43;
const MAX_CODE_CHALLENGE_LENGTH: usize = 128;

pub(crate) fn is_valid_code_challenge(value: &str) -> bool {
    (MIN_CODE_CHALLENGE_LENGTH..=MAX_CODE_CHALLENGE_LENGTH).contains(&value.len())
        && value.bytes().all(is_code_challenge_byte)
}

const fn is_code_challenge_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

#[cfg(test)]
mod tests {
    use super::is_valid_code_challenge;

    #[test]
    fn accepts_rfc7636_unreserved_values() {
        assert!(is_valid_code_challenge(&format!("{}.-_~", "a".repeat(39))));
    }

    #[test]
    fn rejects_values_outside_length_or_character_bounds() {
        assert!(!is_valid_code_challenge(&"a".repeat(42)));
        assert!(!is_valid_code_challenge(&"a".repeat(129)));
        assert!(!is_valid_code_challenge(&format!("{}=", "a".repeat(42))));
    }
}
