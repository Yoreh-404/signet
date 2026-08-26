pub(crate) fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::escape;

    #[test]
    fn escape_rejects_markup_in_text_and_attributes() {
        assert_eq!(
            escape("<script>alert(\"x\")</script>'"),
            "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&#39;"
        );
    }
}
