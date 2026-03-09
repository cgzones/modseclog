#[must_use]
pub(crate) fn contains_case_insensitive(
    haystack: impl AsRef<str>,
    needle: impl AsRef<str>,
) -> bool {
    fn inner(haystack: &str, needle: &str) -> bool {
        let haystack_lower = haystack.to_ascii_lowercase();
        let needle_lower = needle.to_ascii_lowercase();
        haystack_lower.contains(&needle_lower)
    }

    inner(haystack.as_ref(), needle.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_case_insensitive() {
        assert!(contains_case_insensitive("hello", ""));
        assert!(contains_case_insensitive("", ""));
        assert!(!contains_case_insensitive("", "hello"));
        assert!(contains_case_insensitive("foobar", "foo"));
        assert!(contains_case_insensitive("barfoo", "foo"));
        assert!(!contains_case_insensitive("bar", "foo"));
        assert!(!contains_case_insensitive("baz", "bar"));
        assert!(!contains_case_insensitive("bar", "foobar"));
        assert!(contains_case_insensitive("fOo", "foo"));
        assert!(!contains_case_insensitive("Foo", "fOu"));
    }

    #[test]
    fn test_contains_case_insensitive_overlapping() {
        assert!(contains_case_insensitive("aaab", "aab"));
        assert!(contains_case_insensitive("ababa", "aba"));
        assert!(contains_case_insensitive("baa", "aa"));
        assert!(contains_case_insensitive("aaab", "AAB"));
        assert!(contains_case_insensitive("AAAB", "aab"));

        assert!(contains_case_insensitive("hello", "hello"));
        assert!(contains_case_insensitive("hello", "HELLO"));
        assert!(contains_case_insensitive("HELLO", "hello"));

        assert!(contains_case_insensitive("hello world!", "world"));
        assert!(contains_case_insensitive("hello world!", "WORLD"));
        assert!(contains_case_insensitive("hello world!", "lo wo"));
    }
}
