#[must_use]
pub(crate) fn contains_case_insensitive(
    needle: impl AsRef<str>,
    haystack: impl AsRef<str>,
) -> bool {
    let needle = needle.as_ref();
    let haystack = haystack.as_ref();

    let mut needle_iter = needle.chars();

    for char in haystack.chars() {
        let Some(needle_char) = needle_iter.next() else {
            return true;
        };

        if !char.eq_ignore_ascii_case(&needle_char) {
            needle_iter = needle.chars();
        }
    }

    needle_iter.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_case_insensitive() {
        assert!(contains_case_insensitive("", "hello"));
        assert!(!contains_case_insensitive("hello", ""));
        assert!(contains_case_insensitive("foo", "foobar"));
        assert!(contains_case_insensitive("foo", "barfoo"));
        assert!(!contains_case_insensitive("foo", "bar"));
        assert!(!contains_case_insensitive("bar", "baz"));
        assert!(!contains_case_insensitive("foobar", "bar"));
        assert!(contains_case_insensitive("foo", "fOo"));
        assert!(!contains_case_insensitive("fOu", "Foo"));
    }
}
