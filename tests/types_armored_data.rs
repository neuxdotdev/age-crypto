use age_crypto::types::ArmoredData;
fn create_armored(s: &str) -> ArmoredData {
    ArmoredData::from(s.to_string())
}
#[test]
fn test_as_str() {
    let armored = create_armored("test");
    assert_eq!(armored.as_str(), "test");
}
#[test]
fn test_len() {
    let armored = create_armored("hello");
    assert_eq!(armored.len(), 5);
    let empty = create_armored("");
    assert_eq!(empty.len(), 0);
}
#[test]
fn test_is_empty() {
    let armored = create_armored("");
    assert!(armored.is_empty());
    let armored2 = create_armored("not empty");
    assert!(!armored2.is_empty());
}
#[test]
fn test_is_valid_armored_valid() {
    let valid = "-----BEGIN AGE ENCRYPTED FILE-----\n...\n-----END AGE ENCRYPTED FILE-----";
    assert!(ArmoredData::is_valid_armored(valid));
}
#[test]
fn test_is_valid_armored_missing_begin() {
    let invalid = "-----BEGIN WRONG-----\n...\n-----END AGE ENCRYPTED FILE-----";
    assert!(!ArmoredData::is_valid_armored(invalid));
}
#[test]
fn test_is_valid_armored_missing_end() {
    let invalid = "-----BEGIN AGE ENCRYPTED FILE-----\n...";
    assert!(!ArmoredData::is_valid_armored(invalid));
}
#[test]
fn test_is_valid_armored_empty() {
    assert!(!ArmoredData::is_valid_armored(""));
}
#[test]
fn test_is_valid_armored_only_begin() {
    let invalid = "-----BEGIN AGE ENCRYPTED FILE-----";
    assert!(!ArmoredData::is_valid_armored(invalid));
}
#[test]
fn test_is_valid_armored_case_sensitive() {
    let lower_begin = "-----begin age encrypted file-----\n...\n-----END AGE ENCRYPTED FILE-----";
    assert!(!ArmoredData::is_valid_armored(lower_begin));
}
#[test]
fn test_as_ref_str() {
    let armored = create_armored("content");
    let as_ref: &str = armored.as_ref();
    assert_eq!(as_ref, "content");
}
#[test]
fn test_deref() {
    let armored = create_armored("deref test");
    let deref_str: &str = &armored;
    assert_eq!(deref_str, "deref test");
    assert_eq!(armored.len(), 10);
    assert!(armored.contains("test"));
}
#[test]
fn test_from_string() {
    let s = "from string".to_string();
    let armored: ArmoredData = s.clone().into();
    assert_eq!(armored.as_str(), "from string");
}
#[test]
fn test_into_string() {
    let armored = create_armored("into string");
    let s: String = armored.into();
    assert_eq!(s, "into string");
}
#[test]
fn test_display() {
    let armored = create_armored("abc");
    assert_eq!(format!("{}", armored), "[ArmoredData: 3 chars]");
    let empty = create_armored("");
    assert_eq!(format!("{}", empty), "[ArmoredData: 0 chars]");
    let long = create_armored(&"x".repeat(1000));
    assert_eq!(format!("{}", long), "[ArmoredData: 1000 chars]");
}
#[test]
fn test_debug() {
    let armored = create_armored("debug");
    let debug_str = format!("{:?}", armored);
    assert!(debug_str.starts_with("ArmoredData("));
    assert!(debug_str.contains("debug"));
}
#[test]
fn test_clone() {
    let armored = create_armored("clone me");
    let cloned = armored.clone();
    assert_eq!(armored.as_str(), cloned.as_str());
    assert_eq!(armored, cloned);
}
#[test]
fn test_partial_eq() {
    let a1 = create_armored("same");
    let a2 = create_armored("same");
    let b = create_armored("different");
    assert_eq!(a1, a2);
    assert_ne!(a1, b);
}
#[test]
fn test_eq_after_from() {
    let s = "hello".to_string();
    let a = create_armored(&s);
    let b = ArmoredData::from(s);
    assert_eq!(a, b);
}
#[test]
fn test_large_data() {
    let large = "x".repeat(10_000);
    let armored = create_armored(&large);
    assert_eq!(armored.len(), 10_000);
    assert_eq!(armored.as_str(), large);
}
#[test]
fn test_unicode() {
    let unicode = "Hello 世界 🦀";
    let armored = create_armored(unicode);
    assert_eq!(armored.len(), unicode.len());
    assert_eq!(armored.as_str(), unicode);
}
#[test]
fn test_is_valid_armored_with_extra_content() {
    let valid = "-----BEGIN AGE ENCRYPTED FILE-----\nsome data\nmore data\n-----END AGE ENCRYPTED FILE-----";
    assert!(ArmoredData::is_valid_armored(valid));
}
#[test]
fn test_is_valid_armored_with_whitespace() {
    let valid = "  -----BEGIN AGE ENCRYPTED FILE-----\n...\n-----END AGE ENCRYPTED FILE-----  ";
    assert!(!ArmoredData::is_valid_armored(valid));
    let trimmed = valid.trim();
    assert!(ArmoredData::is_valid_armored(trimmed));
}
#[test]
fn test_from_into_roundtrip() {
    let original = "roundtrip".to_string();
    let armored = ArmoredData::from(original.clone());
    let back: String = armored.into();
    assert_eq!(original, back);
}
#[test]
fn test_from_empty_string() {
    let armored = ArmoredData::from(String::new());
    assert!(armored.is_empty());
    assert_eq!(armored.as_str(), "");
}
