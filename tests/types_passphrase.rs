use age_crypto::types::Passphrase;
#[test]
fn test_new_and_expose() {
    let pass = Passphrase::new("secret123");
    assert_eq!(pass.expose(), "secret123");
}
#[test]
fn test_len() {
    let pass = Passphrase::new("hello");
    assert_eq!(pass.len(), 5);
    let empty = Passphrase::new("");
    assert_eq!(empty.len(), 0);
}
#[test]
fn test_is_empty() {
    let pass = Passphrase::new("");
    assert!(pass.is_empty());
    let pass2 = Passphrase::new("not empty");
    assert!(!pass2.is_empty());
}
#[test]
fn test_display_redacted() {
    let pass = Passphrase::new("my secret");
    assert_eq!(format!("{}", pass), "[REDACTED]");
}
#[test]
fn test_debug_redacted() {
    let pass = Passphrase::new("hunter2");
    let debug_str = format!("{:?}", pass);
    assert!(debug_str.contains("len: 7"));
    assert!(debug_str.contains("value: \"[REDACTED]\""));
    assert!(!debug_str.contains("hunter2"));
}
#[test]
fn test_clone() {
    let pass = Passphrase::new("cloneable");
    let cloned = pass.clone();
    assert_eq!(pass.expose(), cloned.expose());
    assert_eq!(pass.len(), cloned.len());
}
#[test]
fn test_zeroization_on_drop() {
    let pass = Passphrase::new("to be zeroed");
    drop(pass);
}
#[test]
fn test_unicode_passphrase() {
    let pass = Passphrase::new("你好世界 🦀");
    assert_eq!(pass.len(), "你好世界 🦀".len());
    assert_eq!(pass.expose(), "你好世界 🦀");
}
#[test]
fn test_long_passphrase() {
    let long = "x".repeat(10000);
    let pass = Passphrase::new(&long);
    assert_eq!(pass.len(), 10000);
    assert_eq!(pass.expose(), long);
}
#[test]
fn test_empty_passphrase() {
    let pass = Passphrase::new("");
    assert_eq!(pass.len(), 0);
    assert!(pass.is_empty());
    assert_eq!(pass.expose(), "");
}
#[test]
fn test_multiple_clones_independent() {
    let original = Passphrase::new("original");
    let clone1 = original.clone();
    let clone2 = original.clone();
    assert_eq!(original.expose(), "original");
    assert_eq!(clone1.expose(), "original");
    assert_eq!(clone2.expose(), "original");
    drop(original);
    assert_eq!(clone1.expose(), "original");
    assert_eq!(clone2.expose(), "original");
}
#[test]
fn test_debug_does_not_leak() {
    let pass = Passphrase::new("supersecret");
    let debug_output = format!("{:?}", pass);
    assert!(!debug_output.contains("supersecret"));
    assert!(debug_output.contains("[REDACTED]"));
}
#[test]
fn test_display_does_not_leak() {
    let pass = Passphrase::new("password");
    let display_output = format!("{}", pass);
    assert_eq!(display_output, "[REDACTED]");
}
