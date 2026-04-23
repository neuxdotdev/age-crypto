use age_crypto::types::EncryptedData;
fn create_encrypted(data: Vec<u8>) -> EncryptedData {
    EncryptedData::from(data)
}
#[test]
fn test_as_bytes() {
    let data = vec![1, 2, 3];
    let encrypted = create_encrypted(data.clone());
    assert_eq!(encrypted.as_bytes(), data.as_slice());
}
#[test]
fn test_to_vec() {
    let data = vec![1, 2, 3];
    let encrypted = create_encrypted(data.clone());
    assert_eq!(encrypted.to_vec(), data);
    assert_eq!(encrypted.as_bytes(), data.as_slice());
}
#[test]
fn test_len() {
    let encrypted = create_encrypted(vec![1, 2, 3, 4, 5]);
    assert_eq!(encrypted.len(), 5);
    let empty = create_encrypted(vec![]);
    assert_eq!(empty.len(), 0);
}
#[test]
fn test_is_empty() {
    let encrypted = create_encrypted(vec![]);
    assert!(encrypted.is_empty());
    let encrypted2 = create_encrypted(vec![0]);
    assert!(!encrypted2.is_empty());
}
#[test]
fn test_as_ref_bytes() {
    let data = vec![10, 20, 30];
    let encrypted = create_encrypted(data.clone());
    let as_ref: &[u8] = encrypted.as_ref();
    assert_eq!(as_ref, data.as_slice());
}
#[test]
fn test_from_vec() {
    let data = vec![100, 200, 255];
    let encrypted: EncryptedData = data.clone().into();
    assert_eq!(encrypted.as_bytes(), data.as_slice());
}
#[test]
fn test_into_vec() {
    let encrypted = create_encrypted(vec![5, 6, 7]);
    let vec: Vec<u8> = encrypted.into();
    assert_eq!(vec, vec![5, 6, 7]);
}
#[test]
fn test_display() {
    let encrypted = create_encrypted(vec![1, 2, 3]);
    assert_eq!(format!("{}", encrypted), "[EncryptedData: 3 bytes]");
    let empty = create_encrypted(vec![]);
    assert_eq!(format!("{}", empty), "[EncryptedData: 0 bytes]");
    let long = create_encrypted(vec![0; 1000]);
    assert_eq!(format!("{}", long), "[EncryptedData: 1000 bytes]");
}
#[test]
fn test_debug() {
    let encrypted = create_encrypted(vec![1, 2, 3]);
    let debug_str = format!("{:?}", encrypted);
    assert!(debug_str.starts_with("EncryptedData("));
    assert!(debug_str.contains("1, 2, 3"));
}
#[test]
fn test_clone() {
    let encrypted = create_encrypted(vec![10, 20, 30]);
    let cloned = encrypted.clone();
    assert_eq!(encrypted.as_bytes(), cloned.as_bytes());
    assert_eq!(encrypted, cloned);
}
#[test]
fn test_partial_eq() {
    let a1 = create_encrypted(vec![1, 2, 3]);
    let a2 = create_encrypted(vec![1, 2, 3]);
    let b = create_encrypted(vec![1, 2, 4]);
    assert_eq!(a1, a2);
    assert_ne!(a1, b);
}
#[test]
fn test_eq_after_from() {
    let data = vec![255, 0, 128];
    let a = create_encrypted(data.clone());
    let b = EncryptedData::from(data);
    assert_eq!(a, b);
}
#[test]
fn test_large_data() {
    let large = vec![42; 10_000];
    let encrypted = create_encrypted(large.clone());
    assert_eq!(encrypted.len(), 10_000);
    assert_eq!(encrypted.as_bytes(), large.as_slice());
}
#[test]
fn test_empty_data() {
    let empty = create_encrypted(vec![]);
    assert_eq!(empty.as_bytes(), &[]);
    assert_eq!(empty.to_vec(), Vec::<u8>::new());
}
#[test]
fn test_from_into_roundtrip() {
    let original = vec![1, 2, 3, 4, 5];
    let encrypted = EncryptedData::from(original.clone());
    let back: Vec<u8> = encrypted.into();
    assert_eq!(original, back);
}
#[test]
fn test_zero_bytes() {
    let data = vec![0, 0, 0];
    let encrypted = create_encrypted(data.clone());
    assert_eq!(encrypted.as_bytes(), data.as_slice());
}
