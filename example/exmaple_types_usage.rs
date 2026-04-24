
use age_crypto::types::{EncryptedData, ArmoredData, Passphrase};
fn main() {
    let enc = EncryptedData::from(vec![1, 2, 3]);
    println!("{}", enc);                              
    println!("as_bytes: {:?}", enc.as_bytes());
    println!("to_vec: {:?}", enc.to_vec());
    let armored = ArmoredData::from("-----BEGIN AGE ENCRYPTED FILE-----\n...\n-----END AGE ENCRYPTED FILE-----".to_string());
    println!("{}", armored);                          
    println!("is valid armor: {}", ArmoredData::is_valid_armored(armored.as_str()));
    println!("as_str: {}", armored.as_str());
    let pass = Passphrase::new("my-secret");
    println!("{}", pass);                             
    println!("length: {}", pass.len());
    let _secret: &str = pass.expose();
}