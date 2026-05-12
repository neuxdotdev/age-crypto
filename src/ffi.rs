#![allow(unsafe_code)]
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::slice;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn age_last_error_message() -> *mut c_char {
    ptr::null_mut()
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn age_free_string(s: *mut c_char) {
    unsafe {
        if !s.is_null() {
            drop(CString::from_raw(s));
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn age_free_bytes(data: *mut u8, len: usize) {
    unsafe {
        if !data.is_null() && len > 0 {
            drop(Vec::from_raw_parts(data, len, len));
        }
    }
}
fn handle_error_to_code(err: crate::Error) -> i32 {
    eprintln!("Age Crypto Error: {}", err);
    -1
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn age_encrypt(
    plaintext: *const u8,
    plaintext_len: usize,
    recipients: *const *const c_char,
    recipients_count: usize,
    out_data: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let plaintext = unsafe { slice::from_raw_parts(plaintext, plaintext_len) };
    let mut recips = Vec::new();
    let ptr_slice = unsafe { slice::from_raw_parts(recipients, recipients_count) };
    for &p in ptr_slice {
        let c_str = unsafe { CStr::from_ptr(p) };
        match c_str.to_str() {
            Ok(s) => recips.push(s),
            Err(_) => return -2,
        }
    }
    match crate::encrypt(plaintext, &recips) {
        Ok(data) => {
            let mut buf: Vec<u8> = data.into();
            unsafe {
                *out_data = buf.as_mut_ptr();
                *out_len = buf.len();
            }
            std::mem::forget(buf);
            0
        }
        Err(e) => handle_error_to_code(e),
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn age_encrypt_armor(
    plaintext: *const u8,
    plaintext_len: usize,
    recipients: *const *const c_char,
    recipients_count: usize,
    out_str: *mut *mut c_char,
) -> i32 {
    let plaintext = unsafe { slice::from_raw_parts(plaintext, plaintext_len) };
    let mut recips = Vec::new();
    let ptr_slice = unsafe { slice::from_raw_parts(recipients, recipients_count) };
    for &p in ptr_slice {
        let c_str = unsafe { CStr::from_ptr(p) };
        match c_str.to_str() {
            Ok(s) => recips.push(s),
            Err(_) => return -2,
        }
    }
    match crate::encrypt_armor(plaintext, &recips) {
        Ok(data) => {
            let s = data.to_string();
            match CString::new(s) {
                Ok(c_s) => {
                    unsafe { *out_str = c_s.into_raw() };
                    0
                }
                Err(_) => -3,
            }
        }
        Err(e) => handle_error_to_code(e),
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn age_encrypt_with_passphrase(
    plaintext: *const u8,
    plaintext_len: usize,
    passphrase: *const c_char,
    out_data: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let plaintext = unsafe { slice::from_raw_parts(plaintext, plaintext_len) };
    let pass = unsafe { CStr::from_ptr(passphrase) };
    let pass_str = match pass.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    match crate::encrypt_with_passphrase(plaintext, pass_str) {
        Ok(data) => {
            let mut buf: Vec<u8> = data.into();
            unsafe {
                *out_data = buf.as_mut_ptr();
                *out_len = buf.len();
            }
            std::mem::forget(buf);
            0
        }
        Err(e) => handle_error_to_code(e),
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn age_encrypt_with_passphrase_armor(
    plaintext: *const u8,
    plaintext_len: usize,
    passphrase: *const c_char,
    out_str: *mut *mut c_char,
) -> i32 {
    let plaintext = unsafe { slice::from_raw_parts(plaintext, plaintext_len) };
    let pass = unsafe { CStr::from_ptr(passphrase) };
    let pass_str = match pass.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    match crate::encrypt_with_passphrase_armor(plaintext, pass_str) {
        Ok(data) => {
            let s = data.to_string();
            match CString::new(s) {
                Ok(c_s) => {
                    unsafe { *out_str = c_s.into_raw() };
                    0
                }
                Err(_) => -3,
            }
        }
        Err(e) => handle_error_to_code(e),
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn age_decrypt(
    ciphertext: *const u8,
    ciphertext_len: usize,
    secret_key: *const c_char,
    out_data: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let ciphertext = unsafe { slice::from_raw_parts(ciphertext, ciphertext_len) };
    let key = unsafe { CStr::from_ptr(secret_key) };
    let key_str = match key.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    match crate::decrypt(ciphertext, key_str) {
        Ok(mut data) => {
            unsafe {
                *out_data = data.as_mut_ptr();
                *out_len = data.len();
            }
            std::mem::forget(data);
            0
        }
        Err(e) => handle_error_to_code(e),
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn age_decrypt_armor(
    armored_str: *const c_char,
    secret_key: *const c_char,
    out_data: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let armored = unsafe { CStr::from_ptr(armored_str) };
    let armored_s = match armored.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let key = unsafe { CStr::from_ptr(secret_key) };
    let key_str = match key.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    match crate::decrypt_armor(armored_s, key_str) {
        Ok(mut data) => {
            unsafe {
                *out_data = data.as_mut_ptr();
                *out_len = data.len();
            }
            std::mem::forget(data);
            0
        }
        Err(e) => handle_error_to_code(e),
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn age_decrypt_with_passphrase(
    ciphertext: *const u8,
    ciphertext_len: usize,
    passphrase: *const c_char,
    out_data: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let ciphertext = unsafe { slice::from_raw_parts(ciphertext, ciphertext_len) };
    let pass = unsafe { CStr::from_ptr(passphrase) };
    let pass_str = match pass.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    match crate::decrypt_with_passphrase(ciphertext, pass_str) {
        Ok(mut data) => {
            unsafe {
                *out_data = data.as_mut_ptr();
                *out_len = data.len();
            }
            std::mem::forget(data);
            0
        }
        Err(e) => handle_error_to_code(e),
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn age_decrypt_with_passphrase_armor(
    armored_str: *const c_char,
    passphrase: *const c_char,
    out_data: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let armored = unsafe { CStr::from_ptr(armored_str) };
    let armored_s = match armored.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let pass = unsafe { CStr::from_ptr(passphrase) };
    let pass_str = match pass.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    match crate::decrypt_with_passphrase_armor(armored_s, pass_str) {
        Ok(mut data) => {
            unsafe {
                *out_data = data.as_mut_ptr();
                *out_len = data.len();
            }
            std::mem::forget(data);
            0
        }
        Err(e) => handle_error_to_code(e),
    }
}