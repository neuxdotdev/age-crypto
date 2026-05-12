#include <stdio.h>
#include <string.h>
#include "age-crypto.h"
void print_hex(const char* label, uint8_t* data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for(size_t i=0; i<len; i++) printf("%02x", data[i]);
    printf("\n");
}
int main() {
    printf("=== Age Crypto C Binding Test ===\n");
    const char* secret_key = "AGE-SECRET-KEY-1GQ9HZ5M..."; 
    const char* recipient = "age1qy3..."; 
    const char* passphrase = "my-super-secret-password";
    const char* plaintext = "Hello from C!";
    size_t pt_len = strlen(plaintext);
    char* armored_out = NULL;
    int res = age_encrypt_with_passphrase_armor((uint8_t*)plaintext, pt_len, passphrase, &armored_out);
    if (res == 0 && armored_out) {
        printf("Encryption Success!\n");
        printf("Armored Data:\n%s\n", armored_out);
        uint8_t* decrypted = NULL;
        size_t dec_len = 0;
        res = age_decrypt_with_passphrase_armor(armored_out, passphrase, &decrypted, &dec_len);
        if (res == 0 && decrypted) {
            printf("Decryption Success!\n");
            printf("Decrypted Text: %.*s\n", (int)dec_len, decrypted);
            if (dec_len == pt_len && memcmp(plaintext, decrypted, pt_len) == 0) {
                printf(">>> Roundtrip MATCH!\n");
            } else {
                printf(">>> Roundtrip MISMATCH!\n");
            }
            age_free_bytes(decrypted, dec_len);
        } else {
            printf("Decryption Failed with code: %d\n", res);
        }
        age_free_string(armored_out);
    } else {
        printf("Encryption Failed with code: %d\n", res);
    }
    return 0;
}