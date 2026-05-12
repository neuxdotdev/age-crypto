#ifndef AGE_CRYPTO_H
#define AGE_CRYPTO_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "stdint.h"
#include "stdlib.h"

char *age_last_error_message(void);

void age_free_string(char *s);

void age_free_bytes(uint8_t *data, uintptr_t len);

int32_t age_encrypt(const uint8_t *plaintext,
                    uintptr_t plaintext_len,
                    const char *const *recipients,
                    uintptr_t recipients_count,
                    uint8_t **out_data,
                    uintptr_t *out_len);

int32_t age_encrypt_armor(const uint8_t *plaintext,
                          uintptr_t plaintext_len,
                          const char *const *recipients,
                          uintptr_t recipients_count,
                          char **out_str);

int32_t age_encrypt_with_passphrase(const uint8_t *plaintext,
                                    uintptr_t plaintext_len,
                                    const char *passphrase,
                                    uint8_t **out_data,
                                    uintptr_t *out_len);

int32_t age_encrypt_with_passphrase_armor(const uint8_t *plaintext,
                                          uintptr_t plaintext_len,
                                          const char *passphrase,
                                          char **out_str);

int32_t age_decrypt(const uint8_t *ciphertext,
                    uintptr_t ciphertext_len,
                    const char *secret_key,
                    uint8_t **out_data,
                    uintptr_t *out_len);

int32_t age_decrypt_armor(const char *armored_str,
                          const char *secret_key,
                          uint8_t **out_data,
                          uintptr_t *out_len);

int32_t age_decrypt_with_passphrase(const uint8_t *ciphertext,
                                    uintptr_t ciphertext_len,
                                    const char *passphrase,
                                    uint8_t **out_data,
                                    uintptr_t *out_len);

int32_t age_decrypt_with_passphrase_armor(const char *armored_str,
                                          const char *passphrase,
                                          uint8_t **out_data,
                                          uintptr_t *out_len);

#endif  /* AGE_CRYPTO_H */
