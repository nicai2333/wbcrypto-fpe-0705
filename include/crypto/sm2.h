/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_SM2_H
# define OSSL_CRYPTO_SM2_H
# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_SM2

#  include <openssl/ec.h>

/* The default user id as specified in GM/T 0009-2012 */
#  define SM2_DEFAULT_USERID "1234567812345678"

int sm2_sig_set(uint8_t sig_bin[], int *sig_len, const uint8_t r_bin[32], const uint8_t s_bin[32]);
int sm2_sig_get(const uint8_t sig_bin[], int sig_len,  uint8_t r_bin[32], uint8_t s_bin[32]);
int sm2_get_ciphertext(const uint8_t *ciphertext, size_t ciphertext_len,
                  uint8_t *C1_x, uint8_t *C1_y,  uint8_t *C2, int *C2_len, uint8_t *C3, int *C3_len);
int sm2_set_ciphertext(uint8_t *ciphertext_buf, size_t *ciphertext_len,
                  const uint8_t *C1_x, const uint8_t *C1_y, const uint8_t *C2, int C2_len, const uint8_t *C3, int C3_len);

int sm2_compute_z_digest(uint8_t *out,
                         const EVP_MD *digest,
                         const uint8_t *id,
                         const size_t id_len,
                         const EC_KEY *key);

/*
 * SM2 signature operation. Computes Z and then signs H(Z || msg) using SM2
 */
ECDSA_SIG *sm2_do_sign(const EC_KEY *key,
                       const EVP_MD *digest,
                       const uint8_t *id,
                       const size_t id_len,
                       const uint8_t *msg, size_t msg_len);

int sm2_do_verify(const EC_KEY *key,
                  const EVP_MD *digest,
                  const ECDSA_SIG *signature,
                  const uint8_t *id,
                  const size_t id_len,
                  const uint8_t *msg, size_t msg_len);

/*
 * SM2 signature generation.
 */
int sm2_sign(const unsigned char *dgst, int dgstlen,
             unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);

/*
 * SM2 signature generation using precomputed d1, d2.
 */
int sm2_sign_precomp(const unsigned char *dgst, int dgstlen,
             unsigned char *sig, unsigned int *siglen, EC_KEY *eckey, const BIGNUM *d1, const BIGNUM *d2);
/*
 * SM2 signature verification.
 */
int sm2_verify(const unsigned char *dgst, int dgstlen,
               const unsigned char *sig, int siglen, EC_KEY *eckey);

/*
 * SM2 encryption
 */
int sm2_ciphertext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len,
                        size_t *ct_size);

int sm2_plaintext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len,
                       size_t *pt_size);

int sm2_encrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *msg,
                size_t msg_len,
                uint8_t *ciphertext_buf, size_t *ciphertext_len);

int sm2_decrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *ciphertext,
                size_t ciphertext_len, uint8_t *ptext_buf, size_t *ptext_len);

# endif /* OPENSSL_NO_SM2 */
#endif
