#ifndef WBCRYPTO_SDF_SM4_H
#define WBCRYPTO_SDF_SM4_H

# include <wbcrypto/conf.h>
#include <crypto/sdf.h>
#include <crypto/sdf_ext.h>
#include <crypto/sdf_mem.h>
#include <crypto/sdf_sm4.h>
#include <crypto/sdf_error.h>

# define SM4_KEY_SCHEDULE   32

#ifdef __cplusplus
extern "C" {
#endif
    struct sdf_sm4_context {
        void *hDeviceHandle ;
        void *hSessionHandle ;
        void *hKeyHandle ;
    };
      
    typedef struct sdf_sm4_context WBCRYPTO_sdf_sm4_context;

      /******************************************basic function**********************************************/
      /**
      * the function initializes the sm4 context
      * @param ctx Context to initialize, MUST be NULL
      * @return NULL is fault, otherwise successful
      */
      // WBCRYPTO_sm4_context *WBCRYPTO_sm4_context_init();
      WBCRYPTO_sdf_sm4_context *WBCRYPTO_sdf_sm4_context_init();

      static int generate_kek(unsigned int uiKEKIndex);

      /**
      * the function generate sm4 round key
      * @param key used to generate round key
      * @return 1 if success, 0 if error
      */
    int WBCRYPTO_sdf_sm4_init_key(WBCRYPTO_sdf_sm4_context *ctx, unsigned char *key, char * soft_sdf_path, unsigned int uiKEKIndex);

      /**
      * the function is used to encrypt(**generally not used directly**)
      * @param ctx sm4-ctx must be init
      * @param input plaintext
      * @param output ciphertext
      * @return 1 if success, 0 if error
      */
    int WBCRYPTO_sdf_sm4_encrypt(const unsigned char *input, unsigned char *output, const WBCRYPTO_sdf_sm4_context *ctx);

      /**
      * the function is used to decrypt(**generally not used directly**)
      * @param ctx sm4-ctx must be init
      * @param input ciphertext
      * @param output plaintext
      * @return 1 if success, 0 if error
      */
    int WBCRYPTO_sdf_sm4_decrypt(const unsigned char *input, unsigned char *output, const WBCRYPTO_sdf_sm4_context *ctx);

      /**
        * free context
        * @param ctx
        */
    void WBCRYPTO_sdf_sm4_context_free(WBCRYPTO_sdf_sm4_context *ctx);
      
    WBCRYPTO_fpe_context *WBCRYPTO_sdf_sm4_fpe_init(WBCRYPTO_sdf_sm4_context *key, const char *twkbuf, size_t twklen, unsigned int radix);

      /******************************************aux-fun(unimportance)*********************************************/
      /**
      * auxiliary function, internal call
      * used to generate SM4
      **/
#ifdef __cplusplus
}
#endif

#endif //WBCRYPTO_SDF_SM4_H