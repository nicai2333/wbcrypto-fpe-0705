#include <wbcrypto/fpe_app.h>
#include <wbcrypto/aes.h>
#include <wbcrypto/wbaes.h>
#include <wbcrypto/wbaes.h>
#include <wbcrypto/sm4.h>
#include <wbcrypto/wbsm4.h>
#include <wbcrypto/wbsm4_se_la.h>
#include <wbcrypto/sm4_lut.h>
#include <wbcrypto/wbsm4_xl_la.h>
#include <wbcrypto/sdf_sm4.h>
#include <string.h>

#define TEST_KEK_INDEX	1

static int generate_kek(unsigned int uiKEKIndex)
{
	char filename[256];
	uint8_t kek[16];
	FILE *file;

	if (RAND_bytes(kek, sizeof(kek)) != 1) {
		error_print();
		return -1;
	}

	snprintf(filename, sizeof(filename), "kek-%u.key", uiKEKIndex);
	if (!(file = fopen(filename, "wb"))) {
		error_print();
		return -1;
	}
	if (fwrite(kek, 1, sizeof(kek), file) != sizeof(kek)) {
		fclose(file);
		error_print();
		return -1;
	}
	fclose(file);

	return 1;
}

int WBCRYPTO_fpe_app_init(WBCRYPTO_fpe_app_context *ctx,const char *key, int keylen, char *cipher, char *ffx) {
    int ret = 0;
    ctx->cipher = cipher;
    ctx->ffx = ffx;
    keylen = keylen >= 16 ? 16 : keylen;
    uint8_t input_key[16];
    
    char * soft_sdf_path ="/home/hjc/wbcrypto-fpe/libsoft_sdf.so";

    memcpy(input_key, key, keylen);
    if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_SM4) == 0) {
        WBCRYPTO_sm4_context *sm4_ctx = WBCRYPTO_sm4_context_init();
        WBCRYPTO_sm4_init_key(sm4_ctx, input_key, sizeof(input_key));
        ctx->cipher_ctx = sm4_ctx;
    } else if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_WBSM4) == 0) {
        WBCRYPTO_wbsm4_context *wbsm4_ctx = WBCRYPTO_wbsm4_context_init(1);
        WBCRYPTO_wbsm4_gen_table(wbsm4_ctx, input_key, sizeof(input_key));
        ctx->cipher_ctx = wbsm4_ctx;
    } else if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_WBSM4_SE_LA) == 0) {
        wbcrypto_wbsm4se_la_context *wbsm4_se_la_ctx = wbcrypto_wbsm4se_la_context_init(1);
        wbcrypto_wbsm4_se_la_gen(wbsm4_se_la_ctx, input_key);
        ctx->cipher_ctx = wbsm4_se_la_ctx;
    }else if(strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_WBSM4_XL_LA)==0){
        WBCRYPTO_wbsm4_xl_la_context *wbsm4_xl_la_ctx = WBCRYPTO_wbsm4_xl_la_context_init(1);
        WBCRYPTO_wbsm4_xl_la_gen_table(wbsm4_xl_la_ctx, input_key,sizeof(input_key));
        ctx->cipher_ctx=wbsm4_xl_la_ctx;
    }else if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_SM4_LUT) == 0) {
        wbcrypto_sm4_lut_context *sm4_ctx = wbcrypto_sm4_lut_context_init();
        wbcrypto_sm4_lut_setkey_enc(sm4_ctx,input_key);
        ctx->cipher_ctx = sm4_ctx;
    }else if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_WBAES) == 0) {
        wbcrypto_wbaes_context* wbaes_ctx=WBCRYPTO_wbaes_context_init();
        wbcrypto_wbaes_gen(wbaes_ctx,key);
        ctx->cipher_ctx = wbaes_ctx;
    } else if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_AES) == 0) {
        WBCRYPTO_aes_context *aes_ctx = WBCRYPTO_aes_context_init();
        WBCRYPTO_aes_init_key(aes_ctx, input_key, sizeof(input_key));
        ctx->cipher_ctx = aes_ctx;
    } 
    else if (strcmp(ctx->cipher, WBCRYPTO_FPE_CIPHER_SDF_SM4) == 0) {
        generate_kek(TEST_KEK_INDEX) ;
        WBCRYPTO_sdf_sm4_context *sdf_sm4_ctx = WBCRYPTO_sdf_sm4_context_init();
        unsigned int uiKEKIndex=TEST_KEK_INDEX;
        WBCRYPTO_sdf_sm4_init_key(sdf_sm4_ctx, input_key, soft_sdf_path, uiKEKIndex);
        ctx->cipher_ctx = sdf_sm4_ctx;
    } else {
        // default: aes
        WBCRYPTO_aes_context *aes_ctx = WBCRYPTO_aes_context_init();
        WBCRYPTO_aes_init_key(aes_ctx, input_key, sizeof(input_key));
        ctx->cipher_ctx = aes_ctx;
    }
    ret = 1;
cleanup:
    return ret;
}