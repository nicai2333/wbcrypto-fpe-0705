#include <wbcrypto/sdf_sm4.h>


WBCRYPTO_sdf_sm4_context *WBCRYPTO_sdf_sm4_context_init(){
    struct sdf_sm4_context *ctx=malloc(sizeof(struct sdf_sm4_context));
    if(ctx==NULL){
        WBCRYPTO_THROW_REASON("WBCRYPTO_sdf_sm4_context_init",WBCRYPTO_ERR_ALLOC_FAILED);
        goto cleanup;
    }
    memset(ctx,0,sizeof(WBCRYPTO_sdf_sm4_context));
    ctx->hDeviceHandle=NULL;
    ctx->hKeyHandle=NULL;
    ctx->hSessionHandle=NULL;

    return ctx;
cleanup:
    return NULL;
}

void WBCRYPTO_sdf_sm4_context_free(WBCRYPTO_sdf_sm4_context *ctx){
    
	SDF_DestroyKey(ctx->hSessionHandle, ctx->hKeyHandle);
	SDF_CloseSession(ctx->hSessionHandle);
	SDF_CloseDevice(ctx->hDeviceHandle);

    memset(ctx,0,sizeof(WBCRYPTO_sdf_sm4_context));
    if(ctx!=NULL){
        free(ctx);
        ctx=NULL;
    }

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int WBCRYPTO_sdf_sm4_init_key(WBCRYPTO_sdf_sm4_context *ctx, unsigned char *key, char * soft_sdf_path, unsigned int uiKEKIndex)
{
    size_t len;
    int ret=0;
    unsigned char pucKey[64];
    unsigned int uiKeyBits=128;
    unsigned int uiKeyLength = (unsigned int)sizeof(key);
    char lib_path[1024];

    if (SDF_LoadLibrary(soft_sdf_path, NULL) != SDR_OK){
		error_print();
	}

    ret = SDF_OpenDevice(&ctx->hDeviceHandle);
	if (ret != 0x0) {
        printf("ret=%d\n",ret);
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(ctx->hDeviceHandle, &ctx->hSessionHandle);
	if (ret != 0x0) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

    ret=SDF_GenerateKeyWithKEK(ctx->hSessionHandle, uiKeyBits, SGD_SM4_ECB, uiKEKIndex, pucKey, &uiKeyLength, &ctx->hKeyHandle);
    if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

}

int WBCRYPTO_sdf_sm4_encrypt(const unsigned char *input, unsigned char *output, const WBCRYPTO_sdf_sm4_context *ctx)
{
    size_t len;
    int ret;
    unsigned int *uiEncDataLength;
    // for (size_t i = 0; i < 32; ++i) {
    //     printf("0x%02x ", input[i]);
    // }

    unsigned int uiDateLength ;

    ret = SDF_Encrypt(ctx->hSessionHandle, ctx->hKeyHandle, SGD_SM4_ECB, NULL, input, 16, output, &uiEncDataLength);
    // printf("EncData\n");
	
    // for (size_t i = 0; i < 16; ++i) {
    //     printf("0x%02x ", output[i]);
    // }
    // printf("\n");

};

int WBCRYPTO_sdf_sm4_decrypt(const unsigned char *input, unsigned char *output, const WBCRYPTO_sdf_sm4_context *ctx)
{
    size_t len;
    int ret;
    unsigned int *uiDecDataLength;

    ret = SDF_Decrypt(ctx->hSessionHandle, ctx->hKeyHandle, SGD_SM4_ECB, NULL, input, 16, output, &uiDecDataLength);
    // printf("DecData\n");
	
    // for (size_t i = 0; i < 16; ++i) {
    //     printf("0x%02x ", output[i]);
    // }
    // printf("\n");
}

WBCRYPTO_fpe_context *WBCRYPTO_sdf_sm4_fpe_init(WBCRYPTO_sdf_sm4_context *key, const char *twkbuf, size_t twklen, unsigned int radix)
{
    WBCRYPTO_fpe_context *ctx = WBCRYPTO_fpe_init(twkbuf, twklen, radix, key, (block128_f)WBCRYPTO_sdf_sm4_encrypt);
    return ctx;
}