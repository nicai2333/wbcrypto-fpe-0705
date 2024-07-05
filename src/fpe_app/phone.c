/*
 * @Author: error: error: git config user.name & please set dead value or install git && error: git config user.email & please set dead value or install git & please set dead value or install git
 * @Date: 2023-05-14 22:27:28
 * @LastEditors: error: error: git config user.name & please set dead value or install git && error: git config user.email & please set dead value or install git & please set dead value or install git
 * @LastEditTime: 2023-05-21 10:01:36
 * @FilePath: /wbcrypto-fpe/src/fpe_app/phone.c
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
#include <wbcrypto/fpe_app.h>
#include <wbcrypto/aes.h>
#include <wbcrypto/wbaes.h>
#include <wbcrypto/sm4.h>
#include <wbcrypto/wbsm4.h>
#include <wbcrypto/wbsm4_se_la.h>
#include <wbcrypto/sm4_lut.h>
#include <wbcrypto/wbsm4_xl_la.h>
#include <wbcrypto/sdf_sm4.h>
#include <string.h>
#include <ctype.h>

int aux_fpe_phone(WBCRYPTO_fpe_app_context *ctx, char *phone, char *sample, char *after_phone, fpe_block128_f block) {
    int ret = 0;
    int len = strlen(phone);
    int i, j, k, tweak_len = 0;
    int tweak_ff3_len=0;
    if (strcmp(sample, "") != 0) {
        for (i = 0; i < len; i++) {
            if (sample[i] != '*') {
                ++tweak_len;
                ++tweak_ff3_len;
            }
        }
    }
    char* input=NULL;
    char* ans=NULL;
    char* tweak=NULL;
    if(strcmp(ctx->ffx, WBCYRPTO_FPE_FFX_FF3) == 0){
        tweak_len=8;
        if(tweak_ff3_len>8){   //ff3算法中tweak长度固定8字节
            tweak_ff3_len=8;
        }
        input=(char*)malloc(len-tweak_ff3_len+1);
        input[len-tweak_ff3_len]='\0';
        tweak=(char*)malloc(tweak_len+1);
        tweak[tweak_len]='\0';
        ans=(char*)malloc(len-tweak_ff3_len);
        for(i=0,j=0,k=0;i<len;i++){
            if (strcmp(sample, "") != 0 && sample[i] != '*') {
                tweak[k++] = phone[i];
            }else {
                input[j++] = phone[i];
            }
        }
    
        for(i=0;i<tweak_len-tweak_ff3_len;i++){
            tweak[i+tweak_ff3_len]='a';
        }
    }
    else{   //处理ff1算法tweak
        input=(char*)malloc(len-tweak_len+1);
        input[len - tweak_len] = '\0';
        
        tweak=(char*)malloc(tweak_len+1);
        tweak[tweak_len]='\0';
        
        ans=(char *)malloc(len-tweak_len);
    
        for (i = 0, j = 0, k = 0; i < len; i++) {
            if (strcmp(sample, "") != 0 && sample[i] != '*') {
                tweak[k++] = phone[i];
            } else {
                input[j++] = phone[i];
            }
        }
    }

    WBCRYPTO_fpe_context *fpe_ctx;
    if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_SM4) == 0) {
        fpe_ctx = WBCRYPTO_sm4_fpe_init(ctx->cipher_ctx, tweak, tweak_len, 10);
    } else if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_WBSM4) == 0) {
        fpe_ctx = WBCRYPTO_wbsm4_fpe_init(ctx->cipher_ctx, tweak, tweak_len, 10);
    } else if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_AES) == 0) {
        fpe_ctx = WBCRYPTO_aes_fpe_init(ctx->cipher_ctx, tweak, tweak_len, 10);
    } else if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_SM4_LUT) == 0) {
        fpe_ctx = WBCRYPTO_sm4_lut_fpe_init(ctx->cipher_ctx, tweak, tweak_len, 10);
    }else if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_WBSM4_SE_LA) == 0) {
        fpe_ctx = wbcrypto_wbsm4_se_la_fpe_init(ctx->cipher_ctx, tweak, tweak_len, 10);
    }else if(strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_WBSM4_XL_LA) == 0){
        fpe_ctx=WBCRYPTO_wbsm4_xl_la_fpe_init(ctx->cipher_ctx,tweak,tweak_len,10);
    }else if (strcmp(ctx->cipher, WBCYRPTO_FPE_CIPHER_WBAES) == 0) {
        fpe_ctx = WBCRYPTO_wbaes_fpe_init(ctx->cipher_ctx, tweak, tweak_len, 10);
    }else if (strcmp(ctx->cipher, WBCRYPTO_FPE_CIPHER_SDF_SM4) == 0) {
        fpe_ctx = WBCRYPTO_sdf_sm4_fpe_init(ctx->cipher_ctx, tweak, tweak_len, 10);
    }else { //default:aes
        fpe_ctx = WBCRYPTO_aes_fpe_init(ctx->cipher_ctx, tweak, tweak_len, 10);
    }
    (*block)(fpe_ctx, input, ans);

    for (i = 0, j = 0; i < len; i++) {
        if (strcmp(sample, "") != 0 && sample[i] != '*') {
            after_phone[i] = phone[i];
        } else {
            after_phone[i] = ans[j++];
        }
    }

    ret = 1;
cleanup:
    WBCRYPTO_fpe_free(fpe_ctx);
    return ret;
}

int WBCRYPTO_fpe_encrypt_phone(WBCRYPTO_fpe_app_context *ctx, char *phone, char *after_phone) {
    return WBCRYPTO_fpe_encrypt_phone_with_sample(ctx, phone, after_phone, "");
}

int WBCRYPTO_fpe_decrypt_phone(WBCRYPTO_fpe_app_context *ctx, char *phone, char *after_phone) {
    return WBCRYPTO_fpe_decrypt_phone_with_sample(ctx, phone, after_phone, "");
}

int WBCRYPTO_fpe_encrypt_phone_with_sample(WBCRYPTO_fpe_app_context *ctx, char *phone, char *after_phone, char *sample) {
    fpe_block128_f block;
    if (strcmp(ctx->ffx, WBCYRPTO_FPE_FFX_FF1) == 0) {
        block = (fpe_block128_f) WBCRYPTO_ff1_encrypt;
    } else if (strcmp(ctx->ffx, WBCYRPTO_FPE_FFX_FF3) == 0) {
        block = (fpe_block128_f) WBCRYPTO_ff3_encrypt;
    } else { // default: ff3-1
        block = (fpe_block128_f) WBCRYPTO_ff3_encrypt;
    }
    return aux_fpe_phone(ctx, phone, sample, after_phone, block);
}

int WBCRYPTO_fpe_decrypt_phone_with_sample(WBCRYPTO_fpe_app_context *ctx, char *phone, char *after_phone, char *sample) {
    fpe_block128_f block;
    if (strcmp(ctx->ffx, WBCYRPTO_FPE_FFX_FF1) == 0) {
        block = (fpe_block128_f) WBCRYPTO_ff1_decrypt;
    } else if (strcmp(ctx->ffx, WBCYRPTO_FPE_FFX_FF3) == 0) {
        block = (fpe_block128_f) WBCRYPTO_ff3_decrypt;
    } else { // default: ff3-1
        block = (fpe_block128_f) WBCRYPTO_ff3_decrypt;
    }
    return aux_fpe_phone(ctx, phone, sample, after_phone, block);
}