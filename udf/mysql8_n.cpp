#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <mysql.h>
#include <wbcrypto/fpe_app.h>
#include <wbcrypto/aes.h>
#include <wbcrypto/sm4.h>
#include <wbcrypto/wbsm4.h>
#include <wbcrypto/wbsm4_se_la.h>
#include <wbcrypto/sm4_lut.h>
#include <WBMatrix/WBMatrix.h>

const uint8_t key[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

extern "C" {
    bool fpe_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void fpe_deinit(UDF_INIT *initid);
    char *fpe(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
}

/*
 * fpe(plain, mode, sample)
 * fpe(plain, phone/idcard/address)
 * fpe(plain, phone/idcard/address, "*********")
 */
bool fpe_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    initid->max_length = args->lengths[0];
    initid->maybe_null = args->maybe_null;
    initid->ptr = (char *) malloc(initid->max_length + 1);
    if (initid->ptr == NULL) {
        strcpy(message, "could't allocate memory");
        return 1;
    }
    return 0;
}

void fpe_deinit(UDF_INIT *initid) {
    free(initid->ptr);
}

char *fpe(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error) {
    char *plain = args->args[0];
    char *mode = args->args[1];
    char *cipher=args->args[2];
    char *ffx=args->args[3];
    char *sample;
    int plain_len = args->lengths[0];
    char *ciphers[]={"aes","sm4","wbsm4","sm4_lut","wbsm4_se_la","wbsm4_xl_la","wbaes"};
    char *ffxs[]={"ff1","ff3"};
    //传参顺序,明文，加密内容种类，加密算法,ffx,加密格式
    if (args->arg_count == 5) {
        sample = args->args[4];
    }
    memcpy(initid->ptr, plain, plain_len);
    initid->ptr[plain_len] = '\0';
     
    for(int i=0;i<=7;i++){
        if(i==7){
            strcpy(error, "the cipher of encrypto should be aes,wbaes,sm4,wbsm4,wbsm4_se_la,wbsm4_xl_la or sm4_lut");
            return error;
        }
        if(strcmp(cipher,ciphers[i])==0){
            break;
        }
    }
    for(int i=0;i<=2;i++){
        if(i==2){
            strcpy(error, "the fpe type of encrypto should be ff1 or ff3");
            return error; 
        }
        if(strcmp(ffx,ffxs[i])==0){
            break;
        }
    }
    // char cipher[] = "aes";
    WBCRYPTO_fpe_app_context app_ctx;
    // WBCRYPTO_fpe_app_init(&app_ctx, aes_ctx, cipher, "ff1");
    WBCRYPTO_fpe_app_init(&app_ctx, reinterpret_cast<const char*>(key), sizeof(key), cipher, ffx);
    if (strcmp(mode, "phone") == 0) {
        if (plain_len != 11) {
            strcpy(error, "the length of phone should be 11");
            return error;
        }
        if (args->arg_count == 5) {
            WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx, plain, initid->ptr, sample);
        }else {
            WBCRYPTO_fpe_encrypt_phone(&app_ctx, plain, initid->ptr);
        }
    } else if (strcmp(mode, "idcard") == 0) {
        if (plain_len != 18) {
            strcpy(error, "the length of id-card should be 18");
            return error;
        }
        if (args->arg_count == 5) {
            WBCRYPTO_fpe_encrypt_idcard_with_sample(&app_ctx, plain, initid->ptr, sample);
        }else {
            WBCRYPTO_fpe_encrypt_idcard(&app_ctx, plain, initid->ptr);
        }
    } else if (strcmp(mode, "name") == 0 || strcmp(mode, "address") == 0) {
        if (args->arg_count == 5) {
            WBCRYPTO_fpe_encrypt_cn_utf8_with_sample(&app_ctx, plain, initid->ptr, sample);
        }else {
            WBCRYPTO_fpe_encrypt_cn_utf8(&app_ctx, plain, initid->ptr);
        }
    } else {
        strcpy(error, "requires optional mode: phone or idcard or address");
        return error;
    }

    *length = plain_len;
    memcpy(result, initid->ptr, plain_len);
    // char ret[1024];
    // sprintf(ret, "%s", result);
    return result;
}