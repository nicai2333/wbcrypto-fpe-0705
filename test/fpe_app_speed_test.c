#include "test_local.h"
#include <wbcrypto/fpe_app.h>
#include <time.h>

#define TESTTIME 100000

const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
int test_ff1_sm4_lut_phone() {
    int i;
    const char input[] = "13888888888";
    const char sample[] = "138********";
    char cipher[20] = {0};
    char plain[20] = {0};
    clock_t program_start, program_end;
    double ts;
    WBCRYPTO_fpe_app_context app_ctx;
    WBCRYPTO_fpe_app_init(&app_ctx, key, 16, WBCYRPTO_FPE_CIPHER_SM4_LUT, WBCYRPTO_FPE_FFX_FF1);
    program_start = clock();
    for (i = 0; i < TESTTIME; i++) {
        WBCRYPTO_fpe_encrypt_phone(&app_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FPE Phone] Time cost: %lf s, it means that the encryption speed is: %f 条/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FPE Phone] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone(&app_ctx, cipher, plain);
    printf("[FPE Phone] decrypt answer: %s\n", plain);

    WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx, input, cipher, sample);
    printf("[FPE Phone with sample] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone_with_sample(&app_ctx, cipher, plain, sample);
    printf("[FPE Phone with sample] decrypt answer: %s\n", plain);
}

int test_ff3_sm4_lut_phone() {
    int i;
    const char input[] = "13888888888";
    const char sample[] = "138********";
    char cipher[20] = {0};
    char plain[20] = {0};
    clock_t program_start, program_end;
    double ts;
    WBCRYPTO_fpe_app_context app_ctx;
    WBCRYPTO_fpe_app_init(&app_ctx, key, 16, WBCYRPTO_FPE_CIPHER_SM4_LUT, WBCYRPTO_FPE_FFX_FF3);
    program_start = clock();
    for (i = 0; i < TESTTIME; i++) {
        WBCRYPTO_fpe_encrypt_phone(&app_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FPE Phone] Time cost: %lf s, it means that the encryption speed is: %f 条/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FPE Phone] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone(&app_ctx, cipher, plain);
    printf("[FPE Phone] decrypt answer: %s\n", plain);

    WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx, input, cipher, sample);
    printf("[FPE Phone with sample] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone_with_sample(&app_ctx, cipher, plain, sample);
    printf("[FPE Phone with sample] decrypt answer: %s\n", plain);
}

int test_ff1_wbsm4_se_la_phone() {
    int i;
    const char input[] = "13888888888";
    const char sample[] = "138********";
    char cipher[20] = {0};
    char plain[20] = {0};
    clock_t program_start, program_end;
    double ts;
    WBCRYPTO_fpe_app_context app_ctx;
    WBCRYPTO_fpe_app_init(&app_ctx, key, 16, WBCYRPTO_FPE_CIPHER_WBSM4_SE_LA, WBCYRPTO_FPE_FFX_FF1);
    program_start = clock();
    for (i = 0; i < TESTTIME; i++) {
        WBCRYPTO_fpe_encrypt_phone(&app_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FPE Phone] Time cost: %lf s, it means that the encryption speed is: %f 条/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FPE Phone] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone(&app_ctx, cipher, plain);
    printf("[FPE Phone] decrypt answer: %s\n", plain);

    WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx, input, cipher, sample);
    printf("[FPE Phone with sample] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone_with_sample(&app_ctx, cipher, plain, sample);
    printf("[FPE Phone with sample] decrypt answer: %s\n", plain);
}

int test_ff3_wbsm4_se_la_phone() {
    int i;
    const char input[] = "13888888888";
    const char sample[] = "138********";
    char cipher[20] = {0};
    char plain[20] = {0};
    clock_t program_start, program_end;
    double ts;
    WBCRYPTO_fpe_app_context app_ctx;
    WBCRYPTO_fpe_app_init(&app_ctx, key, 16, WBCYRPTO_FPE_CIPHER_WBSM4_SE_LA, WBCYRPTO_FPE_FFX_FF3);
    program_start = clock();
    for (i = 0; i < TESTTIME; i++) {
        WBCRYPTO_fpe_encrypt_phone(&app_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FPE Phone] Time cost: %lf s, it means that the encryption speed is: %f 条/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FPE Phone] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone(&app_ctx, cipher, plain);
    printf("[FPE Phone] decrypt answer: %s\n", plain);

    WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx, input, cipher, sample);
    printf("[FPE Phone with sample] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone_with_sample(&app_ctx, cipher, plain, sample);
    printf("[FPE Phone with sample] decrypt answer: %s\n", plain);
}

int test_ff1_wbaes_phone() {
    int i;
    const char input[] = "13888888888";
    const char sample[] = "138********";
    char cipher[20] = {0};
    char plain[20] = {0};
    clock_t program_start, program_end;
    double ts;
    WBCRYPTO_fpe_app_context app_ctx;
    WBCRYPTO_fpe_app_init(&app_ctx, key, 16, WBCYRPTO_FPE_CIPHER_WBAES, WBCYRPTO_FPE_FFX_FF1);
    program_start = clock();
    for (i = 0; i < TESTTIME; i++) {
        WBCRYPTO_fpe_encrypt_phone(&app_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FPE Phone] Time cost: %lf s, it means that the encryption speed is: %f 条/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FPE Phone] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone(&app_ctx, cipher, plain);
    printf("[FPE Phone] decrypt answer: %s\n", plain);

    WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx, input, cipher, sample);
    printf("[FPE Phone with sample] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone_with_sample(&app_ctx, cipher, plain, sample);
    printf("[FPE Phone with sample] decrypt answer: %s\n", plain);
}

int test_ff3_wbaes_phone() {
    int i;
    const char input[] = "13888888888";
    const char sample[] = "138********";
    char cipher[20] = {0};
    char plain[20] = {0};
    clock_t program_start, program_end;
    double ts;
    WBCRYPTO_fpe_app_context app_ctx;
    WBCRYPTO_fpe_app_init(&app_ctx, key, 16, WBCYRPTO_FPE_CIPHER_WBAES, WBCYRPTO_FPE_FFX_FF3);
    program_start = clock();
    for (i = 0; i < TESTTIME; i++) {
        WBCRYPTO_fpe_encrypt_phone(&app_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FPE Phone] Time cost: %lf s, it means that the encryption speed is: %f 条/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FPE Phone] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone(&app_ctx, cipher, plain);
    printf("[FPE Phone] decrypt answer: %s\n", plain);

    WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx, input, cipher, sample);
    printf("[FPE Phone with sample] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone_with_sample(&app_ctx, cipher, plain, sample);
    printf("[FPE Phone with sample] decrypt answer: %s\n", plain);
}

int test_ff1_wbsm4_xl_la_phone() {
    int i;
    const char input[] = "13888888888";
    const char sample[] = "138********";
    char cipher[20] = {0};
    char plain[20] = {0};
    clock_t program_start, program_end;
    double ts;
    WBCRYPTO_fpe_app_context app_ctx;
    WBCRYPTO_fpe_app_init(&app_ctx, key, 16, WBCYRPTO_FPE_CIPHER_WBSM4_XL_LA, WBCYRPTO_FPE_FFX_FF1);
    program_start = clock();
    for (i = 0; i < TESTTIME; i++) {
        WBCRYPTO_fpe_encrypt_phone(&app_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FPE Phone] Time cost: %lf s, it means that the encryption speed is: %f 条/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FPE Phone] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone(&app_ctx, cipher, plain);
    printf("[FPE Phone] decrypt answer: %s\n", plain);

    WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx, input, cipher, sample);
    printf("[FPE Phone with sample] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone_with_sample(&app_ctx, cipher, plain, sample);
    printf("[FPE Phone with sample] decrypt answer: %s\n", plain);
}

int test_ff3_wbsm4_xl_la_phone() {
    int i;
    const char input[] = "13888888888";
    const char sample[] = "138********";
    char cipher[20] = {0};
    char plain[20] = {0};
    clock_t program_start, program_end;
    double ts;
    WBCRYPTO_fpe_app_context app_ctx;
    WBCRYPTO_fpe_app_init(&app_ctx, key, 16, WBCYRPTO_FPE_CIPHER_WBSM4_XL_LA, WBCYRPTO_FPE_FFX_FF3);
    program_start = clock();
    for (i = 0; i < TESTTIME; i++) {
        WBCRYPTO_fpe_encrypt_phone(&app_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FPE Phone] Time cost: %lf s, it means that the encryption speed is: %f 条/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FPE Phone] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone(&app_ctx, cipher, plain);
    printf("[FPE Phone] decrypt answer: %s\n", plain);

    WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx, input, cipher, sample);
    printf("[FPE Phone with sample] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone_with_sample(&app_ctx, cipher, plain, sample);
    printf("[FPE Phone with sample] decrypt answer: %s\n", plain);
}

int test_ff1_sdf_sm4_phone() {
    int i;
    const char input[] = "13888888888";
    const char sample[] = "138********";
    char cipher[20] = {0};
    char plain[20] = {0};
    clock_t program_start, program_end;
    double ts;
    WBCRYPTO_fpe_app_context app_ctx;
    WBCRYPTO_fpe_app_init(&app_ctx, key, 16, WBCRYPTO_FPE_CIPHER_SDF_SM4, WBCYRPTO_FPE_FFX_FF1);

    program_start = clock();
    for (i = 0; i < TESTTIME; i++) {

        WBCRYPTO_fpe_encrypt_phone(&app_ctx, input, cipher);
    }

    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
 
    printf("[FPE Phone] Time cost: %lf s, it means that the encryption speed is: %f 条/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FPE Phone] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone(&app_ctx, cipher, plain);
    printf("[FPE Phone] decrypt answer: %s\n", plain);

    WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx, input, cipher, sample);
    printf("[FPE Phone with sample] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone_with_sample(&app_ctx, cipher, plain, sample);
    printf("[FPE Phone with sample] decrypt answer: %s\n", plain);
}

int test_ff3_sdf_sm4_phone() {
    int i;
    const char input[] = "13888888888";
    const char sample[] = "138********";
    char cipher[20] = {0};
    char plain[20] = {0};
    clock_t program_start, program_end;
    double ts;
    WBCRYPTO_fpe_app_context app_ctx;
    WBCRYPTO_fpe_app_init(&app_ctx, key, 16, WBCRYPTO_FPE_CIPHER_SDF_SM4, WBCYRPTO_FPE_FFX_FF3);
    program_start = clock();
    for (i = 0; i < TESTTIME; i++) {
        WBCRYPTO_fpe_encrypt_phone(&app_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FPE Phone] Time cost: %lf s, it means that the encryption speed is: %f 条/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FPE Phone] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone(&app_ctx, cipher, plain);
    printf("[FPE Phone] decrypt answer: %s\n", plain);

    WBCRYPTO_fpe_encrypt_phone_with_sample(&app_ctx, input, cipher, sample);
    printf("[FPE Phone with sample] encrypt answer: %s\n", cipher);
    WBCRYPTO_fpe_decrypt_phone_with_sample(&app_ctx, cipher, plain, sample);
    printf("[FPE Phone with sample] decrypt answer: %s\n", plain);
}

int main() {
    //性能是加密电话号码的性能
    // printf("\nff1_sm4_lut:\n");
    // test_ff1_sm4_lut_phone();
    // printf("\nff3_sm4_lut:\n");
    // test_ff3_sm4_lut_phone();
    // printf("\nff1_wbaes_lut:\n");
    // test_ff1_wbaes_phone();
    // printf("\nff3_wbaes_lut:\n");
    // test_ff3_wbaes_phone();
    // printf("\nff1_wbsm4_xl_la:\n");
    // test_ff1_wbsm4_xl_la_phone();
    // printf("\nff3_wbsm4_xl_la:\n");
    // test_ff3_wbsm4_xl_la_phone();
    // printf("\nff1_wbsm4_se_la:\n");
    // test_ff1_wbsm4_se_la_phone();
    // printf("\nff3_wbsm4_se_la:\n");
    // test_ff3_wbsm4_se_la_phone();
    
    printf("\nff1_sdf_sm4:\n");
    test_ff1_sdf_sm4_phone();
    printf("\nff3_sdf_sm4:\n");
    test_ff3_sdf_sm4_phone();
}
