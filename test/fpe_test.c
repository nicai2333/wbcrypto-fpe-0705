#include "test_local.h"
#include <wbcrypto/aes.h>
#include <wbcrypto/sm4.h>
#include <wbcrypto/wbsm4.h>
//#include <wbcrypto/se_wbsm4.h>
#include <wbcrypto/fpe.h>
#include <wbcrypto/sdf_sm4.h>
#include <time.h>

#define TESTTIME 1
#define TEST_KEK_INDEX 1

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

int test_aes_fpe() {
    int i;

    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char tweak[] = "12345";
    const char input[] = "13888888888";
    char cipher[20] = {0};
    char plain[20] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_aes_context *aes_ctx = WBCRYPTO_aes_context_init();
    WBCRYPTO_aes_init_key(aes_ctx, key, sizeof(key));
    WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_aes_fpe_init(aes_ctx, tweak, sizeof(tweak), 12);
    program_start = clock();
    for (i = 0; i < TESTTIME * 64 * 1024; i++) {
        WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF1] [aes] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FF1] [aes] encrypt answer: %s\n", cipher);

    WBCRYPTO_ff1_decrypt(fpe_ctx, cipher, plain);
    printf("[FF1] [aes] decrypt answer: %s\n", plain);

    program_start = clock();
    for (i = 0; i < TESTTIME * 64 * 1024; i++) {
        WBCRYPTO_ff3_encrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF3] [aes] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FF3] [aes] encrypt answer: %s\n", cipher);

    WBCRYPTO_ff3_decrypt(fpe_ctx, cipher, plain);
    printf("[FF3] [aes] decrypt answer: %s\n", plain);
}

int test_sm4_fpe() {
    int i;

    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char tweak[] = "12345";
    const char input[] = "13888888888";
    char cipher[20] = {0};
    char plain[20] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_sm4_context *sm4_ctx = WBCRYPTO_sm4_context_init();
    WBCRYPTO_sm4_init_key(sm4_ctx, key, sizeof(key));
    WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_sm4_fpe_init(sm4_ctx, tweak, sizeof(tweak), 12);
    program_start = clock();
    for (i = 0; i < TESTTIME * 64 * 1024; i++) {
        WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF1] [sm4] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FF1] [sm4] encrypt answer: %s\n", cipher);

    WBCRYPTO_ff1_decrypt(fpe_ctx, cipher, plain);
    printf("[FF1] [sm4] decrypt answer: %s\n", plain);

    program_start = clock();
    for (i = 0; i < TESTTIME * 64 * 1024; i++) {
        WBCRYPTO_ff3_encrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF3] [sm4] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FF3] [sm4] encrypt answer: %s\n", cipher);

    WBCRYPTO_ff3_decrypt(fpe_ctx, cipher, plain);
    printf("[FF3] [sm4] decrypt answer: %s\n", plain);
}

int test_wbsm4_fpe() {
    int i;

    const uint8_t key[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const char tweak[] = "12345";
    const char input[] = "13888888888";
    char cipher[20] = {0};
    char plain[20] = {0};
    clock_t program_start, program_end;
    double ts;

    WBCRYPTO_wbsm4_context *wbsm4_ctx = WBCRYPTO_wbsm4_context_init(1);
    WBCRYPTO_wbsm4_gen_table(wbsm4_ctx, key, sizeof(key));
    WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_wbsm4_fpe_init(wbsm4_ctx, tweak, sizeof(tweak), 10);
    WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    WBCRYPTO_ff1_decrypt(fpe_ctx, cipher, plain);
    program_start = clock();
    for (i = 0; i < TESTTIME * 64 * 1024; i++) {
        WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF1] [wbsm4] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FF1] [wbsm4] encrypt answer: %s\n", cipher);

    WBCRYPTO_ff1_decrypt(fpe_ctx, cipher, plain);
    printf("[FF1] [wbsm4] decrypt answer: %s\n", plain);

    program_start = clock();
    for (i = 0; i < TESTTIME * 64 * 1024; i++) {
        WBCRYPTO_ff3_encrypt(fpe_ctx, input, cipher);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[FF3] [wbsm4] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("[FF3] [wbsm4] encrypt answer: %s\n", cipher);

    WBCRYPTO_ff3_decrypt(fpe_ctx, cipher, plain);
    printf("[FF3] [wbsm4] decrypt answer: %s\n", plain);
}

// int test_se_wbsm4_fpe() {
//     int i;

//     const uint8_t key[] = {
//             0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
//             0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
//     };
//     const char tweak[] = "12345";
//     const char input[] = "13888888888";
//     char cipher[20] = {0};
//     char plain[20] = {0};
//     clock_t program_start, program_end;
//     double ts;

//     WBCRYPTO_se_wbsm4_context *wbsm4_ctx = WBCRYPTO_se_wbsm4_context_init(1);
//     WBCRYPTO_se_wbsm4_gen_table(wbsm4_ctx, key, sizeof(key));
//     WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_se_wbsm4_fpe_init(wbsm4_ctx, tweak, sizeof(tweak), 10);
//     WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
//     WBCRYPTO_ff1_decrypt(fpe_ctx, cipher, plain);
//     program_start = clock();
//     for (i = 0; i < TESTTIME * 64 * 1024; i++) {
//         WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
//     }
//     program_end = clock();
//     ts = program_end - program_start;
//     ts = ts / CLOCKS_PER_SEC;
//     printf("[FF1] [se-wbsm4] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME,
//            1 / (ts / TESTTIME));
//     printf("[FF1] [se-wbsm4] encrypt answer: %s\n", cipher);

//     WBCRYPTO_ff1_decrypt(fpe_ctx, cipher, plain);
//     printf("[FF1] [se-wbsm4] decrypt answer: %s\n", plain);

//     program_start = clock();
//     for (i = 0; i < TESTTIME * 64 * 1024; i++) {
//         WBCRYPTO_ff3_encrypt(fpe_ctx, input, cipher);
//     }
//     program_end = clock();
//     ts = program_end - program_start;
//     ts = ts / CLOCKS_PER_SEC;
//     printf("[FF3] [se-wbsm4] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME,
//            1 / (ts / TESTTIME));
//     printf("[FF3] [se-wbsm4] encrypt answer: %s\n", cipher);

//     WBCRYPTO_ff3_decrypt(fpe_ctx, cipher, plain);
//     printf("[FF3] [se-wbsm4] decrypt answer: %s\n", plain);
// }

int test_sdf_sm4_fpe() {
    unsigned char pucKey[16];
	unsigned char pucData[32];
	unsigned char pucEncData[64];
	unsigned int uiEncDataLength = (unsigned int)sizeof(pucEncData);
	unsigned char pucCiphertext[64];
    unsigned int uiKEKIndex=TEST_KEK_INDEX;
    size_t uiDataLength;

    char  * soft_sdf_path ="/home/hjc/wbcrypto-fpe/libsoft_sdf.so";

    char *key = "0123456789abcdeffedcba9876543210";
    char *plain = "0123456789abcdeffedcba9876543210";
    char *cipher = "681EDF34D206965E86B3E94F536E4246";

    size_t len;

	hex_to_bytes(key, strlen(key), pucKey, &len);
	hex_to_bytes(plain, strlen(plain), pucData, &uiDataLength);
	hex_to_bytes(cipher, strlen(cipher), pucCiphertext, &len);
    
    unsigned char ciphertext[16]={0};
    unsigned char plaintext[16]={0};

    WBCRYPTO_sdf_sm4_context *sdf_sm4_ctx = WBCRYPTO_sdf_sm4_context_init();

    WBCRYPTO_sdf_sm4_init_key(sdf_sm4_ctx, pucKey, soft_sdf_path, uiKEKIndex);
    WBCRYPTO_sdf_sm4_encrypt(pucData,ciphertext,sdf_sm4_ctx);

    // if (memcmp(ciphertext, pucCiphertext, 16) != 0) {
	// 	error_print();
	// 	return -1;
	// }
    
    WBCRYPTO_sdf_sm4_decrypt(ciphertext,plaintext,sdf_sm4_ctx);
    
    if (memcmp(plaintext, pucData, 16) != 0) {
		error_print();
		return -1;
	}

    WBCRYPTO_sdf_sm4_context_free(sdf_sm4_ctx);
    
    // WBCRYPTO_fpe_context *fpe_ctx = WBCRYPTO_wbsm4_fpe_init(wbsm4_ctx, tweak, sizeof(tweak), 10);
    // WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    // WBCRYPTO_ff1_decrypt(fpe_ctx, cipher, plain);
    // program_start = clock();
    // for (i = 0; i < TESTTIME * 64 * 1024; i++) {
    //     WBCRYPTO_ff1_encrypt(fpe_ctx, input, cipher);
    // }
    // program_end = clock();
    // ts = program_end - program_start;
    // ts = ts / CLOCKS_PER_SEC;
    // printf("[FF1] [wbsm4] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME,
    //        1 / (ts / TESTTIME));
    // printf("[FF1] [wbsm4] encrypt answer: %s\n", cipher);

    // WBCRYPTO_ff1_decrypt(fpe_ctx, cipher, plain);
    // printf("[FF1] [wbsm4] decrypt answer: %s\n", plain);

    // program_start = clock();
    // for (i = 0; i < TESTTIME * 64 * 1024; i++) {
    //     WBCRYPTO_ff3_encrypt(fpe_ctx, input, cipher);
    // }
    // program_end = clock();
    // ts = program_end - program_start;
    // ts = ts / CLOCKS_PER_SEC;
    // printf("[FF3] [wbsm4] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME,
    //        1 / (ts / TESTTIME));
    // printf("[FF3] [wbsm4] encrypt answer: %s\n", cipher);

    // WBCRYPTO_ff3_decrypt(fpe_ctx, cipher, plain);
    // printf("[FF3] [wbsm4] decrypt answer: %s\n", plain);
}

int main() {
    if (generate_kek(TEST_KEK_INDEX) != 1) {
		error_print();
	}
    // test_aes_fpe();
    // test_sm4_fpe();
    // test_wbsm4_fpe();
    //test_se_wbsm4_fpe();
    test_sdf_sm4_fpe();
}
