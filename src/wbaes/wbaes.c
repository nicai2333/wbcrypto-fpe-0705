#include <wbcrypto/wbaes.h>


wbcrypto_wbaes_context *WBCRYPTO_wbaes_context_init(){
    struct wbaes_context *ctx=malloc(sizeof(struct wbaes_context));
    if(ctx==NULL){
        WBCRYPTO_THROW_REASON("WBCRYPTO_wbaes_context_init",WBCRYPTO_ERR_ALLOC_FAILED);
        goto cleanup;
    }
    memset(ctx,0,sizeof(struct wbaes_context));
    return ctx;
cleanup:
    return NULL;
}

void generatePermutation(uint8_t *permutation, uint8_t *inverse)
{
    int i, j;
    uint8_t temp;
    for (i = 0; i < 16; i++)
    {
        permutation[i] = i;
    }
    for (i = 0; i < 15; i++)
    {
        j = cus_random()%(16 - i);
        temp = permutation[i];
        permutation[i] = permutation[i+j];
        permutation[i + j] = temp;
    }
    for (i = 0; i < 16; i++)
    {
        inverse[permutation[i]] = i;
    }
}

void wbcrypto_wbaes_gen(wbcrypto_wbaes_context *ctx, const uint8_t *key)
{
    int i, j, x, y, k;
    wbcrypto_aes_context aes_key;
    wbcrypto_aes_setkey_enc(&aes_key, key);

    M8 L[9][16];
    M8 L_inv[9][16];
    M32 MB[9][4];
    M32 MB_inv[9][4];
    M8 ex_in[16];
    M8 ex_in_inv[16];
    M8 ex_out[16];
    M8 ex_out_inv[16];
    for(i = 0; i < 9; i++)
    {
        for(j = 0; j < 16; j++)
        {
            genMatpairM8(&L[i][j], &L_inv[i][j]);
        }
    }
    for(i = 0; i < 9; i++)
    {
        for(j = 0; j < 4; j++)
        {
            genMatpairM32(&MB[i][j], &MB_inv[i][j]);
        }
    }
    for(i = 0; i < 16; i++)
    {
        genMatpairM8(&ex_in[i], &ex_in_inv[i]);
        genMatpairM8(&ex_out[i], &ex_out_inv[i]);
    }

    uint32_t Tyi[4][256] = {0};
    for (x = 0; x < 256; x++)
    {
        Tyi[0][x] = (gMul(2, x) << 24) | (x << 16) | (x << 8) | gMul(3, x);
        Tyi[1][x] = (gMul(3, x) << 24) | (gMul(2, x) << 16) | (x << 8) | x;
        Tyi[2][x] = (x << 24) | (gMul(3, x) << 16) | (gMul(2, x) << 8) | x;
        Tyi[3][x] = (x << 24) | (x << 16) | (gMul(3, x) << 8) | gMul(2, x);
    }

    M32 Out_L[9][4];
    for(i = 0; i < 9; i++)
    {
        for(j = 0; j < 4; j++)
        {
            MatrixcomM8to32(L[i][4 * j], L[i][4 * j + 1], L[i][4 * j + 2], L[i][4 * j + 3], &Out_L[i][j]);
        }
    }

    uint8_t TypeII_out[9][16][8][16];
    uint8_t TypeII_out_inv[9][16][8][16];
    uint8_t TypeIV_II_out1[9][8][8][16];
    uint8_t TypeIV_II_out1_inv[9][8][8][16];
    uint8_t TypeIV_II_out2[9][4][8][16];
    uint8_t TypeIV_II_out2_inv[9][4][8][16];

    uint8_t TypeIII_out[9][16][8][16];
    uint8_t TypeIII_out_inv[9][16][8][16];
    uint8_t TypeIV_III_out1[9][8][8][16];
    uint8_t TypeIV_III_out1_inv[9][8][8][16];
    uint8_t TypeIV_III_out2[9][4][8][16];
    uint8_t TypeIV_III_out2_inv[9][4][8][16];

    uint8_t TypeII_ex_in[16][2][16];
    uint8_t TypeII_ex_in_inv[16][2][16];
    uint8_t TypeIII_ex_out[16][2][16];
    uint8_t TypeIII_ex_out_inv[16][2][16];

    InitRandom((unsigned int)time(NULL));
    for(i = 0; i < 9; i++)
    {
        for(j = 0; j < 16; j++)
        {
            for(k = 0; k < 8; k++)
            {
                uint8_t permutation[16];
                uint8_t inverse[16];
                generatePermutation(permutation, inverse);
                for(x = 0; x < 16; x++)
                {
                    TypeII_out[i][j][k][x] = permutation[x];
                    TypeII_out_inv[i][j][k][x] = inverse[x];
                }
                generatePermutation(permutation, inverse);
                for(x = 0; x < 16; x++)
                {
                    TypeIII_out[i][j][k][x] = permutation[x];
                    TypeIII_out_inv[i][j][k][x] = inverse[x];
                }
            }
        }
    }
    for(i = 0; i < 9; i++)
    {
        for(j = 0; j < 8; j++)
        {
            for(k = 0; k < 8; k++)
            {
                uint8_t permutation[16];
                uint8_t inverse[16];
                generatePermutation(permutation, inverse);
                for(x = 0; x < 16; x++)
                {
                    TypeIV_II_out1[i][j][k][x] = permutation[x];
                    TypeIV_II_out1_inv[i][j][k][x] = inverse[x];
                }
                generatePermutation(permutation, inverse);
                for(x = 0; x < 16; x++)
                {
                    TypeIV_III_out1[i][j][k][x] = permutation[x];
                    TypeIV_III_out1_inv[i][j][k][x] = inverse[x];
                }
            }
        }
    }
    for(i = 0; i < 9; i++)
    {
        for(j = 0; j < 4; j++)
        {
            for(k = 0; k < 8; k++)
            {
                uint8_t permutation[16];
                uint8_t inverse[16];
                generatePermutation(permutation, inverse);
                for(x = 0; x < 16; x++)
                {
                    TypeIV_II_out2[i][j][k][x] = permutation[x];
                    TypeIV_II_out2_inv[i][j][k][x] = inverse[x];
                }
                generatePermutation(permutation, inverse);
                for(x = 0; x < 16; x++)
                {
                    TypeIV_III_out2[i][j][k][x] = permutation[x];
                    TypeIV_III_out2_inv[i][j][k][x] = inverse[x];
                }
            }
        }
    }

    for(i = 0; i < 16; i++)
    {
        for(j = 0; j < 2; j++)
        {
            uint8_t permutation[16];
            uint8_t inverse[16];
            generatePermutation(permutation, inverse);
            for(x = 0; x < 16; x++)
            {
                TypeII_ex_in[i][j][x] = permutation[x];
                TypeII_ex_in_inv[i][j][x] = inverse[x];
            }
            generatePermutation(permutation, inverse);
            for(x = 0; x < 16; x++)
            {
                TypeIII_ex_out[i][j][x] = permutation[x];
                TypeIII_ex_out_inv[i][j][x] = inverse[x];
            }
        }
    }

    int columnindex[]={0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3};
    int shiftindex[]={0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
    //Round 1
    shiftRows (aes_key.expandedKey + 16 * 0);
    for(j = 0; j < 16; j++)//type_II
    {
        uint8_t temp_uint8_t;
        uint32_t temp_u32;
        for(x = 0; x < 256; x++)
        {
            temp_uint8_t = (TypeII_ex_in_inv[shiftindex[j]][0][(x & 0xf0) >> 4] << 4) | (TypeII_ex_in_inv[shiftindex[j]][1][(x & 0x0f)]);
            temp_uint8_t = MatMulNumM8(ex_in_inv[shiftindex[j]], temp_uint8_t);
            temp_uint8_t = SBox[temp_uint8_t ^ aes_key.expandedKey[16 * 0 + j]];
            temp_u32 = Tyi[j % 4][temp_uint8_t];
            temp_u32 = MatMulNumM32(MB[0][columnindex[j]], temp_u32);
            ctx->TypeII[0][j][x] = (TypeII_out[0][j][0][(temp_u32 & 0xf0000000) >> 28] << 28) | (TypeII_out[0][j][1][(temp_u32 & 0x0f000000) >> 24] << 24) | (TypeII_out[0][j][2][(temp_u32 & 0x00f00000) >> 20] << 20) | (TypeII_out[0][j][3][(temp_u32 & 0x000f0000) >> 16] << 16) | (TypeII_out[0][j][4][(temp_u32 & 0x0000f000) >> 12] << 12) | (TypeII_out[0][j][5][(temp_u32 & 0x00000f00) >> 8] << 8) | (TypeII_out[0][j][6][(temp_u32 & 0x000000f0) >> 4] << 4) | (TypeII_out[0][j][7][(temp_u32 & 0x0000000f)]);
        }
    }
    for(j = 0; j < 16; j++)//type_III
    {
        uint8_t temp_uint8_t;
        uint32_t temp_u32;
        int shiftbit[]={24, 16, 8, 0};
        for(x = 0; x < 256; x++)
        {
            temp_uint8_t = (TypeIV_II_out2_inv[0][columnindex[j]][(j % 4) * 2][(x & 0xf0) >> 4] << 4) | (TypeIV_II_out2_inv[0][columnindex[j]][(j % 4) * 2 + 1][(x & 0x0f)]);
            temp_u32 = temp_uint8_t << shiftbit[j % 4];
            temp_u32 = MatMulNumM32(MB_inv[0][columnindex[j]], temp_u32);
            temp_u32 = MatMulNumM32(Out_L[0][columnindex[j]], temp_u32);
            ctx->TypeIII[0][j][x] = (TypeIII_out[0][j][0][(temp_u32 & 0xf0000000) >> 28] << 28) | (TypeIII_out[0][j][1][(temp_u32 & 0x0f000000) >> 24] << 24) | (TypeIII_out[0][j][2][(temp_u32 & 0x00f00000) >> 20] << 20) | (TypeIII_out[0][j][3][(temp_u32 & 0x000f0000) >> 16] << 16) | (TypeIII_out[0][j][4][(temp_u32 & 0x0000f000) >> 12] << 12) | (TypeIII_out[0][j][5][(temp_u32 & 0x00000f00) >> 8] << 8) | (TypeIII_out[0][j][6][(temp_u32 & 0x000000f0) >> 4] << 4) | (TypeIII_out[0][j][7][(temp_u32 & 0x0000000f)]);
        }
    }

    //Round 2-9
    for (i = 1; i < 9; i++)//Type_II
    {
        shiftRows (aes_key.expandedKey + 16 * i);
        for(j = 0; j < 16; j++)
        {
            uint8_t temp_uint8_t;
            uint32_t temp_u32;
            for(x = 0; x < 256; x++)
            {
                temp_uint8_t = (TypeIV_III_out2_inv[i - 1][columnindex[shiftindex[j]]][(shiftindex[j] % 4) * 2][(x & 0xf0) >> 4] << 4) | (TypeIV_III_out2_inv[i - 1][columnindex[shiftindex[j]]][(shiftindex[j] % 4) * 2 + 1][(x & 0x0f)]);
                temp_uint8_t = MatMulNumM8(L_inv[i - 1][shiftindex[j]], temp_uint8_t);
                temp_uint8_t = SBox[temp_uint8_t ^ aes_key.expandedKey[16 * i + j]];
                temp_u32 = Tyi[j % 4][temp_uint8_t];
                temp_u32 = MatMulNumM32(MB[i][columnindex[j]], temp_u32);
                ctx->TypeII[i][j][x] = (TypeII_out[i][j][0][(temp_u32 & 0xf0000000) >> 28] << 28) | (TypeII_out[i][j][1][(temp_u32 & 0x0f000000) >> 24] << 24) | (TypeII_out[i][j][2][(temp_u32 & 0x00f00000) >> 20] << 20) | (TypeII_out[i][j][3][(temp_u32 & 0x000f0000) >> 16] << 16) | (TypeII_out[i][j][4][(temp_u32 & 0x0000f000) >> 12] << 12) | (TypeII_out[i][j][5][(temp_u32 & 0x00000f00) >> 8] << 8) | (TypeII_out[i][j][6][(temp_u32 & 0x000000f0) >> 4] << 4) | (TypeII_out[i][j][7][(temp_u32 & 0x0000000f)]);
            }
        }

        for(j = 0; j < 16; j++)//type_III
        {
            uint8_t temp_uint8_t;
            uint32_t temp_u32;
            int shiftbit[]={24, 16, 8, 0};
            for(x = 0; x < 256; x++)
            {
                temp_uint8_t = (TypeIV_II_out2_inv[i][columnindex[j]][(j % 4) * 2][(x & 0xf0) >> 4] << 4) | (TypeIV_II_out2_inv[i][columnindex[j]][(j % 4) * 2 + 1][(x & 0x0f)]);
                temp_u32 = temp_uint8_t << shiftbit[j % 4];
                temp_u32 = MatMulNumM32(MB_inv[i][columnindex[j]], temp_u32);
                temp_u32 = MatMulNumM32(Out_L[i][columnindex[j]], temp_u32);
                ctx->TypeIII[i][j][x] = (TypeIII_out[i][j][0][(temp_u32 & 0xf0000000) >> 28] << 28) | (TypeIII_out[i][j][1][(temp_u32 & 0x0f000000) >> 24] << 24) | (TypeIII_out[i][j][2][(temp_u32 & 0x00f00000) >> 20] << 20) | (TypeIII_out[i][j][3][(temp_u32 & 0x000f0000) >> 16] << 16) | (TypeIII_out[i][j][4][(temp_u32 & 0x0000f000) >> 12] << 12) | (TypeIII_out[i][j][5][(temp_u32 & 0x00000f00) >> 8] << 8) | (TypeIII_out[i][j][6][(temp_u32 & 0x000000f0) >> 4] << 4) | (TypeIII_out[i][j][7][(temp_u32 & 0x0000000f)]);
            }
        }
    }

    //Round 10
    shiftRows (aes_key.expandedKey + 16 * 9);
    for(j = 0; j < 16; j++)//type_II
    {
        uint8_t temp_uint8_t;
        for(x = 0; x < 256; x++)
        {
            temp_uint8_t = (TypeIV_III_out2_inv[8][columnindex[shiftindex[j]]][(shiftindex[j] % 4) * 2][(x & 0xf0) >> 4] << 4) | (TypeIV_III_out2_inv[8][columnindex[shiftindex[j]]][(shiftindex[j] % 4) * 2 + 1][(x & 0x0f)]);
            temp_uint8_t = MatMulNumM8(L_inv[8][shiftindex[j]], temp_uint8_t);
            temp_uint8_t = SBox[temp_uint8_t ^ aes_key.expandedKey[16 * 9 + j]] ^ aes_key.expandedKey[16 * 10 + j];
            temp_uint8_t = MatMulNumM8(ex_out[j], temp_uint8_t);
            ctx->TypeII[9][j][x] = (TypeIII_ex_out[j][0][(temp_uint8_t & 0xf0) >> 4] << 4) | (TypeIII_ex_out[j][1][(temp_uint8_t & 0x0f)]);
        }
    }

    for(i = 0; i < 9; i++)
    {
        for(j = 0; j < 4; j++)
        {
            for(k = 0; k < 8; k++)
            {
                for(x = 0; x < 16; x++)
                {
                    for(y = 0; y < 16; y++)
                    {
                        ctx->TypeIV_II[i][j][0][k][x][y] = TypeIV_II_out1[i][2 * j][k][TypeII_out_inv[i][4 * j][k][x] ^ TypeII_out_inv[i][4 * j + 1][k][y]];
                        ctx->TypeIV_II[i][j][1][k][x][y] = TypeIV_II_out1[i][2 * j + 1][k][TypeII_out_inv[i][4 * j + 2][k][x] ^ TypeII_out_inv[i][4 * j + 3][k][y]];
                        ctx->TypeIV_II[i][j][2][k][x][y] = TypeIV_II_out2[i][j][k][TypeIV_II_out1_inv[i][2 * j][k][x] ^ TypeIV_II_out1_inv[i][2 * j + 1][k][y]];

                        ctx->TypeIV_III[i][j][0][k][x][y] = TypeIV_III_out1[i][2 * j][k][TypeIII_out_inv[i][4 * j][k][x] ^ TypeIII_out_inv[i][4 * j + 1][k][y]];
                        ctx->TypeIV_III[i][j][1][k][x][y] = TypeIV_III_out1[i][2 * j + 1][k][TypeIII_out_inv[i][4 * j + 2][k][x] ^ TypeIII_out_inv[i][4 * j + 3][k][y]];
                        ctx->TypeIV_III[i][j][2][k][x][y] = TypeIV_III_out2[i][j][k][TypeIV_III_out1_inv[i][2 * j][k][x] ^ TypeIV_III_out1_inv[i][2 * j + 1][k][y]];
                    }
                }
            }
        }
    }

    for(i = 0; i < 16; i++)
    {
        uint8_t temp_uint8_t;
        for(x = 0; x < 256; x++)
        {
            temp_uint8_t = MatMulNumM8(ex_in[i], x);
            ctx->TypeIa[i][x] = (TypeII_ex_in[i][0][(temp_uint8_t & 0xf0) >> 4] << 4) | (TypeII_ex_in[i][1][(temp_uint8_t & 0x0f)]);
            temp_uint8_t = (TypeIII_ex_out_inv[i][0][(x & 0xf0) >> 4] << 4) | (TypeIII_ex_out_inv[i][1][(x & 0x0f)]);
            ctx->TypeIb[i][x] = MatMulNumM8(ex_out_inv[i], temp_uint8_t);
        }
    }
}

void wbcrypto_wbaes_encrypt_withEX(const uint8_t *input, uint8_t *output, wbcrypto_wbaes_context *ctx)
{
    int i, j;
    uint32_t a, b, c, d, ab, cd;
    uint8_t state[16];
    for(i = 0; i < 16; i++)
    {
        state[i] = input[i];
    }

    for (i = 0; i < 9; i++)
    {
        shiftRows (state);
        for (j = 0; j < 4; j++)
        {
            a = ctx->TypeII[i][4*j + 0][state[4*j + 0]];
            b = ctx->TypeII[i][4*j + 1][state[4*j + 1]];
            c = ctx->TypeII[i][4*j + 2][state[4*j + 2]];
            d = ctx->TypeII[i][4*j + 3][state[4*j + 3]];

            ab = (ctx->TypeIV_II[i][j][0][0][(a >> 28) & 0xf][(b >> 28) & 0xf] << 28) | (ctx->TypeIV_II[i][j][0][1][(a >> 24) & 0xf][(b >> 24) & 0xf] << 24) | (ctx->TypeIV_II[i][j][0][2][(a >> 20) & 0xf][(b >> 20) & 0xf] << 20) |(ctx->TypeIV_II[i][j][0][3][(a >> 16) & 0xf][(b >> 16) & 0xf] << 16) |\
            (ctx->TypeIV_II[i][j][0][4][(a >> 12) & 0xf][(b >> 12) & 0xf] << 12) | (ctx->TypeIV_II[i][j][0][5][(a >> 8) & 0xf][(b >> 8) & 0xf] << 8) | (ctx->TypeIV_II[i][j][0][6][(a >> 4) & 0xf][(b >> 4) & 0xf] << 4) | ctx->TypeIV_II[i][j][0][7][a & 0xf][b & 0xf];

            cd = (ctx->TypeIV_II[i][j][1][0][(c >> 28) & 0xf][(d >> 28) & 0xf] << 28) | (ctx->TypeIV_II[i][j][1][1][(c >> 24) & 0xf][(d >> 24) & 0xf] << 24) | (ctx->TypeIV_II[i][j][1][2][(c >> 20) & 0xf][(d >> 20) & 0xf] << 20) |(ctx->TypeIV_II[i][j][1][3][(c >> 16) & 0xf][(d >> 16) & 0xf] << 16) |\
            (ctx->TypeIV_II[i][j][1][4][(c >> 12) & 0xf][(d >> 12) & 0xf] << 12) | (ctx->TypeIV_II[i][j][1][5][(c >> 8) & 0xf][(d >> 8) & 0xf] << 8) | (ctx->TypeIV_II[i][j][1][6][(c >> 4) & 0xf][(d >> 4) & 0xf] << 4) | ctx->TypeIV_II[i][j][1][7][c & 0xf][d & 0xf];

            state[4*j + 0] = (ctx->TypeIV_II[i][j][2][0][(ab >> 28) & 0xf][(cd >> 28) & 0xf] << 4) | ctx->TypeIV_II[i][j][2][1][(ab >> 24) & 0xf][(cd >> 24) & 0xf];
            state[4*j + 1] = (ctx->TypeIV_II[i][j][2][2][(ab >> 20) & 0xf][(cd >> 20) & 0xf] << 4) | ctx->TypeIV_II[i][j][2][3][(ab >> 16) & 0xf][(cd >> 16) & 0xf];
            state[4*j + 2] = (ctx->TypeIV_II[i][j][2][4][(ab >> 12) & 0xf][(cd >> 12) & 0xf] << 4) | ctx->TypeIV_II[i][j][2][5][(ab >> 8) & 0xf][(cd >> 8) & 0xf];
            state[4*j + 3] = (ctx->TypeIV_II[i][j][2][6][(ab >> 4) & 0xf][(cd >> 4) & 0xf] << 4) | ctx->TypeIV_II[i][j][2][7][ab & 0xf][cd & 0xf];

            a = ctx->TypeIII[i][4*j + 0][state[4*j + 0]];
            b = ctx->TypeIII[i][4*j + 1][state[4*j + 1]];
            c = ctx->TypeIII[i][4*j + 2][state[4*j + 2]];
            d = ctx->TypeIII[i][4*j + 3][state[4*j + 3]];

            ab = (ctx->TypeIV_III[i][j][0][0][(a >> 28) & 0xf][(b >> 28) & 0xf] << 28) | (ctx->TypeIV_III[i][j][0][1][(a >> 24) & 0xf][(b >> 24) & 0xf] << 24) | (ctx->TypeIV_III[i][j][0][2][(a >> 20) & 0xf][(b >> 20) & 0xf] << 20) |(ctx->TypeIV_III[i][j][0][3][(a >> 16) & 0xf][(b >> 16) & 0xf] << 16) |\
            (ctx->TypeIV_III[i][j][0][4][(a >> 12) & 0xf][(b >> 12) & 0xf] << 12) | (ctx->TypeIV_III[i][j][0][5][(a >> 8) & 0xf][(b >> 8) & 0xf] << 8) | (ctx->TypeIV_III[i][j][0][6][(a >> 4) & 0xf][(b >> 4) & 0xf] << 4) | ctx->TypeIV_III[i][j][0][7][a & 0xf][b & 0xf];

            cd = (ctx->TypeIV_III[i][j][1][0][(c >> 28) & 0xf][(d >> 28) & 0xf] << 28) | (ctx->TypeIV_III[i][j][1][1][(c >> 24) & 0xf][(d >> 24) & 0xf] << 24) | (ctx->TypeIV_III[i][j][1][2][(c >> 20) & 0xf][(d >> 20) & 0xf] << 20) |(ctx->TypeIV_III[i][j][1][3][(c >> 16) & 0xf][(d >> 16) & 0xf] << 16) |\
            (ctx->TypeIV_III[i][j][1][4][(c >> 12) & 0xf][(d >> 12) & 0xf] << 12) | (ctx->TypeIV_III[i][j][1][5][(c >> 8) & 0xf][(d >> 8) & 0xf] << 8) | (ctx->TypeIV_III[i][j][1][6][(c >> 4) & 0xf][(d >> 4) & 0xf] << 4) | ctx->TypeIV_III[i][j][1][7][c & 0xf][d & 0xf];

            state[4*j + 0] = (ctx->TypeIV_III[i][j][2][0][(ab >> 28) & 0xf][(cd >> 28) & 0xf] << 4) | ctx->TypeIV_III[i][j][2][1][(ab >> 24) & 0xf][(cd >> 24) & 0xf];
            state[4*j + 1] = (ctx->TypeIV_III[i][j][2][2][(ab >> 20) & 0xf][(cd >> 20) & 0xf] << 4) | ctx->TypeIV_III[i][j][2][3][(ab >> 16) & 0xf][(cd >> 16) & 0xf];
            state[4*j + 2] = (ctx->TypeIV_III[i][j][2][4][(ab >> 12) & 0xf][(cd >> 12) & 0xf] << 4) | ctx->TypeIV_III[i][j][2][5][(ab >> 8) & 0xf][(cd >> 8) & 0xf];
            state[4*j + 3] = (ctx->TypeIV_III[i][j][2][6][(ab >> 4) & 0xf][(cd >> 4) & 0xf] << 4) | ctx->TypeIV_III[i][j][2][7][ab & 0xf][cd & 0xf];
        }
    }
    //Round 10
    shiftRows(state);
    for (j = 0; j < 16; j++)
    {
        output[j] = ctx->TypeII[9][j][state[j]];
    }
}

// standard aes encryption
void wbcrypto_wbaes_encrypt(const uint8_t *input, uint8_t *output, wbcrypto_wbaes_context *ctx){
    int i;
    unsigned char EX_IN[16];
    unsigned char EX_OUT[16];
    // external encodings
    for(i = 0; i < 16; i++)
    {
        EX_IN[i] = ctx->TypeIa[i][input[i]];
    }
    // encryption with external encodings
    wbcrypto_wbaes_encrypt_withEX(EX_IN, EX_OUT, ctx);
    // external encodings
    for(i = 0; i < 16; i++)
    {
        output[i] = ctx->TypeIb[i][EX_OUT[i]];
    }
}

int wbcrypto_wbaes_gcm_encrypt_init(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, wbcrypto_wbaes_context *ctx, unsigned char* iv, size_t ivlen, unsigned char* aad, size_t aadlen)
{
    WBCRYPTO_gcm128_init(gcm_ctx, ctx, (WBCRYPTO_block128_f)wbcrypto_wbaes_encrypt);
    WBCRYPTO_gcm128_setiv(gcm_ctx, iv, ivlen);
    WBCRYPTO_gcm128_aad(gcm_ctx, aad, aadlen);
    return 0;
}
    
int wbcrypto_wbaes_gcm_encrypt(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, const uint8_t *input, size_t ilen, uint8_t *output)
{
    return WBCRYPTO_gcm128_encrypt(gcm_ctx, input, output, ilen);
}

void wbcrypto_wbaes_free(wbcrypto_wbaes_context *ctx)
{
    memset( ctx, 0, sizeof(wbcrypto_wbaes_context) );
    if(ctx!=NULL){
        free(ctx);
        ctx=NULL;
    }
}