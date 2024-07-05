/*
 * @Author: Bin Li
 * @Date: 2023/5/28 11:53
 * @Description:
 */

#include <wbcrypto/wbaes.h>
#include <wbcrypto/wbaes_modes.h>

int wbcrypto_wbaes_cbc_encrypt(wbcrypto_wbaes_context *ctx,
                             unsigned char *iv,
                             const unsigned char *input,
                             size_t length,
                             unsigned char *output)
{
    WBCRYPTO_cbc128_encrypt_(input, output, length, ctx, iv, (WBCRYPTO_block128_f)wbcrypto_wbaes_encrypt);
    return 0;
}