#include <wbcrypto/wbaes.h>

WBCRYPTO_fpe_context *WBCRYPTO_wbaes_fpe_init(wbcrypto_wbaes_context *key, const char *twkbuf, size_t twklen, unsigned int radix)
{
    WBCRYPTO_fpe_context *ctx = WBCRYPTO_fpe_init(twkbuf, twklen, radix, key, (block128_f)wbcrypto_wbaes_encrypt);
    return ctx;
}