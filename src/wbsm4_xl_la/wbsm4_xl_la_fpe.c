#include <wbcrypto/wbsm4_xl_la.h>

WBCRYPTO_fpe_context *WBCRYPTO_wbsm4_xl_la_fpe_init(WBCRYPTO_wbsm4_xl_la_context *key, const char *twkbuf, size_t twklen, unsigned int radix)
{
    WBCRYPTO_fpe_context *ctx = WBCRYPTO_fpe_init(twkbuf, twklen, radix, key, (block128_f)WBCRYPTO_wbsm4_xl_la_encrypt);
    return ctx;
}