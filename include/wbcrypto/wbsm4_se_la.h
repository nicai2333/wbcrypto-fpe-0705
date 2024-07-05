#ifndef WBCRYPTO_WBSM4_SE_LA_H
#define WBCRYPTO_WBSM4_SE_LA_H

#include <wbcrypto/conf.h>
#include <wbcrypto/sm4.h>
#include <WBMatrix/WBMatrix.h>

#ifdef __cplusplus
extern "C" {
#endif
	typedef unsigned char  u8;
	typedef unsigned int   u32;
	static Aff8 A[2039], B[2039];

	#define GET32(pc)  (\
	((uint32_t)(pc)[0] << 24) ^\
	((uint32_t)(pc)[1] << 16) ^\
	((uint32_t)(pc)[2] <<  8) ^\
	((uint32_t)(pc)[3]))

	#define PUT32(st, ct)\
	(ct)[0] = (uint8_t)((st) >> 24);\
	(ct)[1] = (uint8_t)((st) >> 16);\
	(ct)[2] = (uint8_t)((st) >>  8);\
	(ct)[3] = (uint8_t)(st)

	typedef struct wbcrypto_wbsm4se_la_context
	{
		int encmode;
		uint32_t MM[32][3][4][256];
		uint32_t CC[32][4][256];
		uint32_t DD[32][4][256];
		uint32_t SEE[4][4][256];
		uint32_t FEE[4][4][256];
	}wbcrypto_wbsm4se_la_context;
	wbcrypto_wbsm4se_la_context *wbcrypto_wbsm4se_la_context_init(int encmode);

	void wbcrypto_wbsm4_se_la_gen(wbcrypto_wbsm4se_la_context *ctx,const uint8_t *key);
	void wbcrypto_wbsm4_se_la_encrypt(unsigned char IN[], unsigned char OUT[], wbcrypto_wbsm4se_la_context *ctx);
	void wbcrypto_wbsm4_se_la_free(wbcrypto_wbsm4se_la_context *ctx);

	WBCRYPTO_fpe_context *wbcrypto_wbsm4_se_la_fpe_init(wbcrypto_wbsm4se_la_context *key, const char *twkbuf, size_t twklen, unsigned int radix);
#ifdef __cplusplus
}
#endif

#endif