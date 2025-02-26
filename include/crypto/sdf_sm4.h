#ifndef SDF_SM4_H
#define SDF_SM4_H

#include <stdint.h>
#include <crypto/sm4.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	SM4_KEY key;
	uint8_t iv[16];
	size_t ivlen;
} SM4_CBC_MAC_CTX;

#define SM4_CBC_MAC_SIZE	(SM4_BLOCK_SIZE)

void sm4_cbc_mac_init(SM4_CBC_MAC_CTX *ctx, const uint8_t key[16]);
void sm4_cbc_mac_update(SM4_CBC_MAC_CTX *ctx, const uint8_t *data, size_t datalen);
void sm4_cbc_mac_finish(SM4_CBC_MAC_CTX *ctx, uint8_t mac[16]);


#ifdef __cplusplus
}
#endif
#endif

