/*
 * libwebsockets - generic AES api hiding the backend
 *
 * Copyright (C) 2017 - 2018 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 *  lws_genaes provides an abstraction api for AES in lws that works the
 *  same whether you are using openssl or mbedtls hash functions underneath.
 */
#include "core/private.h"
#include "../../jose/private.h"

static int operation_map[] = { MBEDTLS_AES_ENCRYPT, MBEDTLS_AES_DECRYPT };

LWS_VISIBLE int
lws_genaes_create(struct lws_genaes_ctx *ctx, enum enum_aes_operation op,
		  enum enum_aes_modes mode, struct lws_gencrypto_keyelem *el,
		  int padding, void *engine)
{
	int n;

	ctx->mode = mode;
	ctx->k = el;
	ctx->op = operation_map[op];
	ctx->underway = 0;

	switch (ctx->mode) {
	case LWS_GAESM_XTS:
#if defined(MBEDTLS_CIPHER_MODE_XTS)
		mbedtls_aes_xts_init(&ctx->u.ctx_xts);
		break;
#else
		return -1;
#endif
	case LWS_GAESM_GCM:
		mbedtls_gcm_init(&ctx->u.ctx_gcm);
		n = mbedtls_gcm_setkey(&ctx->u.ctx_gcm, MBEDTLS_CIPHER_ID_AES,
				       ctx->k->buf, ctx->k->len * 8);
		if (n) {
			lwsl_notice("%s: mbedtls_gcm_setkey: -0x%x\n",
				    __func__, -n);
			return n;
		}
		return n;
	default:
		mbedtls_aes_init(&ctx->u.ctx);
		break;
	}

	switch (op) {
	case LWS_GAESO_ENC:
		if (ctx->mode == LWS_GAESM_XTS)
#if defined(MBEDTLS_CIPHER_MODE_XTS)
			n = mbedtls_aes_xts_setkey_enc(&ctx->u.ctx_xts,
						       ctx->k->buf,
						       ctx->k->len * 8);
#else
			return -1;
#endif
		else
			n = mbedtls_aes_setkey_enc(&ctx->u.ctx, ctx->k->buf,
						   ctx->k->len * 8);
		break;
	case LWS_GAESO_DEC:
		switch (ctx->mode) {
		case LWS_GAESM_XTS:
#if defined(MBEDTLS_CIPHER_MODE_XTS)
			n = mbedtls_aes_xts_setkey_dec(&ctx->u.ctx_xts,
						       ctx->k->buf,
						       ctx->k->len * 8);
			break;
#else
			return -1;
#endif

		case LWS_GAESM_CFB128:
		case LWS_GAESM_CFB8:
		case LWS_GAESM_CTR:
		case LWS_GAESM_OFB:
			n = mbedtls_aes_setkey_enc(&ctx->u.ctx, ctx->k->buf,
						   ctx->k->len * 8);
			break;
		default:
			n = mbedtls_aes_setkey_dec(&ctx->u.ctx, ctx->k->buf,
						   ctx->k->len * 8);
			break;
		}
		break;
	}

	if (n)
		lwsl_notice("%s: setting key: -0x%x\n", __func__, -n);

	return n;
}

LWS_VISIBLE int
lws_genaes_destroy(struct lws_genaes_ctx *ctx, unsigned char *tag, size_t tlen)
{
	int n;

	if (ctx->mode == LWS_GAESM_GCM) {
		if (tag) {
			n = mbedtls_gcm_finish(&ctx->u.ctx_gcm, tag, tlen);
			if (n)
				lwsl_notice("%s: mbedtls_gcm_finish: -0x%x\n",
					    __func__, -n);
			else
				if (lws_timingsafe_bcmp(ctx->tag, tag, ctx->taglen)) {
					lwsl_err("%s: lws_genaes_crypt tag "
						 "mismatch (bad first)\n",
							__func__);
					lwsl_hexdump_notice(tag, tlen);
					lwsl_hexdump_notice(ctx->tag, ctx->taglen);
					n = -1;
				}
		}
		mbedtls_gcm_free(&ctx->u.ctx_gcm);
		return n;
	}
	if (ctx->mode == LWS_GAESM_XTS)
#if defined(MBEDTLS_CIPHER_MODE_XTS)
		mbedtls_aes_xts_free(&ctx->u.ctx_xts);
#else
		return -1;
#endif
	else
		mbedtls_aes_free(&ctx->u.ctx);

	return 0;
}

static int
lws_genaes_rfc3394_wrap(int wrap, int bits, const uint8_t *kek,
			const uint8_t *in, uint8_t *out)
{
	int n, m, ret = -1, c64 = bits / 64;
	mbedtls_aes_context ctx;
	uint8_t a[8], b[16];

	/*
	 * notice the key used to perform the wrapping or unwrapping is always
	 * 128 bits.  The key being wrapped or unwrapped may be larger and is
	 * set by the 'bits' parameter.
	 */

	mbedtls_aes_init(&ctx);

	if (wrap) {
		/*
		 * The inputs to the key wrapping process are the KEK and the
		 * plaintext to be wrapped.  The plaintext consists of n 64-bit
		 * blocks, containing the key data being wrapped.
		 *
		 * Inputs:      Plaintext, n 64-bit values {P1, P2, ..., Pn},
		 *		and Key, K (the KEK).
		 * Outputs:     Ciphertext, (n+1) 64-bit values
		 *		{C0, C1, ..., Cn}.
		 *
		 * The default initial value (IV) is defined to be the
		 * hexadecimal constant:
		 *
		 * A[0] = IV = A6A6A6A6A6A6A6A6
		 */
		memset(out, 0xa6, 8);
		memcpy(out + 8, in, 8 * c64);
		n = mbedtls_aes_setkey_enc(&ctx, kek, 128);
	} else {
		/*
		 * 2.2.2 Key Unwrap
		 *
		 * The inputs to the unwrap process are the KEK and (n+1)
		 * 64-bit blocks of ciphertext consisting of previously
		 * wrapped key.  It returns n blocks of plaintext consisting
		 * of the n 64-bit blocks of the decrypted key data.
		 *
		 * Inputs:  Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn},
		 * and Key, K (the KEK).
		 *
		 * Outputs: Plaintext, n 64-bit values {P1, P2, ..., Pn}.
		 */
		memcpy(a, in, 8);
		memcpy(out, in + 8, 8 * c64);
		n = mbedtls_aes_setkey_dec(&ctx, kek, 128);
	}

	if (n < 0) {
		lwsl_err("%s: setkey failed\n", __func__);
		goto bail;
	}

	if (wrap) {
		for (n = 0; n <= 5; n++) {
			uint8_t *r = out + 8;
			for (m = 1; m <= c64; m++) {
				memcpy(b, out, 8);
				memcpy(b + 8, r, 8);
				if (mbedtls_internal_aes_encrypt(&ctx, b, b))
					goto bail;

				memcpy(out, b, 8);
				out[7] ^= c64 * n + m;
				memcpy(r, b + 8, 8);
				r += 8;
			}
		}
		ret = 0;
	} else {
		/*
		 *
		 */
		for (n = 5; n >= 0; n--) {
			uint8_t *r = out + (c64 - 1) * 8;
			for (m = c64; m >= 1; m--) {
				memcpy(b, a, 8);
				b[7] ^= c64 * n + m;
				memcpy(b + 8, r, 8);
				if (mbedtls_internal_aes_decrypt(&ctx, b, b))
					goto bail;

				memcpy(a, b, 8);
				memcpy(r, b + 8, 8);
				r -= 8;
			}
		}

		if (*((uint64_t *)a) == 0xa6a6a6a6a6a6a6a6ull)
			ret = 0;
	}

bail:
	if (ret)
		lwsl_notice("%s: failed\n", __func__);
	mbedtls_aes_free(&ctx);

	return ret;
}

LWS_VISIBLE int
lws_genaes_crypt(struct lws_genaes_ctx *ctx, const uint8_t *in, size_t len,
		 uint8_t *out, uint8_t *iv_or_nonce_ctr_or_data_unit_16,
		 uint8_t *stream_block_16, size_t *nc_or_iv_off, int taglen)
{
	uint8_t iv[16], sb[16];
	int n;

	switch (ctx->mode) {
	case LWS_GAESM_KW:
		n = lws_genaes_rfc3394_wrap(ctx->op == MBEDTLS_AES_ENCRYPT,
				    256/*ctx->k->len * 8*/, ctx->k->buf, in, out);
		break;
	case LWS_GAESM_CBC:
		memcpy(iv, iv_or_nonce_ctr_or_data_unit_16, 16);
		n = mbedtls_aes_crypt_cbc(&ctx->u.ctx, ctx->op, len, iv,
					  in, out);
		break;

	case LWS_GAESM_CFB128:
		memcpy(iv, iv_or_nonce_ctr_or_data_unit_16, 16);
		n = mbedtls_aes_crypt_cfb128(&ctx->u.ctx, ctx->op, len,
					     nc_or_iv_off, iv, in, out);
		break;

	case LWS_GAESM_CFB8:
		memcpy(iv, iv_or_nonce_ctr_or_data_unit_16, 16);
		n = mbedtls_aes_crypt_cfb8(&ctx->u.ctx, ctx->op, len, iv,
					   in, out);
		break;

	case LWS_GAESM_CTR:
		memcpy(iv, iv_or_nonce_ctr_or_data_unit_16, 16);
		memcpy(sb, stream_block_16, 16);
		n = mbedtls_aes_crypt_ctr(&ctx->u.ctx, len, nc_or_iv_off,
					  iv, sb, in, out);
		memcpy(iv_or_nonce_ctr_or_data_unit_16, iv, 16);
		memcpy(stream_block_16, sb, 16);
		break;

	case LWS_GAESM_ECB:
		n = mbedtls_aes_crypt_ecb(&ctx->u.ctx, ctx->op, in, out);
		break;

	case LWS_GAESM_OFB:
#if defined(MBEDTLS_CIPHER_MODE_OFB)
		memcpy(iv, iv_or_nonce_ctr_or_data_unit_16, 16);
		n = mbedtls_aes_crypt_ofb(&ctx->u.ctx, len, nc_or_iv_off, iv,
					  in, out);
		break;
#else
		return -1;
#endif

	case LWS_GAESM_XTS:
#if defined(MBEDTLS_CIPHER_MODE_XTS)
		memcpy(iv, iv_or_nonce_ctr_or_data_unit_16, 16);
		n = mbedtls_aes_crypt_xts(&ctx->u.ctx_xts, ctx->op, len, iv,
					  in, out);
		break;
#else
		return -1;
#endif
	case LWS_GAESM_GCM:
		if (!ctx->underway) {
			ctx->underway = 1;

			memcpy(ctx->tag, stream_block_16, taglen);
			ctx->taglen = taglen;

			/*
			 * iv:                   iv_or_nonce_ctr_or_data_unit_16
			 * iv_len:               *nc_or_iv_off
			 * stream_block_16:      pointer to tag
			 * additional data:      in
			 * additional data len:  len
			 */

			n = mbedtls_gcm_starts(&ctx->u.ctx_gcm, ctx->op,
					       iv_or_nonce_ctr_or_data_unit_16,
					       *nc_or_iv_off, in, len);
			if (n) {
				lwsl_notice("%s: mbedtls_gcm_starts: -0x%x\n",
					    __func__, -n);

				return -1;
			}
			break;
		}

		n = mbedtls_gcm_update(&ctx->u.ctx_gcm, len, in, out);
		if (n) {
			lwsl_notice("%s: mbedtls_gcm_update: -0x%x\n",
				    __func__, -n);

			return -1;
		}
		break;
	}

	if (n) {
		lwsl_notice("%s: failed: -0x%x, len %d\n", __func__, -n, (int)len);

		return -1;
	}

	return 0;
}
