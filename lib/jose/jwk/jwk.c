/*
 * libwebsockets - JSON Web Key support
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
 */

#include "core/private.h"
#include "jose/private.h"

#include <fcntl.h>
#include <unistd.h>

static const char * const kty_names[] = {
	"unknown",	/* LWS_GENCRYPTO_KTY_UNKNOWN */
	"oct",		/* LWS_GENCRYPTO_KTY_OCT */
	"RSA",		/* LWS_GENCRYPTO_KTY_RSA */
	"EC"		/* LWS_GENCRYPTO_KTY_EC */
};

/*
 * These are the entire legal token set for names in jwk.
 *
 * The first version is used to parse a detached single jwk that don't have any
 * parent JSON context.  The second version is used to parse full jwk objects
 * that has a "keys": [ ] array containing the keys.
 */

static const char * const jwk_tok[] = {
	"keys[]",			/* dummy */
	"e", "n", "d", "p", "q", "dp", "dq", "qi", /* RSA */
	"kty",				/* generic */
	"k",				/* symmetric key data */
	"crv", "x", "y",		/* EC (also "D") */
	"kid",				/* generic */
	"use"				/* mutually exclusive with "key_ops" */,
	"key_ops"			/* mutually exclusive with "use" */,
	"x5c",				/* generic */
	"alg"				/* generic */
}, * const jwk_outer_tok[] = {
	"keys[]",
	"keys[].e", "keys[].n", "keys[].d", "keys[].p", "keys[].q", "keys[].dp",
	"keys[].dq", "keys[].qi",

	"keys[].kty", "keys[].k",		/* generic */
	"keys[].crv", "keys[].x", "keys[].y",	/* EC (also "D") */
	"keys[].kid", "keys[].use"	/* mutually exclusive with "key_ops" */,
	"keys[].key_ops",		/* mutually exclusive with "use" */
	"keys[].x5c", "keys[].alg"
};

/* information about each token declared above */

#define F_M	(1 <<  9)	/* Mandatory for key type */
#define F_B64	(1 << 10)	/* Base64 coded octets */
#define F_B64U	(1 << 11)	/* Base64 Url coded octets */
#define F_META	(1 << 12)	/* JWK key metainformation */
#define F_RSA	(1 << 13)	/* RSA key */
#define F_EC	(1 << 14)	/* Elliptic curve key */
#define F_OCT	(1 << 15)	/* octet key */

static unsigned short tok_map[] = {
	F_RSA | F_EC | F_OCT | F_META |		 0xff,
	F_RSA |				F_B64U | F_M | LWS_GENCRYPTO_RSA_KEYEL_E,
	F_RSA |				F_B64U | F_M | LWS_GENCRYPTO_RSA_KEYEL_N,
	F_RSA | F_EC |			F_B64U |       LWS_GENCRYPTO_RSA_KEYEL_D,
	F_RSA |				F_B64U |       LWS_GENCRYPTO_RSA_KEYEL_P,
	F_RSA |				F_B64U |       LWS_GENCRYPTO_RSA_KEYEL_Q,
	F_RSA |				F_B64U |       LWS_GENCRYPTO_RSA_KEYEL_DP,
	F_RSA |				F_B64U |       LWS_GENCRYPTO_RSA_KEYEL_DQ,
	F_RSA |				F_B64U |       LWS_GENCRYPTO_RSA_KEYEL_QI,

	F_RSA | F_EC | F_OCT | F_META |		 F_M | JWK_META_KTY,
		       F_OCT |		F_B64U | F_M | LWS_GENCRYPTO_OCT_KEYEL_K,

		F_EC |				 F_M | LWS_GENCRYPTO_EC_KEYEL_CRV,
		F_EC |			F_B64U | F_M | LWS_GENCRYPTO_EC_KEYEL_X,
		F_EC |			F_B64U | F_M | LWS_GENCRYPTO_EC_KEYEL_Y,

	F_RSA | F_EC | F_OCT | F_META |		       JWK_META_KID,
	F_RSA | F_EC | F_OCT | F_META |		       JWK_META_USE,

	F_RSA | F_EC | F_OCT | F_META |		       JWK_META_KEY_OPS,
	F_RSA | F_EC | F_OCT | F_META | F_B64 |	       JWK_META_X5C,
	F_RSA | F_EC | F_OCT | F_META |		       JWK_META_ALG,
};

static const char *meta_names[] = {
	"kty", "kid", "use", "key_ops", "x5c", "alg"
};
static const char meta_b64[] = { 0, 0, 0, 0, 1, 0 };

static const char *oct_names[] = {
	"k"
};
static const char oct_b64[] = { 1 };

static const char *rsa_names[] = {
	"e", "n", "d", "p", "q", "dp", "dq", "qi"
};
static const char rsa_b64[] = { 1, 1, 1, 1, 1, 1, 1, 1 };

static const char *ec_names[] = {
	"crv", "x", "d", "y",
};
static const char ec_b64[] = { 0, 1, 1, 1 };

LWS_VISIBLE int
lws_jwk_dump(struct lws_jwk *jwk)
{
	const char **enames, *b64;
	int elems;
	int n;

	switch (jwk->kty) {
	default:
	case LWS_GENCRYPTO_KTY_UNKNOWN:
		lwsl_err("%s: jwk %p: unknown type\n", __func__, jwk);

		return 1;
	case LWS_GENCRYPTO_KTY_OCT:
		elems = LWS_GENCRYPTO_OCT_KEYEL_COUNT;
		enames = oct_names;
		b64 = oct_b64;
		break;
	case LWS_GENCRYPTO_KTY_RSA:
		elems = LWS_GENCRYPTO_RSA_KEYEL_COUNT;
		enames = rsa_names;
		b64 = rsa_b64;
		break;
	case LWS_GENCRYPTO_KTY_EC:
		elems = LWS_GENCRYPTO_EC_KEYEL_COUNT;
		enames = ec_names;
		b64 = ec_b64;
		break;
	}

	lwsl_info("%s: jwk %p\n", __func__, jwk);

	for (n = 0; n < LWS_COUNT_JWK_ELEMENTS; n++) {
		if (jwk->meta[n].buf && meta_b64[n]) {
			lwsl_info("  meta: %s\n", meta_names[n]);
			lwsl_hexdump_info(jwk->meta[n].buf, jwk->meta[n].len);
		}
		if (jwk->meta[n].buf && !meta_b64[n])
			lwsl_info("  meta: %s: '%s'\n", meta_names[n],
					jwk->meta[n].buf);
	}

	for (n = 0; n < elems; n++) {
		if (jwk->e[n].buf && b64[n]) {
			lwsl_info("  e: %s\n", enames[n]);
			lwsl_hexdump_info(jwk->e[n].buf, jwk->e[n].len);
		}
		if (jwk->e[n].buf && !b64[n])
			lwsl_info("  e: %s: '%s'\n", enames[n], jwk->e[n].buf);
	}

	return 0;
}

static int
_lws_jwk_set_element_jwk(struct lws_gencrypto_keyelem *e, char *in, int len)
{
	e->buf = lws_malloc(len + 1, "jwk");
	if (!e->buf)
		return -1;

	memcpy(e->buf, in, len);
	e->buf[len] = '\0';
	e->len = len;

	return 0;
}

static int
_lws_jwk_set_element_jwk_b64(struct lws_gencrypto_keyelem *e, char *in, int len)
{
	int dec_size = ((len * 3) / 4) + 4, n;

	e->buf = lws_malloc(dec_size, "jwk");
	if (!e->buf)
		return -1;

	/* same decoder accepts both url or original styles */

	n = lws_b64_decode_string_len(in, len, (char *)e->buf, dec_size - 1);
	if (n < 0)
		return -1;
	e->len = n;

	return 0;
}

static int
_lws_jwk_set_element_jwk_b64u(struct lws_gencrypto_keyelem *e, char *in, int len)
{
	int dec_size = ((len * 3) / 4) + 4, n;

	e->buf = lws_malloc(dec_size, "jwk");
	if (!e->buf)
		return -1;

	/* same decoder accepts both url or original styles */

	n = lws_b64_decode_string_len(in, len, (char *)e->buf, dec_size - 1);
	if (n < 0)
		return -1;
	e->len = n;

	return 0;
}

void
lws_jwk_destroy_elements(struct lws_gencrypto_keyelem *el, int m)
{
	int n;

	for (n = 0; n < m; n++)
		if (el[n].buf)
			lws_free_set_NULL(el[n].buf);
}

LWS_VISIBLE void
lws_jwk_destroy(struct lws_jwk *jwk)
{
	lws_jwk_destroy_elements(jwk->e, LWS_ARRAY_SIZE(jwk->e));
	lws_jwk_destroy_elements(jwk->meta, LWS_ARRAY_SIZE(jwk->meta));
}

static signed char
cb_jwk(struct lejp_ctx *ctx, char reason)
{
	struct lws_jwk_parse_state *jps = (struct lws_jwk_parse_state *)ctx->user;
	struct lws_jwk *jwk = jps->jwk;
	unsigned int idx, poss, n;

	if (reason == LEJPCB_VAL_STR_START)
		jps->pos = 0;

	if (reason == LEJPCB_OBJECT_START && ctx->path_match == 0 + 1)
		/*
		 * new keys[] member is starting
		 *
		 * Until we see some JSON names, it could be anything...
		 * there is no requirement for kty to be given first and eg,
		 * ACME specifies the keys must be ordered in lexographic
		 * order - where kty is not first.
		 */
		jps->possible = F_RSA | F_EC | F_OCT;

	if (reason == LEJPCB_OBJECT_END && ctx->path_match == 0 + 1) {
		/* we completed parsing a key */
		if (jps->per_key_cb && jps->possible) {
			if (jps->per_key_cb(jps->jwk, jps->user)) {

				lwsl_notice("%s: user cb halts import\n",
					    __func__);

				return -2;
			}

			/* clear it down */
			lws_jwk_destroy(jps->jwk);
			jps->possible = 0;
		}
	}

	if (reason == LEJPCB_COMPLETE) {

		/*
		 * Now we saw the whole jwk and know the key type, let'jwk insist
		 * that as a whole, it must be consistent and complete.
		 *
		 * The tracking of ->possible bits from even before we know the
		 * kty already makes certain we cannot have key element members
		 * defined that are inconsistent with the key type.
		 */

		for (n = 0; n < LWS_ARRAY_SIZE(tok_map); n++)
			/*
			 * All mandataory elements for the key type
			 * must be present
			 */
			if ((tok_map[n] & jps->possible) && (
			    ((tok_map[n] & (F_M | F_META)) == (F_M | F_META) &&
			     !jwk->meta[tok_map[n] & 0xff].buf) ||
			    ((tok_map[n] & (F_M | F_META)) == F_M &&
			     !jwk->e[tok_map[n] & 0xff].buf))) {
				lwsl_notice("%s: missing %s\n", __func__,
					    jwk_tok[n]);
					return -3;
				}

		/*
		 * When the key may be public or public + private, ensure the
		 * intra-key members related to that are consistent.
		 *
		 * Only RSA keys need extra care, since EC keys are already
		 * confirmed by making CRV, X and Y mandatory and only D
		 * (the singular private part) optional.  For RSA, N and E are
		 * also already known to be present using mandatory checking.
		 */

		/*
		 * If a private key, it must have all D, P and Q.  Public key
		 * must have none of them.
		 */
		if (jwk->kty == LWS_GENCRYPTO_KTY_RSA &&
		    !(((!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf) &&
		      (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf) &&
		      (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf)) ||
		      (jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf &&
		       jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf &&
		       jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf))
		      ) {
			lwsl_notice("%s: RSA requires D, P and Q for private\n",
				    __func__);
			return -3;
		}

		/*
		 * If the precomputed private key terms appear, they must all
		 * appear together.
		 */
		if (jwk->kty == LWS_GENCRYPTO_KTY_RSA &&
		    !(((!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DP].buf) &&
		      (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DQ].buf) &&
		      (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_QI].buf)) ||
		      (jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DP].buf &&
		       jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DQ].buf &&
		       jwk->e[LWS_GENCRYPTO_RSA_KEYEL_QI].buf))
		      ) {
			lwsl_notice("%s: RSA DP, DQ, QI must all appear "
				    "or none\n", __func__);
			return -3;
		}

		/*
		 * The precomputed private key terms must not appear without
		 * the private key itself also appearing.
		 */
		if (jwk->kty == LWS_GENCRYPTO_KTY_RSA &&
		    !jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf &&
		     jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DQ].buf) {
			lwsl_notice("%s: RSA DP, DQ, QI can appear only with "
				    "private key\n", __func__);
			return -3;
		}

		if ((jwk->kty == LWS_GENCRYPTO_KTY_RSA ||
		     jwk->kty == LWS_GENCRYPTO_KTY_EC) &&
		    jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf)
		jwk->private_key = 1;
	}

	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	if (ctx->path_match == 0 + 1)
		return 0;

	idx = tok_map[ctx->path_match - 1];
	if ((idx & 0xff) == 0xff)
		return 0;

	switch (idx) {
	/* note: kty is not necessarily first... we have to keep track of
	 * what could match given which element names have already been
	 * seen.  Once kty comes, we confirm it'jwk still possible (ie, it'jwk
	 * not trying to tell us that it'jwk RSA now when we saw a "crv"
	 * earlier) and then reduce the possibilities to just the one that
	 * kty told. */
	case F_RSA | F_EC | F_OCT | F_META | F_M | JWK_META_KTY:

		if (ctx->npos == 3 && !strncmp(ctx->buf, "oct", 3)) {
			if (!(jps->possible & F_OCT))
				goto elements_mismatch;
			jwk->kty = LWS_GENCRYPTO_KTY_OCT;
			jps->possible = F_OCT;
			goto cont;
		}
		if (ctx->npos == 3 && !strncmp(ctx->buf, "RSA", 3)) {
			if (!(jps->possible & F_RSA))
				goto elements_mismatch;
			jwk->kty = LWS_GENCRYPTO_KTY_RSA;
			jps->possible = F_RSA;
			goto cont;
		}
		if (ctx->npos == 2 && !strncmp(ctx->buf, "EC", 2)) {
			if (!(jps->possible & F_EC))
				goto elements_mismatch;
			jwk->kty = LWS_GENCRYPTO_KTY_EC;
			jps->possible = F_EC;
			goto cont;
		}
		lwsl_err("%s: Unknown KTY '%.*s'\n", __func__, ctx->npos, ctx->buf);
		return -1;

	default:
cont:
		if (jps->pos + ctx->npos >= (int)sizeof(jps->b64))
			goto bail;

		memcpy(jps->b64 + jps->pos, ctx->buf, ctx->npos);
		jps->pos += ctx->npos;

		if (reason == LEJPCB_VAL_STR_CHUNK)
			return 0;

		/* chunking has been collated */

		poss = idx & (F_RSA | F_EC | F_OCT);
		jps->possible &= poss;
		if (!jps->possible)
			goto elements_mismatch;

		if (idx & F_META) {
			if (_lws_jwk_set_element_jwk(&jwk->meta[idx & 0x7f],
						     jps->b64, jps->pos) < 0)
				goto bail;

			break;
		}

		if (idx & F_B64U) {
			/* key data... do the base64 decode as needed */
			if (_lws_jwk_set_element_jwk_b64u(&jwk->e[idx & 0x7f],
							  jps->b64, jps->pos)
								< 0)
				goto bail;
			return 0;
		}

		if (idx & F_B64) {
			/* cert data... do non-urlcoded base64 decode */
			if (_lws_jwk_set_element_jwk_b64(&jwk->e[idx & 0x7f],
							 jps->b64, jps->pos)
								< 0)
				goto bail;
			return 0;
		}

			if (_lws_jwk_set_element_jwk(&jwk->e[idx & 0x7f],
						     jps->b64, jps->pos) < 0)
				goto bail;
		break;
	}

	return 0;

elements_mismatch:
	lwsl_err("%s: jwk elements mismatch\n", __func__);

bail:
	lwsl_err("%s: element failed\n", __func__);

	return -1;
}

void
lws_jwk_init_jps(struct lejp_ctx *jctx, struct lws_jwk_parse_state *jps,
		 struct lws_jwk *jwk, lws_jwk_key_import_callback cb,
		 void *user)
{
	if (jwk)
		memset(jwk, 0, sizeof(*jwk));

	jps->jwk = jwk;
	jps->possible = F_RSA | F_EC | F_OCT;
	jps->per_key_cb = cb;
	jps->user = user;
	jps->pos = 0;

	lejp_construct(jctx, cb_jwk, jps, cb ? jwk_outer_tok: jwk_tok,
		       LWS_ARRAY_SIZE(jwk_tok));
}

LWS_VISIBLE int
lws_jwk_import(struct lws_jwk *jwk, lws_jwk_key_import_callback cb, void *user,
	       const char *in, size_t len)
{
	struct lejp_ctx jctx;
	struct lws_jwk_parse_state jps;
	int m;

	lws_jwk_init_jps(&jctx, &jps, jwk, cb, user);

	m = (int)(signed char)lejp_parse(&jctx, (uint8_t *)in, len);
	lejp_destruct(&jctx);

	if (m < 0) {
		lwsl_notice("%s: parse got %d\n", __func__, m);

		return -1;
	}

	if (jwk->kty == LWS_GENCRYPTO_KTY_UNKNOWN) {
		lwsl_notice("%s: missing or unknown kyt\n", __func__);
		return -1;
	}

	return 0;
}

LWS_VISIBLE int
lws_jwk_export(struct lws_jwk *jwk, int private, char *p, size_t len)
{
	char *start = p, *end = &p[len - 1];
	int n, limit = LWS_COUNT_JWK_ELEMENTS;

	/* RFC7638 lexicographic order requires
	 *  RSA: e -> kty -> n
	 *  oct: k -> kty
	 */

	p += lws_snprintf(p, end - p, "{");

	switch (jwk->kty) {

	case LWS_GENCRYPTO_KTY_OCT:
		if (!jwk->e[LWS_GENCRYPTO_OCT_KEYEL_K].buf)
			return -1;

		p += lws_snprintf(p, end - p, "\"k\":\"");
		n = lws_jws_base64_enc(
			(const char *)jwk->e[LWS_GENCRYPTO_OCT_KEYEL_K].buf,
				jwk->e[LWS_GENCRYPTO_OCT_KEYEL_K].len, p, end - p - 4);
		if (n < 0) {
			lwsl_notice("%s: enc failed\n", __func__);
			return -1;
		}
		p += n;

		p += lws_snprintf(p, end - p, "\",\"kty\":\"%s\"}",
				  kty_names[jwk->kty]);

		return p - start;

	case LWS_GENCRYPTO_KTY_RSA:
		if (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf ||
		    !jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf ||
		    (private && (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf ||
				 !jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf ||
				 !jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf))
		) {
			lwsl_notice("%s: not enough elements filled\n",
				    __func__);
			return -1;
		}

		if (!private)
			limit = LWS_GENCRYPTO_RSA_KEYEL_N + 1;

		for (n = 0; n < limit; n++) {
			int m;

			if (!jwk->e[n].buf)
				continue;
			lwsl_info("%d: len %d\n", n, jwk->e[n].len);

			if (n)
				p += lws_snprintf(p, end - p, ",");
			p += lws_snprintf(p, end - p, "\"%s\":\"", jwk_tok[n]);
			m = lws_jws_base64_enc((const char *)jwk->e[n].buf,
						      jwk->e[n].len, p,
						      end - p - 4);
			if (m < 0) {
				lwsl_notice("%s: enc fail inlen %d outlen %d\n",
						__func__, (int)jwk->e[n].len,
						lws_ptr_diff(end, p) - 4);
				return -1;
			}
			p += m;
			*p++ = '\"';

			if (!n) /* RFC7638 lexicographic order */
				p += lws_snprintf(p, end - p, ",\"kty\":\"%s\"",
						  kty_names[jwk->kty]);
		}

		p += lws_snprintf(p, end - p, "}");

		return p - start;

	case LWS_GENCRYPTO_KTY_EC:
		return p - start;

	default:
		break;
	}

	lwsl_err("%s: unknown key type %d\n", __func__, jwk->kty);

	return -1;
}

LWS_VISIBLE int
lws_jwk_rfc7638_fingerprint(struct lws_jwk *jwk, char *digest32)
{
	struct lws_genhash_ctx hash_ctx;
	int tmpsize = 2536, n;
	char *tmp;

	tmp = lws_malloc(tmpsize, "rfc7638 tmp");

	n = lws_jwk_export(jwk, 0, tmp, tmpsize);
	if (n < 0)
		goto bail;

	if (lws_genhash_init(&hash_ctx, LWS_GENHASH_TYPE_SHA256))
		goto bail;

	if (lws_genhash_update(&hash_ctx, tmp, n)) {
		lws_genhash_destroy(&hash_ctx, NULL);

		goto bail;
	}
	lws_free(tmp);

	if (lws_genhash_destroy(&hash_ctx, digest32))
		return -1;

	return 0;

bail:
	lws_free(tmp);

	return -1;
}

LWS_VISIBLE int
lws_jwk_load(struct lws_jwk *jwk, const char *filename,
	     lws_jwk_key_import_callback cb, void *user)
{
	int buflen = 4096;
	char *buf = lws_malloc(buflen, "jwk-load");
	int n;

	if (!buf)
		return -1;

	n = lws_plat_read_file(filename, buf, buflen);
	if (n < 0)
		goto bail;

	n = lws_jwk_import(jwk, cb, user, buf, n);
	lws_free(buf);

	return n;
bail:
	lws_free(buf);

	return -1;
}

LWS_VISIBLE int
lws_jwk_save(struct lws_jwk *jwk, const char *filename)
{
	int buflen = 4096;
	char *buf = lws_malloc(buflen, "jwk-save");
	int n, m;

	if (!buf)
		return -1;

	n = lws_jwk_export(jwk, 1, buf, buflen);
	if (n < 0)
		goto bail;

	m = lws_plat_write_file(filename, buf, n);

	lws_free(buf);
	if (m)
		return -1;

	return 0;

bail:
	lws_free(buf);

	return -1;
}
