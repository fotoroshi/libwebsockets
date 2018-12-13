/*
 * lws-api-test-jose - RFC7516 jwe tests
 *
 * Copyright (C) 2018 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>

/*
 * These are the inputs and outputs from the worked example in RFC7516
 * Appendix A.1
 */


/* A.2.  Example JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256
 *
 * This example encrypts the plaintext "Live long and prosper." to the
 * recipient using RSAES-PKCS1-v1_5 for key encryption and
 * AES_128_CBC_HMAC_SHA_256 for content encryption.
 */

/* "Live long and prosper." */
static uint8_t

ex_a2_ptext[] = {
	76, 105, 118, 101, 32, 108, 111, 110,
	103, 32, 97, 110, 100, 32,  112, 114,
	111, 115, 112, 101, 114, 46
}, *lws_jwe_ex_a2_jwk_json = (uint8_t *)
	"{"
	 "\"kty\":\"RSA\","
	 "\"n\":\"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl"
		 "UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre"
		 "cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_"
		 "7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI"
		 "Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU"
		 "7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw\","
	 "\"e\":\"AQAB\","
	 "\"d\":\"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq"
		 "1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry"
		 "nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_"
		 "0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj"
		 "-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj"
		 "T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ\","
	 "\"p\":\"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68"
		 "ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP"
		 "krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM\","
	 "\"q\":\"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y"
		 "BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN"
		 "-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0\","
	 "\"dp\":\"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv"
		 "ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra"
		 "Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs\","
	 "\"dq\":\"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff"
		 "7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_"
		 "odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU\","
	 "\"qi\":\"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC"
		 "tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ"
		 "B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo\""
	"}",

*ex_a2_compact = (uint8_t *)
	"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
	"."
	"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm"
	"1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc"
	"HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF"
	"NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8"
	"rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv"
	"-B3oWh2TbqmScqXMR4gp_A"
	"."
	"AxY8DCtDaGlsbGljb3RoZQ"
	"."
	"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY"
	"."
	"9hH0vgRfYgPnAHOd8stkvw"
;

static int
test_jwe_a2(struct lws_context *context)
{
	struct lws_jose jose;
	struct lws_jws jws;
	struct lws_jwk jwk;
	char buf[2048];
	int n, ret = -1;

	lws_jose_init(&jose);
	memset(&jws, 0, sizeof(jws));
	jws.context = context;
	jws.jwk = &jwk;

	if (lws_jwk_import(&jwk, NULL, NULL, (char *)lws_jwe_ex_a2_jwk_json,
			   strlen((char *)lws_jwe_ex_a2_jwk_json)) < 0) {
		lwsl_notice("%s: Failed to decode JWK test key\n", __func__);
		goto bail;
	}

	/* converts a compact serialization to jws b64 + decoded maps */
	if (lws_jws_compact_decode((const char *)ex_a2_compact,
				   strlen((char *)ex_a2_compact),
				   &jws.map, &jws.map_b64,
				   (char *)buf, sizeof(buf)) != 5) {
		lwsl_err("%s: lws_jws_compact_decode failed\n", __func__);
		goto bail;
	}

	n = lws_jwe_authenticate_and_decrypt(&jose, &jws);
	lws_jwk_destroy(&jwk);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_authenticate_and_decrypt failed\n",
			 __func__);
		goto bail;
	}

	/* allowing for trailing padding, confirm the plaintext */
	if (jws.map.len[LJWE_CTXT] < sizeof(ex_a2_ptext) ||
	    lws_timingsafe_bcmp(jws.map.buf[LJWE_CTXT], ex_a2_ptext,
			        sizeof(ex_a2_ptext))) {
		lwsl_err("%s: plaintext AES decrypt wrong\n", __func__);
		lwsl_hexdump_notice(ex_a2_ptext, sizeof(ex_a2_ptext));
		lwsl_hexdump_notice(jws.map.buf[LJWE_CTXT],
				    jws.map.len[LJWE_CTXT]);
		goto bail;
	}

	ret = 0;

bail:
	lws_jose_destroy(&jose);
	if (ret)
		lwsl_err("%s: selftest failed +++++++++++++++++++\n", __func__);
	else
		lwsl_notice("%s: selftest OK\n", __func__);

	return ret;
}

/* A.3.  Example JWE Using AES Key Wrap and AES_128_CBC_HMAC_SHA_256
 *
 * This example encrypts the plaintext "Live long and prosper." to the
 * recipient using AES Key Wrap for key encryption and
 * AES_128_CBC_HMAC_SHA_256 for content encryption.
 */

/* "Live long and prosper." */
static uint8_t

ex_a3_ptext[] = {
	76, 105, 118, 101, 32, 108, 111, 110,
	103, 32, 97, 110, 100, 32,  112, 114,
	111, 115, 112, 101, 114, 46
},

*ex_a3_compact = (uint8_t *)
	"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
	"."
	"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"
	"."
	"AxY8DCtDaGlsbGljb3RoZQ"
	"."
	"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY"
	"."
	"U0m_YmjN04DJvceFICbCVQ",

*ex_a3_key = (uint8_t *)
	"{\"kty\":\"oct\","
	   "\"k\":\"GawgguFyGrWKav7AX4VKUg\""
	"}"
;

static int
test_jwe_a3(struct lws_context *context)
{
	struct lws_jose jose;
	struct lws_jws jws;
	struct lws_jwk jwk;
	char buf[2048];
	int n, ret = -1;

	lws_jose_init(&jose);
	memset(&jws, 0, sizeof(jws));
	jws.context = context;
	jws.jwk = &jwk;

	if (lws_jwk_import(&jwk, NULL, NULL, (char *)ex_a3_key,
			   strlen((char *)ex_a3_key)) < 0) {
		lwsl_notice("%s: Failed to decode JWK test key\n", __func__);
		goto bail;
	}

	/* converts a compact serialization to jws b64 + decoded maps */
	if (lws_jws_compact_decode((const char *)ex_a3_compact,
				   strlen((char *)ex_a3_compact),
				   &jws.map, &jws.map_b64,
				   (char *)buf, sizeof(buf)) != 5) {
		lwsl_err("%s: lws_jws_compact_decode failed\n", __func__);
		goto bail;
	}

	n = lws_jwe_authenticate_and_decrypt(&jose, &jws);
	lws_jwk_destroy(&jwk);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_authenticate_and_decrypt failed\n",
			 __func__);
		goto bail;
	}

	/* allowing for trailing padding, confirm the plaintext */
	if (jws.map.len[LJWE_CTXT] < sizeof(ex_a3_ptext) ||
	    lws_timingsafe_bcmp(jws.map.buf[LJWE_CTXT], ex_a3_ptext,
			        sizeof(ex_a3_ptext))) {
		lwsl_err("%s: plaintext AES decrypt wrong\n", __func__);
		lwsl_hexdump_notice(ex_a3_ptext, sizeof(ex_a3_ptext));
		lwsl_hexdump_notice(jws.map.buf[LJWE_CTXT],
				    jws.map.len[LJWE_CTXT]);
		goto bail;
	}

	lwsl_notice("%s: selftest OK\n", __func__);

	ret = 0;

bail:
	lws_jose_destroy(&jose);
	if (ret)
		lwsl_err("%s: selftest failed +++++++++++++++++++\n", __func__);
	else
		lwsl_notice("%s: selftest OK\n", __func__);

	return ret;
}

/* JWA B.2.  Test Cases for AES_192_CBC_HMAC_SHA_384
 *
 * Unfortunately JWA just gives this test case as hex literals, not
 * inside a JWE.  So we have to prepare the inputs "by hand".
 */

static uint8_t

jwa_b2_ptext[] = {
	0x41, 0x20, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72,
	0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x20,
	0x6d, 0x75, 0x73, 0x74, 0x20, 0x6e, 0x6f, 0x74,
	0x20, 0x62, 0x65, 0x20, 0x72, 0x65, 0x71, 0x75,
	0x69, 0x72, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20,
	0x62, 0x65, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65,
	0x74, 0x2c, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x69,
	0x74, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x62,
	0x65, 0x20, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x74,
	0x6f, 0x20, 0x66, 0x61, 0x6c, 0x6c, 0x20, 0x69,
	0x6e, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20,
	0x68, 0x61, 0x6e, 0x64, 0x73, 0x20, 0x6f, 0x66,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x65, 0x6e, 0x65,
	0x6d, 0x79, 0x20, 0x77, 0x69, 0x74, 0x68, 0x6f,
	0x75, 0x74, 0x20, 0x69, 0x6e, 0x63, 0x6f, 0x6e,
	0x76, 0x65, 0x6e, 0x69, 0x65, 0x6e, 0x63, 0x65
},

jwa_b2_rawkey[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
},

jwa_b2_iv[] = {
	0x1a, 0xf3, 0x8c, 0x2d, 0xc2, 0xb9, 0x6f, 0xfd,
	0xd8, 0x66, 0x94, 0x09, 0x23, 0x41, 0xbc, 0x04
},

jwa_b2_e[] = {
	0xea, 0x65, 0xda, 0x6b, 0x59, 0xe6, 0x1e, 0xdb,
	0x41, 0x9b, 0xe6, 0x2d, 0x19, 0x71, 0x2a, 0xe5,
	0xd3, 0x03, 0xee, 0xb5, 0x00, 0x52, 0xd0, 0xdf,
	0xd6, 0x69, 0x7f, 0x77, 0x22, 0x4c, 0x8e, 0xdb,
	0x00, 0x0d, 0x27, 0x9b, 0xdc, 0x14, 0xc1, 0x07,
	0x26, 0x54, 0xbd, 0x30, 0x94, 0x42, 0x30, 0xc6,
	0x57, 0xbe, 0xd4, 0xca, 0x0c, 0x9f, 0x4a, 0x84,
	0x66, 0xf2, 0x2b, 0x22, 0x6d, 0x17, 0x46, 0x21,
	0x4b, 0xf8, 0xcf, 0xc2, 0x40, 0x0a, 0xdd, 0x9f,
	0x51, 0x26, 0xe4, 0x79, 0x66, 0x3f, 0xc9, 0x0b,
	0x3b, 0xed, 0x78, 0x7a, 0x2f, 0x0f, 0xfc, 0xbf,
	0x39, 0x04, 0xbe, 0x2a, 0x64, 0x1d, 0x5c, 0x21,
	0x05, 0xbf, 0xe5, 0x91, 0xba, 0xe2, 0x3b, 0x1d,
	0x74, 0x49, 0xe5, 0x32, 0xee, 0xf6, 0x0a, 0x9a,
	0xc8, 0xbb, 0x6c, 0x6b, 0x01, 0xd3, 0x5d, 0x49,
	0x78, 0x7b, 0xcd, 0x57, 0xef, 0x48, 0x49, 0x27,
	0xf2, 0x80, 0xad, 0xc9, 0x1a, 0xc0, 0xc4, 0xe7,
	0x9c, 0x7b, 0x11, 0xef, 0xc6, 0x00, 0x54, 0xe3
},

jwa_b2_a[] = { /* "The second principle of Auguste Kerckhoffs" */
	0x54, 0x68, 0x65, 0x20, 0x73, 0x65, 0x63, 0x6f,
	0x6e, 0x64, 0x20, 0x70, 0x72, 0x69, 0x6e, 0x63,
	0x69, 0x70, 0x6c, 0x65, 0x20, 0x6f, 0x66, 0x20,
	0x41, 0x75, 0x67, 0x75, 0x73, 0x74, 0x65, 0x20,
	0x4b, 0x65, 0x72, 0x63, 0x6b, 0x68, 0x6f, 0x66,
	0x66, 0x73
},

jwa_b2_tag[] = {
	0x84, 0x90, 0xac, 0x0e, 0x58, 0x94, 0x9b, 0xfe,
	0x51, 0x87, 0x5d, 0x73, 0x3f, 0x93, 0xac, 0x20,
	0x75, 0x16, 0x80, 0x39, 0xcc, 0xc7, 0x33, 0xd7

}
;

static int
test_jwa_b2(struct lws_context *context)
{
	struct lws_jose jose;
	struct lws_jws jws;
	struct lws_jwk jwk;
	int n, ret = -1;
	char buf[2048];

	lws_jose_init(&jose);
	memset(&jws, 0, sizeof(jws));
	jws.context = context;
	jws.jwk = &jwk;

	/*
	 * normally all this is interpreted from the JWE blob.  But we don't
	 * have JWE test vectors for AES_256_CBC_HMAC_SHA_512, just a standalone
	 * one.  So we have to create it all by hand.
	 *
	 * See test_jwe_a3 above for a more normal usage pattern.
	 */

	memset(&jwk, 0, sizeof(jwk));
	jwk.kty = LWS_GENCRYPTO_KTY_OCT;
	jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf = (uint8_t *)jwa_b2_rawkey;
	jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].len = sizeof(jwa_b2_rawkey);

	memcpy(buf, jwa_b2_e, sizeof(jwa_b2_e));

	jws.map.buf[LJWE_IV] = (char *)jwa_b2_iv;
	jws.map.len[LJWE_IV] = sizeof(jwa_b2_iv);

	jws.map.buf[LJWE_CTXT] = buf;
	jws.map.len[LJWE_CTXT] = sizeof(jwa_b2_e);

	jws.map.buf[LJWE_ATAG] = (char *)jwa_b2_tag;
	jws.map.len[LJWE_ATAG] = sizeof(jwa_b2_tag);

	/*
	 * Normally this comes from the JOSE header.  But this test vector
	 * doesn't have one... so...
	 */

	if (lws_gencrypto_jwe_alg_to_definition("A128KW", &jose.alg))
		goto bail;
	if (lws_gencrypto_jwe_enc_to_definition("A192CBC-HS384", &jose.enc_alg))
		goto bail;

	n = lws_jwe_a_cbc_hs(&jose, &jws, jwa_b2_rawkey, jwa_b2_a,
			     sizeof(jwa_b2_a));
	if (n < 0) {
		lwsl_err("%s: lws_jwe_a_cbc_hs failed\n", __func__);

		goto bail;
	}

	/* allowing for trailing padding, confirm the plaintext */
	if (jws.map.len[LJWE_CTXT] < sizeof(jwa_b2_ptext) ||
	    lws_timingsafe_bcmp(jws.map.buf[LJWE_CTXT],jwa_b2_ptext,
			        sizeof(jwa_b2_ptext))) {
		lwsl_err("%s: plaintext AES decrypt wrong\n", __func__);
		lwsl_hexdump_notice(jwa_b2_ptext, sizeof(jwa_b2_ptext));
		lwsl_hexdump_notice(jws.map.buf[LJWE_CTXT],
				    jws.map.len[LJWE_CTXT]);
		goto bail;
	}

	ret = 0;

bail:
	lws_jose_destroy(&jose);
	if (ret)
		lwsl_err("%s: selftest failed +++++++++++++++++++\n", __func__);
	else
		lwsl_notice("%s: selftest OK\n", __func__);

	return ret;
}



/* JWA B.3.  Test Cases for AES_256_CBC_HMAC_SHA_512
 *
 * Unfortunately JWA just gives this test case as hex literals, not
 * inside a JWE.  So we have to prepare the inputs "by hand".
 */

static uint8_t

jwa_b3_ptext[] = {
	0x41, 0x20, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72,
	0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x20,
	0x6d, 0x75, 0x73, 0x74, 0x20, 0x6e, 0x6f, 0x74,
	0x20, 0x62, 0x65, 0x20, 0x72, 0x65, 0x71, 0x75,
	0x69, 0x72, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20,
	0x62, 0x65, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65,
	0x74, 0x2c, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x69,
	0x74, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x62,
	0x65, 0x20, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x74,
	0x6f, 0x20, 0x66, 0x61, 0x6c, 0x6c, 0x20, 0x69,
	0x6e, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20,
	0x68, 0x61, 0x6e, 0x64, 0x73, 0x20, 0x6f, 0x66,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x65, 0x6e, 0x65,
	0x6d, 0x79, 0x20, 0x77, 0x69, 0x74, 0x68, 0x6f,
	0x75, 0x74, 0x20, 0x69, 0x6e, 0x63, 0x6f, 0x6e,
	0x76, 0x65, 0x6e, 0x69, 0x65, 0x6e, 0x63, 0x65
},


jwa_b3_rawkey[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
},

jwa_b3_iv[] = {
	0x1a, 0xf3, 0x8c, 0x2d, 0xc2, 0xb9, 0x6f, 0xfd,
	0xd8, 0x66, 0x94, 0x09, 0x23, 0x41, 0xbc, 0x04
},

jwa_b3_e[] = {
	0x4a, 0xff, 0xaa, 0xad, 0xb7, 0x8c, 0x31, 0xc5,
	0xda, 0x4b, 0x1b, 0x59, 0x0d, 0x10, 0xff, 0xbd,
	0x3d, 0xd8, 0xd5, 0xd3, 0x02, 0x42, 0x35, 0x26,
	0x91, 0x2d, 0xa0, 0x37, 0xec, 0xbc, 0xc7, 0xbd,
	0x82, 0x2c, 0x30, 0x1d, 0xd6, 0x7c, 0x37, 0x3b,
	0xcc, 0xb5, 0x84, 0xad, 0x3e, 0x92, 0x79, 0xc2,
	0xe6, 0xd1, 0x2a, 0x13, 0x74, 0xb7, 0x7f, 0x07,
	0x75, 0x53, 0xdf, 0x82, 0x94, 0x10, 0x44, 0x6b,
	0x36, 0xeb, 0xd9, 0x70, 0x66, 0x29, 0x6a, 0xe6,
	0x42, 0x7e, 0xa7, 0x5c, 0x2e, 0x08, 0x46, 0xa1,
	0x1a, 0x09, 0xcc, 0xf5, 0x37, 0x0d, 0xc8, 0x0b,
	0xfe, 0xcb, 0xad, 0x28, 0xc7, 0x3f, 0x09, 0xb3,
	0xa3, 0xb7, 0x5e, 0x66, 0x2a, 0x25, 0x94, 0x41,
	0x0a, 0xe4, 0x96, 0xb2, 0xe2, 0xe6, 0x60, 0x9e,
	0x31, 0xe6, 0xe0, 0x2c, 0xc8, 0x37, 0xf0, 0x53,
	0xd2, 0x1f, 0x37, 0xff, 0x4f, 0x51, 0x95, 0x0b,
	0xbe, 0x26, 0x38, 0xd0, 0x9d, 0xd7, 0xa4, 0x93,
	0x09, 0x30, 0x80, 0x6d, 0x07, 0x03, 0xb1, 0xf6,
},

jwa_b3_a[] = { /* "The second principle of Auguste Kerckhoffs" */
	0x54, 0x68, 0x65, 0x20, 0x73, 0x65, 0x63, 0x6f,
	0x6e, 0x64, 0x20, 0x70, 0x72, 0x69, 0x6e, 0x63,
	0x69, 0x70, 0x6c, 0x65, 0x20, 0x6f, 0x66, 0x20,
	0x41, 0x75, 0x67, 0x75, 0x73, 0x74, 0x65, 0x20,
	0x4b, 0x65, 0x72, 0x63, 0x6b, 0x68, 0x6f, 0x66,
	0x66, 0x73
},

jws_b3_tag[] = {
	0x4d, 0xd3, 0xb4, 0xc0, 0x88, 0xa7, 0xf4, 0x5c,
	0x21, 0x68, 0x39, 0x64, 0x5b, 0x20, 0x12, 0xbf,
	0x2e, 0x62, 0x69, 0xa8, 0xc5, 0x6a, 0x81, 0x6d,
	0xbc, 0x1b, 0x26, 0x77, 0x61, 0x95, 0x5b, 0xc5
}
;

static int
test_jwa_b3(struct lws_context *context)
{
	struct lws_jose jose;
	struct lws_jws jws;
	struct lws_jwk jwk;
	char buf[2048];
	int n;

	lws_jose_init(&jose);
	memset(&jws, 0, sizeof(jws));
	jws.context = context;
	jws.jwk = &jwk;

	/*
	 * normally all this is interpreted from the JWE blob.  But we don't
	 * have JWE test vectors for AES_256_CBC_HMAC_SHA_512, just a standalone
	 * one.  So we have to create it all by hand.
	 *
	 * See test_jwe_a3 above for a more normal usage pattern.
	 */

	memset(&jwk, 0, sizeof(jwk));
	jwk.kty = LWS_GENCRYPTO_KTY_OCT;
	jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf = (uint8_t *)jwa_b3_rawkey;
	jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].len = sizeof(jwa_b3_rawkey);

	memcpy(buf, jwa_b3_e, sizeof(jwa_b3_e));

	jws.map.buf[LJWE_IV] = (char *)jwa_b3_iv;
	jws.map.len[LJWE_IV] = sizeof(jwa_b3_iv);

	jws.map.buf[LJWE_CTXT] = buf;
	jws.map.len[LJWE_CTXT] = sizeof(jwa_b3_e);

	jws.map.buf[LJWE_ATAG] = (char *)jws_b3_tag;
	jws.map.len[LJWE_ATAG] = sizeof(jws_b3_tag);

	/*
	 * Normally this comes from the JOSE header.  But this test vector
	 * doesn't feature one...
	 */

	if (lws_gencrypto_jwe_alg_to_definition("A128KW", &jose.alg))
		goto bail;
	if (lws_gencrypto_jwe_enc_to_definition("A256CBC-HS512", &jose.enc_alg))
		goto bail;

	n = lws_jwe_a_cbc_hs(&jose, &jws, jwa_b3_rawkey, jwa_b3_a,
			     sizeof(jwa_b3_a));
	if (n < 0) {
		lwsl_err("%s: lws_jwe_a_cbc_hs failed\n", __func__);

		goto bail;
	}

	/* allowing for trailing padding, confirm the plaintext */
	if (jws.map.len[LJWE_CTXT] < sizeof(jwa_b3_ptext) ||
	    lws_timingsafe_bcmp(jws.map.buf[LJWE_CTXT],jwa_b3_ptext,
			        sizeof(jwa_b3_ptext))) {
		lwsl_err("%s: plaintext AES decrypt wrong\n", __func__);
		lwsl_hexdump_notice(jwa_b3_ptext, sizeof(jwa_b3_ptext));
		lwsl_hexdump_notice(jws.map.buf[LJWE_CTXT],
				    jws.map.len[LJWE_CTXT]);
		goto bail;
	}

	lwsl_notice("%s: selftest OK\n", __func__);

	return 0;

bail:
	lwsl_err("%s: selftest failed ++++++++++++++++++++\n", __func__);

	return -1;
}

/* JWA C.  Example ECDH-ES Key Agreement Computation
 *
 * This example uses ECDH-ES Key Agreement and the Concat KDF to derive
 * the CEK in the manner described in Section 4.6.  In this example, the
 * ECDH-ES Direct Key Agreement mode ("alg" value "ECDH-ES") is used to
 * produce an agreed-upon key for AES GCM with a 128-bit key ("enc"
 * value "A128GCM").
 *
 * In this example, a producer Alice is encrypting content to a consumer
 * Bob.  The producer (Alice) generates an ephemeral key for the key
 * agreement computation.
 */

static const char

*ex_jwa_c_jose =
	"{\"alg\":\"ECDH-ES\","
	 "\"enc\":\"A128GCM\","
	 "\"apu\":\"QWxpY2U\","	/* b64u("Alice") */
	 "\"apv\":\"Qm9i\","	/* b64u("Bob") */
	 "\"epk\":" /* public part of A's ephemeral key */
	 "{\"kty\":\"EC\","
	  "\"crv\":\"P-256\","
	  "\"x\":\"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0\","
	  "\"y\":\"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps\""
	 "}"
	"}"
;

static uint8_t
ex_jwa_c_z[] = {
	158,  86, 217,  29, 129, 113,  53, 211,
	114, 131,  66, 131, 191, 132,  38, 156,
	251,  49, 110, 163, 218, 128, 106,  72,
	246, 218, 167, 121, 140, 254, 144, 196
},
ex_jwa_c_derived_key[] = {
	 86, 170, 141, 234, 248,  35, 109,  32,
	 92,  34,  40, 205, 113, 167,  16,  26
};


static int
test_jwa_c(struct lws_context *context)
{
	uint8_t buf[2048], temp[256];
	struct lws_jose jose;
	struct lws_jws jws;
	int ret = -1;

	lws_jose_init(&jose);
	memset(&jws, 0, sizeof(jws));
	jws.context = context;

	/*
	 * again the JWA Appendix C test vectors are not in the form of a
	 * complete JWE, but just the JWE JOSE header, so we must fake up the
	 * pieces and perform just the (normally internal) key agreement step
	 * for this test.
	 *
	 * See test_jwe_a3 above for a more normal usage pattern.
	 */

	if (lws_jwe_parse_jose(&jose, ex_jwa_c_jose, strlen(ex_jwa_c_jose),
			       temp, sizeof(temp))) {
		lwsl_err("%s: JOSE parse failed\n", __func__);

		goto bail;
	}

	/*
	 * The ephemeral key has been parsed into a jwk "jose.jwk_ephemeral"
	 *
	 *  In this example, the ECDH-ES Direct Key Agreement mode ("alg" value
	 *  "ECDH-ES") is used to produce an agreed-upon key for AES GCM with a
	 *  128-bit key ("enc" value "A128GCM").
	 */

	if (lws_jwa_concat_kdf(&jose, &jws, 1, buf,
			       ex_jwa_c_z, sizeof(ex_jwa_c_z))) {
		lwsl_err("%s: JOSE parse failed\n", __func__);

		goto bail;
	}

	/* allowing for trailing padding, confirm the plaintext */
	if (lws_timingsafe_bcmp(buf, ex_jwa_c_derived_key,
			        sizeof(ex_jwa_c_derived_key))) {
		lwsl_err("%s: ECDH derived key wrong\n", __func__);
		lwsl_hexdump_notice(ex_jwa_c_derived_key,
				    sizeof(ex_jwa_c_derived_key));
		lwsl_hexdump_notice(buf, sizeof(ex_jwa_c_derived_key));
		goto bail;
	}

	ret = 0;

bail:
	lws_jose_destroy(&jose);
	if (ret)
		lwsl_err("%s: selftest failed +++++++++++++++++++\n", __func__);
	else
		lwsl_notice("%s: selftest OK\n", __func__);

	return ret;
}



#if 0
static char *complete =
    "{"
      "\"protected\":"
       "\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\","
      "\"unprotected\":"
       "{\"jku\":\"https://server.example.com/keys.jwks\"},"
      "\"recipients\":["
       "{\"header\":"
         "{\"alg\":\"RSA1_5\",\"kid\":\"2011-04-29\"},"
        "\"encrypted_key\":"
         "\"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-"
          "kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKx"
          "GHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3"
          "YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPh"
          "cCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPg"
          "wCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A\"},"
       "{\"header\":"
         "{\"alg\":\"A128KW\",\"kid\":\"7\"},"
        "\"encrypted_key\":"
         "\"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ\"}],"
      "\"iv\":"
       "\"AxY8DCtDaGlsbGljb3RoZQ\","
      "\"ciphertext\":"
       "\"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY\","
      "\"tag\":"
       "\"Mz-VPPyU4RlcuYv1IwIvzw\""
     "}\""
;


#endif

int
test_jwe(struct lws_context *context)
{
	int n = 0;

	n |= test_jwe_a2(context);
	n |= test_jwe_a3(context);
	n |= test_jwa_b2(context);
	n |= test_jwa_b3(context);
	n |= test_jwa_c(context);
//	n |= test_jwe_json_complete(context);

	return n;
}
