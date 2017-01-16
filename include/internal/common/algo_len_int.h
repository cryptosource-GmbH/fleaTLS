/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_algo_len_int__H_
#define _flea_algo_len_int__H_

#include "internal/common/default.h"
#include "flea/calc_util.h"
#include "internal/common/ecc_int.h"

/****** begin hash length ******/

/**
 * minimal hash output length (for MD5 and AES-based)
 */
#define __FLEA_MIN_HASH_OUT_LEN 16

/**
 * minimal hash block length (AES-based)
 */
#define __FLEA_MIN_HASH_BLOCK_LEN 16

/**
 * minimal hash cnt-block length for cipher-based, MD5, SHA1 and SHA224,-256
 */
#define __FLEA_MIN_HASH_CNT_LEN 8

/**
 * minimal hash state length for cipher-based and MD5
 */
#define __FLEA_MIN_HASH_STATE_LEN 16

#ifdef FLEA_HAVE_MD5
#define __FLEA_MD5_HASH_BLOCK_LEN_SWITCHED 64
#else
#define __FLEA_MD5_HASH_BLOCK_LEN_SWITCHED 0
#endif

#ifdef FLEA_HAVE_SHA1
#define __FLEA_SHA1_HASH_BLOCK_LEN_SWITCHED 64
#define __FLEA_SHA1_OUT_LEN_SWITCHED 20
#define __FLEA_SHA1_HASH_STATE_LEN_SWITCHED 20
#else
#define __FLEA_SHA1_HASH_BLOCK_LEN_SWITCHED 0
#define __FLEA_SHA1_OUT_LEN_SWITCHED 0
#define __FLEA_SHA1_HASH_STATE_LEN_SWITCHED 0
#endif

#ifdef FLEA_HAVE_SHA224_256
#define __FLEA_SHA224_256_HASH_BLOCK_LEN_SWITCHED 64
#define __FLEA_SHA224_256_OUT_LEN_SWITCHED 32
#define __FLEA_SHA224_256_HASH_STATE_LEN_SWITCHED 32
#else
#define __FLEA_SHA224_256_HASH_BLOCK_LEN_SWITCHED 0
#define __FLEA_SHA224_256_OUT_LEN_SWITCHED 0
#define __FLEA_SHA224_256_HASH_STATE_LEN_SWITCHED 0
#endif

#ifdef FLEA_HAVE_SHA384_512
#define __FLEA_SHA384_512_HASH_BLOCK_LEN_SWITCHED 128
#define __FLEA_SHA384_512_OUT_LEN_SWITCHED 64
#define __FLEA_SHA384_512_HASH_CNT_LEN_SWITCHED 16
#define __FLEA_SHA384_512_HASH_STATE_LEN_SWITCHED 64
#else
#define __FLEA_SHA384_512_HASH_BLOCK_LEN_SWITCHED 0
#define __FLEA_SHA384_512_OUT_LEN_SWITCHED 0
#define __FLEA_SHA384_512_HASH_CNT_LEN_SWITCHED 0
#define __FLEA_SHA384_512_HASH_STATE_LEN_SWITCHED 0
#endif

#define __FLEA_COMPUTED_MAX_HASH_BLOCK_LEN FLEA_MAX5(__FLEA_MIN_HASH_BLOCK_LEN, __FLEA_MD5_HASH_BLOCK_LEN_SWITCHED, __FLEA_SHA1_HASH_BLOCK_LEN_SWITCHED, __FLEA_SHA224_256_HASH_BLOCK_LEN_SWITCHED, __FLEA_SHA384_512_HASH_BLOCK_LEN_SWITCHED)

#define __FLEA_COMPUTED_MAX_HASH_OUT_LEN FLEA_MAX4(__FLEA_MIN_HASH_OUT_LEN, __FLEA_SHA1_OUT_LEN_SWITCHED, __FLEA_SHA224_256_OUT_LEN_SWITCHED, __FLEA_SHA384_512_OUT_LEN_SWITCHED)

#define __FLEA_COMPUTED_MAX_HASH_CNT_LEN FLEA_MAX(__FLEA_MIN_HASH_CNT_LEN, __FLEA_SHA384_512_HASH_CNT_LEN_SWITCHED)

#define __FLEA_COMPUTED_MAX_HASH_STATE_LEN FLEA_MAX4(__FLEA_MIN_HASH_STATE_LEN, __FLEA_SHA1_HASH_STATE_LEN_SWITCHED, __FLEA_SHA224_256_HASH_STATE_LEN_SWITCHED, __FLEA_SHA384_512_HASH_STATE_LEN_SWITCHED)

/****** end hash lengths ******/


/****** begin block cipher lengths *******/

/**
 * AES always configured
 */
#define __FLEA_AES_U32_EXPANDED_KEY_LEN_SWITCHED 60

/**
 * AES always configured
 */
#define __FLEA_AES_MAX_PLAIN_KEY_LEN_SWITCHED (256 / 8)

#ifdef FLEA_HAVE_DES
#define __FLEA_DES_U32_EXPANDED_KEY_LEN_SWITCHED 32
#else
#define __FLEA_DES_U32_EXPANDED_KEY_LEN_SWITCHED
#endif

#ifdef FLEA_HAVE_DESX
#define __FLEA_DESX_U32_EXPANDED_KEY_LEN_SWITCHED (__FLEA_DES_U32_EXPANDED_KEY_LEN_SWITCHED + 16)
#define __FLEA_DESX_PLAIN_KEY_LEN_SWITCHED 24
#else
#define __FLEA_DESX_U32_EXPANDED_KEY_LEN_SWITCHED 0
#define __FLEA_DESX_PLAIN_KEY_LEN_SWITCHED 0
#endif

#ifdef FLEA_HAVE_TDES_2KEY
#define __FLEA_TDES_2KEY_U32_EXPANDED_KEY_LEN_SWITCHED (__FLEA_DES_U32_EXPANDED_KEY_LEN_SWITCHED * 2 )
#define __FLEA_TDES_2KEY_PLAIN_KEY_LEN_SWITCHED 16
#else
#define __FLEA_TDES_2KEY_U32_EXPANDED_KEY_LEN_SWITCHED 0
#define __FLEA_TDES_2KEY_PLAIN_KEY_LEN_SWITCHED 0
#endif

#ifdef FLEA_HAVE_TDES_3KEY
#define __FLEA_TDES_3KEY_U32_EXPANDED_KEY_LEN_SWITCHED (__FLEA_DES_U32_EXPANDED_KEY_LEN_SWITCHED * 3 )
#define __FLEA_TDES_3KEY_PLAIN_KEY_LEN_SWITCHED 16
#else
#define __FLEA_TDES_3KEY_U32_EXPANDED_KEY_LEN_SWITCHED 0
#define __FLEA_TDES_3KEY_PLAIN_KEY_LEN_SWITCHED 0
#endif

#define __FLEA_COMPUTED_BLOCK_CIPHER_MAX_EXPANDED_KEY_U32_SIZE FLEA_MAX5(__FLEA_AES_U32_EXPANDED_KEY_LEN_SWITCHED, __FLEA_DES_U32_EXPANDED_KEY_LEN_SWITCHED, __FLEA_TDES_2KEY_U32_EXPANDED_KEY_LEN_SWITCHED, __FLEA_TDES_3KEY_U32_EXPANDED_KEY_LEN_SWITCHED, __FLEA_DESX_U32_EXPANDED_KEY_LEN_SWITCHED)

#define __FLEA_COMPUTED_BLOCK_CIPHER_MAX_PLAIN_KEY_LEN FLEA_MAX4(__FLEA_AES_MAX_PLAIN_KEY_LEN_SWITCHED, __FLEA_DESX_PLAIN_KEY_LEN_SWITCHED, __FLEA_TDES_2KEY_PLAIN_KEY_LEN_SWITCHED, __FLEA_TDES_3KEY_PLAIN_KEY_LEN_SWITCHED )

/****** end block cipher lengths *******/

/****** begin MAC lengths *******/

#ifdef FLEA_HAVE_HMAC
#define __FLEA_COMPUTED_MAX_MAC_HMAC_KEY_SIZE_SWITCHED __FLEA_COMPUTED_MAX_HASH_BLOCK_LEN
#else
#define __FLEA_COMPUTED_MAX_MAC_HMAC_KEY_SIZE_SWITCHED 0
#endif

#ifdef FLEA_HAVE_CMAC
#define __FLEA_COMPUTED_MAX_MAC_CMAC_KEY_SIZE_SWITCHED __FLEA_COMPUTED_BLOCK_CIPHER_MAX_PLAIN_KEY_LEN
#else
#define __FLEA_COMPUTED_MAX_MAC_CMAC_KEY_SIZE_SWITCHED 0
#endif

#define __FLEA_COMPUTED_MAC_MAX_KEY_LEN FLEA_MAX(__FLEA_COMPUTED_MAX_MAC_CMAC_KEY_SIZE_SWITCHED,  __FLEA_COMPUTED_MAX_MAC_HMAC_KEY_SIZE_SWITCHED)

#ifdef FLEA_HAVE_HMAC
#define FLEA_MAC_MAX_OUTPUT_LENGTH __FLEA_COMPUTED_MAX_HASH_OUT_LEN
#else
#define FLEA_MAC_MAX_OUTPUT_LENGTH 16 /* AES block size */
#endif

/****** end MAC lengths *******/

/****** begin public key lengths ******/

#define FLEA_ECC_MAX_ENCODED_POINT_LEN (((((FLEA_ECC_MAX_MOD_BIT_SIZE)+7) / 8) * 2) + 1)

#define FLEA_ECC_DP_CONCAT_BYTE_SIZE_FROM_MOD_BIT_SIZE(mod_bit_size) ((((((mod_bit_size)+7) / 8) * 6) + 2*(32/8)+1))

#define FLEA_ECC_MAX_DP_CONCAT_BYTE_SIZE FLEA_ECC_DP_CONCAT_BYTE_SIZE_FROM_MOD_BIT_SIZE(FLEA_ECC_MAX_MOD_BIT_SIZE)

#define FLEA_RSA_MAX_MOD_BYTE_LEN (((FLEA_RSA_MAX_KEY_BIT_SIZE)+7) / 8)

#define FLEA_RSA_MAX_PUB_EXP_BYTE_LEN (((FLEA_RSA_MAX_PUB_EXP_BIT_LEN)+7) / 8)

#ifdef FLEA_HAVE_RSA
#define __FLEA_RSA_MAX_MOD_LEN_SWITCHED FLEA_RSA_MAX_MOD_BYTE_LEN
#else
#define __FLEA_RSA_MAX_MOD_LEN_SWITCHED  0
#endif

#ifdef FLEA_HAVE_ECC
#define __FLEA_ECC_MAX_ENCODED_POINT_LEN_SWITCHED FLEA_ECC_MAX_ENCODED_POINT_LEN
#else
#define __FLEA_ECC_MAX_ENCODED_POINT_LEN_SWITCHED 0
#endif

#define __FLEA_COMPUTED_MAX_INTERNAL_FORMAT_PUBKEY_LEN FLEA_MAX(__FLEA_ECC_MAX_ENCODED_POINT_LEN_SWITCHED, __FLEA_RSA_MAX_MOD_LEN_SWITCHED)

/* refers to keys in internal format */
#ifdef FLEA_HAVE_ECC
#define __FLEA_ECC_MAX_INTERNAL_FORMAT_PRIVKEY_LEN_SWITCHED ((FLEA_ECC_MAX_ORDER_BIT_SIZE + 7) / 8)
#else
#define __FLEA_ECC_MAX_INTERNAL_FORMAT_PRIVKEY_LEN_SWITCHED 0
#endif

#ifdef FLEA_HAVE_RSA
#define __FLEA_RSA_CRT_KEY_INTERNAL_FORMAT_MAX_LEN_SWITCHED FLEA_RSA_CRT_KEY_INTERNAL_FORMAT_MAX_BYTE_SIZE
#else
#define __FLEA_RSA_CRT_KEY_INTERNAL_FORMAT_MAX_LEN_SWITCHED 0
#endif

#define __FLEA_COMPUTED_PK_MAX_ASYM_PRIVKEY_LEN FLEA_MAX(__FLEA_ECC_MAX_INTERNAL_FORMAT_PRIVKEY_LEN_SWITCHED, __FLEA_RSA_CRT_KEY_INTERNAL_FORMAT_MAX_LEN_SWITCHED)

#define __FLEA_RSA_MAX_SIG_LEN_SWITCHED __FLEA_RSA_MAX_MOD_LEN_SWITCHED

#ifdef FLEA_HAVE_ECDSA
#define __FLEA_ECDSA_MAX_SIG_LEN_SWITCHED FLEA_ECDSA_MAX_SIG_LEN
#else
#define __FLEA_ECDSA_MAX_SIG_LEN_SWITCHED 0
#endif

#define __FLEA_COMPUTED_MAX_ASYM_SIG_LEN FLEA_MAX(__FLEA_ECDSA_MAX_SIG_LEN_SWITCHED, __FLEA_RSA_MAX_SIG_LEN_SWITCHED)


#define __FLEA_ECDSA_MAX_PRIMITIVE_INPUT_LEN_SWITCHED __FLEA_ECC_MAX_INTERNAL_FORMAT_PRIVKEY_LEN_SWITCHED
#define __FLEA_RSA_MAX_PRIMITIVE_INPUT_LEN_SWITCHED __FLEA_RSA_MAX_MOD_LEN_SWITCHED

#define __FLEA_COMPUTED_ASYM_PRIMITIVE_INPUT_LEN FLEA_MAX(__FLEA_ECDSA_MAX_PRIMITIVE_INPUT_LEN_SWITCHED, __FLEA_RSA_MAX_PRIMITIVE_INPUT_LEN_SWITCHED)

#define __FLEA_COMPUTED_ASYM_MAX_PRIMITIVE_OUTPUT_LEN __FLEA_RSA_MAX_MOD_LEN_SWITCHED

/****** end public key lengths ******/

#endif /* h-guard */
