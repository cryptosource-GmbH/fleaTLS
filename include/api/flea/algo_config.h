/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_algo_config__H_
#define _flea_algo_config__H_

#include "internal/common/algo_len_int.h"


/**
 * Maximal size of the
 */
#define FLEA_RSA_CRT_KEY_INTERNAL_FORMAT_MAX_BYTE_SIZE (FLEA_RSA_CRT_KEY_COMPONENT_MAX_BYTE_SIZE * 5)

/**
 * Maximal length of the ECDSA signature in simple concatenation format
 */
#define FLEA_ECDSA_MAX_SIG_LEN ((FLEA_ECC_MAX_MOD_BYTE_SIZE * 2))

/**
 * the maximal output length in bytes of the supported hash algorithms.
 */
#define FLEA_MAX_HASH_OUT_LEN __FLEA_COMPUTED_MAX_HASH_OUT_LEN

/**
 * Maximal size of an encoded public key.
 */
#define FLEA_PK_MAX_INTERNAL_FORMAT_PUBKEY_LEN __FLEA_COMPUTED_MAX_INTERNAL_FORMAT_PUBKEY_LEN

/**
 * Maximal length of a private key of a public key scheme
 */
#define FLEA_PK_MAX_PRIVKEY_LEN __FLEA_COMPUTED_PK_MAX_ASYM_PRIVKEY_LEN
/**
 * Maximal length of a signature of a public key scheme
 */
#define FLEA_PK_MAX_SIGNATURE_LEN __FLEA_COMPUTED_MAX_ASYM_SIG_LEN
/**
 * Maximal output length of a raw public key scheme function
 */
#define FLEA_PK_MAX_PRIMITIVE_INPUT_LEN __FLEA_COMPUTED_ASYM_PRIMITIVE_INPUT_LEN
/**
 * Maximal input length of a raw public key scheme function
 */
#define FLEA_PK_MAX_PRIMITIVE_OUTPUT_LEN __FLEA_COMPUTED_ASYM_MAX_PRIMITIVE_OUTPUT_LEN

#endif /* h-guard */
