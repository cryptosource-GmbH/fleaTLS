/* fleaTLS cryptographic library
Copyright (C) 2015-2019 cryptosource GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

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
#define FLEA_ECDSA_MAX_CONCAT_SIG_LEN ((FLEA_ECC_MAX_ORDER_BYTE_SIZE * 2))

/**
 * Maximal length of the ECDSA signature in ASN.1/DER format.
 */
#define FLEA_ECDSA_MAX_ASN1_SIG_LEN (__FLEA_COMPUTED_ECDSA_MAX_ASN1_SIG_LEN)

/**
 * Maximal byte length of a plain signature. In case of RSA, this means the
 * signature represantative, in case of ECDSA, it means r and s concatenated,
 * each having the same length as the base point order.
 */
#define FLEA_ASYM_MAX_PLAIN_SIG_LEN __FLEA_COMPUTED_MAX_ASYM_PLAIN_SIG_LEN

/**
 * Maximal byte length of an encoded signature. With respect to RSA, this is the same
 * as FLEA_ASYM_MAX_PLAIN_SIG_LEN, for ECDSA, this respects the ASN.1/DER
 * encoded format of the signature, and is thus reserving more space than FLEA_ASYM_MAX_PLAIN_SIG_LEN.
 */
#define FLEA_ASYM_MAX_ENCODED_SIG_LEN __FLEA_COMPUTED_MAX_ASYM_ENCODED_SIG_LEN

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
 * Maximal output length of a raw public key scheme function
 */
#define FLEA_PK_MAX_PRIMITIVE_INPUT_LEN __FLEA_COMPUTED_ASYM_PRIMITIVE_INPUT_LEN

/**
 * Maximal input length of a raw public key scheme function
 */
#define FLEA_PK_MAX_PRIMITIVE_OUTPUT_LEN __FLEA_COMPUTED_ASYM_MAX_PRIMITIVE_OUTPUT_LEN

#endif /* h-guard */
