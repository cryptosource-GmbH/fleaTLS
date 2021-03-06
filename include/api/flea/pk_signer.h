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

#ifndef _flea_pk_api__H_
#define _flea_pk_api__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/hash.h"
#include "internal/common/pk_api_int.h"
#include "flea/ec_dom_par.h"
#include "flea/pubkey.h"
#include "flea/privkey.h"


#ifdef FLEA_HAVE_ASYM_ALGS

# ifdef __cplusplus
extern "C" {
# endif


/**
 * Signature generation or verification with public key signer object.
 */
typedef enum { flea_sign, flea_verify } flea_pk_signer_direction_e;

struct struct_flea_pk_config_t;

typedef struct struct_flea_pk_config_t flea_pk_config_t;

/**
 * Public key signer type. Used to perform signature generation and verification. After its creation, it can be updated with signature data, and then be used to either create a signature or verify an existing signature.
 */
typedef struct
{
  flea_hash_ctx_t hash_ctx;
  flea_hash_id_e  hash_id__t;
} flea_pk_signer_t;


# ifdef FLEA_HEAP_MODE
#  define flea_pk_signer_t__INIT(__p) do {flea_hash_ctx_t__INIT(&(__p)->hash_ctx);} while(0)
# else
#  define flea_pk_signer_t__INIT(__p) do {flea_hash_ctx_t__INIT(&(__p)->hash_ctx);} while(0)
# endif


/**
 * Construct a public key signer object. Can be used signature generation or
 * verification.
 *
 * @param signer the signer object to create
 * @param hash_id the ID of the hash algorithm to use in the public key scheme
 * to hash the message
 *
 * @return an error code
 */
flea_err_e THR_flea_pk_signer_t__ctor(
  flea_pk_signer_t* signer,
  flea_hash_id_e    hash_id
);

/**
 * Destroy a public key signer object.
 *
 * @param signer the signer object to destroy
 */
void flea_pk_signer_t__dtor(flea_pk_signer_t* signer);

/**
 * Update a public key signer object with message data.
 *
 * @param signer the signer object to use
 * @param message pointer to the message data
 * @param message_len the length of message
 *
 * @return an error code
 */
flea_err_e THR_flea_pk_signer_t__update(
  flea_pk_signer_t* signer,
  const flea_u8_t*  message,
  flea_al_u16_t     message_len
);


/**
 * Finalize the signature verification.
 *
 * @param signer the signer object to use
 * @param id the ID of the signature scheme to use
 * @param pubkey pointer to the public key to be used in the operation
 * @param signature pointer to the memory area for the signature to be verified.
 * @param signature_len length of signature
 * @return flea error code FLEA_ERR_FINE indicates successful verification and FLEA_ERR_INV_SIGNATURE indicates a
 * failed signature verification
 *
 * @return an error code
 */
flea_err_e THR_flea_pk_signer_t__final_verify(
  flea_pk_signer_t*    signer,
  flea_pk_scheme_id_e  id,
  const flea_pubkey_t* pubkey,
  const flea_u8_t*     signature,
  flea_al_u16_t        signature_len
);


/**
 * Finalize the signature generation.
 *
 * @param signer the signer object to use
 * @param id the id of the signature scheme to be used
 * @param privkey the private key to be used for the signature operation
 * @param signature receives the generated signature after function completion
 *
 * @return an error code
 */
flea_err_e THR_flea_pk_signer_t__final_sign(
  flea_pk_signer_t*     signer,
  flea_pk_scheme_id_e   id,
  const flea_privkey_t* privkey,
  flea_byte_vec_t*      signature
);


# ifdef __cplusplus
}
# endif

#endif /* #ifdef FLEA_HAVE_ASYM_ALGS */

#endif /* h-guard */
