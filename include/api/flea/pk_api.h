/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_pk_api__H_
#define _flea_pk_api__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/hash.h"
#include "internal/common/pk_api_int.h"
#include "flea/ec_gfp_dom_par.h"
#include "flea/pubkey.h"
#include "flea/privkey.h"


#ifdef FLEA_HAVE_ASYM_ALGS

# ifdef __cplusplus
extern "C" {
# endif


typedef union
{
  flea_byte_vec_t           rsa_public_exp__ru8;

# ifdef FLEA_HAVE_ECC
  flea_ec_gfp_dom_par_ref_t ecc_dom_par__t;
# endif /* #ifdef FLEA_HAVE_ECC */
} flea_pub_key_param_u;

/**
 * Supported
 */
typedef enum { flea_sign, flea_verify } flea_pk_signer_direction_t;

struct struct_flea_pk_config_t;

typedef struct struct_flea_pk_config_t flea_pk_config_t;

/**
 * Public signer struct. Used to perform signature generation and verification.
 */
typedef struct
{
  flea_hash_ctx_t hash_ctx;
  flea_hash_id_t  hash_id__t;
} flea_pk_signer_t;


# define flea_pk_signer_t__INIT_VALUE {.hash_ctx = flea_hash_ctx_t__INIT_VALUE}

# ifdef FLEA_USE_HEAP_BUF
#  define flea_pk_signer_t__INIT(__p) do {flea_hash_ctx_t__INIT(&(__p)->hash_ctx);} while(0)
# else
/* needed for secret wiping in hash ctx*/
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
 * @return flea error code
 */
flea_err_t THR_flea_pk_signer_t__ctor(
  flea_pk_signer_t* signer,
  flea_hash_id_t    hash_id
);

/**
 * Destroy a public key signer object.
 *
 * @param signer the signer object to destroy
 */
void flea_pk_signer_t__dtor(flea_pk_signer_t* signer);

/**
 * Update a public key signer object with signature data.
 *
 * @param signer the signer object to use
 * @param message pointer to the message data
 * @param message_len the length of message
 *
 * @return flea error code
 */
flea_err_t THR_flea_pk_signer_t__update(
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
 */
flea_err_t THR_flea_pk_signer_t__final_verify(
  flea_pk_signer_t*        signer,
  flea_pk_scheme_id_t      id,
  const flea_public_key_t* pubkey,
  const flea_u8_t*         signature,
  flea_al_u16_t            signature_len
);


/**
 * Create a signature.
 *
 * @param message the message to sign
 * @param signature receives the created signature after function completion
 * @param privkey the private key to be used for the signature creation
 * @param pk_scheme_id ID of the signature scheme to be used
 * @param hash_id hash algorithm to be used for the digest computation
 *
 */
// TODO: WITHOUT BYTEVEC FOR MESSAGE
flea_err_t THR_flea_pk_api__sign(
  const flea_byte_vec_t*    message,
  flea_byte_vec_t*          signature,
  const flea_private_key_t* privkey,
  flea_pk_scheme_id_t       pk_scheme_id,
  flea_hash_id_t            hash_id
);

/**
 * Finalize the signature generation.
 *
 * @param signer the signer object to use
 * @param id the id of the signature scheme to be used
 * @param privkey the private key to be used for the signature operation
 * @param signature receives the generated signature after function completion
 */

flea_err_t THR_flea_pk_signer_t__final_sign(
  flea_pk_signer_t*         signer,
  flea_pk_scheme_id_t       id,
  const flea_private_key_t* privkey,
  flea_byte_vec_t*          signature
);

/**
 * The same operation as THR_flea_pk_signer_t__final_sign, except that the
 * digest (i.e. hash value) is directly provided by the caller instead of being
 * computed by the function.
 *
 * @param digest the digest to verify
 * @param digest_len length of digest
 * @param hash_id id of the hash algorithm that was used to compute digest
 * @param id the ID of the signature scheme to use
 * @param privkey the private key to be used for the signature operation
 * @param signature receives the generated signature after function completion
 */
flea_err_t THR_flea_pk_api__sign_digest(
  const flea_u8_t*          digest,
  flea_al_u8_t              digest_len,
  flea_hash_id_t            hash_id,
  flea_pk_scheme_id_t       id,
  const flea_private_key_t* privkey,
  flea_byte_vec_t*          signature
);

/**
 *  Encrypt a message using a public key scheme.
 * TODO:UPDATE
 *  @param id ID of the encryption scheme to use
 *  @param hash_id ID of the hash scheme to use (if applicable)
 *  @param message the message to be encrypted
 *  @param message_len the length of message
 *  @param result buffer to store the ciphertext
 *  number of bytes written to result
 *  @param key the public key to use for the encryption
 *  @param key_len the length of key
 *  @param params public parameters associated with the key
 *  @param params_len the length of params
 */
// TODO: REPLACE THIS WITH THR_flea_public_key_t__encrypt_message
flea_err_t THR_flea_pk_api__encrypt_message(
  flea_pk_scheme_id_t id,
  flea_hash_id_t      hash_id,
  const flea_u8_t*    message,
  flea_al_u16_t       message_len,
  flea_byte_vec_t*    result,
  const flea_u8_t*    key,
  flea_al_u16_t       key_len,
  const flea_u8_t*    params,
  flea_al_u16_t       params_len
);

/**
 *  Decrypt a message using a public key scheme.
 *
 *  @param id ID of the encryption scheme to use
 *  @param hash_id ID of the hash scheme to use (if applicable)
 *  @param ciphertext the ciphertext to be encrypted
 *  @param ciphertext_len the length of ciphertext
 *  @param result receives the result after successful operation
 *  @param key the private key to use for the decryption
 *  @param enforced_pkcs1_v1_5_decryption_result_len This value is only interpreted in case of PKCS#1 v1.5 decryption.
 *                                                   For normal PKCS#1 v1.5 decoding,
 *                                                   this must be set to zero. Set this
 *                                                   value to the expected message
 *                                                   length to achieve timing neutral
 *                                                   fake result generation in case of
 *                                                   a padding error (defense against
 *                                                   Bleichenbacher's attack).
 */
flea_err_t THR_flea_pk_api__decrypt_message(
  flea_pk_scheme_id_t       id,
  flea_hash_id_t            hash_id,
  const flea_u8_t*          ciphertext,
  flea_al_u16_t             ciphertext_len,
  flea_byte_vec_t*          result,
  const flea_private_key_t* privkey,
  flea_al_u16_t             enforced_decryption_result_len
);


# ifdef __cplusplus
}
# endif

#endif /* #ifdef FLEA_HAVE_ASYM_ALGS */

#endif /* h-guard */
