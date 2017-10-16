/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_pubkey__H_
#define _flea_pubkey__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/hash.h"
#include "flea/x509.h"
#include "flea/ec_gfp_dom_par.h"

#ifdef FLEA_HAVE_ASYM_ALGS

# ifdef __cplusplus
extern "C" {
# endif

# define FLEA_PK_ID_OFFS_PRIMITIVE 4

/**
 * Supported encryption and signature public key primitives.
 */
typedef enum
{
  flea_rsa_sign   = 0 << FLEA_PK_ID_OFFS_PRIMITIVE,
    flea_rsa_encr = 1 << FLEA_PK_ID_OFFS_PRIMITIVE,
    flea_ecdsa    = 2 << FLEA_PK_ID_OFFS_PRIMITIVE
} flea_pk_primitive_id_t;

/**
 * Supported public key encoding schemes.
 */
typedef enum { flea_emsa1 = 0, flea_pkcs1_v1_5 = 1, flea_oaep = 2 } flea_pk_encoding_id_t;

/**
 * Supported public key encryption and signature configurations.
 */
typedef enum
{
  flea_ecdsa_emsa1         = flea_ecdsa | flea_emsa1,
  flea_rsa_oaep_encr       = flea_rsa_encr | flea_oaep,
  flea_rsa_pkcs1_v1_5_encr = flea_rsa_encr | flea_pkcs1_v1_5,
  flea_rsa_pkcs1_v1_5_sign = flea_rsa_sign | flea_pkcs1_v1_5,
} flea_pk_scheme_id_t;

typedef enum { flea_ecc_key, flea_rsa_key } flea_pk_key_type_t;

# ifdef FLEA_HAVE_ECC

typedef struct
{
  flea_byte_vec_t           public_point_encoded__rcu8;
  flea_ec_gfp_dom_par_ref_t dp__t;
#  ifdef FLEA_USE_STACK_BUF
  flea_u8_t                 dp_mem__bu8[FLEA_ECC_MAX_DP_CONCAT_BYTE_SIZE];
  flea_u8_t                 pub_point__mem__bu8[FLEA_ECC_MAX_ENCODED_POINT_LEN];
#  else
  flea_u8_t*                dp_mem__bu8;
  flea_u8_t*                pub_point__mem__bu8;
#  endif
} flea_ec_pubkey_val_t;
# endif /* #ifdef FLEA_HAVE_ECC */

# ifdef FLEA_HAVE_RSA

typedef struct
{
  flea_ref_cu8_t mod__rcu8;
  flea_ref_cu8_t pub_exp__rcu8;
#  ifdef FLEA_USE_STACK_BUF
  flea_u8_t      mod_mem__bu8[FLEA_RSA_MAX_MOD_BYTE_LEN];
  flea_u8_t      exp_mem__bu8[FLEA_RSA_MAX_PUB_EXP_BYTE_LEN];
#  else
  flea_u8_t*     mod_mem__bu8;
  flea_u8_t*     exp_mem__bu8;
#  endif
} flea_rsa_pubkey_val_t;

# endif /* FLEA_HAVE_RSA */


typedef union
{
# ifdef FLEA_HAVE_RSA
  flea_rsa_pubkey_val_t rsa_public_val__t;
# endif
# ifdef FLEA_HAVE_ECC
  flea_ec_pubkey_val_t  ec_public_val__t;
# endif
} flea_public_key_val_with_params_u;

typedef struct
{
  flea_pk_key_type_t                key_type__t;
  flea_u16_t                        key_bit_size__u16;
  flea_u16_t                        primitive_input_size__u16;
  flea_public_key_val_with_params_u pubkey_with_params__u;
} flea_public_key_t;


flea_ref_cu8_t flea_public_key__get_encoded_public_component(flea_public_key_t* pk);

# define flea_public_key_t__INIT(__p) memset((__p), 0, sizeof(*(__p)))
# define flea_public_key_t__INIT_VALUE {.key_bit_size__u16 = 0}

void flea_public_key_t__dtor(flea_public_key_t* key__pt);


/**
 * create a public key from a the bit string TLV structure found e.g. in an
 * X.509 certificate.
 */
flea_err_t THR_flea_public_key_t__ctor_asn1(
  flea_public_key_t*     key,
  const flea_byte_vec_t* key_as_bit_string_tlv,
  const flea_byte_vec_t* encoded_params,
  const flea_byte_vec_t* alg_oid
);

/**
 * Create a public key from a certificate.
 *
 * @param key the key to construct.
 * @param cert_ref the certificate structure of the certificate which contains
 * the encoded public key
 */
flea_err_t THR_flea_public_key_t__ctor_cert(
  flea_public_key_t*          key,
  const flea_x509_cert_ref_t* cert_ref
);

/**
 * Create an RSA public key from the modulus and the public exponent.
 *
 * @param key the key to be constructed
 * @param mod the big endian encoded modulus
 * @param pub_exp the big endian encoded public exponent
 */
flea_err_t THR_flea_public_key_t__ctor_rsa(
  flea_public_key_t*    key,
  const flea_ref_cu8_t* mod,
  const flea_ref_cu8_t* pub_exp
);

/**
 * Create an ECC public key from the public point and the domain parameters.
 *
 * @param key the public key to construct
 * @param public_key_value the encoded public point
 * @param dp the ECC domain parameters to be used
 */
flea_err_t THR_flea_public_key_t__ctor_ecc(
  flea_public_key_t*               key,
  const flea_byte_vec_t*           public_key_value,
  const flea_ec_gfp_dom_par_ref_t* dp
);


/**
 * Verify a signature using a public key. In case of ECDSA, an ASN.1/DER encoded
 * signature is expected.
 *
 * @param key the public key to be used for the verification
 * @param pk_scheme_id the signature scheme to be used for the verification
 * @param hash_id the id of the hash algorithm used for the signature generation
 * @param message the message which was signed
 * @param signature the signature to verify
 *
 *
 */
flea_err_t THR_flea_public_key_t__verify_signature(
  const flea_public_key_t* key,
  flea_pk_scheme_id_t      pk_scheme_id,
  flea_hash_id_t           hash_id,
  const flea_byte_vec_t*   message,
  const flea_byte_vec_t*   signature
);


/**
 * Verify a signature using a public key. In case of ECDSA, a raw concatenation
 * of r and s encoded in the base point order length is expected as the
 * signature.
 *
 * @param key the public key to be used for the verification
 * @param pk_scheme_id the signature scheme to be used for the verification
 * @param hash_id the id of the hash algorithm used for the signature generation
 * @param message the message which was signed
 * @param signature the signature to verify
 *
 */
// TODO: WITHOUT BYTEVECS
flea_err_t THR_flea_public_key_t__verify_signature_plain_format(
  const flea_public_key_t* key,
  flea_pk_scheme_id_t      pk_scheme_id,
  flea_hash_id_t           hash_id,
  const flea_byte_vec_t*   message,
  const flea_byte_vec_t*   signature
);


/**
 * The same operation as THR_flea_public_key_t__verify_signature_plain_format(), except that the
 * digest (i.e. hash value) is directly provided by the caller instead of being
 * computed by the function.
 *
 * @param digest the digest to verify
 * @param digest_len length of digest
 * @param hash_id id of the hash algorithm that was used to compute digest
 * @param id the ID of the signature scheme to use
 * @param pubkey pointer to the public key to be used in the operation
 * @param signature pointer to the memory area for the signature to be verified.
 * @param signature_len length of signature
 */
flea_err_t THR_flea_public_key_t__verify_digest_plain_format(
  const flea_public_key_t* pubkey,
  flea_pk_scheme_id_t      id,
  flea_hash_id_t           hash_id,
  const flea_u8_t*         digest,
  flea_al_u8_t             digest_len,
  const flea_u8_t*         signature,
  flea_al_u16_t            signature_len
);

/**
 * Verify a signature using a specific X.509 signature algorithm ID.
 */
flea_err_t THR_flea_public_key_t__verify_signature_use_sigalg_id(
  const flea_public_key_t*     public_key,
  const flea_x509_algid_ref_t* sigalg_id,
  const flea_byte_vec_t*       tbs_data,
  const flea_byte_vec_t*       signature
);

/**
 * Encrypt a message using a public key.
 *
 * @param key the public key to be used for the verification
 * @param pk_scheme_id the encryption scheme to be used for the encryption
 * @param hash_id the id of the hash algorithm used for the signature generation
 * @param message the message to be encrypted
 * @param message_len the length of the message to be encrypted
 * @param result receives the encrypted message after successful completion
 */
flea_err_t THR_flea_public_key_t__encrypt_message(
  const flea_public_key_t* key,
  flea_pk_scheme_id_t      pk_scheme_id,
  flea_hash_id_t           hash_id,
  const flea_u8_t*         message,
  flea_al_u16_t            message_len,
  flea_byte_vec_t*         result
);


# ifdef __cplusplus
}
# endif

#endif /* #ifdef FLEA_HAVE_ASYM_ALGS */

#endif /* h-guard */
