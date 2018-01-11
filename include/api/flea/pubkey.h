/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_pubkey__H_
#define _flea_pubkey__H_

#include "internal/common/default.h"
#include "internal/common/pubkey_int.h"
#include "flea/types.h"
#include "flea/hash.h"
#include "flea/x509.h"
#include "flea/ec_dom_par.h"

#ifdef FLEA_HAVE_ASYM_ALGS

# ifdef __cplusplus
extern "C" {
# endif


/**
 * Supported encryption and signature public key primitives.
 */
typedef enum
{
  /**
   * RSA signature primitive
   */
  flea_rsa_sign   = 0 << FLEA_PK_ID_OFFS_PRIMITIVE,

    /**
     * RSA encryption primitive
     */
    flea_rsa_encr = 1 << FLEA_PK_ID_OFFS_PRIMITIVE,

    /**
     * ECDSA signature primitive
     */
    flea_ecdsa    = 2 << FLEA_PK_ID_OFFS_PRIMITIVE
} flea_pk_primitive_id_e;

/**
 * Supported public key encoding schemes.
 */
typedef enum
{
  /**
   * EMSA1 signature encoding (for ECDSA)
   */
  flea_emsa1      = 0,

  /**
   * PKCS#1 v1.5 encoding method
   */
  flea_pkcs1_v1_5 = 1,

  /**
   * OAEP encoding method for RSA
   */
  flea_oaep       = 2
} flea_pk_encoding_id_e;

/**
 * Supported public key encryption and signature schemes resulting from the
 * combination of a primitive with an encoding method.
 */
typedef enum
{
  /**
   * ECDSA with EMSA1 encoding
   */
  flea_ecdsa_emsa1         = flea_ecdsa | flea_emsa1,

  /**
   * RSA-OAEP encryption scheme
   */
  flea_rsa_oaep_encr       = flea_rsa_encr | flea_oaep,

  /**
   * RSA PKCS#1 v1.5 encryption scheme
   */
  flea_rsa_pkcs1_v1_5_encr = flea_rsa_encr | flea_pkcs1_v1_5,

  /**
   * RSA PKCS#1 v1.5 signature scheme
   */
  flea_rsa_pkcs1_v1_5_sign = flea_rsa_sign | flea_pkcs1_v1_5,
} flea_pk_scheme_id_e;

/**
 * Key type enumeration.
 */
typedef enum
{
  /**
   * An elliptic curve key type
   */
  flea_ecc_key,

  /**
   * An RSA key type
   */
  flea_rsa_key
} flea_pk_key_type_e;

/**
 * Abstract public key type.
 */
typedef struct
{
  flea_pk_key_type_e                key_type__t;
  flea_u16_t                        key_bit_size__u16;
  flea_u16_t                        primitive_input_size__u16;
  flea_public_key_val_with_params_u pubkey_with_params__u;
} flea_public_key_t;


# define flea_public_key_t__INIT(__p) memset((__p), 0, sizeof(*(__p)))
# define flea_public_key_t__INIT_VALUE {.key_bit_size__u16 = 0}

/**
 * Destroy a public key object.
 *
 * @param [out] key the key to destroy
 */
void flea_public_key_t__dtor(flea_public_key_t* key);


/**
 * Encode a public key in plain format.
 *
 * An encoded ECC public key is the uncompressed public point
 * in the format 0x04 | P_x | P_y.
 *
 * An encoded RSA key is the big endian encoded modulus.
 *
 * Key Parameters are not encoded.
 *
 * @param [in] key the public key to be encoded.
 * @param [out] result the encoded public key as a reference to the public key
 * object.
 *
 * @return an error code
 */
void flea_public_key_t__get_encoded_plain_ref(
  const flea_public_key_t* key,
  flea_ref_cu8_t*          result
);

/**
 * Create a public key from a the bit string TLV structure found for example in an
 * X.509 certificate.
 *
 * @param key the public key object to create.
 * @param key_as_bit_string_tlv the ASN.1/DER encoded bit string representing
 * the public key including the ASN.1 tag and length field of the bit string.
 * @param encoded_params the ASN.1/DER encoded key parameters associated with
 * the public key.
 * @param alg_oid the ASN.1/DER encoded algorithm identifier associated with the
 * public key.
 *
 * @return an error code
 */
flea_err_e THR_flea_public_key_t__ctor_asn1(
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
 *
 * @return an error code
 */
flea_err_e THR_flea_public_key_t__ctor_cert(
  flea_public_key_t*          key,
  const flea_x509_cert_ref_t* cert_ref
);

/**
 * Create an RSA public key from the modulus and the public exponent.
 *
 * @param key the key to be constructed
 * @param mod the big endian encoded modulus
 * @param pub_exp the big endian encoded public exponent
 *
 * @return an error code
 */
flea_err_e THR_flea_public_key_t__ctor_rsa(
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
 *
 * @return an error code
 */
flea_err_e THR_flea_public_key_t__ctor_ecc(
  flea_public_key_t*           key,
  const flea_byte_vec_t*       public_key_value,
  const flea_ec_dom_par_ref_t* dp
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
 * @return an error code
 */
flea_err_e THR_flea_public_key_t__verify_signature(
  const flea_public_key_t* key,
  flea_pk_scheme_id_e      pk_scheme_id,
  flea_hash_id_e           hash_id,
  const flea_byte_vec_t*   message,
  const flea_byte_vec_t*   signature
);


/**
 * Verify a signature using a public key. In case of ECDSA, a raw concatenation
 * of r and s encoded in the base point order length is expected as the
 * signature. For RSA, this function behaves equally to THR_flea_public_key_t__verify_signature().
 *
 * @param key the public key to be used for the verification
 * @param pk_scheme_id the signature scheme to be used for the verification
 * @param hash_id the id of the hash algorithm used for the signature generation
 * @param message the message which was signed
 * @param signature the signature to verify
 *
 * @return an error code
 */
flea_err_e THR_flea_public_key_t__verify_signature_plain_format(
  const flea_public_key_t* key,
  flea_pk_scheme_id_e      pk_scheme_id,
  flea_hash_id_e           hash_id,
  const flea_byte_vec_t*   message,
  const flea_byte_vec_t*   signature
);


/**
 * The same operation as THR_flea_public_key_t__verify_signature_plain_format(), except that the
 * digest (i.e. hash value) is directly provided by the caller instead of being
 * computed by the function.
 *
 * @param pubkey pointer to the public key to be used in the operation
 * @param digest the digest to verify
 * @param digest_len length of digest
 * @param hash_id id of the hash algorithm that was used to compute digest
 * @param id the ID of the signature scheme to use
 * @param signature pointer to the memory area for the signature to be verified.
 * @param signature_len length of signature
 *
 * @return an error code
 */
flea_err_e THR_flea_public_key_t__verify_digest_plain_format(
  const flea_public_key_t* pubkey,
  flea_pk_scheme_id_e      id,
  flea_hash_id_e           hash_id,
  const flea_u8_t*         digest,
  flea_al_u8_t             digest_len,
  const flea_u8_t*         signature,
  flea_al_u16_t            signature_len
);

/**
 * Verify a signature using a specific X.509 signature algorithm ID.
 *
 * @param key the public key to be used for the verification
 * @param sigalg_id the signature algorithm OID to be used for the verification
 * @param message the message which was signed
 * @param signature the signature to verify
 * @param flags a combination of flags potentially affecting the signature verification
 *
 * @return an error code
 */
flea_err_e THR_flea_public_key_t__verify_signature_use_sigalg_id(
  const flea_public_key_t*     key,
  const flea_x509_algid_ref_t* sigalg_id,
  const flea_byte_vec_t*       message,
  const flea_byte_vec_t*       signature,
  flea_x509_validation_flags_e flags
);

/**
 * Encrypt a message using a public key.
 *
 * @param key the public key to be used for the encryption
 * @param pk_scheme_id the encryption scheme to be used for the encryption
 * @param hash_id the id of the hash algorithm used for the signature generation
 * @param message the message to be encrypted
 * @param message_len the length of the message to be encrypted
 * @param result receives the encrypted message after successful completion
 *
 * @return an error code
 */
flea_err_e THR_flea_public_key_t__encrypt_message(
  const flea_public_key_t* key,
  flea_pk_scheme_id_e      pk_scheme_id,
  flea_hash_id_e           hash_id,
  const flea_u8_t*         message,
  flea_al_u16_t            message_len,
  flea_byte_vec_t*         result
);

/**
 * Encode a public key in plain format.
 *
 * An encoded ECC public key is the uncompressed public point
 * in the format 0x04 | P_x | P_y.
 *
 * An encoded RSA key is the big endian encoded modulus.
 *
 * Key Parameters are not encoded.
 *
 * @param [in] key the public key to be encoded.
 * @param [out] result the encoded public key.
 *
 * @return an error code
 */
flea_err_e THR_flea_public_key__t__get_encoded_plain(
  const flea_public_key_t* key,
  flea_byte_vec_t*         result
);


# ifdef __cplusplus
}
# endif

#endif /* #ifdef FLEA_HAVE_ASYM_ALGS */

#endif /* h-guard */
