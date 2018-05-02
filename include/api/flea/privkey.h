/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_privkey__H_
#define _flea_privkey__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/hash.h"
#include "flea/x509.h"
#include "flea/ec_dom_par.h"
#include "flea/pubkey.h"
#include "internal/common/privkey_val.h"

#ifdef FLEA_HAVE_ASYM_ALGS

# ifdef __cplusplus
extern "C" {
# endif

/**
 * Abstract private key type.
 */
typedef struct
{
  flea_pk_key_type_e key_type__t;
  flea_u16_t         key_bit_size__u16;
  flea_u16_t         max_primitive_input_len__u16;
  union
  {
# ifdef FLEA_HAVE_RSA
    flea_rsa_privkey_val_t rsa_priv_key_val__t;
# endif
# ifdef FLEA_HAVE_ECC
    flea_ec_privkey_val_t  ec_priv_key_val__t;
# endif
  } privkey_with_params__u;
} flea_privkey_t;


/**
 * Initialize a private key object.
 *
 * @param [out] key pointer to the flea_privkey_t object to initialize
 *
 */
# define flea_privkey_t__INIT(key) memset(key, 0, sizeof(*(key)))

/**
 * Destroy a private key object.
 *
 * @param [out] privkey private key object to destroy
 *
 */
void flea_privkey_t__dtor(flea_privkey_t* privkey);

# ifdef FLEA_HAVE_RSA

/**
 * Create an RSA private key fromt the flea RSA private key internal format.
 *
 * @param key the private key to create
 * @param priv_key_enc_internal_format The private RSA-CRT in the fleaTLS
 * internal format
 * @param key_bit_size bit size of the public modulus of the key
 *
 * @return an error code
 */
flea_err_e THR_flea_privkey_t__ctor_rsa_internal_format(
  flea_privkey_t*       key,
  const flea_ref_cu8_t* priv_key_enc_internal_format,
  flea_al_u16_t         key_bit_size
);

/**
 * Create an RSA key from the CRT key components. All supplied numbers are big endian
 * encoded. All array lengths are byte lengths.
 *
 * @param key the key to create
 * @param key_bit_size the bit size of the RSA modulus
 * @param p the prime p
 * @param p_len the length of p
 * @param q the prime q
 * @param q_len the length of q
 * @param dp d mod (p-1)
 * @param dp_len the length of dp
 * @param dq d mod (q-1)
 * @param dq_len the length of dq
 * @param c q^{-1} mod p
 * @param c_len the length of c
 *
 * @return an error code
 */
flea_err_e THR_flea_privkey_t__ctor_rsa_components(
  flea_privkey_t*  key,
  flea_al_u16_t    key_bit_size,
  const flea_u8_t* p,
  flea_al_u16_t    p_len,
  const flea_u8_t* q,
  flea_al_u16_t    q_len,
  const flea_u8_t* dp,
  flea_al_u16_t    dp_len,
  const flea_u8_t* dq,
  flea_al_u16_t    dq_len,
  const flea_u8_t* c,
  flea_al_u16_t    c_len
);
# endif // ifdef FLEA_HAVE_RSA

# ifdef FLEA_HAVE_ECC

/**
 * Create an ECC public key from the compontents.
 *
 * @param key the private key to create
 * @param scalar the big endian encoded secret scalar s representing the private
 * key.
 * @param dp_ref a domain parameters reference object specifying the domain
 * parameters for the key. The private key receives an internal copy of the
 * domain parameters, so the data pointed to by dp_ref need not to be preserved
 * during the lifetime of the private key.
 *
 * @return an error code
 *
 */
flea_err_e THR_flea_privkey_t__ctor_ecc(
  flea_privkey_t*              key,
  const flea_byte_vec_t*       scalar,
  const flea_ec_dom_par_ref_t* dp_ref
);
# endif // ifdef FLEA_HAVE_ECC

/**
 * Create a signature using a private key.
 *
 * @param privkey the private key to be used for the signature creation
 * @param pk_scheme_id ID of the signature scheme to be used
 * @param hash_id hash algorithm to be used for the digest computation
 * @param message the message to sign
 * @param signature receives the created signature after function completion
 *
 * @return an error code
 *
 */
flea_err_e THR_flea_privkey_t__sign(
  const flea_privkey_t*  privkey,
  flea_pk_scheme_id_e    pk_scheme_id,
  flea_hash_id_e         hash_id,
  const flea_byte_vec_t* message,
  flea_byte_vec_t*       signature
);

/**
 * The same operation as THR_flea_privkey_t__sign_plain_format, except that the
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
flea_err_e THR_flea_privkey_t__sign_digest(
  const flea_privkey_t* privkey,
  flea_pk_scheme_id_e   id,
  flea_hash_id_e        hash_id,
  const flea_u8_t*      digest,
  flea_al_u8_t          digest_len,
  flea_byte_vec_t*      signature
);

/**
 *  Decrypt a message using a public key scheme.
 *
 *  @param [in] privkey the private key to use for the decryption
 *  @param [in] id ID of the encryption scheme to use
 *  @param [in] hash_id ID of the hash scheme to use (if applicable)
 *  @param [in] ciphertext the ciphertext to be encrypted
 *  @param [in] ciphertext_len the length of ciphertext
 *  @param [out] result receives the result after successful operation
 *
 *  @return an error code
 */
flea_err_e THR_flea_privkey_t__decrypt_message(
  const flea_privkey_t* privkey,
  flea_pk_scheme_id_e   id,
  flea_hash_id_e        hash_id,
  const flea_u8_t*      ciphertext,
  flea_al_u16_t         ciphertext_len,
  flea_byte_vec_t*      result
);

/**
 *  Decrypt a message using a public key scheme. Provides enhanced
 *  features to achieve secure application of the RSA-PKCS#1-v1.5 decryption
 *  with respect to Bleichenbacher's Attack by removing timing and error side-channels. For other public key schemes, it behaves equally to THR_flea_privkey_t__decrypt_message.
 *
 *  @param [in] privkey the private key to use for the decryption
 *  @param [in] id ID of the encryption scheme to use
 *  @param [in] hash_id ID of the hash scheme to use (if applicable)
 *  @param [in] ciphertext the ciphertext to be encrypted
 *  @param [in] ciphertext_len the length of ciphertext
 *  @param [out] result receives the result after successful operation
 *  @param [in] enforced_pkcs1_v1_5_decryption_result_len This value is only
 *  interpreted in case of PKCS#1 v1.5 decryption. For normal PKCS#1 v1.5
 *  decoding, this must be set to zero. Set this value to the expected message
 *  length to achieve constant time fake result generation in case of a padding
 *  error (defense against Bleichenbacher's attack).
 *  @param [out] silent_alarm_mbn meaningful only in case of PKCS#1 v1.5 decryption and if
 *  enforced_pkcs1_v1_5_decryption_result_len is non-zero. May be set to null.
 *  Otherwise, and if enforced_pkcs1_v1_5_decryption_result_len is non-zero,
 *  then this value will be set to non-zero if a format/padding error occurred
 *  during the decryption.
 *
 *  @return an error code
 */
flea_err_e THR_flea_privkey_t__decr_msg_secure(
  const flea_privkey_t* privkey,
  flea_pk_scheme_id_e   id,
  flea_hash_id_e        hash_id,
  const flea_u8_t*      ciphertext,
  flea_al_u16_t         ciphertext_len,
  flea_byte_vec_t*      result,
  flea_al_u16_t         enforced_pkcs1_v1_5_decryption_result_len,
  flea_u8_t*            silent_alarm_mbn
);


/**
 * Encode a private key in plain format.
 *
 * Only supported by ECC keys. The encoded private key is the big endian encoded secret scalar s.
 *
 * Key Parameters are not encoded.
 *
 * @param [in] key the private key to be encoded.
 * @param [out] result the encoded private key.
 *
 * @return an error code
 */
flea_err_e THR_flea_privkey_t__get_encoded_plain(
  const flea_privkey_t* key,
  flea_byte_vec_t*      result
);


/**
 * Compute the ECKA (ECDH) raw or with the ANSI X9.63 KDF. Note: the function
 * does not verify the equality of the ECC parameters of both keys.
 *
 * @param [in] pubkey the peer's public key
 * @param [in] privkey the private key
 * @param [in] kdf_out_len determined the length of the data generated by the KDF. If
 * set to zero, then no KDF will be used ( raw ECKA / ECDH ).
 * @param [in] shared_info_mbn shared info for the KDF. May be null with or without
 * use of KDF
 * @param [in] shared_info_mbn_len length of shared_info_mbn. Set to zero if
 * shared_info_mbn is null.
 * @param [in] hash_id the hash algorithm to use in the KDF. Is ignored if no KDF is
 * used.
 * @param [out] result the output. Will have kdf_out_len length if kdf_out_len >
 * 0 and thus a KDF is used. Otherwise, the length of result will be equal to
 * the byte length of the prime p of the underlying elliptic curve.
 *
 * @return an error code
 */
flea_err_e THR_flea_pubkey__compute_ecka(
  const flea_pubkey_t*  pubkey,
  const flea_privkey_t* privkey,
  flea_dtl_t            kdf_out_len,
  const flea_u8_t*      shared_info_mbn,
  flea_al_u16_t         shared_info_mbn_len,
  flea_hash_id_e        hash_id,
  flea_byte_vec_t*      result
);

# ifdef __cplusplus
}
# endif

#endif /* #ifdef FLEA_HAVE_ASYM_ALGS */

#endif /* h-guard */
