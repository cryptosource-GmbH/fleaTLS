/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "flea/byte_vec.h"
#include "flea/pubkey.h"

#ifndef _flea_pk_api_int__H_
# define _flea_pk_api_int__H_

# define FLEA_PK_GET_PRIMITIVE_ID_FROM_SCHEME_ID(x) ((x >> FLEA_PK_ID_OFFS_PRIMITIVE) << FLEA_PK_ID_OFFS_PRIMITIVE)
# define FLEA_PK_GET_ENCODING_ID_FROM_SCHEME_ID(x)  (x & ((1 << FLEA_PK_ID_OFFS_PRIMITIVE) - 1))

flea_err_t THR_flea_pk_api__encode_message__emsa1(
  flea_u8_t*     input_output,
  flea_al_u16_t  input_len,
  flea_al_u16_t* output_len,
  flea_al_u16_t  bit_size
);
flea_err_t THR_flea_pk_api__verify_message__pkcs1_v1_5(
  const flea_u8_t* encoded,
  flea_al_u16_t    encoded_len,
  const flea_u8_t* digest,
  flea_al_u16_t    digest_len,
  flea_al_u16_t    bit_size,
  flea_hash_id_t   hash_id
);

flea_err_t THR_flea_pk_api__encode_message__pkcs1_v1_5_encr(
  flea_u8_t*     input_output__pu8,
  flea_al_u16_t  input_len__alu16,
  flea_al_u16_t* output_len__palu16,
  flea_al_u16_t  bit_size,
  flea_hash_id_t hash_id__t
);

flea_err_t THR_flea_pk_api__encode_message__pkcs1_v1_5_sign(
  flea_u8_t*     input_output__pu8,
  flea_al_u16_t  input_len__alu16,
  flea_al_u16_t* output_len__palu16,
  flea_al_u16_t  bit_size,
  flea_hash_id_t hash_id__t
);

/**
 * @param enforced_decoding_result_len__alu16 For normal PKCS#1 v1.5 decoding,
 *                                            this must be set to zero. Set this
 *                                            value to the expected message
 *                                            length to achieve timing neutral
 *                                            fake result generation in case of
 *                                            a padding error (defense against
 *                                            Bleichenbacher's attack).
 */
flea_err_t THR_flea_pk_api__decode_message__pkcs1_v1_5(
  const flea_u8_t* encoded__pcu8,
  flea_al_u16_t    encoded_len__alu16,
  flea_byte_vec_t* result_vec__pt,
  flea_al_u16_t    bit_size__alu16,
  flea_al_u16_t    enforced_decoding_result_len__alu16
);


/**
 *  Encrypt a message using a public key scheme.
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


#endif /* h-guard */
