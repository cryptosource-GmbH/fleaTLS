/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_pk_api_int__H_
#define _flea_pk_api_int__H_


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
  flea_u8_t*       output_message__pu8,
  flea_al_u16_t*   output_message_len__palu16,
  flea_al_u16_t    bit_size__alu16,
  flea_al_u16_t    enforced_decoding_result_len__alu16
);

#endif /* h-guard */
