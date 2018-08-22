/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_pkcs1_v1_5__H_
# define _flea_pkcs1_v1_5__H_

# include "internal/common/default.h"
# include "flea/error.h"
# include "flea/hash.h"

# ifdef __cplusplus
extern "C" {
# endif


flea_err_e THR_flea_pk_api__verify_message__pkcs1_v1_5(
  const flea_u8_t* encoded,
  flea_al_u16_t    encoded_len,
  const flea_u8_t* digest,
  flea_al_u16_t    digest_len,
  flea_al_u16_t    bit_size,
  flea_hash_id_e   hash_id
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_pk_api__enc_msg_encr_pkcs1_v1_5(
  flea_u8_t*     input_output__pu8,
  flea_al_u16_t  input_len__alu16,
  flea_al_u16_t* output_len__palu16,
  flea_al_u16_t  bit_size,
  flea_hash_id_e hash_id__t
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_pk_api__enc_msg_sign_pkcs1_v1_5(
  flea_u8_t*     input_output__pu8,
  flea_al_u16_t  input_len__alu16,
  flea_al_u16_t* output_len__palu16,
  flea_al_u16_t  bit_size,
  flea_hash_id_e hash_id__t
) FLEA_ATTRIB_UNUSED_RESULT;

/**
 * @param enforced_decoding_result_len__alu16 For normal PKCS#1 v1.5 decoding,
 *                                            this must be set to zero. Set this
 *                                            value to the expected message
 *                                            length to achieve timing neutral
 *                                            fake result generation in case of
 *                                            a padding error (defense against
 *                                            Bleichenbacher's attack).
 */
flea_err_e THR_flea_pk_api__dec_msg__pkcs1_v1_5(
  const flea_u8_t* encoded__pcu8,
  flea_al_u16_t    encoded_len__alu16,
  flea_byte_vec_t* result_vec__pt,
  flea_al_u16_t    bit_size__alu16,
  flea_al_u16_t    enforced_decoding_result_len__alu16,
  flea_u8_t*       silent_alarm_mbn__pu8
) FLEA_ATTRIB_UNUSED_RESULT;


# ifdef __cplusplus
}
# endif
#endif /* h-guard */
