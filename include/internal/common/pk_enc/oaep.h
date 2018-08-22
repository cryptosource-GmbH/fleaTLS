/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_oaep__H_
#define _flea_oaep__H_

#include "flea/types.h"
#include "flea/hash.h"
#include "flea/byte_vec.h"


flea_err_e THR_flea_pk_api__enc_msg_oaep(
  flea_u8_t*     input_output__pu8,
  flea_al_u16_t  input_len__alu16,
  flea_al_u16_t* output_len__palu16,
  flea_al_u16_t  bit_size__alu16,
  flea_hash_id_e hash_id__t
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_pk_api__dec_msg__oaep(
  flea_byte_vec_t* result_vec__pt,
  flea_u8_t*       input__pu8,
  flea_al_u16_t    input_len__alu16,
  flea_al_u16_t    bit_size__alu16,
  flea_hash_id_e   hash_id__t
) FLEA_ATTRIB_UNUSED_RESULT;


#endif /* h-guard */
