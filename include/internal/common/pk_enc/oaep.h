/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_oaep__H_
#define _flea_oaep__H_

#include "flea/types.h"
#include "flea/hash.h"


flea_err_t
THR_flea_pkcs1_mgf1(flea_u8_t *output__pu8, flea_al_u16_t output_len__alu16, const flea_u8_t *seed__pu8, flea_al_u16_t seed_len__alu16, flea_hash_id_t hash_id__t);

flea_err_t
THR_flea_pk_api__encode_message__oaep(flea_u8_t *input_output__pu8, flea_al_u16_t input_len__alu16, flea_al_u16_t *output_len__palu16, flea_al_u16_t bit_size__alu16, flea_hash_id_t hash_id__t);

flea_err_t
THR_flea_pk_api__decode_message__oaep(flea_u8_t *result__pu8, flea_al_u16_t *result_len__palu16, flea_u8_t *input__pu8, flea_al_u16_t input_len__alu16, flea_al_u16_t bit_size__alu16, flea_hash_id_t hash_id__t);

#endif /* h-guard */
