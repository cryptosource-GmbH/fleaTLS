/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_tdes__H_
#define _flea_tdes__H_

#include "flea/types.h"
#include "flea/block_cipher.h"
#include "internal/common/block_cipher/tdes.h"

flea_err_t THR_flea_triple_des_ede_2key_setup_key(
  flea_ecb_mode_ctx_t* ctx__pt,
  const flea_u8_t*     key
);

void flea_triple_des_ede_2key_encrypt_block(
  const flea_ecb_mode_ctx_t* ctx__pt,
  const flea_u8_t*           input__pcu8,
  flea_u8_t*                 output__pu8
);

void flea_triple_des_ede_2key_decrypt_block(
  const flea_ecb_mode_ctx_t* ctx__pt,
  const flea_u8_t*           input__pcu8,
  flea_u8_t*                 output__pu8
);

flea_err_t THR_flea_triple_des_ede_3key_setup_key(
  flea_ecb_mode_ctx_t* ctx__pt,
  const flea_u8_t*     key
);

void flea_triple_des_ede_3key_encrypt_block(
  const flea_ecb_mode_ctx_t* ctx__pt,
  const flea_u8_t*           input__pcu8,
  flea_u8_t*                 output__pu8
);

void flea_triple_des_ede_3key_decrypt_block(
  const flea_ecb_mode_ctx_t* ctx__pt,
  const flea_u8_t*           input__pcu8,
  flea_u8_t*                 output__pu8
);

#endif /* h-guard */
