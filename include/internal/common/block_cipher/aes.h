/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef __flea_aes_H_
#define __flea_aes_H_

#include "flea/types.h"
#include "flea/block_cipher.h"


void flea_aes_decrypt_block(
  const flea_ecb_mode_ctx_t* ctx,
  const flea_u8_t*           ct,
  flea_u8_t*                 pt
);

void flea_aes_encrypt_block(
  const flea_ecb_mode_ctx_t* ctx,
  const flea_u8_t*           pt,
  flea_u8_t*                 ct
);

void flea_aes_setup_encr_key(
  flea_ecb_mode_ctx_t* ctx,
  const flea_u8_t*     key
);

flea_err_e THR_flea_aes_setup_encr_key(
  flea_ecb_mode_ctx_t* ctx,
  const flea_u8_t*     key
);

flea_err_e THR_flea_aes_setup_decr_key(
  flea_ecb_mode_ctx_t* ctx,
  const flea_u8_t*     key
);

#endif /* h-guard */
