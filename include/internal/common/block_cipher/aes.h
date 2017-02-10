/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef __flea_aes_H_
#define __flea_aes_H_

#include "flea/types.h"
#include "flea/block_cipher.h"

#define FLEA_AES256_KEY_BYTE_LENGTH 32
#define FLEA_AES192_KEY_BYTE_LENGTH 24
#define FLEA_AES128_KEY_BYTE_LENGTH 16
#define FLEA_AES_BLOCK_LENGTH       16

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

flea_err_t THR_flea_aes_setup_encr_key(
  flea_ecb_mode_ctx_t* ctx,
  const flea_u8_t*     key
);

flea_err_t THR_flea_aes_setup_decr_key(
  flea_ecb_mode_ctx_t* ctx,
  const flea_u8_t*     key
);

#endif /* h-guard */
