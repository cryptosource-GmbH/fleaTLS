/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_desx__H_
#define _flea_desx__H_

/**
 * expects the key as k||k1||k2 where DESX_ENC(k,k1,k2,m) = DES_ENC_k(m^k1)^k2
 */
flea_err_e THR_flea_desx_setup_key(
  flea_ecb_mode_ctx_t* ctx__pt,
  const flea_u8_t*     key
);

void flea_desx_encrypt_block(
  const flea_ecb_mode_ctx_t* ctx__pt,
  const flea_u8_t*           input__pcu8,
  flea_u8_t*                 output__pu8
);

void flea_desx_decrypt_block(
  const flea_ecb_mode_ctx_t* ctx__pt,
  const flea_u8_t*           input__pcu8,
  flea_u8_t*                 output__pu8
);

#endif /* h-guard */
