

/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "flea/types.h"
#include "flea/block_cipher.h"

/**
 * The lowest bit of each byte is unused.
 */
flea_err_t THR_flea_single_des_setup_key(flea_ecb_mode_ctx_t* ctx__p_t, const flea_u8_t *key);

flea_err_t THR_flea_single_des_setup_key_with_key_offset(flea_ecb_mode_ctx_t* ctx__p_t, flea_al_u16_t expanded_key_offset__alu16,  const flea_u8_t *key);


void flea_single_des_encrypt_block(const flea_ecb_mode_ctx_t* ctx__p_t, const flea_u8_t* input__pc_u8, flea_u8_t* output__p_u8);

void flea_single_des_encrypt_block_with_key_offset(const flea_ecb_mode_ctx_t* ctx__p_t, flea_al_u16_t expanded_key_offset__alu16, const flea_u8_t* input__pc_u8, flea_u8_t* output__p_u8);


void flea_single_des_decrypt_block(const flea_ecb_mode_ctx_t* ctx__p_t, const flea_u8_t* input__pc_u8, flea_u8_t* output__p_u8);

void flea_single_des_decrypt_block_with_key_offset(const flea_ecb_mode_ctx_t* ctx__p_t, flea_al_u16_t expanded_key_offset__alu16, const flea_u8_t* input__pc_u8, flea_u8_t* output__p_u8);





