/* fleaTLS cryptographic library
Copyright (C) 2015-2019 cryptosource GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

#include "flea/types.h"
#include "flea/block_cipher.h"

/**
 * The lowest bit of each byte is unused.
 */
flea_err_e THR_flea_single_des_setup_key(
  flea_ecb_mode_ctx_t* ctx__p_t,
  const flea_u8_t*     key
);

flea_err_e THR_flea_single_des_setup_key_with_key_offset(
  flea_ecb_mode_ctx_t* ctx__p_t,
  flea_al_u16_t        expanded_key_offset__alu16,
  const flea_u8_t*     key
);


void flea_single_des_encrypt_block(
  const flea_ecb_mode_ctx_t* ctx__p_t,
  const flea_u8_t*           input__pc_u8,
  flea_u8_t*                 output__p_u8
);

void flea_single_des_encrypt_block_with_key_offset(
  const flea_ecb_mode_ctx_t* ctx__p_t,
  flea_al_u16_t              expanded_key_offset__alu16,
  const flea_u8_t*           input__pc_u8,
  flea_u8_t*                 output__p_u8
);


void flea_single_des_decrypt_block(
  const flea_ecb_mode_ctx_t* ctx__p_t,
  const flea_u8_t*           input__pc_u8,
  flea_u8_t*                 output__p_u8
);

void flea_single_des_decrypt_block_with_key_offset(
  const flea_ecb_mode_ctx_t* ctx__p_t,
  flea_al_u16_t              expanded_key_offset__alu16,
  const flea_u8_t*           input__pc_u8,
  flea_u8_t*                 output__p_u8
);
