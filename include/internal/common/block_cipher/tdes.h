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


#ifndef _flea_tdes__H_
#define _flea_tdes__H_

#include "flea/types.h"
#include "flea/block_cipher.h"
#include "internal/common/block_cipher/tdes.h"

flea_err_e THR_flea_triple_des_ede_2key_setup_key(
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

flea_err_e THR_flea_triple_des_ede_3key_setup_key(
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
