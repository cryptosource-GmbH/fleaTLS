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
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_aes_setup_decr_key(
  flea_ecb_mode_ctx_t* ctx,
  const flea_u8_t*     key
) FLEA_ATTRIB_UNUSED_RESULT;

#endif /* h-guard */
