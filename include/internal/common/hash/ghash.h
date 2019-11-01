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

#ifndef _flea_gcm__H_
# define _flea_gcm__H_

# include "internal/common/default.h"
# include "flea/types.h"
# include "flea/block_cipher.h"
# include "internal/common/len_ctr.h"

# ifdef __cplusplus
extern "C" {
# endif
# define __FLEA_GHASH_BLOCK_SIZE 16

typedef struct
{
  flea_len_ctr_t len_ctr__t;
  flea_u16_t     hdr_len__u16;
# ifdef FLEA_HEAP_MODE
  flea_u32_t*    hl__bu32;
  flea_u32_t*    hh__bu32;
  flea_u8_t*     base_ctr__bu8;
  flea_u8_t*     state__bu8;
# else // ifdef FLEA_HEAP_MODE
  flea_u32_t     hl__bu32[32];
  flea_u32_t     hh__bu32[32];
  flea_u8_t      base_ctr__bu8[16];
  flea_u8_t      state__bu8[16];
# endif // ifdef FLEA_HEAP_MODE
  flea_u8_t      pend_input_len__u8;
} flea_ghash_ctx_t;

flea_err_e THR_flea_ghash_ctx_t__ctor(
  flea_ghash_ctx_t*          ctx__pt,
  const flea_ecb_mode_ctx_t* ecb_ctx__pt
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_ghash_ctx_t__start(
  flea_ghash_ctx_t*          ctx,
  const flea_ecb_mode_ctx_t* ecb_ctx__pt,
  const flea_u8_t*           iv,
  size_t                     iv_len,
  const flea_u8_t*           add,
  flea_al_u16_t              add_len,
  flea_u8_t*                 ctr_block__pu8
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_ghash_ctx_t__update(
  flea_ghash_ctx_t* ctx,
  flea_dtl_t        length,
  const flea_u8_t*  input
) FLEA_ATTRIB_UNUSED_RESULT;

void flea_ghash_ctx_t__finish(
  flea_ghash_ctx_t* ctx,
  flea_u8_t*        tag,
  size_t            tag_len
);

void flea_ghash_ctx_t__dtor(flea_ghash_ctx_t* ctx__pt);

# ifdef __cplusplus
}
# endif

#endif /* h-guard */
