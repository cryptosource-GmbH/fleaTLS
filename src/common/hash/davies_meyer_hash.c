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


#include "internal/common/default.h"
#include "internal/common/hash/davies_meyer_hash.h"
#include "flea/hash.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "internal/common/block_cipher/aes.h"
#include "flea/alloc.h"
#include "flea/bin_utils.h"
#include <string.h>

#ifdef FLEA_HAVE_DAVIES_MEYER_HASH
void flea_hash_davies_meyer_aes128_init(flea_hash_ctx_t* ctx__pt)
{
  memset(ctx__pt->hash_state, 0, sizeof(ctx__pt->hash_state[0]) * 4);
}

flea_err_e THR_flea_hash_davies_meyer_aes128_compression(
  flea_hash_ctx_t* ctx__pt,
  const flea_u8_t* input
)
{
  flea_ecb_mode_ctx_t aes_ctx;

  FLEA_DECL_BUF(tmp_state, flea_u8_t, FLEA_AES_BLOCK_LENGTH);
  FLEA_THR_BEG_FUNC();
  flea_ecb_mode_ctx_t__INIT(&aes_ctx);


  FLEA_ALLOC_BUF(tmp_state, FLEA_AES_BLOCK_LENGTH);

  FLEA_CCALL(THR_flea_ecb_mode_ctx_t__ctor(&aes_ctx, flea_aes128, input, FLEA_AES128_KEY_BYTE_LENGTH, flea_encrypt));

  flea_aes_encrypt_block(&aes_ctx, (flea_u8_t*) ctx__pt->hash_state, tmp_state);

  flea__xor_bytes_in_place((flea_u8_t*) ctx__pt->hash_state, tmp_state, FLEA_AES_BLOCK_LENGTH);

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(tmp_state);
    flea_ecb_mode_ctx_t__dtor(&aes_ctx);
  );
}

#endif // #ifdef FLEA_HAVE_DAVIES_MEYER_HASH
