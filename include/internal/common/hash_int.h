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


#ifndef _flea_hash_int__H_
#define _flea_hash_int__H_

#include "flea/hash_fwd.h"
#include "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* internal function pointer types */
typedef flea_err_e (* THR_flea_hash_compression_f)(
  flea_hash_ctx_t* ctx,
  const flea_u8_t* input
);
typedef void (* flea_hash_init_f)(flea_hash_ctx_t* ctx);
typedef void (* flea_hash_encode_hash_state_f)(
  const flea_hash_ctx_t* ctx,
  flea_u8_t*             output,
  flea_al_u8_t           output_len
);

struct struct_flea_hash_config_entry_t;

typedef struct struct_flea_hash_config_entry_t flea_hash_config_entry_t;


/**
 * Hash context type.
 */
struct struct_flea_hash_ctx_t
{
#ifdef FLEA_HEAP_MODE
  flea_u8_t*                      pending_buffer;
  flea_u32_t*                     hash_state;
#elif defined FLEA_STACK_MODE
  flea_u8_t                       pending_buffer[__FLEA_COMPUTED_MAX_HASH_BLOCK_LEN];
  flea_u32_t                      hash_state[__FLEA_COMPUTED_MAX_HASH_STATE_LEN / sizeof(flea_u32_t)];
#endif // ifdef FLEA_HEAP_MODE
  flea_u64_t                      total_byte_length;
  const flea_hash_config_entry_t* p_config;
  flea_len_ctr_t                  len_ctr__t;
  flea_al_u8_t                    pending;
};

#ifdef __cplusplus
}
#endif


#endif /* h-guard */
