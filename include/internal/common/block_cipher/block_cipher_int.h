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

#ifndef _flea_block_cipher_int__H_
#define _flea_block_cipher_int__H_

#include "flea/error.h"
#include "flea/block_cipher_fwd.h"

#define FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH          16

#define FLEA_BLOCK_CIPHER_MAX_EXPANDED_KEY_U32_SIZE __FLEA_COMPUTED_BLOCK_CIPHER_MAX_EXPANDED_KEY_U32_SIZE


typedef void (* flea_cipher_block_processing_f)(
  const flea_ecb_mode_ctx_t* p_ctx,
  const flea_u8_t*           input,
  flea_u8_t*                 output
);

typedef flea_err_e (* THR_flea_block_cipher_key_sched_f)(
  flea_ecb_mode_ctx_t* ctx,
  const flea_u8_t*     cipherKey
);

struct struct_flea_block_cipher_config_entry_t;

typedef struct struct_flea_block_cipher_config_entry_t flea_block_cipher_config_entry_t;

typedef enum { des, aes } flea_block_cipher_raw_id_t;

struct struct_flea_block_cipher_config_entry_t
{
  flea_block_cipher_id_e            ext_id__t;
  flea_block_cipher_raw_id_t        raw_id__t;
  flea_u16_t                        key_bit_size;
  flea_u16_t                        expanded_key_u32_size__u16;

  flea_cipher_block_processing_f    cipher_block_encr_function;
  flea_cipher_block_processing_f    cipher_block_decr_function;

  THR_flea_block_cipher_key_sched_f THR_key_sched_encr_function;
  THR_flea_block_cipher_key_sched_f THR_key_sched_decr_function;

  flea_u8_t                         block_length__u8;
};


/**
 * Block cipher context type.
 */
struct struct_flea_ecb_mode_ctx_t
{
  const flea_block_cipher_config_entry_t* config__pt;
  flea_u8_t                               key_byte_size__u8;
  flea_u8_t                               block_length__u8;
  flea_u8_t                               nb_rounds__u8;
  flea_cipher_dir_e                       dir__t;
#ifdef FLEA_HEAP_MODE
  flea_u32_t*                             expanded_key__bu8;
#elif defined FLEA_STACK_MODE
  flea_u32_t                              expanded_key__bu8 [FLEA_BLOCK_CIPHER_MAX_EXPANDED_KEY_U32_SIZE];
#endif // ifdef FLEA_HEAP_MODE
  flea_cipher_block_processing_f          block_crypt_f;
};

struct struct_flea_ctr_mode_ctx_t
{
#ifdef FLEA_HEAP_MODE
  flea_u8_t*                              ctr_block__bu8;
  flea_u8_t*                              pending_mask__bu8;
#else
  flea_u8_t                               ctr_block__bu8 [FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH];
  flea_u8_t                               pending_mask__bu8[FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH];
#endif // ifdef FLEA_HEAP_MODE
  flea_al_u8_t                            pending_offset__alu8;
  flea_al_u8_t                            ctr_len__alu8;
  const flea_block_cipher_config_entry_t* config__pt;
  flea_ecb_mode_ctx_t                     cipher_ctx__t;
};

struct struct_flea_cbc_mode_ctx_t
{
#ifdef FLEA_HEAP_MODE
  flea_u8_t*          iv__bu8;
#else
  flea_u8_t           iv__bu8[FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH];
#endif
  flea_ecb_mode_ctx_t cipher_ctx__t;
};

#endif /* h-guard */
