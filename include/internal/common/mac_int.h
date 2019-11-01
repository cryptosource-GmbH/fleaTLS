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

#ifndef _flea_mac_int__H_
#define _flea_mac_int__H_

#include "internal/common/default.h"
#include "flea/mac_fwd.h"

typedef enum { flea_cmac, flea_hmac } flea_mac_mode_id_t;

typedef struct
{
  flea_hash_ctx_t hash_ctx__t;
  flea_u8_t       hash_output_len__u8;
  flea_u8_t       key_byte_len__u8;
#ifdef FLEA_HEAP_MODE
  flea_u8_t*      key__bu8;
#else
  flea_u8_t       key__bu8[__FLEA_COMPUTED_MAC_MAX_KEY_LEN];
#endif
} flea_mac_ctx_hmac_specific_t;

typedef struct
{
  flea_u8_t           pending__u8;
  flea_ecb_mode_ctx_t cipher_ctx__t;

#ifdef FLEA_HEAP_MODE
  flea_u8_t*          prev_ct__bu8;
#else
  flea_u8_t           prev_ct__bu8[FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH];
#endif
} flea_mac_ctx_cmac_specific_t;


struct mac_config_entry_struct;

typedef struct mac_config_entry_struct mac_config_entry_t;


/**
 * MAC context type
 */
struct struct_flea_mac_ctx_t
{
  flea_u8_t          output_len__u8;
  flea_mac_mode_id_t mode_id__t;
  union
  {
    flea_mac_ctx_hmac_specific_t hmac_specific__t;
    flea_mac_ctx_cmac_specific_t cmac_specific__t;
  } primitive_specific_ctx__u;
};

void flea_mac_ctx_t__dtor_cipher_ctx_ref(flea_mac_ctx_t* ctx__pt);

void flea_mac_ctx_t__reset_cmac(flea_mac_ctx_t* ctx__pt);

flea_err_e THR_flea_mac_ctx_t__ctor_cmac(
  flea_mac_ctx_t*           ctx,
  const mac_config_entry_t* config_entry,
  const flea_u8_t*          key,
  flea_al_u16_t             key_len,
  flea_ecb_mode_ctx_t*      ciph_ctx_ref
) FLEA_ATTRIB_UNUSED_RESULT;

#endif /* h-guard */
