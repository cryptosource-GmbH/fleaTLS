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


#ifndef _flea_ae_int__H_
#define _flea_ae_int__H_

#include "internal/common/default.h"
#include "internal/common/hash/ghash.h"

#ifdef FLEA_HAVE_EAX

typedef struct
{
  flea_ctr_mode_ctx_t ctr_ctx__t;
  flea_mac_ctx_t      cmac_ctx__t;
# ifdef FLEA_HEAP_MODE
  flea_u8_t*          nonce__bu8;
  flea_u8_t*          header_omac__bu8;
# else
  flea_u8_t           nonce__bu8 [FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH];
  flea_u8_t           header_omac__bu8[FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH];
# endif // ifdef FLEA_HEAP_MODE
} flea_ae_eax_specific_t;
#endif // ifdef FLEA_HAVE_EAX

#ifdef FLEA_HAVE_GCM

typedef struct
{
  flea_ghash_ctx_t    ghash_ctx__t;
  flea_ctr_mode_ctx_t ctr_ctx__t;
} flea_ae_gcm_specific_t;
#endif // ifdef FLEA_HAVE_GCM

/* fwd declaration */
struct flea_ae_config_entry_struct;

typedef struct flea_ae_config_entry_struct flea_ae_config_entry_t;

#endif /* h-guard */
