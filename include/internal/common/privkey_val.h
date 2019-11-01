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

#ifndef _flea_privkey_val__H_
#define _flea_privkey_val__H_

#include "internal/common/default.h"
#include "flea/byte_vec.h"
#include "flea/ec_dom_par.h"

#ifdef __cplusplus
extern "C" {
#endif


#ifdef FLEA_HAVE_ECC

typedef struct
{
  flea_ec_dom_par_ref_t dp__t;
  flea_byte_vec_t       scalar__rcu8;
# ifdef FLEA_STACK_MODE
  flea_u8_t             dp_mem__bu8[FLEA_ECC_MAX_DP_CONCAT_BYTE_SIZE];
  flea_u8_t             priv_scalar__mem__bu8[FLEA_ECC_MAX_ORDER_BYTE_SIZE];
# else
  flea_u8_t*            dp_mem__bu8;
  flea_u8_t*            priv_scalar__mem__bu8;
# endif  // ifdef FLEA_STACK_MODE
} flea_ec_privkey_val_t;
#endif  // ifdef FLEA_HAVE_ECC

#ifdef FLEA_HAVE_RSA

typedef struct
{
  flea_byte_vec_t pqd1d2c__rcu8 [5];
# ifdef FLEA_STACK_MODE
  flea_u8_t       priv_key_mem__bu8 [FLEA_RSA_CRT_KEY_INTERNAL_FORMAT_MAX_BYTE_SIZE];
# else
  flea_u8_t*      priv_key_mem__bu8;
# endif
} flea_rsa_privkey_val_t;
#endif  // ifdef FLEA_HAVE_RSA


#ifdef __cplusplus
}
#endif
#endif /* h-guard */
