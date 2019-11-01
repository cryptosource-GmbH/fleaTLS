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
#ifndef _flea_ec_key_gen__H_
#define _flea_ec_key_gen__H_

#include "flea/types.h"
#include "flea/ec_dom_par.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef FLEA_HAVE_ECC

/**
 * Generate an EC key pair.
 *
 * @param result_public pointer to the memory area where to store the resulting public key
 * @param result_public_len the caller must provide a pointer to a value representing
 * the available length in result_public, upon function return this value will
 * be updated with the length of the data written to result_public
 * @param result_private pointer to the memory area where to store the resulting private key
 * @param result_private_len the caller must provide a pointer to a value representing
 * the available length in result_private, upon function return this value will
 * be updated with the length of the data written to result_private
 * @param dom_par domain parameters
 *
 * @result flea error code
 */
flea_err_e THR_flea_generate_ecc_key(
  flea_u8_t*                   result_public,
  flea_al_u8_t*                result_public_len,
  flea_u8_t*                   result_private,
  flea_al_u8_t*                result_private_len,
  const flea_ec_dom_par_ref_t* dom_par
);

#endif /* #ifdef FLEA_HAVE_ECC */

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
