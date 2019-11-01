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

#ifndef _flea_kdf__H_
# define _flea_kdf__H_

# include "flea/hash.h"

# ifdef __cplusplus
extern "C" {
# endif


/**
 * Peform the ANSI X9.63 key derivation function.
 *
 * @param hash_id id of the hash algorithm to use in the key derivation function
 * @param input pointer to the input data
 * @param input_len length of input
 * @param shared_info shared info value to be used in the key derivation
 * function, may be NULL, then also its length must be 0
 * @param shared_info_len the length of shared_info
 * @param output pointer to the memory area where to store the computation
 * result
 * @param output_len the caller must provide a pointer to a value which contains
 * the available length of output. when the function returns, *output_len will
 * contain the length of the data set in output
 *
 * @return flea error code
 */
flea_err_e THR_flea_kdf_X9_63(
  flea_hash_id_e   hash_id,
  const flea_u8_t* input,
  flea_al_u16_t    input_len,
  const flea_u8_t* shared_info,
  flea_al_u16_t    shared_info_len,
  flea_u8_t*       output,
  flea_al_u16_t    output_len
) FLEA_ATTRIB_UNUSED_RESULT;

# ifdef __cplusplus
}
# endif

#endif /* h-guard */
