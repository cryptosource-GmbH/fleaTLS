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

#ifndef _flea_rsa_pub_op__H_
#define _flea_rsa_pub_op__H_

#include "internal/common/default.h"
#include  "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  RSA raw public operation for the RSA public operation.
 *  @param result_arr array to receive the big endian encoded exponentiation
 *  result. Must have length of the modulus.
 *  @param exponent_enc big endian encoded exponent used in the exponentiation.
 *  @param exponent_length length of the exponent_enc array
 *  @param base_enc big endian encoded base used in the exponentiation
 *  @param base_length length of the base_enc array
 *  @param modulus_enc big endian encoded modulus
 *  @param modulus_length length of the modulus_enc array
 *
 *  @return error code
 */
flea_err_e THR_flea_rsa_raw_operation(
  flea_u8_t*       result_arr,
  const flea_u8_t* exponent_enc,
  flea_al_u16_t    exponent_length,
  const flea_u8_t* base_enc,
  flea_al_u16_t    base_length,
  const flea_u8_t* modulus_enc,
  flea_al_u16_t    modulus_length
);


#ifdef __cplusplus
}
#endif
#endif /* h-guard */
