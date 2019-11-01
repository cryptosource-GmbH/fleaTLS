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

#ifndef _flea_enc_ecdsa_sig__H_
# define _flea_enc_ecdsa_sig__H_

# include "flea/types.h"
# include "flea/byte_vec.h"

# ifdef __cplusplus
extern "C" {
# endif

/**
 * append the signature to result__pt
 */
flea_err_e THR_flea_asn1_encode_ecdsa_sig(
  const flea_u8_t* r__pcu8,
  flea_al_u8_t     r_len__alu8,
  const flea_u8_t* s__pcu8,
  flea_al_u8_t     s_len__alu8,
  flea_byte_vec_t* result__pt
) FLEA_ATTRIB_UNUSED_RESULT;


# ifdef __cplusplus
}
# endif
#endif /* h-guard */
