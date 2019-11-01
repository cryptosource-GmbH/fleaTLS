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

#ifndef _flea_pk_key_int__H_
# define _flea_pk_key_int__H_

# include "flea/privkey.h"

# ifdef FLEA_HAVE_ASYM_ALGS

#  ifdef __cplusplus
extern "C" {
#  endif


flea_err_e THR_flea_rsa_raw_operation_crt_private_key(
  const flea_privkey_t* priv_key__pt,
  flea_u8_t*            result_enc,
  const flea_u8_t*      base_enc,
  flea_al_u16_t         base_length
) FLEA_ATTRIB_UNUSED_RESULT;


#  ifdef __cplusplus
}
#  endif

# endif // ifdef FLEA_HAVE_ASYM_ALGS

#endif /* h-guard */
