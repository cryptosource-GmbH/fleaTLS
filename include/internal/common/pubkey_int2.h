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

#ifndef _flea_pubkey_int2__H_
# define _flea_pubkey_int2__H_

# include "flea/pubkey.h"

# ifdef __cplusplus
extern "C" {
# endif

# ifdef FLEA_HAVE_ASYM_ALGS

flea_err_e THR_flea_pk_ensure_key_strength(
  flea_pk_sec_lev_e  required_strength__e,
  flea_al_u16_t      key_bit_size__alu16,
  flea_pk_key_type_e key_type
) FLEA_ATTRIB_UNUSED_RESULT;


flea_pk_sec_lev_e flea_pk_sec_lev_from_bit_mask(flea_al_u8_t bit_mask__alu8);

# endif // ifdef FLEA_HAVE_ASYM_ALGS

# ifdef __cplusplus
}
# endif
#endif /* h-guard */
