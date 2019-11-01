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

#ifndef _flea_pkcs8__H_
# define _flea_pkcs8__H_

# include "flea/types.h"
# include "flea/privkey.h"

# ifdef FLEA_HAVE_ASYM_ALGS
#  ifdef __cplusplus
extern "C" {
#  endif

/**
 * Construct a private key from an unencrypted DER encoded PKCS#8 structure.
 *
 * @param key the key to construct
 * @param der_key the DER encoded structure
 * @param der_key_len the length of the DER encoded structure
 */
flea_err_e THR_flea_privkey_t__ctor_pkcs8(
  flea_privkey_t*  key,
  const flea_u8_t* der_key,
  flea_al_u16_t    der_key_len
) FLEA_ATTRIB_UNUSED_RESULT;

/**
 * Construct a public key from an unencrypted DER encoded PKCS#8 structure.
 *
 * @param key the key to construct
 * @param der_key the DER encoded structure
 * @param der_key_len the length of the DER encoded structure
 */
flea_err_e THR_flea_pubkey_t__ctor_pkcs8(
  flea_pubkey_t*   key,
  const flea_u8_t* der_key,
  flea_al_u16_t    der_key_len
) FLEA_ATTRIB_UNUSED_RESULT;

#  ifdef __cplusplus
}
#  endif

# endif /* #ifdef FLEA_HAVE_ASYM_ALGS */

#endif /* h-guard */
