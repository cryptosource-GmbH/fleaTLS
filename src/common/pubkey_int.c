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


#include "internal/common/default.h"
#include "internal/common/pubkey_int2.h"
#include "flea/pubkey.h"

#ifdef FLEA_HAVE_ASYM_ALGS
flea_err_e THR_flea_pk_ensure_key_strength(
  flea_pk_sec_lev_e  required_strength__e,
  flea_al_u16_t      key_bit_size__alu16,
  flea_pk_key_type_e key_type
)
{
  FLEA_THR_BEG_FUNC();
  if(key_type == flea_ecc_key)
  {
    if(((flea_al_u16_t) (required_strength__e) * 4) > key_bit_size__alu16)
    {
      FLEA_THROW("public/private EC key size does not meet required security level", FLEA_ERR_PUBKEY_SEC_LEV_NOT_MET);
    }
  }
  else if(key_type == flea_rsa_key)
  {
    if(((required_strength__e == flea_pubkey_80bit) && (key_bit_size__alu16 < 1024)) ||
      ((required_strength__e == flea_pubkey_112bit) && (key_bit_size__alu16 < 2048)) ||
      ((required_strength__e == flea_pubkey_128bit) && (key_bit_size__alu16 < 3072)) ||
      ((required_strength__e == flea_pubkey_192bit) && (key_bit_size__alu16 < 7680)) ||
      ((required_strength__e == flea_pubkey_256bit) && (key_bit_size__alu16 < 15360)))
    {
      FLEA_THROW("public/private RSA key size does not meet required security level", FLEA_ERR_PUBKEY_SEC_LEV_NOT_MET);
    }
  }
  FLEA_THR_FIN_SEC_empty();
}

#endif /* ifdef FLEA_HAVE_ASYM_ALGS */
