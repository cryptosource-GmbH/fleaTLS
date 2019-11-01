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

#ifndef _flea_x509_key__H_
#define _flea_x509_key__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/byte_vec.h"
#include "flea/ec_dom_par.h"
#include "flea/hash.h"
#include "flea/pubkey.h"

#ifdef FLEA_HAVE_ASYM_ALGS

# ifdef __cplusplus
extern "C" {
# endif

# ifdef FLEA_HAVE_ECC
flea_err_e THR_flea_x509_parse_ecc_public_params(
  const flea_byte_vec_t* encoded_parameters__pt,
  flea_ec_dom_par_ref_t* dom_par__pt
);
# endif // ifdef FLEA_HAVE_ECC

flea_err_e THR_flea_x509_get_hash_id_and_key_type_from_oid(
  const flea_u8_t*    oid__pcu8,
  flea_al_u16_t       oid_len__alu16,
  flea_hash_id_e*     result_hash_id__pe,
  flea_pk_key_type_e* result_key_type_e
);

# ifdef __cplusplus
}
# endif

#endif // ifdef FLEA_HAVE_ASYM_ALGS
#endif /* h-guard */
