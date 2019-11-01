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

#ifndef _flea_pk_keypair__H_
#define _flea_pk_keypair__H_


#include "internal/common/default.h"
#include "flea/ec_dom_par.h"
#include "flea/pubkey.h"
#include "flea/privkey.h"

#ifdef FLEA_HAVE_ECC

# ifdef __cplusplus
extern "C" {
# endif

/**
 * Generate an ECC key pair.
 *
 * @param pubkey the public key object to create.
 * @param privkey the private key object to create.
 * @param dp domain parameter object to use for the key generation
 *
 * @return an error code
 */
flea_err_e THR_flea_pubkey__generate_ecc_key_pair_by_dp(
  flea_pubkey_t*               pubkey,
  flea_privkey_t*              privkey,
  const flea_ec_dom_par_ref_t* dp
);

/**
 * Generate an ECC key pair.
 *
 * @param pubkey the public key object to create.
 * @param privkey the private key object to create.
 * @param dp_id domain parameter id to use for the key generation
 *
 * @return an error code
 */
flea_err_e THR_flea_pubkey__by_dp_id_gen_ecc_key_pair(
  flea_pubkey_t*       pubkey,
  flea_privkey_t*      privkey,
  flea_ec_dom_par_id_e dp_id
);
# ifdef __cplusplus
}
# endif

#endif // ifdef FLEA_HAVE_ECC
#endif /* h-guard */
