/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

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
  flea_public_key_t*           pubkey,
  flea_private_key_t*          privkey,
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
flea_err_e THR_flea_pubkey__generate_ecc_key_pair_by_dp_id(
  flea_public_key_t*   pubkey,
  flea_private_key_t*  privkey,
  flea_ec_dom_par_id_e dp_id
);
# ifdef __cplusplus
}
# endif

#endif // ifdef FLEA_HAVE_ECC
#endif /* h-guard */
