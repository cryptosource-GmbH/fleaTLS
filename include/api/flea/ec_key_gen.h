/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */
#ifndef _flea_ec_key_gen__H_
# define _flea_ec_key_gen__H_

# include "flea/types.h"
# include "flea/ec_dom_par.h"

# ifdef __cplusplus
extern "C" {
# endif

# ifdef FLEA_HAVE_ECC

/**
 * Generate an EC key pair.
 *
 * @param result_public pointer to the memory area where to store the resulting public key
 * @param result_public_len the caller must provide a pointer to a value representing
 * the available length in result_public, upon function return this value will
 * be updated with the length of the data written to result_public
 * @param result_private pointer to the memory area where to store the resulting private key
 * @param result_private_len the caller must provide a pointer to a value representing
 * the available length in result_private, upon function return this value will
 * be updated with the length of the data written to result_private
 * @param dom_par domain parameters
 *
 * @result flea error code
 */
flea_err_e THR_flea_generate_ecc_key(
  flea_u8_t*                   result_public,
  flea_al_u8_t*                result_public_len,
  flea_u8_t*                   result_private,
  flea_al_u8_t*                result_private_len,
  const flea_ec_dom_par_ref_t* dom_par
) FLEA_ATTRIB_UNUSED_RESULT;

# endif /* #ifdef FLEA_HAVE_ECC */

# ifdef __cplusplus
}
# endif

#endif /* h-guard */
