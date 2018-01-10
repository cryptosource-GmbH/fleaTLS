/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_ecka__H_
#define _flea_ecka__H_

#include "flea/types.h"
#include "flea/hash.h"
#include "flea/ec_dom_par.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef FLEA_HAVE_ECC

/**
 * Carry out the EC key agreement operation as specified in ANSI X9.63 and BSI TR-03111 v2.0 (Sec. 4.3)
 *
 * @param public_point_enc the encoded public point of the other party
 * @param public_point_enc_len the length of public_point_enc
 * @param secret_key the secret key, big endian encoded
 * @param secret_key_len the length of secret_key
 * @param result pointer to the memory area where to store the computation
 * result
 * @param result_len the caller must provide a pointer to a value which contains
 * the available length of result. when the function returns, *result_len will
 * contain the length of the data set in result
 * @param dom_par pointer the EC domain parameters object to use
 *
 * @return flea error code
 *
 */
flea_err_e THR_flea_ecka__compute_raw(
  const flea_u8_t*             public_point_enc,
  flea_al_u8_t                 public_point_enc_len,
  const flea_u8_t*             secret_key,
  flea_al_u8_t                 secret_key_len,
  flea_u8_t*                   result,
  flea_al_u8_t*                result_len,
  const flea_ec_dom_par_ref_t* dom_par
);

/**
 * Carry out the EC key agreement operation using ANSI X9.63 key derivation
 * function.
 *
 * @param hash_id id of the hash algorithm to use in the key derivation function
 * @param public_point_enc the encoded public point of the other party
 * @param public_point_enc_len the length of public_point_enc
 * @param secret_key the secret key, big endian encoded
 * @param secret_key_len the length of secret_key
 * @param shared_info shared info value to be used in the key derivation
 * function, may be NULL, then also its length must be 0
 * @param shared_info_len the length of shared_info
 * @param result pointer to the memory area where to store the computation
 * result
 * @param result_len The caller must provide a pointer to a value which contains
 * the available length of result. When the function returns, *result_len will
 * contain the length of the data set in result
 * @param dom_par Pointer to the associated domain parameters object
 *
 * @return flea error code
 *
 */
flea_err_e THR_flea_ecka__compute_ecka_with_kdf_ansi_x9_63(
  flea_hash_id_e               hash_id,
  const flea_u8_t*             public_point_enc,
  flea_al_u8_t                 public_point_enc_len,
  const flea_u8_t*             secret_key,
  flea_al_u8_t                 secret_key_len,
  const flea_u8_t*             shared_info,
  flea_al_u16_t                shared_info_len,
  flea_u8_t*                   result,
  flea_al_u16_t                result_len,
  const flea_ec_dom_par_ref_t* dom_par
);

# ifdef __cplusplus
}
# endif

#endif /* #ifdef FLEA_HAVE_ECC */

#endif /* h-guard */
