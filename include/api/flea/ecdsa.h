/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_ecdsa__H_
#define _flea_ecdsa__H_

#include "flea/types.h"
#include "flea/ec_gfp_dom_par.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef FLEA_HAVE_ECC

/**
 * Verify an ECDSA signature on a hash value.
 *
 * @param enc_r big endian encoded value of the signature part r
 * @param enc_r_len length of encr_r
 * @param enc_s big endian encoded value of the signature part s
 * @param enc_s_len length of encr_r
 * @param message the hash value that was signed
 * @param message_len the length of message
 * @param dp pointer to the domain parameters in the flea internal format
 * associated with the key
 * @param pub_point_enc the encoded public point
 * @param pub_point_enc_len the length of pub_point_enc
 *
 * @return flea error code: FLEA_ERR_FINE on success verification, FLEA_ERR_INV_SIGNATURE if the signature is
 * invalid
 *
 */
flea_err_t
THR_flea_ecdsa__raw_verify(const flea_u8_t *enc_r, flea_al_u8_t enc_r_len, const flea_u8_t *enc_s, flea_al_u8_t enc_s_len, const flea_u8_t *message, flea_al_u8_t message_len, const flea_u8_t *pub_point_enc, flea_al_u8_t pub_point_enc_len, const flea_ec_gfp_dom_par_ref_t *dom_par__pt);

/**
 * Generate an ECDSA signature on a hash value.
 *
 * @param result_r pointer to the memory area where to store the signature part r
 * @param result_r_len the length of result_r
 * @param result_r pointer to the memory area where to store the signature part s
 * @param result_s_len the length of result_s
 * @param message the hash value that to be signed signed
 * @param message_len the length of message
 * @param dp pointer to the domain parameters in the flea internal format
 * @param priv_key_enc the big endian encoded private key value
 * @param priv_key_enc_len the length of priv_key_enc
 *
 * @return flea error code
 */
flea_err_t
THR_flea_ecdsa__raw_sign(flea_u8_t *res_r_arr, flea_al_u8_t *res_r_arr_len, flea_u8_t *res_s_arr, flea_al_u8_t *res_s_arr_len, const flea_u8_t *message, flea_al_u8_t message_len, const flea_u8_t *priv_key_enc_arr, flea_al_u8_t priv_key_enc_arr_len, const flea_ec_gfp_dom_par_ref_t *dom_par__pt);

#endif /* #ifdef FLEA_HAVE_ECC */
#ifdef __cplusplus
}
#endif

#endif /* h-guard */
