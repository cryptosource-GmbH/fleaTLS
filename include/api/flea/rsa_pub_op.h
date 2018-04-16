/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_rsa_pub_op__H_
#define _flea_rsa_pub_op__H_

#include "internal/common/default.h"
#include  "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  RSA raw public operation for the RSA public operation.
 *  @param result_arr array to receive the big endian encoded exponentiation
 *  result. Must have length of the modulus.
 *  @param exponent_enc big endian encoded exponent used in the exponentiation.
 *  @param exponent_length length of the exponent_enc array
 *  @param base_enc big endian encoded base used in the exponentiation
 *  @param base_length length of the base_enc array
 *  @param modulus_enc big endian encoded modulus
 *  @param modulus_length length of the modulus_enc array
 *
 *  @return error code
 */
flea_err_e THR_flea_rsa_raw_operation(
  flea_u8_t*       result_arr,
  const flea_u8_t* exponent_enc,
  flea_al_u16_t    exponent_length,
  const flea_u8_t* base_enc,
  flea_al_u16_t    base_length,
  const flea_u8_t* modulus_enc,
  flea_al_u16_t    modulus_length
);


#ifdef __cplusplus
}
#endif
#endif /* h-guard */
