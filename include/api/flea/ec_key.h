/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_ec_key__H_
#define _flea_ec_key__H_

#include "flea/types.h"
#include "flea/x509.h"

/**
 * Get the x and y coordinate as references to an encoded elliptic curve point (i.e. 0x04 | x | y) in a byte
 * vector.
 *
 * @param [in] encoded the encoded point
 * @param [out] x the x coordinate of the encoded point
 * @param [out] y the y coordinate of the encoded point
 *
 * return an error code
 *
 */
flea_err_e THR_flea_ecc_key__dec_uncompressed_point(
  const flea_byte_vec_t* encoded,
  flea_ref_cu8_t*        x,
  flea_ref_cu8_t*        y
) FLEA_ATTRIB_UNUSED_RESULT;

/**
 * Determine the byte length of a point coordinate from an encoded elliptic curve point (i.e. 0x04 | x | y), which is equal to the byte length of the curve's prime p.
 *
 * @param [in] encoded the encoded point
 *
 * @return the byte length of a point coordinate
 */
flea_al_u8_t flea_ecc_key__get_coordinate_len_from_encoded_point(const flea_byte_vec_t* encoded);

#endif /* h-guard */
