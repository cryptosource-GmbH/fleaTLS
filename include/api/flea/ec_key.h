/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_ec_key__H_
#define _flea_ec_key__H_

#include "flea/types.h"
#include "flea/x509.h"

flea_err_t THR_flea_ec_key__decode_uncompressed_point(const flea_ref_cu8_t *encoded__pt, flea_ref_cu8_t *x__t, flea_ref_cu8_t *y__t);

flea_al_u8_t flea_ecc_key__get_coordinate_len_from_encoded_point(const flea_ref_cu8_t *encoded__pt);

#endif /* h-guard */
