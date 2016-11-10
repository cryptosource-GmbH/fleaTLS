/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_ec_key__H_
#define _flea_ec_key__H_

#include "flea/types.h"
#include "flea/x509.h"

flea_err_t THR_flea_ec_key__decode_uncompressed_point(const flea_der_ref_t *encoded__pt, flea_der_ref_t *x__t, flea_der_ref_t *y__t);

#endif /* h-guard */
