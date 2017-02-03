/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_ecc__H_
#define _flea_ecc__H_
#include "internal/common/default.h"
#include "internal/common/ecc_int.h"
#include "flea/ec_gfp_dom_par.h"

#ifdef FLEA_HAVE_ECC

/**
 * The maximal size of an uncompressed or hybrid encoded EC point.
 */
# define FLEA_ECC_MAX_UNCOMPR_POINT_SIZE (2 * (FLEA_ECC_MAX_MOD_BYTE_SIZE) +1)

/**
 * The maximal byte size of an EC private key.
 */
# define FLEA_ECC_MAX_PRIVATE_KEY_BYTE_SIZE FLEA_ECC_MAX_ORDER_BYTE_SIZE

#endif /* #ifdef FLEA_HAVE_ECC */

#endif /* h-guard */
