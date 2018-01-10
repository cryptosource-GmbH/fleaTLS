/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_ecc_named_curves__H_
#define _flea_ecc_named_curves__H_

#include "flea/ec_dom_par.h"
#include "flea/types.h"

#ifdef FLEA_HAVE_ECC

flea_err_e THR_flea_ecc_gfp_dom_par_t__set_by_named_curve_oid(
  flea_ec_dom_par_ref_t* dp_to_set__pt,
  const flea_u8_t*       oid__pcu8,
  flea_al_u8_t           oid_len__alu8
);

#endif /* #ifdef FLEA_HAVE_ECC */
#endif /* h-guard */
