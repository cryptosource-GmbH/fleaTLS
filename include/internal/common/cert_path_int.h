/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_cert_path_int__H_
#define _flea_cert_path_int__H_

#include "flea/x509.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * validate notBefore & notAfter and Basic Constraint (but not the pathlen)
 */
flea_err_e THR_flea_cert_path__validate_single_cert(
  flea_x509_cert_ref_t*  cert_ref__pt,
  flea_bool_e            is_trusted__b,
  flea_bool_e            is_target__b,
  const flea_gmt_time_t* arg_compare_time_mbn__pt
);
#ifdef __cplusplus
}
#endif

#endif /* h-guard */
