/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_cert_path_int__H_
# define _flea_cert_path_int__H_

# include "flea/x509.h"

# ifdef __cplusplus
extern "C" {
# endif

typedef struct
{
  flea_ref_cu8_t data_ref__rcu8;
  flea_u8_t      trusted_flag;
} flea_enc_cert_ref_t;

/**
 * validate notBefore & notAfter and Basic Constraint (but not the pathlen)
 */
flea_err_e THR_flea_cert_path__validate_single_cert(
  flea_x509_cert_ref_t*  cert_ref__pt,
  flea_bool_t            is_trusted__b,
  flea_bool_t            is_target__b,
  const flea_gmt_time_t* arg_compare_time_mbn__pt
) FLEA_ATTRIB_UNUSED_RESULT;
# ifdef __cplusplus
}
# endif

#endif /* h-guard */
