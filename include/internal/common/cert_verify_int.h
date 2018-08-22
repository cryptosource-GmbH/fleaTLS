/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_cert_verify_int__H_
# define _flea_cert_verify_int__H_

# include "internal/common/cert_info_int.h"

# ifdef __cplusplus
extern "C" {
# endif


/**
 * Verify that a certificate is signed by the public key of another
 * certificate. Does not perform certificate path validation, only the
 * signature verification itself.
 *
 */
flea_err_e THR_flea_x509_verify_cert_info_signature(
  const flea_x509_cert_info_t* subject_cert_ref__pt,
  const flea_x509_cert_info_t* issuer_cert_ref__pt,
  flea_x509_validation_flags_e cert_ver_flags__e
) FLEA_ATTRIB_UNUSED_RESULT;


# ifdef __cplusplus
}
# endif

#endif /* h-guard */
