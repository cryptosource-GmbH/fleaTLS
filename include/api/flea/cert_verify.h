/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_cert_verify__H_
#define _flea_cert_verify__H_

#include "internal/common/ber_dec.h"
#include "flea/x509.h"
#include "flea/types.h"
#include "flea/pubkey.h"
#include "flea/cert_info.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Verify that a certificate is signed by the public key of another
 * certificate. Does not perform certificate path validation, only the
 * signature verification itself.
 *
 */
flea_err_t THR_flea_x509_verify_cert_signature(
  const flea_u8_t* enc_subject_cert__pcu8,
  flea_dtl_t       enc_subject_cert_len__dtl,
  const flea_u8_t* enc_issuer_cert__pcu8,
  flea_dtl_t       enc_issuer_cert_len__dtl
);


/**
 * Verify that a certificate is signed by the public key of another
 * certificate. Does not perform certificate path validation, only the
 * signature verification itself.
 *
 */
flea_err_t THR_flea_x509_verify_cert_info_signature(
  const flea_x509_cert_info_t* subject_cert_ref__pt,
  const flea_x509_cert_info_t* issuer_cert_ref__pt
);
#ifdef __cplusplus
}
#endif

#endif /* h-guard */
