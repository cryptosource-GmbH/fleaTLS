/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_cert_verify__H_
#define _flea_cert_verify__H_


#include "flea/ber_dec.h"
#include "flea/x509.h"
#include "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif

flea_err_t THR_flea_x509_verify_cert_signature( const flea_u8_t *enc_subject_cert__pcu8, flea_dtl_t enc_subject_cert_len__dtl, const flea_u8_t *enc_issuer_cert__pcu8, flea_dtl_t enc_issuer_cert_len__dtl);


flea_err_t THR_flea_x509_verify_cert_ref_signature(const flea_x509_cert_ref_t *subject_cert_ref__pt, const flea_x509_cert_ref_t *issuer_cert_ref__t);

flea_err_t THR_flea_x509_verify_signature(const flea_x509_algid_ref_t *alg_id__t, const flea_x509_public_key_info_t *public_key_info__pt, const flea_der_ref_t* tbs_data__pt, const flea_der_ref_t *signature__pt  );

#ifdef __cplusplus
}
#endif
#endif /* h-guard */

