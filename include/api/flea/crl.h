/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_crl__H_
#define _flea_crl__H_

#include "internal/common/default.h"
#include "flea/x509.h"
#include "flea/pubkey.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef FLEA_HAVE_ASYM_ALGS

typedef enum { flea_revstat_undetermined, flea_revstat_revoked, flea_revstat_good } flea_revocation_status_e;

flea_err_t THR_flea_crl__check_revocation_status(

  /*const flea_x509_cert_ref_t* subject__pt,
   * const flea_x509_cert_ref_t* issuer__pt,*/
  const flea_byte_vec_t*   crl_der__cprcu8,
  flea_al_u16_t            nb_crls__alu16,
  const flea_gmt_time_t*   verification_date__pt,
  flea_bool_t              is_ca_cert__b,
  const flea_byte_vec_t*   subjects_issuer_dn_raw__pt,
  const flea_byte_vec_t*   subjects_sn__pt,
  const flea_byte_vec_t*   subjects_crldp_raw__pt,
  const flea_public_key_t* issuers_public_key__pt
);

/*
 * flea_err_t THR_flea_crl__check_revocation_status_crl_stream(
 * const flea_x509_cert_ref_t* subject__pt,
 * const flea_x509_cert_ref_t* issuer__pt,
 * const flea_byte_vec_t*      crl_der__cprcu8,
 * flea_al_u16_t               nb_crls__alu16,
 * const flea_gmt_time_t*      verification_date__pt,
 * flea_bool_t                 is_ca_cert__b,
 * const flea_byte_vec_t*      subjects_issuer_dn_raw__pt,
 * const flea_byte_vec_t*      subjects_sn__pt,
 * const flea_byte_vec_t*      subjects_crldp_raw__pt,
 * const flea_public_key_t*    issuers_public_key__pt
 * );*/

#endif // ifdef FLEA_HAVE_ASYM_ALGS

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
