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

typedef enum
{
  /** check revocation information for all certificates in the path */
  flea_rev_chk_all,

  /** do not check revocation at all */
  flea_rev_chk_none,

  /** check revocation information only for the end entity certificate, i.e.
   * target certificate */
  flea_rev_chk_only_ee
} flea_rev_chk_mode_e;


flea_err_t THR_flea_crl__check_revocation_status(
  const flea_ref_cu8_t*        crl_der__cprcu8,
  flea_al_u16_t                nb_crls__alu16,
  const flea_gmt_time_t*       verification_date__pt,
  flea_bool_t                  is_ca_cert__b,
  const flea_byte_vec_t*       subjects_issuer_dn_raw__pt,
  const flea_byte_vec_t*       subjects_sn__pt,
  const flea_byte_vec_t*       subjects_crldp_raw__pt,
  const flea_public_key_t*     issuers_public_key__pt,
  flea_x509_validation_flags_e cert_ver_flags__e
);

#endif // ifdef FLEA_HAVE_ASYM_ALGS

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
