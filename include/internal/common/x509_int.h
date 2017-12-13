#ifndef _flea_x509_int__H_
#define _flea_x509_int__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "internal/common/ber_dec.h"
#include "flea/x509.h"

#ifdef __cplusplus
extern "C" {
#endif


flea_err_t THR_flea_x509__decode_algid_ref(
  flea_x509_algid_ref_t* algid_ref__pt,
  flea_ber_dec_t*        dec__pt
);

flea_err_t THR_flea_x509__parse_dn_ref(
  flea_x509_dn_ref_t* dn_ref__pt,
  flea_ber_dec_t*     dec__pt
);

flea_err_t THR_flea_x509__decode_dn_ref_elements(
  flea_x509_dn_ref_t* dn_ref__pt,
  const flea_u8_t*    data__pcu8,
  flea_dtl_t          data_len__dtl,
  flea_bool_t         with_outer_seq__b
);

flea_err_t THR_flea_x509__process_alg_ids(
  flea_x509_algid_ref_t*       tbs_ref__pt,
  const flea_x509_algid_ref_t* outer_ref__pt
);

flea_err_t THR_flea_x509_cert__parse_key_usage(
  flea_ber_dec_t*   cont_dec__pt,
  flea_key_usage_t* key_usage__pt
);

flea_err_t THR_flea_x509_cert_parse_basic_constraints(
  flea_ber_dec_t*           cont_dec__pt,
  flea_basic_constraints_t* basic_constraints__pt
);

flea_err_t THR_flea_x509_cert__parse_eku(
  flea_ber_dec_t*   cont_dec__pt,
  flea_key_usage_t* ext_key_usage__pt
);

flea_bool_t flea_x509_has_key_usages(
  flea_key_usage_t const*      key_usage__t,
  flea_key_usage_e             required_usages__u16,
  flea_key_usage_exlicitness_e explicitness
);

flea_bool_t flea_x509_has_extended_key_usages(
  flea_key_usage_t const*      key_usage__pt,
  flea_key_usage_e             required_usages__u16,
  flea_key_usage_exlicitness_e explicitness__e
);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
