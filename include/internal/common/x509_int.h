/* fleaTLS cryptographic library
Copyright (C) 2015-2019 cryptosource GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

#ifndef _flea_x509_int__H_
#define _flea_x509_int__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "internal/common/ber_dec.h"
#include "flea/x509.h"

#ifdef __cplusplus
extern "C" {
#endif


flea_err_e THR_flea_x509__dec_algid_ref(
  flea_x509_algid_ref_t* algid_ref__pt,
  flea_bdec_t*           dec__pt
);

flea_err_e THR_flea_x509__parse_dn_ref(
  flea_x509_dn_ref_t* dn_ref__pt,
  flea_bdec_t*        dec__pt
);

flea_err_e THR_flea_x509__dec_dn_ref_elements(
  flea_x509_dn_ref_t* dn_ref__pt,
  const flea_u8_t*    data__pcu8,
  flea_dtl_t          data_len__dtl,
  flea_bool_t         with_outer_seq__b
);

flea_err_e THR_flea_x509__process_alg_ids(
  flea_x509_algid_ref_t*       tbs_ref__pt,
  const flea_x509_algid_ref_t* outer_ref__pt
);

flea_err_e THR_flea_x509_cert__parse_key_usage(
  flea_bdec_t*      cont_dec__pt,
  flea_key_usage_t* key_usage__pt
);

flea_err_e THR_flea_x509_cert_parse_basic_constraints(
  flea_bdec_t*              cont_dec__pt,
  flea_basic_constraints_t* basic_constraints__pt
);

flea_err_e THR_flea_x509_cert__parse_eku(
  flea_bdec_t*      cont_dec__pt,
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
