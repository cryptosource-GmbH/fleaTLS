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

#ifndef _flea_crl__H_
#define _flea_crl__H_

#include "internal/common/default.h"
#include "flea/x509.h"
#include "flea/pubkey.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef FLEA_HAVE_ASYM_ALGS


flea_err_e THR_flea_crl__check_revocation_status(
  const flea_ref_cu8_t*        crl_der__cprcu8,
  flea_al_u16_t                nb_crls__alu16,
  const flea_gmt_time_t*       verification_date__pt,
  flea_bool_t                  is_ca_cert__b,
  const flea_byte_vec_t*       subjects_issuer_dn_raw__pt,
  const flea_byte_vec_t*       subjects_sn__pt,
  const flea_byte_vec_t*       subjects_crldp_raw__pt,
  const flea_pubkey_t*         issuers_public_key__pt,
  flea_x509_validation_flags_e cert_ver_flags__e
);

#endif // ifdef FLEA_HAVE_ASYM_ALGS

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
