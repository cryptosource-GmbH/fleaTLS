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


#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "internal/common/ber_dec.h"
#include "flea/x509.h"
#include "flea/pk_signer.h"
#include "flea/alloc.h"
#include "flea/hash.h"
#include "flea/array_util.h"
#include "flea/cert_verify.h"
#include "flea/ecc.h"
#include "internal/common/namespace_asn1.h"
#include "flea/ec_key.h"
#include "flea/ecc_named_curves.h"
#include "flea/pubkey.h"
#include "internal/common/cert_info_int.h"
#include "internal/common/cert_verify_int.h"

#ifdef FLEA_HAVE_ASYM_SIG
static flea_err_e THR_flea_x509_verify_cert_ref_signature_inner(
  const flea_x509_cert_ref_t*  subject_cert_ref__pt,
  const flea_byte_vec_t*       subject_tbs_ref__prcu8,
  const flea_x509_cert_ref_t*  issuer_cert_ref__pt,
  flea_x509_validation_flags_e cert_ver_flags__e
)
{
  flea_byte_vec_t sig_content__t;
  flea_pubkey_t key__t;

  FLEA_THR_BEG_FUNC();
  flea_pubkey_t__INIT(&key__t);
  FLEA_CCALL(THR_flea_pubkey_t__ctor_cert(&key__t, issuer_cert_ref__pt));
  FLEA_CCALL(
    THR_flea_ber_dec__get_ref_to_bit_string_content_no_unused_bits(
      &subject_cert_ref__pt->
      cert_signature_as_bit_string__t,
      &sig_content__t
    )
  );
  FLEA_CCALL(
    THR_flea_pubkey_t__vrfy_sgntr_use_sigalg_id(
      &key__t,
      &subject_cert_ref__pt->tbs_sig_algid__t,
      subject_tbs_ref__prcu8,
      &sig_content__t,
      cert_ver_flags__e
    )
  );
  FLEA_THR_FIN_SEC(
    flea_pubkey_t__dtor(&key__t);
  );
}

flea_err_e THR_flea_x509_verify_cert_signature(
  const flea_u8_t*             enc_subject_cert__pcu8,
  flea_dtl_t                   enc_subject_cert_len__dtl,
  const flea_u8_t*             enc_issuer_cert__pcu8,
  flea_dtl_t                   enc_issuer_cert_len__dtl,
  flea_x509_validation_flags_e cert_ver_flags__e
)
{
  flea_x509_cert_ref_t subj_ref__t;
  flea_x509_cert_ref_t iss_ref__t;
  flea_byte_vec_t subj_tbs_ref__rcu8 = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE;

  FLEA_THR_BEG_FUNC();
  flea_x509_cert_ref_t__INIT(&subj_ref__t);
  flea_x509_cert_ref_t__INIT(&iss_ref__t);
  FLEA_CCALL(
    THR_flea_x509_cert__get_bv_ref_to_tbs(
      enc_subject_cert__pcu8,
      enc_subject_cert_len__dtl,
      &subj_tbs_ref__rcu8
    )
  );
  FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(&subj_ref__t, enc_subject_cert__pcu8, enc_subject_cert_len__dtl));
  FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(&iss_ref__t, enc_issuer_cert__pcu8, enc_issuer_cert_len__dtl));
  FLEA_CCALL(
    THR_flea_x509_verify_cert_ref_signature_inner(
      &subj_ref__t,
      &subj_tbs_ref__rcu8,
      &iss_ref__t,
      cert_ver_flags__e
    )
  );
  FLEA_THR_FIN_SEC(
    flea_x509_cert_ref_t__dtor(&subj_ref__t);
    flea_x509_cert_ref_t__dtor(&iss_ref__t);
  );
}

flea_err_e THR_flea_x509_verify_cert_info_signature(
  const flea_x509_cert_info_t* subject_cert_ref__pt,
  const flea_x509_cert_info_t* issuer_cert_ref__pt,
  flea_x509_validation_flags_e cert_ver_flags__e
)
{
  return THR_flea_x509_verify_cert_ref_signature_inner(
    &subject_cert_ref__pt->cert_ref__t,
    &subject_cert_ref__pt->ref_to_tbs__rcu8,
    &issuer_cert_ref__pt->cert_ref__t,
    cert_ver_flags__e
  );
}

#endif /* #ifdef FLEA_HAVE_ASYM_SIG */
