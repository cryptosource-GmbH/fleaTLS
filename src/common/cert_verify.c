/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "internal/common/ber_dec.h"
#include "flea/x509.h"
#include "flea/pk_api.h"
#include "flea/alloc.h"
#include "flea/hash.h"
#include "flea/array_util.h"
#include "flea/cert_verify.h"
#include "flea/namespace_asn1.h"
#include "flea/ecc.h"
#include "flea/ec_key.h"
#include "flea/ecc_named_curves.h"
#include "flea/pubkey.h"

#ifdef FLEA_HAVE_ASYM_SIG

flea_err_t THR_flea_x509_verify_cert_signature(const flea_u8_t *enc_subject_cert__pcu8, flea_dtl_t enc_subject_cert_len__dtl, const flea_u8_t *enc_issuer_cert__pcu8, flea_dtl_t enc_issuer_cert_len__dtl)
{
  FLEA_DECL_OBJ(subj_ref__t, flea_x509_cert_ref_t);
  FLEA_DECL_OBJ(iss_ref__t, flea_x509_cert_ref_t);
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(&subj_ref__t, enc_subject_cert__pcu8, enc_subject_cert_len__dtl));
  FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(&iss_ref__t, enc_issuer_cert__pcu8, enc_issuer_cert_len__dtl));
  FLEA_CCALL(THR_flea_x509_verify_cert_ref_signature(&subj_ref__t, &iss_ref__t));
  FLEA_THR_FIN_SEC(
    flea_x509_cert_ref_t__dtor(&subj_ref__t);
    flea_x509_cert_ref_t__dtor(&iss_ref__t);
  );
}

flea_err_t THR_flea_x509_verify_cert_ref_signature(const flea_x509_cert_ref_t *subject_cert_ref__pt, const flea_x509_cert_ref_t *issuer_cert_ref__pt)
{
  flea_ref_cu8_t sig_content__t;
  flea_public_key_t key__t = flea_public_key_t__INIT_VALUE;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_public_key_t__ctor_cert(&key__t, issuer_cert_ref__pt));
  FLEA_CCALL(THR_flea_ber_dec__get_ref_to_bit_string_content_no_unused_bits(&subject_cert_ref__pt->cert_signature_as_bit_string__t, &sig_content__t));
  FLEA_CCALL(THR_flea_public_key_t__verify_signature_use_sigalg_id(
      &key__t,
      &subject_cert_ref__pt->tbs_sig_algid__t,
      &subject_cert_ref__pt->tbs_ref__t,
      &sig_content__t
    ));
  FLEA_THR_FIN_SEC(
    flea_public_key_t__dtor(&key__t);
  );
}

#endif /* #ifdef FLEA_HAVE_ASYM_SIG */
