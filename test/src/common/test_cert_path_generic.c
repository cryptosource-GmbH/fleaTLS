/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "flea/cert_path.h"
#include "flea/asn1_date.h"
#include "internal/common/ber_dec.h"
#include "flea/pubkey.h"
#include "test_data_x509_certs.h"
#include "flea/rng.h"
#include "flea/hostn_ver.h"
#include "self_test.h"

#if defined FLEA_HAVE_RSA && (defined FLEA_USE_HEAP_BUF || FLEA_RSA_MAX_KEY_BIT_SIZE >= 4096)
flea_err_e THR_flea_test_cert_path_generic(
  const flea_u8_t*      target_cert_ptr,
  flea_u32_t            target_cert_len,
  flea_u8_t**           trust_anchor_ptrs,
  flea_u32_t*           trust_anchor_lens,
  flea_u32_t            nb_trust_anchors,
  flea_u8_t**           cert_ptrs,
  flea_u32_t*           cert_lens,
  flea_u32_t            nb_certs,
  flea_u8_t**           crl_ptrs,
  flea_u32_t*           crl_lens,
  flea_u32_t            nb_crls,
  const flea_u8_t*      validation_date_utctime,
  flea_al_u16_t         validation_date_utctime_len,
  flea_rev_chk_mode_e   rev_chk_mode__e,
  const flea_ref_cu8_t* host_id_mbn__pcrcu8,
  flea_host_id_type_e   host_id_type
)
{
  flea_public_key_t target_pubkey__t = flea_public_key_t__INIT_VALUE;

  /** this parameter is actually superflous and misleading, the caller evaluates
   * the test result: */
  const flea_bool_t is_valid_chain = FLEA_TRUE;
  flea_err_e err;

  FLEA_DECL_OBJ(cert_chain__t, flea_cert_path_validator_t);
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(
    THR_flea_cert_path_validator_t__ctor_cert(
      &cert_chain__t,
      &target_cert_ptr[0],
      target_cert_len,
      rev_chk_mode__e,
      flea_x509_validation_allow_sha1
    )
  );
  flea_gmt_time_t time__t;
  while(nb_trust_anchors || nb_certs)
  {
    const flea_u8_t use_the_one_with_some_left = 0;
    const flea_u8_t use_ta   = 1;
    const flea_u8_t use_cert = 2;
    flea_u8_t what_to_use    = use_the_one_with_some_left;
    flea_u32_t i;
    FLEA_CCALL(THR_flea_rng__randomize((flea_u8_t*) &i, sizeof(i)));
    if(nb_trust_anchors && nb_certs)
    {
      flea_u8_t r;
      FLEA_CCALL(THR_flea_rng__randomize(&r, 1));
      if(r & 1)
      {
        what_to_use = use_ta;
      }
      else
      {
        what_to_use = use_cert;
      }
    }
    if((what_to_use == use_ta) || ((what_to_use == use_the_one_with_some_left) && nb_trust_anchors))
    {
      i %= nb_trust_anchors;
      FLEA_CCALL(
        THR_flea_cert_path_validator_t__add_trust_anchor_cert(
          &cert_chain__t,
          trust_anchor_ptrs[i],
          trust_anchor_lens[i]
        )
      );
      trust_anchor_ptrs[i] = trust_anchor_ptrs[nb_trust_anchors - 1];
      trust_anchor_lens[i] = trust_anchor_lens[nb_trust_anchors - 1];
      nb_trust_anchors--;
    }
    else
    {
      i %= nb_certs;
      FLEA_CCALL(
        THR_flea_cert_path_validator_t__add_cert_without_trust_status(
          &cert_chain__t,
          cert_ptrs[i],
          cert_lens[i]
        )
      );

      cert_ptrs[i] = cert_ptrs[nb_certs - 1];
      cert_lens[i] = cert_lens[nb_certs - 1];
      nb_certs--;
    }
  }
  while(nb_crls)
  {
    flea_u32_t i;
    FLEA_CCALL(THR_flea_rng__randomize((flea_u8_t*) &i, sizeof(i)));
    i %= nb_crls;
    FLEA_CCALL(THR_flea_cert_path_validator_t__add_crl(&cert_chain__t, crl_ptrs[i], crl_lens[i]));

    crl_ptrs[i] = crl_ptrs[nb_crls - 1];
    crl_lens[i] = crl_lens[nb_crls - 1];
    nb_crls--;
  }
  FLEA_CCALL(THR_flea_asn1_parse_utc_time(validation_date_utctime, validation_date_utctime_len, &time__t));
  if(host_id_mbn__pcrcu8)
  {
    flea_byte_vec_t host_id_vec__t = flea_byte_vec_t__CONSTR_EXISTING_BUF_CONTENT_NOT_ALLOCATABLE(
      host_id_mbn__pcrcu8->data__pcu8,
      host_id_mbn__pcrcu8->len__dtl
      );
    err = THR_flea_cert_path_validator__build_and_verify_cert_chain_and_hostid_and_create_pub_key(
      &cert_chain__t,
      &time__t,
      &host_id_vec__t,
      host_id_type,
      &target_pubkey__t
      );
  }
  else
  {
    err = THR_flea_cert_path_validator__build_and_verify_cert_chain_and_create_pub_key(
      &cert_chain__t,
      &time__t,
      &target_pubkey__t
      );
  }
  if(is_valid_chain)
  {
    if(err)
    {
      FLEA_THROW("failed cert verification", err);
    }
  }
  else if(!err)
  {
    FLEA_THROW("success of cert verification", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    flea_cert_path_validator_t__dtor(&cert_chain__t);
    flea_public_key_t__dtor(&target_pubkey__t);
  );
} /* THR_flea_test_cert_path_generic */

#endif /* #if defined FLEA_HAVE_RSA && (defined FLEA_USE_HEAP_BUF || FLEA_RSA_MAX_KEY_BIT_SIZE >= 4096) */
