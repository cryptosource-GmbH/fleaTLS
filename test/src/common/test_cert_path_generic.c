/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "flea/cert_chain.h"
#include "flea/asn1_date.h"
#include "flea/ber_dec.h"
#include "flea/pubkey.h"
#include "test_data_x509_certs.h"
#include "flea/rng.h"

#if defined FLEA_HAVE_RSA && (defined FLEA_USE_HEAP_BUF || FLEA_RSA_MAX_KEY_BIT_SIZE >= 4096)
flea_err_t THR_flea_test_cert_path_generic(
    const flea_u8_t *target_cert_ptr,
    flea_u32_t target_cert_len,
    flea_u8_t **trust_anchor_ptrs,
    flea_u32_t *trust_anchor_lens,
    flea_u32_t nb_trust_anchors,
    flea_u8_t **cert_ptrs,
    flea_u32_t *cert_lens,
    flea_u32_t nb_certs,
    const flea_u8_t* validation_date_utctime, 
    flea_al_u16_t validation_date_utctime_len
    )
{

  flea_public_key_t target_pubkey__t = flea_public_key_t__INIT_VALUE;
  const flea_bool_t is_valid_chain = FLEA_TRUE;
  flea_x509_cert_ref_t cert_refs[20] = { {.is_trusted__b = 0 } }; // TODO: THIS WILL CHANGE
  flea_u32_t cert_ref_pos = 0;
  //flea_u32_t ta_pos = 0;
  //flea_u32_t cert_pos = 0;
  flea_err_t err;
  FLEA_DECL_OBJ(cert_chain__t, flea_cert_chain_t);
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(&cert_refs[cert_ref_pos], &target_cert_ptr[0], target_cert_len ));
  FLEA_CCALL(THR_flea_cert_chain_t__ctor(&cert_chain__t, &cert_refs[cert_ref_pos] ));
  flea_gmt_time_t time__t;
  cert_ref_pos++;
  while(nb_trust_anchors || nb_certs)
  {
    const flea_u8_t use_the_one_with_some_left = 0;
    const flea_u8_t use_ta = 1;
    const flea_u8_t use_cert = 2;
    flea_u8_t what_to_use = use_the_one_with_some_left;
    //printf("nb_trust_anchors = %u, nb_certs = %u\n", nb_trust_anchors, nb_certs);
    flea_u32_t i;
    flea_rng__randomize((flea_u8_t*)&i, sizeof(i));
    if(nb_trust_anchors && nb_certs)
    {
      flea_u8_t r;
      flea_rng__randomize(&r, 1);
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
      FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(&cert_refs[cert_ref_pos], trust_anchor_ptrs[i], trust_anchor_lens[i] ));
      FLEA_CCALL(THR_flea_cert_chain_t__add_trust_anchor_cert(&cert_chain__t, &cert_refs[cert_ref_pos]));
      cert_ref_pos++; 
      trust_anchor_ptrs[i] = trust_anchor_ptrs[nb_trust_anchors - 1];
      trust_anchor_lens[i] = trust_anchor_lens[nb_trust_anchors - 1];
      nb_trust_anchors--;
    }
    else 
    {
      i %= nb_certs;
      FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(&cert_refs[cert_ref_pos], cert_ptrs[i], cert_lens[i] ));
      FLEA_CCALL(THR_flea_cert_chain_t__add_cert_without_trust_status(&cert_chain__t, &cert_refs[cert_ref_pos]));
      cert_ref_pos++; 
      cert_ptrs[i] = cert_ptrs[nb_certs - 1];
      cert_lens[i] = cert_lens[nb_certs - 1];
      nb_certs--;
    }


  }
  FLEA_CCALL(THR_flea_asn1_parse_utc_time(validation_date_utctime, validation_date_utctime_len, &time__t));
  flea_cert_chain_t__disable_revocation_checking(&cert_chain__t);
  err = THR_flea_cert_chain__build_and_verify_cert_chain_and_create_pub_key(&cert_chain__t, &time__t, &target_pubkey__t);
  if(is_valid_chain)
  {
    if(err)
    {
      FLEA_THROW("error in verification of correct certificate path", err);
    }
  }
  else if(!err)
  {
    FLEA_THROW("accepted an incorrect certificate path", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
      flea_cert_chain_t__dtor(&cert_chain__t); 
      flea_public_key_t__dtor(&target_pubkey__t);
      );
}
    
    
#endif /* #if defined FLEA_HAVE_RSA && (defined FLEA_USE_HEAP_BUF || FLEA_RSA_MAX_KEY_BIT_SIZE >= 4096) */
