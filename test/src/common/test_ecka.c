/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "flea/error_handling.h"
#include <stdlib.h>
#include <string.h>
#include "flea/error.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/util.h"
#include "flea/ec_gfp_dom_par.h"
#include "flea/ecka.h"
#include "flea/algo_config.h"
#include "flea/ec_key_gen.h"
#include "flea/ecc.h"
#include "self_test.h"

#ifdef FLEA_HAVE_ECKA
//static flea_err_t THR_flea_test_ecka_raw_basic_inner (const flea_u8_t* dp__pcu8)
static flea_err_t THR_flea_test_ecka_raw_basic_inner (const flea_ec_gfp_dom_par_ref_t *dom_par__pt)
{
  FLEA_DECL_BUF(res_a_arr__bu8, flea_u8_t, FLEA_ECC_MAX_MOD_BYTE_SIZE);
  FLEA_DECL_BUF(res_b_arr__bu8, flea_u8_t, FLEA_ECC_MAX_MOD_BYTE_SIZE);

  flea_al_u8_t res_a_len__alu8 = sizeof(res_a_arr__bu8);
  flea_al_u8_t res_b_len__alu8 = sizeof(res_b_arr__bu8);
  flea_al_u8_t pub_point_enc_len__alu8 = FLEA_ECC_MAX_UNCOMPR_POINT_SIZE;
  flea_al_u8_t sk_enc_len__alu8 = FLEA_ECC_MAX_PRIVATE_KEY_BYTE_SIZE;

  flea_al_u8_t pub_point_a_enc_len__alu8 = pub_point_enc_len__alu8;
  flea_al_u8_t pub_point_b_enc_len__alu8 = pub_point_enc_len__alu8;
  flea_al_u8_t sk_a_enc_len__alu8 = sk_enc_len__alu8;
  flea_al_u8_t sk_b_enc_len__alu8 = sk_enc_len__alu8;
  FLEA_DECL_BUF(pub_point_a_enc__bu8, flea_u8_t, pub_point_enc_len__alu8);
  FLEA_DECL_BUF(pub_point_b_enc__bu8, flea_u8_t, pub_point_enc_len__alu8);
  FLEA_DECL_BUF(sk_a_enc__bu8, flea_u8_t, sk_enc_len__alu8);
  FLEA_DECL_BUF(sk_b_enc__bu8, flea_u8_t, sk_enc_len__alu8);


  FLEA_THR_BEG_FUNC();
  //res_a_len__alu8 = res_b_len__alu8 = flea_ec_dom_par__get_elem_len(dp__pcu8, flea_dp__p);
  res_a_len__alu8 = res_b_len__alu8 = dom_par__pt->p__ru8.len__dtl;
  FLEA_ALLOC_BUF(res_a_arr__bu8, res_a_len__alu8);
  FLEA_ALLOC_BUF(res_b_arr__bu8, res_b_len__alu8);
  FLEA_ALLOC_BUF(pub_point_a_enc__bu8, pub_point_enc_len__alu8);
  FLEA_ALLOC_BUF(pub_point_b_enc__bu8, pub_point_enc_len__alu8);
  FLEA_ALLOC_BUF(sk_a_enc__bu8, sk_enc_len__alu8);
  FLEA_ALLOC_BUF(sk_b_enc__bu8, sk_enc_len__alu8);
  FLEA_CCALL(THR_flea_generate_ecc_key(pub_point_a_enc__bu8, &pub_point_a_enc_len__alu8, sk_a_enc__bu8, &sk_a_enc_len__alu8, dom_par__pt));
  FLEA_CCALL(THR_flea_generate_ecc_key(pub_point_b_enc__bu8, &pub_point_b_enc_len__alu8, sk_b_enc__bu8, &sk_b_enc_len__alu8, dom_par__pt));

  FLEA_CCALL(THR_flea_ecka__compute_raw(pub_point_a_enc__bu8, pub_point_a_enc_len__alu8, sk_b_enc__bu8, sk_b_enc_len__alu8, res_b_arr__bu8, &res_b_len__alu8, dom_par__pt));
  FLEA_CCALL(THR_flea_ecka__compute_raw(pub_point_b_enc__bu8, pub_point_b_enc_len__alu8, sk_a_enc__bu8, sk_a_enc_len__alu8, res_a_arr__bu8, &res_a_len__alu8, dom_par__pt));
  if(res_a_len__alu8 != res_b_len__alu8)
  {
    FLEA_THROW("ECKA results differ in length", FLEA_ERR_FAILED_TEST);
  }
  if(memcmp(res_a_arr__bu8, res_b_arr__bu8, res_a_len__alu8))
  {
    FLEA_THROW("ECKA results differ in value", FLEA_ERR_FAILED_TEST);
  }
#if FLEA_ECC_MAX_MOD_BYTE_SIZE >= (224 / 8)
  //res_a_len__alu8 = res_b_len__alu8 = flea_ec_dom_par__get_elem_len(dp__pcu8, flea_dp__p);
  res_a_len__alu8 = res_b_len__alu8 = dom_par__pt->p__ru8.len__dtl;
  FLEA_CCALL(THR_flea_ecka__compute_kdf_ansi_x9_63(flea_sha224, pub_point_a_enc__bu8, pub_point_a_enc_len__alu8, sk_b_enc__bu8, sk_b_enc_len__alu8, NULL, 0, res_b_arr__bu8, res_b_len__alu8, dom_par__pt));
  FLEA_CCALL(THR_flea_ecka__compute_kdf_ansi_x9_63(flea_sha224, pub_point_b_enc__bu8, pub_point_b_enc_len__alu8, sk_a_enc__bu8, sk_a_enc_len__alu8, NULL, 0, res_a_arr__bu8, res_a_len__alu8, dom_par__pt));

  if(memcmp(res_a_arr__bu8, res_b_arr__bu8, res_a_len__alu8))
  {
    FLEA_THROW("ECKA ANSI X9.63 KDF results differ in value", FLEA_ERR_FAILED_TEST);
  }
#endif

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(pub_point_a_enc__bu8);
    FLEA_FREE_BUF_FINAL(pub_point_b_enc__bu8);
    FLEA_FREE_BUF_FINAL(sk_a_enc__bu8);
    FLEA_FREE_BUF_FINAL(sk_b_enc__bu8);
    FLEA_FREE_BUF_FINAL(res_a_arr__bu8);
    FLEA_FREE_BUF_FINAL(res_b_arr__bu8);
    );
}


flea_err_t THR_flea_test_ecka_raw_basic ()
{
  FLEA_THR_BEG_FUNC();
  flea_ec_dom_par_id_t i;
  for(i = 0; i <= flea_gl_ec_dom_par_max_id; i++)
  {
    /*const flea_u8_t* ec_dp = flea_ec_dom_par__get_predefined_dp_ptr(i);
    if(NULL == ec_dp)
    {
      continue;
    }
    FLEA_CCALL(THR_flea_test_ecka_raw_basic_inner(ec_dp));*/

    flea_ec_gfp_dom_par_ref_t dom_par__t;
    flea_err_t err__t = THR_flea_ec_gfp_dom_par_ref_t__set_by_builtin_id(&dom_par__t, i);
    if(err__t)
    {
      if(err__t == FLEA_ERR_ECC_INV_BUILTIN_DP_ID)
      {
        continue;
      }
      else
      {
        FLEA_THROW("an unexpected error occured", FLEA_ERR_FAILED_TEST);
      }
    }
    FLEA_CCALL(THR_flea_test_ecka_raw_basic_inner(&dom_par__t));
  }
  FLEA_THR_FIN_SEC_empty();
}

#endif // #ifdef FLEA_HAVE_ECKA
