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
#include "internal/common/ecc_dp_int.h"
#include "flea/error_handling.h"
#include <stdlib.h>
#include <string.h>
#include "flea/error.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/util.h"
#include "flea/ec_dom_par.h"
#include "flea/ecka.h"
#include "flea/algo_config.h"
#include "flea/ec_key_gen.h"
#include "flea/ecc.h"
#include "self_test.h"

#ifdef FLEA_HAVE_ECKA
static flea_err_e THR_flea_test_ecka_raw_basic_inner(const flea_ec_dom_par_ref_t* dom_par__pt)
{
  FLEA_DECL_BUF(res_a_arr__bu8, flea_u8_t, FLEA_ECC_MAX_MOD_BYTE_SIZE);
  FLEA_DECL_BUF(res_b_arr__bu8, flea_u8_t, FLEA_ECC_MAX_MOD_BYTE_SIZE);

  flea_al_u8_t res_a_len__alu8         = sizeof(res_a_arr__bu8);
  flea_al_u8_t res_b_len__alu8         = sizeof(res_b_arr__bu8);
  flea_al_u8_t pub_point_enc_len__alu8 = FLEA_ECC_MAX_UNCOMPR_POINT_SIZE;
  flea_al_u8_t sk_enc_len__alu8        = FLEA_ECC_MAX_PRIVATE_KEY_BYTE_SIZE;

  flea_al_u8_t pub_point_a_enc_len__alu8 = pub_point_enc_len__alu8;
  flea_al_u8_t pub_point_b_enc_len__alu8 = pub_point_enc_len__alu8;
  flea_al_u8_t sk_a_enc_len__alu8        = sk_enc_len__alu8;
  flea_al_u8_t sk_b_enc_len__alu8        = sk_enc_len__alu8;
  FLEA_DECL_BUF(pub_point_a_enc__bu8, flea_u8_t, pub_point_enc_len__alu8);
  FLEA_DECL_BUF(pub_point_b_enc__bu8, flea_u8_t, pub_point_enc_len__alu8);
  FLEA_DECL_BUF(sk_a_enc__bu8, flea_u8_t, sk_enc_len__alu8);
  FLEA_DECL_BUF(sk_b_enc__bu8, flea_u8_t, sk_enc_len__alu8);


  FLEA_THR_BEG_FUNC();
  res_a_len__alu8 = res_b_len__alu8 = dom_par__pt->p__ru8.len__dtl;
  FLEA_ALLOC_BUF(res_a_arr__bu8, res_a_len__alu8);
  FLEA_ALLOC_BUF(res_b_arr__bu8, res_b_len__alu8);
  FLEA_ALLOC_BUF(pub_point_a_enc__bu8, pub_point_enc_len__alu8);
  FLEA_ALLOC_BUF(pub_point_b_enc__bu8, pub_point_enc_len__alu8);
  FLEA_ALLOC_BUF(sk_a_enc__bu8, sk_enc_len__alu8);
  FLEA_ALLOC_BUF(sk_b_enc__bu8, sk_enc_len__alu8);
  FLEA_CCALL(
    THR_flea_generate_ecc_key(
      pub_point_a_enc__bu8,
      &pub_point_a_enc_len__alu8,
      sk_a_enc__bu8,
      &sk_a_enc_len__alu8,
      dom_par__pt
    )
  );
  FLEA_CCALL(
    THR_flea_generate_ecc_key(
      pub_point_b_enc__bu8,
      &pub_point_b_enc_len__alu8,
      sk_b_enc__bu8,
      &sk_b_enc_len__alu8,
      dom_par__pt
    )
  );

  FLEA_CCALL(
    THR_flea_ecka__compute_raw(
      pub_point_a_enc__bu8,
      pub_point_a_enc_len__alu8,
      sk_b_enc__bu8,
      sk_b_enc_len__alu8,
      res_b_arr__bu8,
      &res_b_len__alu8,
      dom_par__pt
    )
  );
  FLEA_CCALL(
    THR_flea_ecka__compute_raw(
      pub_point_b_enc__bu8,
      pub_point_b_enc_len__alu8,
      sk_a_enc__bu8,
      sk_a_enc_len__alu8,
      res_a_arr__bu8,
      &res_a_len__alu8,
      dom_par__pt
    )
  );
  if(res_a_len__alu8 != res_b_len__alu8)
  {
    FLEA_THROW("ECKA results differ in length", FLEA_ERR_FAILED_TEST);
  }
  if(memcmp(res_a_arr__bu8, res_b_arr__bu8, res_a_len__alu8))
  {
    FLEA_THROW("ECKA results differ in value", FLEA_ERR_FAILED_TEST);
  }
# if FLEA_ECC_MAX_MOD_BYTE_SIZE >= (224 / 8)
  res_a_len__alu8 = res_b_len__alu8 = dom_par__pt->p__ru8.len__dtl;
  FLEA_CCALL(
    THR_flea_ecka__compute_ecka_with_kdf_ansi_x9_63(
      flea_sha224,
      pub_point_a_enc__bu8,
      pub_point_a_enc_len__alu8,
      sk_b_enc__bu8,
      sk_b_enc_len__alu8,
      NULL,
      0,
      res_b_arr__bu8,
      res_b_len__alu8,
      dom_par__pt
    )
  );
  FLEA_CCALL(
    THR_flea_ecka__compute_ecka_with_kdf_ansi_x9_63(
      flea_sha224,
      pub_point_b_enc__bu8,
      pub_point_b_enc_len__alu8,
      sk_a_enc__bu8,
      sk_a_enc_len__alu8,
      NULL,
      0,
      res_a_arr__bu8,
      res_a_len__alu8,
      dom_par__pt
    )
  );

  if(memcmp(res_a_arr__bu8, res_b_arr__bu8, res_a_len__alu8))
  {
    FLEA_THROW("ECKA ANSI X9.63 KDF results differ in value", FLEA_ERR_FAILED_TEST);
  }
# endif /* if FLEA_ECC_MAX_MOD_BYTE_SIZE >= (224 / 8) */

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(pub_point_a_enc__bu8);
    FLEA_FREE_BUF_FINAL(pub_point_b_enc__bu8);
    FLEA_FREE_BUF_FINAL(sk_a_enc__bu8);
    FLEA_FREE_BUF_FINAL(sk_b_enc__bu8);
    FLEA_FREE_BUF_FINAL(res_a_arr__bu8);
    FLEA_FREE_BUF_FINAL(res_b_arr__bu8);
  );
} /* THR_flea_test_ecka_raw_basic_inner */

flea_err_e THR_flea_test_ecka_raw_basic()
{
  FLEA_THR_BEG_FUNC();
  flea_ec_dom_par_id_e i;
  for(i = 0; i <= flea_gl_ec_dom_par_max_id; i++)
  {
    flea_ec_dom_par_ref_t dom_par__t;
    flea_err_e err__t = THR_flea_ec_dom_par_ref_t__set_by_builtin_id(&dom_par__t, i);
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
