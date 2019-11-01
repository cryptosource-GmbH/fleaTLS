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
#include "flea/error.h"
#include "flea/util.h"
#include "flea/alloc.h"
#include "flea/rsa.h"
#include "flea/mac.h"
#include "self_test.h"
#include <string.h>

#ifdef FLEA_HAVE_MAC

static flea_err_e THR_flea_test_mac__init_dtor(void)
{
  flea_mac_ctx_t ctx__t;

  flea_mac_ctx_t__INIT(&ctx__t);
  flea_mac_ctx_t ctx2__t;
  FLEA_THR_BEG_FUNC();
  flea_mac_ctx_t__INIT(&ctx2__t);

  FLEA_THR_FIN_SEC(
    flea_mac_ctx_t__dtor(&ctx__t);
    flea_mac_ctx_t__dtor(&ctx2__t);
  );
}

# ifdef FLEA_HAVE_HMAC
#  ifdef FLEA_HAVE_SHA224_256
static flea_err_e THR_flea_test_mac_special_1(void)
{
  // Test with 64B key as input
  flea_u8_t ctr   = 0;
  flea_u8_t key[] = {0x1, 0x41, 0xf1, 0x31, 0x33, 0x4e, 0xb4, 0x30, 0xc, 0x5d, 0x7f, 0x66, 0x71, 0xf4, 0xad, 0x22, 0xe0, 0x44, 0x7a, 0xe4, 0x46, 0x85, 0x9a, 0x1b, 0x89, 0xfb, 0xf2, 0x9, 0x71, 0xaa, 0x21, 0x43, 0x7c, 0x3a, 0x9f, 0x98, 0xee, 0xdf, 0x54, 0xa, 0x1b, 0xb8, 0x29, 0x78, 0x5, 0xa2, 0x81, 0xb2, 0x94, 0xff, 0xb3, 0x41, 0x8c, 0x90, 0x25, 0xb4, 0x50, 0xb6, 0x92, 0x9b, 0x30, 0xc8, 0xc, 0xc7};
  flea_mac_ctx_t mac_ctx__t;
  flea_u8_t i;
  flea_u8_t sha256_hmac[32];
  flea_u8_t sha256_hash[32];
  flea_al_u8_t sha256_hmac_len = sizeof(sha256_hmac);

  FLEA_THR_BEG_FUNC();
  flea_mac_ctx_t__INIT(&mac_ctx__t);
  FLEA_CCALL(THR_flea_mac_ctx_t__ctor(&mac_ctx__t, flea_hmac_sha256, key, sizeof(key)));

  FLEA_CCALL(THR_flea_mac_ctx_t__update(&mac_ctx__t, key, sizeof(key)));
  FLEA_CCALL(THR_flea_mac_ctx_t__final_compute(&mac_ctx__t, sha256_hmac, &sha256_hmac_len));

  FLEA_CCALL(THR_flea_compute_hash(flea_sha256, sha256_hmac, sizeof(sha256_hmac), sha256_hash, sizeof(sha256_hash)));


  for(i = 0; i < sizeof(sha256_hash); i++)
  {
    if(sha256_hash[i] == 0)
    {
      ctr++;
    }
  }
  if(ctr > sizeof(sha256_hash))
  {
    // should never happen since ctr can't reach this value
    FLEA_THROW("ERROR", FLEA_ERR_INV_MAC);
  }
  FLEA_THR_FIN_SEC(
    flea_mac_ctx_t__dtor(&mac_ctx__t);
  );
} /* THR_flea_test_mac_special_1 */

#  endif /* ifdef FLEA_HAVE_SHA224_256 */
# endif  /* ifdef FLEA_HAVE_HMAC */

static flea_err_e THR_flea_test_mac__final_verify_and_compute_mac(
  flea_mac_id_e    id__t,
  const flea_u8_t* key__pcu8,
  flea_al_u16_t    key_len__alu16,
  const flea_u8_t* input__pcu8,
  flea_al_u16_t    input_len__alu16,
  const flea_u8_t* exp_res__pcu8,
  flea_al_u16_t    exp_res_len__alu16
)
{
  FLEA_DECL_BUF(mac__bu8, flea_u8_t, FLEA_MAC_MAX_OUTPUT_LENGTH);
  flea_mac_ctx_t ctx__t;
  flea_mac_ctx_t__INIT(&ctx__t);
  flea_al_u8_t mac_len__alu8;
  FLEA_THR_BEG_FUNC();
/* ! [mac_update_example] */
  FLEA_CCALL(THR_flea_mac_ctx_t__ctor(&ctx__t, id__t, key__pcu8, key_len__alu16));
  FLEA_ALLOC_BUF(mac__bu8, ctx__t.output_len__u8);
  mac_len__alu8 = ctx__t.output_len__u8;
  if(input_len__alu16 > 2)
  {
    FLEA_CCALL(THR_flea_mac_ctx_t__update(&ctx__t, input__pcu8, 1));
    FLEA_CCALL(THR_flea_mac_ctx_t__update(&ctx__t, input__pcu8 + 1, input_len__alu16 - 1));
  }
  else
  {
    FLEA_CCALL(THR_flea_mac_ctx_t__update(&ctx__t, input__pcu8, input_len__alu16));
  }
  FLEA_CCALL(THR_flea_mac_ctx_t__final_verify(&ctx__t, exp_res__pcu8, exp_res_len__alu16));
/* ! [mac_update_example] */

  FLEA_CCALL(
    THR_flea_mac__compute_mac(
      id__t,
      key__pcu8,
      key_len__alu16,
      input__pcu8,
      input_len__alu16,
      mac__bu8,
      &mac_len__alu8
    )
  );

  if((mac_len__alu8 != exp_res_len__alu16) || memcmp(exp_res__pcu8, mac__bu8, exp_res_len__alu16))
  {
    FLEA_THROW("error with computed MAC", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    flea_mac_ctx_t__dtor(&ctx__t);
    FLEA_FREE_BUF_FINAL(mac__bu8);
  );
} /* THR_flea_test_mac__final_verify_and_compute_mac */

static flea_err_e THR_flea_test_mac__update_with_frag_len_list(
  flea_mac_id_e    id__t,
  const flea_u8_t* key__pcu8,
  flea_al_u16_t    key_len__alu16,
  const flea_u8_t* input__pcu8,
  flea_al_u16_t    input_len__alu16,
  const flea_u8_t* exp_res__pcu8,
  flea_al_u16_t    exp_res_len__alu16,
  const flea_u8_t* frag_len_list__pcu8,
  flea_al_u16_t    frag_len_list_len__alu16
)
{
  flea_mac_ctx_t ctx__t;
  flea_al_u8_t mac_len__alu8, i;

  FLEA_DECL_BUF(mac__bu8, flea_u8_t, FLEA_MAC_MAX_OUTPUT_LENGTH);
  FLEA_THR_BEG_FUNC();
  flea_mac_ctx_t__INIT(&ctx__t);
  FLEA_CCALL(THR_flea_mac_ctx_t__ctor(&ctx__t, id__t, key__pcu8, key_len__alu16));
  mac_len__alu8 = ctx__t.output_len__u8;
  FLEA_ALLOC_BUF(mac__bu8, ctx__t.output_len__u8);
  for(i = 0; i < frag_len_list_len__alu16; i++)
  {
    // also calls to update  with length 0 occur in this loop under certain
    // conditions
    flea_al_u16_t this_update__alu16 = FLEA_MIN(frag_len_list__pcu8[i], input_len__alu16);
    FLEA_CCALL(THR_flea_mac_ctx_t__update(&ctx__t, input__pcu8, this_update__alu16));
    input__pcu8      += this_update__alu16;
    input_len__alu16 -= this_update__alu16;
  }
  // feed the remaining part:
  FLEA_CCALL(THR_flea_mac_ctx_t__update(&ctx__t, input__pcu8, input_len__alu16));

  FLEA_CCALL(THR_flea_mac_ctx_t__final_compute(&ctx__t, mac__bu8, &mac_len__alu8));
  if(mac_len__alu8 != ctx__t.output_len__u8)
  {
    FLEA_THROW("error with MAC length in update test", FLEA_ERR_FAILED_TEST);
  }
  // NOTE: DO NOT USE memcmp() FOR MAC VERIFICATION IN PRODUCTION CODE!
  if(memcmp(mac__bu8, exp_res__pcu8, mac_len__alu8))
  {
    FLEA_THROW("error with MAC value in update test", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    flea_mac_ctx_t__dtor(&ctx__t);
    FLEA_FREE_BUF_FINAL(mac__bu8);
  );
} /* THR_flea_test_mac__update_with_frag_len_list */

static flea_err_e THR_flea_test_mac__update(
  flea_mac_id_e    id__t,
  const flea_u8_t* key__pcu8,
  flea_al_u16_t    key_len__alu16,
  const flea_u8_t* input__pcu8,
  flea_al_u16_t    input_len__alu16,
  const flea_u8_t* exp_res__pcu8,
  flea_al_u16_t    exp_res_len__alu16
)
{
  flea_u8_t frag_len_list_0__au8[] = {1, 15, 7, 13, 12, 17, 33, 1, 83};
  flea_u8_t frag_len_list_1__au8[] = {
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1
  };
  flea_u8_t frag_len_list_2__au8[] = {
    1, 2, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 3, 1, 1, 1, 1,
    1, 6, 1, 3, 1, 1, 1, 1,
    1, 1, 1, 2, 1, 1, 1, 1,
    1, 1, 1, 3, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 3, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 3, 1, 1, 1, 1,
    1, 1, 1, 5, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 2, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 3, 1, 1, 1, 1,
    1, 1, 1, 3, 1, 1, 1, 1,
    1, 1, 1, 3, 2, 1, 1, 1,
    1, 1, 1, 2, 1, 1, 1, 1,
    1, 1, 1, 3, 1, 1, 1, 1,
    1, 1, 1, 3, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1
  };
  flea_u8_t frag_len_list_3__au8[] = {33, 1, 1, 13, 12, 17, 33, 1, 3};
  flea_u8_t frag_len_list_4__au8[] = {47, 1, 1, 13, 12, 17, 33, 1, 42};
  flea_u8_t frag_len_list_5__au8[] = {48, 1, 1, 7, 14, 13, 1, 1, 1};
  flea_u8_t frag_len_list_6__au8[] = {49, 1, 1, 13, 12, 17, 33, 1, 11};

  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(
    THR_flea_test_mac__update_with_frag_len_list(
      id__t,
      key__pcu8,
      key_len__alu16,
      input__pcu8,
      input_len__alu16,
      exp_res__pcu8,
      exp_res_len__alu16,
      frag_len_list_0__au8,
      sizeof(frag_len_list_0__au8)
    )
  );
  FLEA_CCALL(
    THR_flea_test_mac__update_with_frag_len_list(
      id__t,
      key__pcu8,
      key_len__alu16,
      input__pcu8,
      input_len__alu16,
      exp_res__pcu8,
      exp_res_len__alu16,
      frag_len_list_1__au8,
      sizeof(frag_len_list_1__au8)
    )
  );
  FLEA_CCALL(
    THR_flea_test_mac__update_with_frag_len_list(
      id__t,
      key__pcu8,
      key_len__alu16,
      input__pcu8,
      input_len__alu16,
      exp_res__pcu8,
      exp_res_len__alu16,
      frag_len_list_2__au8,
      sizeof(frag_len_list_2__au8)
    )
  );
  FLEA_CCALL(
    THR_flea_test_mac__update_with_frag_len_list(
      id__t,
      key__pcu8,
      key_len__alu16,
      input__pcu8,
      input_len__alu16,
      exp_res__pcu8,
      exp_res_len__alu16,
      frag_len_list_3__au8,
      sizeof(frag_len_list_3__au8)
    )
  );
  FLEA_CCALL(
    THR_flea_test_mac__update_with_frag_len_list(
      id__t,
      key__pcu8,
      key_len__alu16,
      input__pcu8,
      input_len__alu16,
      exp_res__pcu8,
      exp_res_len__alu16,
      frag_len_list_4__au8,
      sizeof(frag_len_list_4__au8)
    )
  );
  FLEA_CCALL(
    THR_flea_test_mac__update_with_frag_len_list(
      id__t,
      key__pcu8,
      key_len__alu16,
      input__pcu8,
      input_len__alu16,
      exp_res__pcu8,
      exp_res_len__alu16,
      frag_len_list_5__au8,
      sizeof(frag_len_list_5__au8)
    )
  );
  FLEA_CCALL(
    THR_flea_test_mac__update_with_frag_len_list(
      id__t,
      key__pcu8,
      key_len__alu16,
      input__pcu8,
      input_len__alu16,
      exp_res__pcu8,
      exp_res_len__alu16,
      frag_len_list_6__au8,
      sizeof(frag_len_list_6__au8)
    )
  );

  FLEA_CCALL(
    THR_flea_test_mac__final_verify_and_compute_mac(
      id__t,
      key__pcu8,
      key_len__alu16,
      input__pcu8,
      input_len__alu16,
      exp_res__pcu8,
      exp_res_len__alu16
    )
  );

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_test_mac__update */

static flea_err_e THR_flea_test_mac__verify_mac(
  flea_mac_id_e    id__t,
  const flea_u8_t* key__pcu8,
  flea_al_u16_t    key_len__alu16,
  const flea_u8_t* input__pcu8,
  flea_al_u16_t    input_len__alu16,
  const flea_u8_t* exp_res__pu8,
  flea_al_u16_t    exp_res_len__alu16
)
{
  FLEA_THR_BEG_FUNC();

  // first try one-pass encryption:
  FLEA_CCALL(
    THR_flea_mac__verify_mac(
      id__t,
      key__pcu8,
      key_len__alu16,
      input__pcu8,
      input_len__alu16,
      exp_res__pu8,
      exp_res_len__alu16
    )
  );

  FLEA_THR_FIN_SEC_empty(
  );
}

static flea_err_e THR_flea_test_mac_inner(
  flea_mac_id_e    id__t,
  const flea_u8_t* key__pcu8,
  flea_al_u16_t    key_len__alu16,
  const flea_u8_t* input__pcu8,
  flea_al_u16_t    input_len__alu16,
  const flea_u8_t* exp_res__pcu8,
  flea_al_u16_t    exp_res_len__alu16
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_test_mac__verify_mac(
      id__t,
      key__pcu8,
      key_len__alu16,
      input__pcu8,
      input_len__alu16,
      exp_res__pcu8,
      exp_res_len__alu16
    )
  );
  FLEA_CCALL(
    THR_flea_test_mac__update(
      id__t,
      key__pcu8,
      key_len__alu16,
      input__pcu8,
      input_len__alu16,
      exp_res__pcu8,
      exp_res_len__alu16
    )
  );
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_test_mac()
{
# ifdef FLEA_HAVE_HMAC
  const flea_u8_t hmac_key_1[] =
  {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
   0x0b};
  const flea_u8_t hmac_data_1[] = {0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65};
#  ifdef FLEA_HAVE_SHA1
  const flea_u8_t hmac_sha1_data_1_cstr[] = "Hi There";
  const flea_u8_t hmac_sha1_exp_1[]       =
  {0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe,
   0x00};
#  endif /* ifdef FLEA_HAVE_SHA1 */
#  ifdef FLEA_HAVE_SHA224_256
  const flea_u8_t hmac_sha224_exp_1[] =
  {0x89, 0x6f, 0xb1, 0x12, 0x8a, 0xbb, 0xdf, 0x19, 0x68, 0x32, 0x10, 0x7c, 0xd4, 0x9d, 0xf3, 0x3f, 0x47, 0xb4, 0xb1,
   0x16, 0x99, 0x12, 0xba, 0x4f, 0x53, 0x68, 0x4b, 0x22};
#  endif

#  ifdef FLEA_HAVE_SHA224_256
  const flea_u8_t hmac_sha256_exp_1[] = {0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};
#  endif

#  ifdef FLEA_HAVE_SHA384_512
  const flea_u8_t hmac_sha384_exp_1[] = {
    0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62, 0x6b, 0x08, 0x25, 0xf4, 0xab, 0x46, 0x90, 0x7f, 0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6, 0x82, 0xaa, 0x03, 0x4c, 0x7c, 0xeb, 0xc5, 0x9c, 0xfa, 0xea, 0x9e, 0xa9, 0x07, 0x6e, 0xde, 0x7f, 0x4a, 0xf1, 0x52, 0xe8, 0xb2, 0xfa, 0x9c, 0xb6
  };
#  endif

#  ifdef FLEA_HAVE_SHA384_512
  const flea_u8_t hmac_sha512_exp_1[] = {0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d, 0x6c, 0xb0, 0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde, 0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4, 0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70, 0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54};
#  endif


#  ifdef FLEA_HAVE_SHA224_256
  const flea_u8_t hmac_key_2[]        = {0x4a, 0x65, 0x66, 0x65};
  const flea_u8_t hmac_data_2[]       = {0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e, 0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f};
  const flea_u8_t hmac_sha224_exp_2[] = {0xa3, 0x0e, 0x01, 0x09, 0x8b, 0xc6, 0xdb, 0xbf, 0x45, 0x69, 0x0f, 0x3a, 0x7e, 0x9e, 0x6d, 0x0f, 0x8b, 0xbe, 0xa2, 0xa3, 0x9e, 0x61, 0x48, 0x00, 0x8f, 0xd0, 0x5e, 0x44};
#  endif

#  ifdef FLEA_HAVE_MD5
  const flea_u8_t hmac_md5_key_1[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
  const flea_u8_t hmac_md5_exp_1[] = {0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c, 0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d};

  const flea_u8_t hmac_md5_key_7[] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
  const flea_u8_t hmac_md5_data_7[] = {'T', 'e', 's', 't', ' ', 'U', 's', 'i', 'n', 'g', ' ', 'L', 'a', 'r', 'g', 'e', 'r', ' ', 'T', 'h', 'a', 'n', ' ', 'B', 'l', 'o', 'c', 'k', '-', 'S', 'i', 'z', 'e', ' ', 'K', 'e', 'y', ' ', 'a', 'n', 'd', ' ', 'L', 'a', 'r', 'g', 'e', 'r', ' ', 'T', 'h', 'a', 'n', ' ', 'O', 'n', 'e', ' ', 'B', 'l', 'o', 'c', 'k', '-', 'S', 'i', 'z', 'e', ' ', 'D', 'a', 't', 'a'};

  const flea_u8_t hmac_md5_exp_7[] = {0x6f, 0x63, 0x0f, 0xad, 0x67, 0xcd, 0xa0, 0xee, 0x1f, 0xb1, 0xf5, 0x62, 0xdb, 0x3a, 0xa5, 0x3e};
#  endif /* ifdef FLEA_HAVE_MD5 */
# endif  // #ifdef FLEA_HAVE_HMAC

  // const flea_u8_t empty_message[0] = { };
# ifdef FLEA_HAVE_CMAC
#  ifdef FLEA_HAVE_AES
  const flea_u8_t cmac_aes128_rfc4493_key [] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

  const flea_u8_t cmac_aes128_rfc4493_exp_res_1_empty_mess [] = {0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46};

  const flea_u8_t cmac_aes128_rfc4493_data_2 [] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
  };

  const flea_u8_t cmac_aes128_rfc4493_exp_res_2 [] = {0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c};

  const flea_u8_t cmac_aes128_rfc4493_data_3 [] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11
  };

  const flea_u8_t cmac_aes128_rfc4493_exp_res_3[] = {0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30, 0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27};

  const flea_u8_t cmac_aes128_rfc4493_data_4[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
  };

  const flea_u8_t cmac_aes128_rfc4493_exp_res_4[] = {0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92, 0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe};

#  endif // #ifdef FLEA_HAVE_AES

#  ifdef FLEA_HAVE_TDES_3KEY
  // from http://csrc.nist.gov/publications/nistpubs/800-38B/Updated_CMAC_Examples.pdf
  const flea_u8_t cmac_tdes_3key_key_1[] = {
    0x8a, 0xa8, 0x3b, 0xf8, 0xcb, 0xda, 0x10, 0x62,
    0x0b, 0xc1, 0xbf, 0x19, 0xfb, 0xb6, 0xcd, 0x58,
    0xbc, 0x31, 0x3d, 0x4a, 0x37, 0x1c, 0xa8, 0xb5
  };

  const flea_u8_t cmac_tdes_3key_message_1[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96};

  const flea_u8_t cmac_tdes_3key_exp_res_1[] = {0x8e, 0x8f, 0x29, 0x31, 0x36, 0x28, 0x37, 0x97};

#  endif // #ifdef FLEA_HAVE_TDES_3KEY

#  ifdef FLEA_HAVE_TDES_2KEY

  const flea_u8_t cmac_tdes_2key_key_1[] = {
    0x4c, 0xf1, 0x51, 0x34, 0xa2, 0x85, 0x0d, 0xd5,
    0x8a, 0x3d, 0x10, 0xba, 0x80, 0x57, 0x0d, 0x38
  };
  const flea_u8_t cmac_tdes_2key_message_1[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57};

  const flea_u8_t cmac_tdes_2key_exp_res_1[] = {0x62, 0xdd, 0x1b, 0x47, 0x19, 0x02, 0xbd, 0x4e};
#  endif /* ifdef FLEA_HAVE_TDES_2KEY */
# endif // #ifdef FLEA_HAVE_CMAC

  FLEA_THR_BEG_FUNC();
# ifdef FLEA_HAVE_HMAC
#  ifdef FLEA_HAVE_SHA1
  FLEA_CCALL(THR_flea_test_mac_inner(flea_hmac_sha1, hmac_key_1, sizeof(hmac_key_1), hmac_sha1_data_1_cstr, sizeof(hmac_sha1_data_1_cstr) - 1, hmac_sha1_exp_1, sizeof(hmac_sha1_exp_1)));
#  endif
#  ifdef FLEA_HAVE_SHA224_256
  FLEA_CCALL(THR_flea_test_mac_inner(flea_hmac_sha224, hmac_key_1, sizeof(hmac_key_1), hmac_data_1, sizeof(hmac_data_1), hmac_sha224_exp_1, sizeof(hmac_sha224_exp_1)));
#  endif
#  ifdef FLEA_HAVE_SHA224_256
  FLEA_CCALL(THR_flea_test_mac_inner(flea_hmac_sha256, hmac_key_1, sizeof(hmac_key_1), hmac_data_1, sizeof(hmac_data_1), hmac_sha256_exp_1, sizeof(hmac_sha256_exp_1)));
#  endif
#  ifdef FLEA_HAVE_SHA384_512
  FLEA_CCALL(THR_flea_test_mac_inner(flea_hmac_sha384, hmac_key_1, sizeof(hmac_key_1), hmac_data_1, sizeof(hmac_data_1), hmac_sha384_exp_1, sizeof(hmac_sha384_exp_1)));
#  endif
#  ifdef FLEA_HAVE_SHA384_512
  FLEA_CCALL(THR_flea_test_mac_inner(flea_hmac_sha512, hmac_key_1, sizeof(hmac_key_1), hmac_data_1, sizeof(hmac_data_1), hmac_sha512_exp_1, sizeof(hmac_sha512_exp_1)));
#  endif

#  ifdef FLEA_HAVE_SHA224_256
  FLEA_CCALL(THR_flea_test_mac_inner(flea_hmac_sha224, hmac_key_2, sizeof(hmac_key_2), hmac_data_2, sizeof(hmac_data_2), hmac_sha224_exp_2, sizeof(hmac_sha224_exp_2)));
#  endif
#  ifdef FLEA_HAVE_MD5
  FLEA_CCALL(THR_flea_test_mac_inner(flea_hmac_md5, hmac_md5_key_1, sizeof(hmac_md5_key_1), hmac_data_1, sizeof(hmac_data_1), hmac_md5_exp_1, sizeof(hmac_md5_exp_1)));
  FLEA_CCALL(THR_flea_test_mac_inner(flea_hmac_md5, hmac_md5_key_7, sizeof(hmac_md5_key_7), hmac_md5_data_7, sizeof(hmac_md5_data_7), hmac_md5_exp_7, sizeof(hmac_md5_exp_7)));
#  endif
# endif // #ifdef FLEA_HAVE_HMAC
# ifdef FLEA_HAVE_CMAC
#  ifdef FLEA_HAVE_AES
  FLEA_CCALL(THR_flea_test_mac_inner(flea_cmac_aes128, cmac_aes128_rfc4493_key, sizeof(cmac_aes128_rfc4493_key), NULL, 0, cmac_aes128_rfc4493_exp_res_1_empty_mess, sizeof(cmac_aes128_rfc4493_exp_res_1_empty_mess)));
  FLEA_CCALL(THR_flea_test_mac_inner(flea_cmac_aes128, cmac_aes128_rfc4493_key, sizeof(cmac_aes128_rfc4493_key), cmac_aes128_rfc4493_data_2, sizeof(cmac_aes128_rfc4493_data_2), cmac_aes128_rfc4493_exp_res_2, sizeof(cmac_aes128_rfc4493_exp_res_2)));
  FLEA_CCALL(THR_flea_test_mac_inner(flea_cmac_aes128, cmac_aes128_rfc4493_key, sizeof(cmac_aes128_rfc4493_key), cmac_aes128_rfc4493_data_3, sizeof(cmac_aes128_rfc4493_data_3), cmac_aes128_rfc4493_exp_res_3, sizeof(cmac_aes128_rfc4493_exp_res_3)));
  FLEA_CCALL(THR_flea_test_mac_inner(flea_cmac_aes128, cmac_aes128_rfc4493_key, sizeof(cmac_aes128_rfc4493_key), cmac_aes128_rfc4493_data_4, sizeof(cmac_aes128_rfc4493_data_4), cmac_aes128_rfc4493_exp_res_4, sizeof(cmac_aes128_rfc4493_exp_res_4)));

#  endif /* ifdef FLEA_HAVE_AES */
#  ifdef FLEA_HAVE_TDES_3KEY
  FLEA_CCALL(THR_flea_test_mac_inner(flea_cmac_tdes_3key, cmac_tdes_3key_key_1, sizeof(cmac_tdes_3key_key_1), cmac_tdes_3key_message_1, sizeof(cmac_tdes_3key_message_1), cmac_tdes_3key_exp_res_1, sizeof(cmac_tdes_3key_exp_res_1)));
#  endif
#  ifdef FLEA_HAVE_TDES_2KEY
  FLEA_CCALL(THR_flea_test_mac_inner(flea_cmac_tdes_2key, cmac_tdes_2key_key_1, sizeof(cmac_tdes_2key_key_1), cmac_tdes_2key_message_1, sizeof(cmac_tdes_2key_message_1), cmac_tdes_2key_exp_res_1, sizeof(cmac_tdes_2key_exp_res_1)));
#  endif
# endif // #ifdef FLEA_HAVE_CMAC


# if defined FLEA_HAVE_HMAC && defined FLEA_HAVE_SHA224_256
  FLEA_CCALL(THR_flea_test_mac_special_1());
# endif
  // NOTE: non-full blocks are tested in test_ae.c in EAX mode, which internally
  // uses CMAC
  FLEA_CCALL(THR_flea_test_mac__init_dtor());
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_test_mac */

#endif // #ifdef FLEA_HAVE_MAC
