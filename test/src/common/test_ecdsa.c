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
#include "self_test.h"
#include "flea/error_handling.h"
#include <stdlib.h>
#include <string.h>
#include "internal/common/math/mpi.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/util.h"
#include "internal/common/math/curve_gfp.h"
#include "flea/ec_dom_par.h"
#include "flea/ecdsa.h"
#include "internal/common/math/point_gfp.h"
#include "flea/algo_config.h"
#include "flea/ec_key_gen.h"
#include "internal/common/ecc_int.h"
#include "flea/pk_signer.h"
#include "internal/common/enc_ecdsa_sig.h"
#include "self_test.h"

#ifdef FLEA_HAVE_ECDSA

flea_err_e THR_flea_test_cvc_sig_ver()
{
# if FLEA_ECC_MAX_MOD_BIT_SIZE >= 224
  flea_pk_signer_t verifier__t;
  flea_pubkey_t public_key__t;
  const flea_u8_t sign_data__acu8[] =
  {0x7f, 0x4e, 0x82, 0x01, 0x43, 0x5f, 0x29, 0x01, 0x00, 0x42, 0x0b, 0x44, 0x45, 0x43, 0x56, 0x43, 0x41, 0x30, 0x30,
   0x30, 0x30, 0x31, 0x7f, 0x49, 0x81,
   0xfd, 0x06, 0x0a, 0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x02, 0x81, 0x1c, 0xd7, 0xc1, 0x34, 0xaa,
   0x26, 0x43, 0x66, 0x86, 0x2a, 0x18, 0x30, 0x25, 0x75, 0xd1, 0xd7,
   0x87, 0xb0, 0x9f, 0x07, 0x57, 0x97, 0xda, 0x89, 0xf5, 0x7e, 0xc8, 0xc0, 0xff, 0x82, 0x1c, 0x68, 0xa5, 0xe6, 0x2c,
   0xa9, 0xce, 0x6c, 0x1c, 0x29, 0x98, 0x03, 0xa6, 0xc1, 0x53, 0x0b,
   0x51, 0x4e, 0x18, 0x2a, 0xd8, 0xb0, 0x04, 0x2a, 0x59, 0xca, 0xd2, 0x9f, 0x43, 0x83, 0x1c, 0x25, 0x80, 0xf6, 0x3c,
   0xcf, 0xe4, 0x41, 0x38, 0x87, 0x07, 0x13, 0xb1, 0xa9, 0x23, 0x69,
   0xe3, 0x3e, 0x21, 0x35, 0xd2, 0x66, 0xdb, 0xb3, 0x72, 0x38, 0x6c, 0x40, 0x0b, 0x84, 0x39, 0x04, 0x0d, 0x90, 0x29,
   0xad, 0x2c, 0x7e, 0x5c, 0xf4, 0x34, 0x08, 0x23, 0xb2, 0xa8, 0x7d,
   0xc6, 0x8c, 0x9e, 0x4c, 0xe3, 0x17, 0x4c, 0x1e, 0x6e, 0xfd, 0xee, 0x12, 0xc0, 0x7d, 0x58, 0xaa, 0x56, 0xf7, 0x72,
   0xc0, 0x72, 0x6f, 0x24, 0xc6, 0xb8, 0x9e, 0x4e, 0xcd, 0xac, 0x24,
   0x35, 0x4b, 0x9e, 0x99, 0xca, 0xa3, 0xf6, 0xd3, 0x76, 0x14, 0x02, 0xcd, 0x85, 0x1c, 0xd7, 0xc1, 0x34, 0xaa, 0x26,
   0x43, 0x66, 0x86, 0x2a, 0x18, 0x30, 0x25, 0x75, 0xd0, 0xfb, 0x98,
   0xd1, 0x16, 0xbc, 0x4b, 0x6d, 0xde, 0xbc, 0xa3, 0xa5, 0xa7, 0x93, 0x9f, 0x86, 0x39, 0x04, 0x77, 0x9c, 0xae, 0x5b,
   0xba, 0xea, 0x19, 0xed, 0x44, 0x14, 0x2b, 0x47, 0xbe, 0x1d, 0xb0,
   0x5e, 0xc9, 0xc7, 0x17, 0xb7, 0x5d, 0x6a, 0xe9, 0xf3, 0x05, 0xb1, 0x0a, 0x90, 0xd4, 0x0c, 0x7b, 0x59, 0x02, 0xd4,
   0xc3, 0x75, 0x4f, 0xf6, 0xfa, 0x6b, 0xc5, 0x19, 0x0f, 0x17, 0x3e,
   0x86, 0x96, 0x06, 0x62, 0xb1, 0x2e, 0xc3, 0x74, 0xd1, 0xd5, 0x98, 0x87, 0x01, 0x01, 0x5f, 0x20, 0x0b, 0x44, 0x45,
   0x43, 0x56, 0x43, 0x41, 0x30, 0x30, 0x30, 0x30, 0x31, 0x7f, 0x4c,
   0x0e, 0x06, 0x09, 0x04, 0x00, 0x7f, 0x00, 0x07, 0x03, 0x01, 0x02, 0x01, 0x53, 0x01, 0xc3, 0x5f, 0x25, 0x06, 0x00,
   0x08, 0x01, 0x00, 0x00, 0x09, 0x5f, 0x24, 0x06, 0x00, 0x09, 0x01,
   0x00, 0x00, 0x09};

  const flea_u8_t cvc_signature_rs__acu8[] =
  {0x0d, 0x62, 0x46, 0x10, 0xd6, 0x7a, 0x9d, 0xff, 0xf8, 0x06, 0xf3, 0x96, 0x8c, 0x3f, 0x6c, 0x6f, 0x6b, 0xa6, 0xdb,
   0x3f, 0x5b, 0x54, 0x96, 0xa1, 0x28, 0x4a, 0x46, 0x8f, 0x18, 0x50, 0xec, 0xc8, 0x6d, 0x11, 0xe0, 0xed, 0x0f, 0x85,
   0x0b, 0x85, 0xaa, 0x11, 0x5a, 0xc6, 0x1d, 0x0b, 0xb6, 0xad, 0x14, 0xbb, 0xde, 0xed, 0xae, 0x7c, 0xb1, 0x0c};
  const flea_u8_t public_key__acu8[] = {
    0x04, 0x77, 0x9C, 0xAE, 0x5B, 0xBA, 0xEA, 0x19, 0xED, 0x44, 0x14, 0x2B, 0x47, 0xBE, 0x1D, 0xB0,
    0x5E, 0xC9, 0xC7, 0x17, 0xB7, 0x5D, 0x6A, 0xE9, 0xF3, 0x05, 0xB1, 0x0A, 0x90, 0xD4, 0x0C, 0x7B,
    0x59, 0x02, 0xD4, 0xC3, 0x75, 0x4F, 0xF6, 0xFA, 0x6B, 0xC5, 0x19, 0x0F, 0x17, 0x3E, 0x86, 0x96,
    0x06, 0x62, 0xB1, 0x2E, 0xC3, 0x74, 0xD1, 0xD5, 0x98
  };

  flea_err_e err_code;
  // flea_pub_key_param_u param__u;

  /*flea_ref_cu8_t pubpoint__crcu8 = {
   * .data__pcu8 = public_key__acu8,
   * .len__dtl   = sizeof(public_key__acu8)
   * };*/
  FLEA_DECL_byte_vec_t__CONSTR_EXISTING_BUF_CONTENT_NOT_ALLOCATABLE(
    pubpoint_vec__t,
    (flea_u8_t*) public_key__acu8,
    sizeof(public_key__acu8)
  );

  flea_ec_dom_par_ref_t ecc_dom_par__t;
  FLEA_THR_BEG_FUNC();
  flea_pk_signer_t__INIT(&verifier__t);
  flea_pubkey_t__INIT(&public_key__t);
  flea_al_u16_t sig_len__alu16 = sizeof(cvc_signature_rs__acu8);
  FLEA_CCALL(THR_flea_pk_signer_t__ctor(&verifier__t, flea_sha224));
  FLEA_CCALL(THR_flea_ec_dom_par_ref_t__set_by_builtin_id(&ecc_dom_par__t, flea_brainpoolP224r1));
  FLEA_CCALL(THR_flea_pk_signer_t__update(&verifier__t, sign_data__acu8, sizeof(sign_data__acu8)));
  FLEA_CCALL(THR_flea_pubkey_t__ctor_ecc(&public_key__t, &pubpoint_vec__t, &ecc_dom_par__t));
  err_code = THR_flea_pk_signer_t__final_verify(
    &verifier__t,
    flea_ecdsa_emsa1_concat,
    &public_key__t,
    (flea_u8_t*) cvc_signature_rs__acu8,
    sig_len__alu16
    );
  if(err_code != FLEA_ERR_FINE)
  {
    FLEA_THROW("verification of reference ECDSA signature failed", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    flea_pk_signer_t__dtor(&verifier__t);
    flea_pubkey_t__dtor(&public_key__t);
  );
# else /* if FLEA_ECC_MAX_MOD_BIT_SIZE >= 224 */
  return FLEA_ERR_FINE;

# endif /* if FLEA_ECC_MAX_MOD_BIT_SIZE >= 224 */
} /* THR_flea_test_cvc_sig_ver */

static flea_err_e THR_flea_test_ecdsa_raw_basic_inner(const flea_ec_dom_par_ref_t* dom_par__pt)
{
  flea_u8_t res_r_arr[FLEA_ECC_MAX_ORDER_BYTE_SIZE];
  flea_u8_t res_s_arr[FLEA_ECC_MAX_ORDER_BYTE_SIZE];
  flea_al_u8_t pub_point_enc_len__al_u8 = 2 * FLEA_ECC_MAX_MOD_BYTE_SIZE + 1;
  flea_al_u8_t sk_enc_len__al_u8        = FLEA_ECC_MAX_ORDER_BYTE_SIZE;

  FLEA_DECL_BUF(pub_point_enc__b_u8, flea_u8_t, pub_point_enc_len__al_u8);
  FLEA_DECL_BUF(sk_enc__b_u8, flea_u8_t, sk_enc_len__al_u8);
  flea_al_u16_t i;

  const flea_u8_t message [] = {
    0x01, 0x81, 0x5F, 0xE5,
    0xD3, 0xA5, 0xB1, 0x24,
    0x5C, 0x8F, 0x5F, 0xA8,
    0xC9, 0x1C
  };

  flea_al_u8_t enc_s_len;
  flea_al_u8_t enc_r_len;
  FLEA_THR_BEG_FUNC();
  enc_r_len = enc_s_len = dom_par__pt->n__ru8.len__dtl;
  FLEA_ALLOC_BUF(pub_point_enc__b_u8, pub_point_enc_len__al_u8);
  FLEA_ALLOC_BUF(sk_enc__b_u8, sk_enc_len__al_u8);

  FLEA_CCALL(
    THR_flea_generate_ecc_key(
      pub_point_enc__b_u8,
      &pub_point_enc_len__al_u8,
      sk_enc__b_u8,
      &sk_enc_len__al_u8,
      dom_par__pt
    )
  );


  // ...encode x and y of pub point and input them to verify
  for(i = 0; i < 1; i++)
  {
    FLEA_CCALL(
      THR_flea_ecdsa__raw_sign(
        res_r_arr,
        &enc_r_len,
        res_s_arr,
        &enc_s_len,
        message,
        sizeof(message),
        sk_enc__b_u8,
        sk_enc_len__al_u8,
        dom_par__pt
      )
    );
    FLEA_CCALL(
      THR_flea_ecdsa__raw_verify(
        res_r_arr,
        enc_r_len,
        res_s_arr,
        enc_s_len,
        message,
        sizeof(message),
        pub_point_enc__b_u8,
        pub_point_enc_len__al_u8,
        dom_par__pt
      )
    );
    res_r_arr[0] ^= 1;
    if(FLEA_ERR_INV_SIGNATURE !=
      THR_flea_ecdsa__raw_verify(
        res_r_arr,
        enc_r_len,
        res_s_arr,
        enc_s_len,
        message,
        sizeof(message),
        pub_point_enc__b_u8,
        pub_point_enc_len__al_u8,
        dom_par__pt
      ))
    {
      FLEA_THROW("did not detect invalid ecdsa signature during verification", FLEA_ERR_FAILED_TEST);
    }
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(pub_point_enc__b_u8);
    FLEA_FREE_BUF_FINAL(sk_enc__b_u8);
  );
} /* THR_flea_test_ecdsa_raw_basic_inner */

flea_err_e THR_flea_test_ecdsa_raw_basic()
{
  FLEA_THR_BEG_FUNC();
  flea_al_u8_t i;

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
    FLEA_CCALL(THR_flea_test_ecdsa_raw_basic_inner(&dom_par__t));
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_test_ecdsa_256bit_sign_loop(unsigned count)
{
  flea_u8_t res_r_arr[FLEA_ECC_MAX_ORDER_BYTE_SIZE];
  flea_u8_t res_s_arr[FLEA_ECC_MAX_ORDER_BYTE_SIZE];
  flea_al_u8_t pub_point_enc_len__al_u8 = 2 * FLEA_ECC_MAX_MOD_BYTE_SIZE + 1;
  flea_al_u8_t sk_enc_len__al_u8        = FLEA_ECC_MAX_ORDER_BYTE_SIZE;


  FLEA_DECL_BUF(pub_point_enc__b_u8, flea_u8_t, pub_point_enc_len__al_u8);
  FLEA_DECL_BUF(sk_enc__b_u8, flea_u8_t, sk_enc_len__al_u8);
  flea_al_u16_t i;

  const flea_u8_t message [] = {
    0x01, 0x81, 0x5F, 0xE5,
    0xD3, 0xA5, 0xB1, 0x24,
    0x5C, 0x8F, 0x5F, 0xA8,
    0xC9, 0x1C
  };

  flea_al_u8_t enc_s_len;
  flea_al_u8_t enc_r_len;
  flea_ec_dom_par_ref_t dom_par__t;
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_ec_dom_par_ref_t__set_by_builtin_id(&dom_par__t, flea_brainpoolP256r1));
  enc_r_len = enc_s_len = dom_par__t.n__ru8.len__dtl;
  FLEA_ALLOC_BUF(pub_point_enc__b_u8, pub_point_enc_len__al_u8);
  FLEA_ALLOC_BUF(sk_enc__b_u8, sk_enc_len__al_u8);

  FLEA_CCALL(
    THR_flea_generate_ecc_key(
      pub_point_enc__b_u8,
      &pub_point_enc_len__al_u8,
      sk_enc__b_u8,
      &sk_enc_len__al_u8,
      &dom_par__t
    )
  );


  // ...encode x and y of pub point and input them to verify
  for(i = 0; i < count; i++)
  {
    FLEA_CCALL(
      THR_flea_ecdsa__raw_sign(
        res_r_arr,
        &enc_r_len,
        res_s_arr,
        &enc_s_len,
        message,
        sizeof(message),
        sk_enc__b_u8,
        sk_enc_len__al_u8,
        &dom_par__t
      )
    );
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(pub_point_enc__b_u8);
    FLEA_FREE_BUF_FINAL(sk_enc__b_u8);
  );
} /* THR_flea_test_ecdsa_256bit_sign_loop */

flea_err_e THR_flea_test_ecdsa_sig_enc()
{
  const flea_u8_t r1__acu8 []        = {0x00, 0x00}; /* on less */
  const flea_u8_t s1__acu8 []        = {0xF4, 0x00}; /* on more */
  const flea_u8_t exp_sig_1__acu8 [] = {0x30, 0x08, FLEA_ASN1_INT, 1, 0x00, FLEA_ASN1_INT, 3, 0x00, 0xF4, 0x00};

  const flea_u8_t r2__acu8 [] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  const flea_u8_t s2__acu8 [] = {
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  const flea_u8_t exp_sig_2__acu8 [] = {
    0x30,          0x81,  131,
    FLEA_ASN1_INT,   63,
    0x01,          0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10,          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10,          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10,          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10,          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10,          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10,          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10,          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    FLEA_ASN1_INT,   64,
    0x00,
    0x80,          0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10,          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10,          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10,          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10,          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10,          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10,          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10,          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  const flea_u8_t r3__acu8 []        = {0x00, 0xF1, 0x00}; /* on less */
  const flea_u8_t s3__acu8 []        = {0x00, 0x7F, 0x00}; /* on more */
  const flea_u8_t exp_sig_3__acu8 [] = {0x30, 0x09, FLEA_ASN1_INT, 3, 0x00, 0xF1, 0x00, FLEA_ASN1_INT, 2, 0x7F, 0x00};

# ifdef FLEA_HEAP_MODE
  flea_byte_vec_t sig__t;
# else
  FLEA_DECL_byte_vec_t__CONSTR_STACK_BUF_EMPTY_NOT_ALLOCATABLE(sig__t, 131 + 3);
# endif

  FLEA_THR_BEG_FUNC();
# ifdef FLEA_HEAP_MODE
  flea_byte_vec_t__ctor_empty_allocatable(&sig__t);
# endif

  FLEA_CCALL(THR_flea_asn1_encode_ecdsa_sig(r1__acu8, sizeof(r1__acu8), s1__acu8, sizeof(s1__acu8), &sig__t));

  if(flea_memcmp_wsize(
      flea_byte_vec_t__GET_DATA_PTR(&sig__t),
      flea_byte_vec_t__GET_DATA_LEN(&sig__t),
      exp_sig_1__acu8,
      sizeof(exp_sig_1__acu8)
    ))
  {
    FLEA_THROW("error with ECDSA sig encoding", FLEA_ERR_FAILED_TEST);
  }
  flea_byte_vec_t__reset(&sig__t);
  FLEA_CCALL(THR_flea_asn1_encode_ecdsa_sig(r2__acu8, sizeof(r2__acu8), s2__acu8, sizeof(s2__acu8), &sig__t));

  if(flea_memcmp_wsize(
      flea_byte_vec_t__GET_DATA_PTR(&sig__t),
      flea_byte_vec_t__GET_DATA_LEN(&sig__t),
      exp_sig_2__acu8,
      sizeof(exp_sig_2__acu8)
    ))
  {
    FLEA_THROW("error with ECDSA sig encoding", FLEA_ERR_FAILED_TEST);
  }
  flea_byte_vec_t__reset(&sig__t);
  FLEA_CCALL(THR_flea_asn1_encode_ecdsa_sig(r3__acu8, sizeof(r3__acu8), s3__acu8, sizeof(s3__acu8), &sig__t));

  if(flea_memcmp_wsize(
      flea_byte_vec_t__GET_DATA_PTR(&sig__t),
      flea_byte_vec_t__GET_DATA_LEN(&sig__t),
      exp_sig_3__acu8,
      sizeof(exp_sig_3__acu8)
    ))
  {
    FLEA_THROW("error with ECDSA sig encoding", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    flea_byte_vec_t__dtor(&sig__t);
  );
} /* THR_flea_test_ecdsa_sig_enc */

flea_err_e THR_flea_test_ec_dp_determination()
{
  flea_ec_dom_par_id_e id1 = flea_brainpoolP160r1;

# if FLEA_ECC_MAX_MOD_BIT_SIZE >= 512
  flea_ec_dom_par_id_e id2 = flea_secp521r1;
  flea_ec_dom_par_ref_t r2;
# endif
  flea_ec_dom_par_ref_t r1;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_ec_dom_par_ref_t__set_by_builtin_id(&r1, id1));
# if FLEA_ECC_MAX_MOD_BIT_SIZE >= 512
  FLEA_CCALL(THR_flea_ec_dom_par_ref_t__set_by_builtin_id(&r2, id2));
# endif

  if((id1 != flea_ec_dom_par_ref_t__determine_known_curve(&r1))
# if FLEA_ECC_MAX_MOD_BIT_SIZE >= 512
    || (id2 != flea_ec_dom_par_ref_t__determine_known_curve(&r2))
# endif
  )
  {
    FLEA_THROW("invalid determined ec dp id", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC_empty();
}

#endif // #ifdef FLEA_HAVE_ECDSA
