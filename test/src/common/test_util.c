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
#include "flea/bin_utils.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "self_test.h"

flea_err_e THR_flea_test_enc_BE_bitlen()
{
  const flea_u8_t e1 []  = {0x01};
  const flea_u8_t e1_len = 1;

  const flea_u8_t e2 []  = {0x80, 0x00};
  const flea_u8_t e2_len = 16;

  const flea_u8_t e3 []  = {0x7F, 0x08, 0x01};
  const flea_u8_t e3_len = 23;

  FLEA_THR_BEG_FUNC();
  if(flea__get_BE_int_bit_len(e1, sizeof(e1)) != e1_len)
  {
    FLEA_THROW("enc BE bit len error 1", FLEA_ERR_FAILED_TEST);
  }
  if(flea__get_BE_int_bit_len(e2, sizeof(e2)) != e2_len)
  {
    FLEA_THROW("enc BE bit len error 2", FLEA_ERR_FAILED_TEST);
  }
  if(flea__get_BE_int_bit_len(e3, sizeof(e3)) != e3_len)
  {
    FLEA_THROW("enc BE bit len error 3", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_test_incr_enc_BE_int()
{
  FLEA_DECL_BUF(block__bu8, flea_u8_t, 4);
  flea_u8_t exp_1__acu8[4] = {0, 0, 0, 1};
  flea_u8_t exp_2__acu8[4] = {0, 0, 1, 0};
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(block__bu8, 4);

  memset(block__bu8, 0, 4);

  flea__increment_encoded_BE_int(block__bu8, 4);

  if(memcmp(block__bu8, exp_1__acu8, sizeof(exp_1__acu8)))
  {
    FLEA_THROW("error in block increment", FLEA_ERR_FAILED_TEST);
  }

  block__bu8[3] = 0xFF;
  flea__increment_encoded_BE_int(block__bu8, 4);

  if(memcmp(block__bu8, exp_2__acu8, sizeof(exp_2__acu8)))
  {
    FLEA_THROW("error in block increment", FLEA_ERR_FAILED_TEST);
  }

  memset(block__bu8, 0xFF, 4);

  flea__increment_encoded_BE_int(block__bu8, 4);
  flea__increment_encoded_BE_int(block__bu8, 4);

  if(memcmp(block__bu8, exp_1__acu8, sizeof(exp_1__acu8)))
  {
    FLEA_THROW("error in block increment", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(block__bu8);
  );
} /* THR_flea_test_incr_enc_BE_int */
