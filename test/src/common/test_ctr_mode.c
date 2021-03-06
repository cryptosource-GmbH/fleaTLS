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


#include "flea/block_cipher.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "self_test.h"
#include <string.h>
#include <stdio.h>

flea_err_e THR_flea_test_ctr_mode_1()
{
  /**
   * Test vector from RFC 3686
   *
   */
  flea_u8_t key[] =
  {0xAE, 0x68, 0x52, 0xF8, 0x12, 0x10, 0x67, 0xCC, 0x4B, 0xF7, 0xA5, 0x76, 0x55, 0x77, 0xF3, 0x9E};
  flea_u8_t nonce[] =
  {0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
  flea_u8_t message[] = {
    0x53, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x62,
    0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x6D, 0x73, 0x67
  };

  flea_u8_t message_padded_for_2nd_block_processing[] = {
    0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
    0x53, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x62,
    0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x6D, 0x73, 0x67
  };
  flea_u8_t exp_ct[] = {
    0xE4, 0x09, 0x5D, 0x4F, 0xB7, 0xA7, 0xB3, 0x79,
    0x2D, 0x61, 0x75, 0xA3, 0x26, 0x13, 0x11, 0xB8
  };
  flea_u8_t decr[sizeof(message)];
  flea_u8_t encr[sizeof(message_padded_for_2nd_block_processing)];
  flea_u8_t message_length  = sizeof(message);
  flea_al_u8_t key_length   = sizeof(key);
  flea_al_u8_t nonce_length = sizeof(nonce);

  flea_ctr_mode_ctx_t ctx;

  FLEA_THR_BEG_FUNC();
  flea_ctr_mode_ctx_t__INIT(&ctx);
  FLEA_CCALL(THR_flea_ctr_mode_ctx_t__ctor(&ctx, flea_aes128, key, key_length, nonce, nonce_length, 16));
  flea_ctr_mode_ctx_t__crypt(&ctx, message, encr, message_length);
  if(memcmp(encr, exp_ct, message_length))
  {
    FLEA_THROW("error with encryption result for counter mode with aes", FLEA_ERR_FAILED_TEST);
  }
  flea_ctr_mode_ctx_t__dtor(&ctx);
  FLEA_CCALL(THR_flea_ctr_mode_ctx_t__ctor(&ctx, flea_aes128, key, key_length, nonce, nonce_length, 16));
  flea_ctr_mode_ctx_t__crypt(&ctx, encr, decr, message_length);
  if(memcmp(decr, message, message_length))
  {
    FLEA_THROW("error with decryption result for counter mode with aes", FLEA_ERR_FAILED_TEST);
  }

  memset(encr, 0, sizeof(message));
  FLEA_CCALL(
    THR_flea_ctr_mode_crypt_data(
      flea_aes128,
      key,
      key_length,
      nonce,
      nonce_length,
      message,
      encr,
      message_length,
      16
    )
  );
  if(memcmp(encr, exp_ct, message_length))
  {
    FLEA_THROW("error with encryption result for counter mode with aes (convenience function)", FLEA_ERR_FAILED_TEST);
  }

  FLEA_THR_FIN_SEC(
    flea_ctr_mode_ctx_t__dtor(&ctx);
  );
} /* THR_flea_test_ctr_mode_1 */

flea_err_e THR_flea_test_ctr_mode_parts()
{
  flea_u8_t key[]   = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
  flea_u8_t nonce[] = {0xAB, 0xCD, 0xEF};

  flea_u8_t message_arr[] =
  {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
   0x02,
   0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00,
   0x00,
   0x03, 0xFF};
  flea_u8_t exp_ct[] = {
    0x26, 0x1d, 0x1d, 0xf5, 0x61, 0xc2, 0xed, 0xf2, 0xf8, 0x39, 0x15, 0xab, 0x4e, 0xe5, 0x1c, 0x2a,
    0xc4, 0x69, 0x74, 0x45, 0xd7, 0x21, 0x37, 0x09, 0x6a, 0xfb, 0x95, 0xc7, 0xcc, 0x39, 0xda, 0xef,
    0xa7, 0x77
  };
  flea_u8_t decr_arr[sizeof(message_arr)];
  flea_u8_t encr_arr[sizeof(message_arr)];
  flea_u8_t message_length  = sizeof(message_arr);
  flea_al_u8_t key_length   = sizeof(key);
  flea_al_u8_t nonce_length = sizeof(nonce);
  flea_u8_t* message        = message_arr;
  flea_u8_t* decr = decr_arr;
  flea_u8_t* encr = encr_arr;
  flea_al_u16_t part_size;

  flea_ctr_mode_ctx_t ctx;

  FLEA_THR_BEG_FUNC();
  flea_ctr_mode_ctx_t__INIT(&ctx);
  FLEA_CCALL(THR_flea_ctr_mode_ctx_t__ctor(&ctx, flea_aes128, key, key_length, nonce, nonce_length, 16));
  part_size = 1;
  flea_ctr_mode_ctx_t__crypt(&ctx, message, encr, part_size);
  message_length -= part_size;
  encr    += part_size;
  message += part_size;

  part_size = 16;
  flea_ctr_mode_ctx_t__crypt(&ctx, message, encr, part_size);
  message_length -= part_size;
  encr    += part_size;
  message += part_size;

  part_size = 1;
  flea_ctr_mode_ctx_t__crypt(&ctx, message, encr, part_size);
  message_length -= part_size;
  encr    += part_size;
  message += part_size;

  part_size = 3;
  flea_ctr_mode_ctx_t__crypt(&ctx, message, encr, part_size);
  message_length -= part_size;
  encr    += part_size;
  message += part_size;

  part_size = 0;
  flea_ctr_mode_ctx_t__crypt(&ctx, message, encr, part_size);
  message_length -= part_size;
  encr    += part_size;
  message += part_size;

  part_size = 3;
  flea_ctr_mode_ctx_t__crypt(&ctx, message, encr, part_size);
  message_length -= part_size;
  encr    += part_size;
  message += part_size;

  part_size = message_length;
  flea_ctr_mode_ctx_t__crypt(&ctx, message, encr, part_size);
  message_length -= part_size;
  encr    += part_size;
  message += part_size;

  if(memcmp(encr_arr, exp_ct, sizeof(message_arr)))
  {
    FLEA_THROW("error with encryption result for counter mode with aes", FLEA_ERR_FAILED_TEST);
  }
  flea_ctr_mode_ctx_t__dtor(&ctx);
  FLEA_CCALL(THR_flea_ctr_mode_ctx_t__ctor(&ctx, flea_aes128, key, key_length, nonce, nonce_length, 16));
  message_length = sizeof(message_arr);
  encr      = encr_arr;
  part_size = 33;
  flea_ctr_mode_ctx_t__crypt(&ctx, encr, decr, part_size);
  encr += part_size;
  decr += part_size;
  message_length -= part_size;
  flea_ctr_mode_ctx_t__crypt(&ctx, encr, decr, message_length);

  if(memcmp(decr_arr, message_arr, sizeof(message_arr)))
  {
    FLEA_THROW("error with decryption result for counter mode with aes", FLEA_ERR_FAILED_TEST);
  }

  FLEA_THR_FIN_SEC(
    flea_ctr_mode_ctx_t__dtor(&ctx);
  );
} /* THR_flea_test_ctr_mode_parts */
