/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "flea/error_handling.h"
#include "flea/error.h"
#include  "flea/rsa.h"
#include <string.h>
#include "flea/hash.h"
#include <stdio.h>
#include "flea/array_util.h"
#include "self_test.h"

flea_err_e THR_flea_test_hash_function_inner(
  const flea_u8_t* message,
  flea_u16_t       message_len,
  const flea_u8_t* expected_digest,
  flea_u16_t       expected_digest_len,
  flea_hash_id_e   id
)
{
  flea_hash_ctx_t ctx;
  flea_u8_t digest[64];

  FLEA_THR_BEG_FUNC();
  flea_hash_ctx_t__INIT(&ctx);

  FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&ctx, id));

  FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx, message, message_len));

  FLEA_CCALL(THR_flea_hash_ctx_t__final(&ctx, digest));
  if(expected_digest_len != flea_hash_ctx_t__get_output_length(&ctx))
  {
    FLEA_THROW("error with hash result length", FLEA_ERR_FAILED_TEST);
  }
  if(memcmp(digest, expected_digest, flea_hash_ctx_t__get_output_length(&ctx)))
  {
    FLEA_THROW("error with hash result value", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    flea_hash_ctx_t__dtor(&ctx);
  );
}

static flea_err_e THR_flea_test_sha256_update_inner(
  const flea_u8_t*  message_ptr,
  flea_u16_t        message_len,
  const flea_u8_t*  expected_digest,
  flea_u16_t        expected_digest_len,
  const flea_u16_t* update_portions,
  flea_u16_t        update_portions_len
)
{
  flea_u32_t i;
  flea_hash_ctx_t ctx;

  flea_u8_t digest[32];

  FLEA_THR_BEG_FUNC();
  flea_hash_ctx_t__INIT(&ctx);

  FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&ctx, flea_sha256));
  for(i = 0; i < update_portions_len; i++)
  {
    flea_u16_t portion = update_portions[i];

    if(portion > message_len)
    {
      FLEA_THROW("error in test design", FLEA_ERR_INT_ERR);
    }
    FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx, message_ptr, portion));
    message_ptr += portion;
    message_len -= portion;
  }
  // update the remaining message part
  FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx, message_ptr, message_len));
  FLEA_CCALL(THR_flea_hash_ctx_t__final(&ctx, digest));
  if(expected_digest_len != flea_hash_ctx_t__get_output_length(&ctx))
  {
    FLEA_THROW("error with hash result length", FLEA_ERR_FAILED_TEST);
  }
  if(memcmp(digest, expected_digest, flea_hash_ctx_t__get_output_length(&ctx)))
  {
    FLEA_THROW("error with hash result value", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    flea_hash_ctx_t__dtor(&ctx);
  );
} /* THR_flea_test_sha256_update_inner */

flea_err_e THR_flea_test_sha256_update()
{
  const flea_u8_t message[] = {
    0x61, 0x1C, 0xEA, 0x48, 0x92, 0xA8, 0x5E, 0x24, 0xDB, 0xB1, 0x38, 0x4E, 0xE9, 0xF4, 0xB4, 0x5C, 0x5D, 0x9A, 0x48,
    0x7A, 0x2B, 0x4D, 0xFE, 0x63, 0x47, 0xFE, 0xB7, 0xB7, 0xA8, 0xEA, 0x0F, 0x0F, 0x85, 0x40, 0x78, 0x53, 0x38, 0x7A,
    0x7F, 0x55, 0x19, 0xCB, 0x07, 0x05, 0x88, 0x1C, 0x4B, 0x0A, 0x96, 0x75, 0x99, 0xB0, 0xE1, 0xD8, 0xCC, 0x0A, 0x8D,
    0xBC, 0x2E, 0x44, 0x2A, 0xE3, 0xEA, 0xD4, 0x37, 0xE4, 0xEF, 0xA6, 0x04, 0x9A, 0xF8, 0xF2, 0x87, 0x5E, 0x61, 0xBF,
    0x9E, 0x6C, 0xCE, 0x95, 0x37, 0x4B, 0x93, 0xB6, 0x94, 0x82, 0x44, 0xA0, 0xBC, 0x1A, 0xCA, 0xD0, 0xEB, 0x31, 0xD4,
    0xE8, 0x36, 0x88, 0x18, 0x2D, 0x5A, 0xF8, 0xD3, 0x78, 0x51, 0xC0, 0xB2, 0x33, 0xCD, 0xD4, 0x1D, 0x43, 0x22, 0x4A,
    0x5A, 0x13, 0x39, 0x5E, 0x9B, 0xBE, 0x01, 0xBF, 0xA0, 0x6C, 0x57, 0xE6, 0xAC, 0x0C, 0x27, 0xD6, 0x10, 0xC8, 0x55,
    0xB7, 0xC4, 0xD3, 0x83, 0xD2, 0x72, 0xDF, 0x16, 0x72, 0xD6, 0x3F, 0x65, 0x90, 0xC5, 0x50, 0xA4, 0x2C, 0x75, 0x79,
    0xC3, 0x48, 0x71, 0xAE, 0x1D, 0x14, 0x22, 0xBE, 0x96, 0xD0, 0x5F, 0xA2, 0xDE, 0x7A, 0xEF, 0x1A, 0xD4, 0xF2, 0xAE,
    0xE1, 0x39, 0x41, 0x95, 0x57, 0x98, 0x3C, 0xB2, 0xE7, 0xFE, 0xA1, 0xE6, 0x9C, 0x46, 0xDA, 0x22, 0x2E, 0x03, 0x06,
    0x81, 0xFC, 0x15, 0xCA, 0x06, 0x96, 0xD5, 0xF4, 0xAB, 0xD8, 0x65, 0x78, 0x63, 0xA1, 0xD7, 0xE1, 0xE4, 0x32, 0x70,
    0xA8, 0xDC, 0xD6, 0xE6, 0x4B, 0xEA, 0x99, 0x75, 0x81, 0xB6, 0xA3, 0xB7, 0x8A, 0xC6, 0xFA, 0x50, 0xF4, 0x7E, 0x7C,
    0x41, 0x70, 0xAC, 0x10, 0xF0, 0xB5, 0x9E, 0x63, 0x0D, 0xD6, 0xA9, 0xAB, 0x88, 0xFC, 0x64, 0x17, 0xF2, 0xC6, 0x5A,
    0x10, 0x1E, 0xCA, 0xAF, 0xDC, 0xCB, 0x5A, 0xCF, 0x80, 0xB2, 0xFB, 0x3A, 0xE4, 0xC6, 0x24, 0x11, 0x62, 0x14, 0x6A,
    0x69, 0x66, 0x16, 0xD4, 0x08, 0xDB, 0xE2, 0x4D, 0x71, 0x4D, 0xD6, 0x26, 0xE0, 0x9B, 0xD1, 0x42, 0x54, 0xFD, 0x41,
    0x48, 0x1A, 0x78, 0x2A, 0xC4, 0xAD, 0x40, 0x00, 0x6E, 0x2B, 0xC2, 0xBF, 0x59, 0x01, 0xA4, 0x33, 0xAD, 0xC6, 0xE0,
    0xF1, 0x1A, 0xFB, 0x46, 0x44, 0xC2, 0xDF, 0x0D, 0x59, 0x2E, 0x0F, 0x2B, 0x63, 0x12, 0x89, 0x38, 0xAE, 0x1C, 0x5C,
    0x20, 0x54, 0x83, 0x29, 0x80, 0xD3, 0x3D, 0x95, 0x3E
  };
  const flea_u8_t expected_digest[] = {
    0x31, 0x86, 0x3D, 0x3F, 0x47, 0x14, 0xE2, 0x66, 0x88, 0x16, 0x01, 0x7D, 0xCB, 0x44, 0x0C, 0x50, 0x41, 0xFB, 0xC7,
    0x3F, 0x53, 0x2A, 0xDE, 0x52, 0xF8, 0x09, 0xE2, 0x11, 0xD5, 0xD6, 0xC9, 0xE5
  };

  flea_u16_t update_portions_1[] = {0, 1, 63, 63, 1, 60, 0, 5, 1, 1, 10, 16, 11, 12, 0, 17};
  flea_u16_t update_portions_2[] = {300, 1};
  flea_u16_t update_portions_3[] = {1, 280, 1};
  flea_u16_t update_portions_4[] = {110, 123, 1};

  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(
    THR_flea_test_sha256_update_inner
    (
      message,
      sizeof(message),
      expected_digest,
      sizeof(expected_digest),
      update_portions_1,
      FLEA_NB_ARRAY_ENTRIES(update_portions_1)
    )
  );

  FLEA_CCALL(
    THR_flea_test_sha256_update_inner
    (
      message,
      sizeof(message),
      expected_digest,
      sizeof(expected_digest),
      update_portions_2,
      FLEA_NB_ARRAY_ENTRIES(update_portions_2)
    )
  );

  FLEA_CCALL(
    THR_flea_test_sha256_update_inner
    (
      message,
      sizeof(message),
      expected_digest,
      sizeof(expected_digest),
      update_portions_3,
      FLEA_NB_ARRAY_ENTRIES(update_portions_3)
    )
  );
  FLEA_CCALL(
    THR_flea_test_sha256_update_inner
    (
      message,
      sizeof(message),
      expected_digest,
      sizeof(expected_digest),
      update_portions_4,
      FLEA_NB_ARRAY_ENTRIES(update_portions_4)
    )
  );
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_test_sha256_update */
