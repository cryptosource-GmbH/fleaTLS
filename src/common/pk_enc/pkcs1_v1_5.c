/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/pk_enc/pkcs1_v1_5.h"
#include "internal/common/mask.h"
#include "flea/rng.h"

#if defined  FLEA_HAVE_ASYM_SIG || defined FLEA_HAVE_PK_CS

# define FLEA_PK_API_PKCS1_MAX_DIGEST_INFO_LEN sizeof(flea_pkcs1_digest_info__sha224__acu8)

const flea_u8_t flea_pkcs1_digest_info__md5__acu8[] =
{0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02, 0x05, 0x00, 0x04, 0x10};
const flea_u8_t flea_pkcs1_digest_info__sha1__acu8[] =
{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
const flea_u8_t flea_pkcs1_digest_info__sha224__acu8[] =
{0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c};

static void flea_pk_api__set_pkcs1_digest_info__sha2(
  flea_u8_t*     digest_info__pu8,
  flea_hash_id_e hash_id__t
)
{
  flea_u8_t di_1__u8, di_14__u8, di_18__u8;

  if(hash_id__t == flea_sha224)
  {
    return;
  }

  if(hash_id__t == flea_sha256)
  {
    di_1__u8  = 0x31;
    di_14__u8 = 0x01;
    di_18__u8 = 0x20;
  }
# ifdef FLEA_HAVE_SHA384_512
  else if(hash_id__t == flea_sha384)
  {
    di_1__u8  = 0x41;
    di_14__u8 = 0x02;
    di_18__u8 = 0x30;
  }
  else /* must be sha512 */
  {
    di_1__u8  = 0x51;
    di_14__u8 = 0x03;
    di_18__u8 = 0x40;
  }
# endif /* ifdef FLEA_HAVE_SHA384_512 */

  digest_info__pu8[1]  = di_1__u8;
  digest_info__pu8[14] = di_14__u8;
  digest_info__pu8[18] = di_18__u8;
} /* flea_pk_api__set_pkcs1_digest_info__sha2 */

static flea_al_u16_t flea_pk_api__pkcs1_set_digest_info(
  flea_u8_t*     target_buffer__pu8,
  flea_al_u16_t  target_buffer_len__alu16,
  flea_hash_id_e hash_id__t
)
{
  flea_al_u16_t offset__alu16;
  flea_al_u16_t len__alu16 = 0;
  const flea_u8_t* source__pu8;

# ifdef FLEA_HAVE_MD5
  if(hash_id__t == flea_md5)
  {
    len__alu16  = sizeof(flea_pkcs1_digest_info__md5__acu8);
    source__pu8 = flea_pkcs1_digest_info__md5__acu8;
  }
  else
# endif /* ifdef FLEA_HAVE_MD5 */
# ifdef FLEA_HAVE_SHA1
  if(hash_id__t == flea_sha1)
  {
    len__alu16  = sizeof(flea_pkcs1_digest_info__sha1__acu8);
    source__pu8 = flea_pkcs1_digest_info__sha1__acu8;
  }
  else
# endif /* ifdef FLEA_HAVE_SHA1 */
  if((hash_id__t == flea_sha224) || (hash_id__t == flea_sha256)
# ifdef FLEA_HAVE_SHA384_512
    || (hash_id__t == flea_sha384) || (hash_id__t == flea_sha512)
# endif
  )
  {
    len__alu16  = sizeof(flea_pkcs1_digest_info__sha224__acu8);
    source__pu8 = flea_pkcs1_digest_info__sha224__acu8;
  }
  if(len__alu16 == 0)
  {
    return 0;
  }
  offset__alu16       = target_buffer_len__alu16 - len__alu16;
  target_buffer__pu8 += offset__alu16;
  memcpy(target_buffer__pu8, source__pu8, len__alu16);
  if(1
# ifdef FLEA_HAVE_MD5
    && (hash_id__t != flea_md5)
# endif
# ifdef FLEA_HAVE_SHA1
    && hash_id__t != flea_sha1
# endif
  )
  {
    flea_pk_api__set_pkcs1_digest_info__sha2(target_buffer__pu8, hash_id__t);
  }
  return len__alu16 + target_buffer__pu8[len__alu16 - 1];
} /* flea_pk_api__pkcs1_set_digest_info */

flea_err_e THR_flea_pk_api__decode_message__pkcs1_v1_5(
  const flea_u8_t* encoded__pcu8,
  flea_al_u16_t    encoded_len__alu16,
  flea_byte_vec_t* result_vec__pt,
  flea_al_u16_t    bit_size__alu16,
  flea_al_u16_t    enforced_decoding_result_len__alu16,
  flea_u8_t*       silent_alarm_mbn__pu8
)
{
  flea_al_u16_t full_size__alu16         = FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(bit_size__alu16);
  flea_al_u16_t error__alu16             = 0;
  flea_bool_t suppress_padding_error__b  = enforced_decoding_result_len__alu16 > 0;
  const flea_u8_t* encoded_start__pcu8   = encoded__pcu8;
  flea_al_u16_t encoded_start_len__alu16 = encoded_len__alu16;

  FLEA_THR_BEG_FUNC();
  // take care of the case where the leading octet is not encoded:
  if(encoded_len__alu16 == full_size__alu16)
  {
    error__alu16 |= encoded__pcu8[0];
    encoded__pcu8++;
    encoded_len__alu16--;
  }
  else if(encoded_len__alu16 != full_size__alu16 - 1)
  {
    error__alu16 = 1;
  }
  error__alu16 |= (*encoded__pcu8 ^ 2);
  encoded__pcu8++;
  encoded_len__alu16--;

  while(encoded_len__alu16 && (*encoded__pcu8 != 0))
  {
    encoded__pcu8++;
    encoded_len__alu16--;
  }
  if(((!suppress_padding_error__b) && error__alu16))
  {
    FLEA_THROW("invalid format of PKCS#1 v1.5 message", FLEA_ERR_INV_CIPHERTEXT);
  }
  // zero byte found, step over it -- or not found, handle error
  if(!suppress_padding_error__b)
  {
    if(encoded_len__alu16 < 2)
    {
      FLEA_THROW("invalid format of PKCS#1 v1.5 message", FLEA_ERR_INV_CIPHERTEXT);
    }
  }
  else
  {
    const flea_u8_t* new_ptr_if_found_zero = encoded__pcu8 + 1;
    flea_al_u8_t zero_not_found_error__alu16;
    flea_al_u16_t new_len_if_found_zero = encoded_len__alu16 - 1;
    zero_not_found_error__alu16  = flea_consttime__select_u32_nz_z(0, 1, encoded_len__alu16);
    zero_not_found_error__alu16 |= flea_consttime__select_u32_nz_z(0, 1, encoded_len__alu16 ^ 1);
    encoded__pcu8 = (const flea_u8_t*) flea_consttime__select_ptr_nz_z(
      (void*) encoded__pcu8,
      (void*) new_ptr_if_found_zero,
      zero_not_found_error__alu16
      );
    encoded_len__alu16 = flea_consttime__select_u32_nz_z(
      encoded_len__alu16,
      new_len_if_found_zero,
      zero_not_found_error__alu16
      );
    error__alu16 |= zero_not_found_error__alu16 | (encoded_len__alu16 ^ enforced_decoding_result_len__alu16);
  }
  if(suppress_padding_error__b)
  {
    const flea_al_u8_t garble_offs__calu8 = 2;
    if(encoded_start_len__alu16 < garble_offs__calu8 + enforced_decoding_result_len__alu16)
    {
      FLEA_THROW("invalid enforced result length for PKCS#1 v1.5 message decoding", FLEA_ERR_BUFF_TOO_SMALL);
    }
    encoded_start_len__alu16 -= garble_offs__calu8;
    encoded_start__pcu8      += garble_offs__calu8;
    encoded__pcu8 = (const flea_u8_t*) flea_consttime__select_ptr_nz_z(
      (void*) encoded_start__pcu8,
      (void*) encoded__pcu8,
      error__alu16
      );
    encoded_len__alu16 = enforced_decoding_result_len__alu16;
  }
  else
  {
    if(!encoded_len__alu16)
    {
      FLEA_THROW("invalid enforced result length for PKCS#1 v1.5 message decoding", FLEA_ERR_BUFF_TOO_SMALL);
    }
    encoded__pcu8++;
    encoded_len__alu16--;
  }
  if(silent_alarm_mbn__pu8)
  {
    *silent_alarm_mbn__pu8 = (error__alu16 >> 8) | error__alu16;
  }
  FLEA_CCALL(THR_flea_byte_vec_t__set_content(result_vec__pt, encoded__pcu8, encoded_len__alu16));
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_pk_api__decode_message__pkcs1_v1_5 */

static flea_err_e THR_flea_pk_api__encode_message__pkcs1_v1_5(
  flea_u8_t*     input_output__pu8,
  flea_al_u16_t  input_len__alu16,
  flea_al_u16_t* output_len__palu16,
  flea_al_u16_t  bit_size,
  flea_hash_id_e hash_id__t,
  flea_al_u8_t   second_byte_val__alu8
)
{
  flea_al_u16_t emLen__alu16 = FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(bit_size);
  flea_al_u16_t rem_len__alu16;
  flea_al_u16_t tLen__alu16;
  flea_al_u16_t ps_len__alu16;
  flea_al_u16_t shift_al_u16;

  FLEA_THR_BEG_FUNC();
  if(bit_size < 512)
  {
    FLEA_THROW("output size too small for PKCS#1 v1.5 encoding", FLEA_ERR_BUFF_TOO_SMALL);
  }
  if(*output_len__palu16 < emLen__alu16)
  {
    FLEA_THROW("output buffer too short for PKCS#1 v1.5 encoding", FLEA_ERR_BUFF_TOO_SMALL);
  }
  *output_len__palu16 = emLen__alu16;
  shift_al_u16        = emLen__alu16 - input_len__alu16;
  // move the hash-value to the end
  memmove(input_output__pu8 + shift_al_u16, input_output__pu8, input_len__alu16);
  // prepend the algorithm-id
  rem_len__alu16 = emLen__alu16 - input_len__alu16;
  // check mLen <= k - 11
  // derive k from bit_size (=rsa-mod bit size)
  // *output_len__palu16 must be k
  // EM = 0x00 || 0x02 || PS || 0x00 || M
# ifdef FLEA_HAVE_ASYM_SIG
  if(second_byte_val__alu8 == 0x01)
  {
    tLen__alu16 = flea_pk_api__pkcs1_set_digest_info(input_output__pu8, rem_len__alu16, hash_id__t);
    if(tLen__alu16 == 0)
    {
      FLEA_THROW("invalid hash algorithm in PKCS#1 v1.5 signature encoding", FLEA_ERR_INV_ALGORITHM);
    }
  }
  else
# endif // #ifdef FLEA_HAVE_ASYM_SIG
  {
    tLen__alu16 = input_len__alu16;
  }
  if(emLen__alu16 < tLen__alu16 + 11)
  {
    FLEA_THROW("encoding error in pkcs#1 v1.5 encoding", FLEA_ERR_INV_ARG);
  }
  rem_len__alu16 = emLen__alu16 - tLen__alu16;
  input_output__pu8[rem_len__alu16 - 1] = 0x00;
  ps_len__alu16 = emLen__alu16 - tLen__alu16 - 3;
  if(second_byte_val__alu8 == 0x01)
  {
    // signature uses 0xff bytes
    memset(input_output__pu8 + 2, 0xff, ps_len__alu16);
  }
  else
  {
    // encryption uses random non-zero octets
    flea_al_u16_t i;
    for(i = 0; i < ps_len__alu16; i++)
    {
      do
      {
        FLEA_CCALL(THR_flea_rng__randomize(&input_output__pu8[2 + i], 1));
      } while(input_output__pu8[2 + i] == 0);
    }
  }
  input_output__pu8[0] = 0x00;
  input_output__pu8[1] = second_byte_val__alu8;

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_pk_api__encode_message__pkcs1_v1_5 */

flea_err_e THR_flea_pk_api__encode_message__pkcs1_v1_5_encr(
  flea_u8_t*     input_output__pu8,
  flea_al_u16_t  input_len__alu16,
  flea_al_u16_t* output_len__palu16,
  flea_al_u16_t  bit_size,
  flea_hash_id_e hash_id__t
)
{
  return THR_flea_pk_api__encode_message__pkcs1_v1_5(
    input_output__pu8,
    input_len__alu16,
    output_len__palu16,
    bit_size,
    hash_id__t,
    0x02
  );
}

flea_err_e THR_flea_pk_api__encode_message__pkcs1_v1_5_sign(
  flea_u8_t*     input_output__pu8,
  flea_al_u16_t  input_len__alu16,
  flea_al_u16_t* output_len__palu16,
  flea_al_u16_t  bit_size,
  flea_hash_id_e hash_id__t
)
{
  return THR_flea_pk_api__encode_message__pkcs1_v1_5(
    input_output__pu8,
    input_len__alu16,
    output_len__palu16,
    bit_size,
    hash_id__t,
    0x01
  );
}

#endif /* if defined  FLEA_HAVE_ASYM_SIG || defined FLEA_HAVE_PK_CS */
