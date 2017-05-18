/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/pk_enc/oaep.h"
#include "flea/pk_api.h"
#include "flea/privkey.h"
#include "flea/array_util.h"
#include "flea/util.h"
#include "flea/alloc.h"
#include "flea/error.h"
#include "flea/error_handling.h"
#include "flea/algo_config.h"
#include "flea/ecdsa.h"
#include "flea/rsa.h"
#include "flea/rng.h"
#include "flea/ec_gfp_dom_par.h"
#include "flea/bin_utils.h"
#include "internal/common/mask.h"
#include <string.h>

#define FLEA_PK_GET_PRIMITIVE_ID_FROM_SCHEME_ID(x) ((x >> FLEA_PK_ID_OFFS_PRIMITIVE) << FLEA_PK_ID_OFFS_PRIMITIVE)
#define FLEA_PK_GET_ENCODING_ID_FROM_SCHEME_ID(x)  (x & ((1 << FLEA_PK_ID_OFFS_PRIMITIVE) - 1))

#ifdef FLEA_HAVE_ASYM_SIG
const flea_u8_t flea_pkcs1_digest_info__md5__acu8[] =
{0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10};
const flea_u8_t flea_pkcs1_digest_info__sha1__acu8[] =
{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
const flea_u8_t flea_pkcs1_digest_info__sha224__acu8[] =
{0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c};

# define FLEA_PK_API_PKCS1_MAX_DIGEST_INFO_LEN sizeof(flea_pkcs1_digest_info__sha224__acu8)

static void flea_pk_api__set_pkcs1_digest_info__sha2(
  flea_u8_t*     digest_info__pu8,
  flea_hash_id_t hash_id__t
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

  digest_info__pu8[1]  = di_1__u8;
  digest_info__pu8[14] = di_14__u8;
  digest_info__pu8[18] = di_18__u8;
}

flea_al_u16_t flea_pk_api__pkcs1_set_digest_info(
  flea_u8_t*     target_buffer__pu8,
  flea_al_u16_t  target_buffer_len__alu16,
  flea_hash_id_t hash_id__t
)
{
  flea_al_u16_t offset__alu16;
  flea_al_u16_t len__alu16;
  const flea_u8_t* source__pu8;

  if(hash_id__t == flea_md5)
  {
    len__alu16  = sizeof(flea_pkcs1_digest_info__md5__acu8);
    source__pu8 = flea_pkcs1_digest_info__md5__acu8;
  }
  else if(hash_id__t == flea_sha1)
  {
    len__alu16  = sizeof(flea_pkcs1_digest_info__sha1__acu8);
    source__pu8 = flea_pkcs1_digest_info__sha1__acu8;
  }
  else
  {
    len__alu16  = sizeof(flea_pkcs1_digest_info__sha224__acu8);
    source__pu8 = flea_pkcs1_digest_info__sha224__acu8;
  }
  offset__alu16       = target_buffer_len__alu16 - len__alu16;
  target_buffer__pu8 += offset__alu16;
  memcpy(target_buffer__pu8, source__pu8, len__alu16);
  if(hash_id__t != flea_md5 && hash_id__t != flea_sha1)
  {
    flea_pk_api__set_pkcs1_digest_info__sha2(target_buffer__pu8, hash_id__t);
  }
  return len__alu16 + target_buffer__pu8[len__alu16 - 1];
}

void flea_pk_signer_t__dtor(flea_pk_signer_t* p_destr)
{
  flea_hash_ctx_t__dtor(&p_destr->hash_ctx);
}

flea_err_t THR_flea_pk_signer_t__ctor(
  flea_pk_signer_t* result__pt,
  flea_hash_id_t    hash_id__t
)
{
  FLEA_THR_BEG_FUNC();
  result__pt->hash_id__t = hash_id__t;
  FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&result__pt->hash_ctx, hash_id__t));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_pk_signer_t__update(
  flea_pk_signer_t* signer__pt,
  const flea_u8_t*  message__pcu8,
  flea_al_u16_t     message_len__alu16
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_hash_ctx_t__update(&signer__pt->hash_ctx, message__pcu8, message_len__alu16));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_pk_signer_t__final_sign(
  flea_pk_signer_t*         signer__pt,
  flea_pk_scheme_id_t       id__t,
  const flea_private_key_t* privkey__pt,
  flea_byte_vec_t*          sig_vec__pt
)
{
  flea_al_u8_t digest_len__alu8;

  FLEA_DECL_BUF(digest_buf__bu8, flea_u8_t, FLEA_MAX_HASH_OUT_LEN);
  FLEA_THR_BEG_FUNC();
  digest_len__alu8 = flea_hash_ctx_t__get_output_length(&signer__pt->hash_ctx);

  FLEA_ALLOC_BUF(digest_buf__bu8, digest_len__alu8);

  FLEA_CCALL(THR_flea_hash_ctx_t__final(&signer__pt->hash_ctx, digest_buf__bu8));
  FLEA_CCALL(
    THR_flea_pk_api__sign_digest(
      digest_buf__bu8,
      digest_len__alu8,
      signer__pt->hash_id__t,
      id__t,
      privkey__pt,
      sig_vec__pt
    )
  );
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(digest_buf__bu8);
  );
}

flea_err_t THR_flea_pk_api__sign_digest(
  const flea_u8_t*          digest__pcu8,
  flea_al_u8_t              digest_len__alu8,
  flea_hash_id_t            hash_id__e,
  flea_pk_scheme_id_t       id__t,
  const flea_private_key_t* privkey__pt,
  flea_byte_vec_t*          sig_vec__pt
)
{
  flea_pk_primitive_id_t primitive_id__t;
  flea_pk_encoding_id_t encoding_id__t;
  // flea_al_u16_t digest_len__alu16;
  flea_al_u16_t key_bit_size__alu16;
  flea_al_u16_t primitive_input_len__alu16;

  FLEA_DECL_BUF(primitive_input__bu8, flea_u8_t, FLEA_MAX(FLEA_PK_MAX_PRIMITIVE_INPUT_LEN, FLEA_MAX_HASH_OUT_LEN));

  FLEA_THR_BEG_FUNC();
  primitive_id__t     = FLEA_PK_GET_PRIMITIVE_ID_FROM_SCHEME_ID(id__t);
  key_bit_size__alu16 = privkey__pt->key_bit_size__u16;

  encoding_id__t = FLEA_PK_GET_ENCODING_ID_FROM_SCHEME_ID(id__t);

  primitive_input_len__alu16 = privkey__pt->max_primitive_input_len__u16;
  if(primitive_input_len__alu16 == 0)
  {
    FLEA_THROW("invalid key length for signature", FLEA_ERR_INV_KEY_SIZE);
  }
  FLEA_ALLOC_BUF(primitive_input__bu8, FLEA_MAX(primitive_input_len__alu16, FLEA_MAX_HASH_OUT_LEN));
  // get the final hash value
  // FLEA_CCALL(THR_flea_hash_ctx_t__final(&signer__pt->hash_ctx, primitive_input__bu8));
  if(digest_len__alu8 > FLEA_MAX_HASH_OUT_LEN)
  {
    FLEA_THROW("signature for extraneous digest length requested", FLEA_ERR_INV_ARG);
  }
  memcpy(primitive_input__bu8, digest__pcu8, digest_len__alu8);
  // digest_len__alu16 = flea_hash_ctx_t__get_output_length(&signer__pt->hash_ctx);
  if(encoding_id__t == flea_emsa1)
  {
    FLEA_CCALL(
      THR_flea_pk_api__encode_message__emsa1(
        primitive_input__bu8,
        digest_len__alu8,
        &primitive_input_len__alu16,
        key_bit_size__alu16
      )
    );
  }
  else if(encoding_id__t == flea_pkcs1_v1_5)
  {
    FLEA_CCALL(
      THR_flea_pk_api__encode_message__pkcs1_v1_5_sign(
        primitive_input__bu8,
        digest_len__alu8,
        &primitive_input_len__alu16,
        key_bit_size__alu16,
        hash_id__e
      )
    );
  }
  else
  {
    FLEA_THROW("invalid signature encoding id", FLEA_ERR_INV_ALGORITHM);
  }
  if(primitive_id__t == flea_ecdsa)
  {
# ifdef FLEA_HAVE_ECDSA
    flea_u8_t* sig_r__pu8;
    flea_u8_t* sig_s__pu8;
    flea_al_u8_t s_len__al_u8;
    flea_al_u8_t r_len__al_u8;// = (*signature_len__palu16) / 2;
    flea_u8_t* signature__pu8;
    flea_al_u8_t max_sig_part_len = privkey__pt->privkey_with_params__u.ec_priv_key_val__t.dp__t.n__ru8.len__dtl;
    if(privkey__pt->key_type__t != flea_ecc_key)
    {
      FLEA_THROW("invalid key type for signing", FLEA_ERR_INV_KEY_TYPE);
    }
    FLEA_CCALL(THR_flea_byte_vec_t__resize(sig_vec__pt, 2 * max_sig_part_len));
    signature__pu8 = sig_vec__pt->data__pu8;
    r_len__al_u8   = max_sig_part_len;
    s_len__al_u8   = r_len__al_u8,
    sig_r__pu8     = signature__pu8;
    sig_s__pu8     = signature__pu8 + r_len__al_u8;
    // concat encoding of r and s

    sig_s__pu8   = sig_r__pu8 + max_sig_part_len;
    s_len__al_u8 = max_sig_part_len;
    r_len__al_u8 = max_sig_part_len;
    FLEA_CCALL(
      THR_flea_ecdsa__raw_sign(
        sig_r__pu8,
        &r_len__al_u8,
        sig_s__pu8,
        &s_len__al_u8,
        primitive_input__bu8,
        primitive_input_len__alu16,
        privkey__pt->privkey_with_params__u.ec_priv_key_val__t.scalar__rcu8.data__pu8,
        privkey__pt->privkey_with_params__u.ec_priv_key_val__t.scalar__rcu8.len__dtl,
        &privkey__pt->privkey_with_params__u.ec_priv_key_val__t.dp__t
      )
    );
    if(s_len__al_u8 < max_sig_part_len)
    {
      flea_al_u8_t shift = max_sig_part_len - s_len__al_u8;
      memmove(sig_s__pu8 + shift, sig_s__pu8, s_len__al_u8);
      memset(sig_s__pu8, 0, shift);
    }
    if(r_len__al_u8 < max_sig_part_len)
    {
      flea_al_u8_t shift = max_sig_part_len - r_len__al_u8;
      memmove(sig_r__pu8 + shift, sig_r__pu8, r_len__al_u8);
      memset(sig_r__pu8, 0, shift);
    }
    // set up the signature with correct length
    // *signature_len__palu16 = 2 * max_sig_part_len;
    // sig_vec__pt->len__dtl = 2 * max_sig_part_len; // ALREADY DONE ABOVE

# else // #ifdef FLEA_HAVE_ECDSA
    FLEA_THROW("ECDSA not supported", FLEA_ERR_INV_ALGORITHM);
# endif // #else of #ifdef FLEA_HAVE_ECDSA
  }
  else if(primitive_id__t == flea_rsa_sign)
  {
# ifdef FLEA_HAVE_RSA
    if(privkey__pt->key_type__t != flea_rsa_key)
    {
      FLEA_THROW("invalid key type for signing", FLEA_ERR_INV_KEY_TYPE);
    }
    // in RSA, input length = output length
    FLEA_CCALL(THR_flea_byte_vec_t__resize(sig_vec__pt, primitive_input_len__alu16));

    /* if(*signature_len__palu16 < primitive_input_len__alu16)
     * {
     * FLEA_THROW("signature buffer too small for RSA signature", FLEA_ERR_BUFF_TOO_SMALL);
     * }*/
    FLEA_CCALL(
      THR_flea_rsa_raw_operation_crt_private_key(
        privkey__pt,
        // signature__pu8,
        sig_vec__pt->data__pu8,
        primitive_input__bu8,
        primitive_input_len__alu16
      )
    );
    // *signature_len__palu16 = (privkey__pt->key_bit_size__u16 + 7) / 8;
    // TODO: LEAVE RESULT LENGTH AT primitive_input_len__alu16 :
    sig_vec__pt->len__dtl = (privkey__pt->key_bit_size__u16 + 7) / 8;


# else // #ifdef FLEA_HAVE_RSA
    FLEA_THROW("rsa not supported", FLEA_ERR_INV_ALGORITHM);
# endif // #else of #ifdef FLEA_HAVE_RSA
  }
  else
  {
    FLEA_THROW("invalid signature primitive id", FLEA_ERR_INV_ALGORITHM);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(primitive_input__bu8);
  );
} /* THR_flea_pk_signer_t__final_sign */

flea_err_t THR_flea_pk_signer_t__final_verify(
  flea_pk_signer_t*        signer__pt,
  flea_pk_scheme_id_t      id__t,
  const flea_public_key_t* pubkey__pt,
  const flea_u8_t*         signature__pcu8,
  flea_al_u16_t            signature_len__alu16
)
{
  flea_al_u8_t digest_len__alu8;

  FLEA_DECL_BUF(digest_buf__bu8, flea_u8_t, FLEA_MAX_HASH_OUT_LEN);
  FLEA_THR_BEG_FUNC();
  digest_len__alu8 = flea_hash_ctx_t__get_output_length(&signer__pt->hash_ctx);

  FLEA_ALLOC_BUF(digest_buf__bu8, digest_len__alu8);

  FLEA_CCALL(THR_flea_hash_ctx_t__final(&signer__pt->hash_ctx, digest_buf__bu8));
  FLEA_CCALL(
    THR_flea_pk_api__verify_digest(
      digest_buf__bu8,
      digest_len__alu8,
      signer__pt->hash_id__t,
      id__t,
      pubkey__pt,
      signature__pcu8,
      signature_len__alu16
    )
  );
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(digest_buf__bu8);
  );
}

flea_err_t THR_flea_pk_api__verify_digest(
  const flea_u8_t*         digest__pcu8,
  flea_al_u8_t             digest_len__alu8,
  flea_hash_id_t           hash_id__t,
  flea_pk_scheme_id_t      id__t,
  const flea_public_key_t* pubkey__pt,
  const flea_u8_t*         signature__pu8,
  flea_al_u16_t            signature_len__alu16
)
{
  flea_pk_primitive_id_t primitive_id__t;
  flea_pk_encoding_id_t encoding_id__t;
  flea_al_u16_t digest_len__alu16;
  flea_al_u16_t key_bit_size__alu16 = 0; // avoid warning
  flea_al_u16_t primitive_input_len__alu16;

  FLEA_DECL_BUF(primitive_input__bu8, flea_u8_t, FLEA_MAX(FLEA_PK_MAX_PRIMITIVE_INPUT_LEN, FLEA_MAX_HASH_OUT_LEN));

  FLEA_DECL_BUF(digest_for_rsa_ver__bu8, flea_u8_t, FLEA_MAX_HASH_OUT_LEN);
  FLEA_THR_BEG_FUNC();
  if(digest_len__alu8 > FLEA_MAX_HASH_OUT_LEN)
  {
    FLEA_THROW("excessive digest len", FLEA_ERR_INV_ARG);
  }
  primitive_id__t     = FLEA_PK_GET_PRIMITIVE_ID_FROM_SCHEME_ID(id__t);
  key_bit_size__alu16 = pubkey__pt->key_bit_size__u16;

  encoding_id__t = FLEA_PK_GET_ENCODING_ID_FROM_SCHEME_ID(id__t);

  primitive_input_len__alu16 = pubkey__pt->primitive_input_size__u16;
  if(primitive_input_len__alu16 == 0)
  {
    FLEA_THROW("invalid key length for signature", FLEA_ERR_INV_KEY_SIZE);
  }
  FLEA_ALLOC_BUF(primitive_input__bu8, FLEA_MAX(primitive_input_len__alu16, FLEA_MAX_HASH_OUT_LEN));
  // get the final hash value
  if(primitive_id__t == flea_rsa_sign)
  {
    FLEA_ALLOC_BUF(digest_for_rsa_ver__bu8, digest_len__alu8);
    // FLEA_CCALL(THR_flea_hash_ctx_t__final(&signer__pt->hash_ctx, digest_for_rsa_ver__bu8));
    memcpy(digest_for_rsa_ver__bu8, digest__pcu8, digest_len__alu8);
  }
  else
  {
    // FLEA_CCALL(THR_flea_hash_ctx_t__final(&signer__pt->hash_ctx, primitive_input__bu8));
    memcpy(primitive_input__bu8, digest__pcu8, digest_len__alu8);
  }
  digest_len__alu16 = digest_len__alu8; // flea_hash_ctx_t__get_output_length(&signer__pt->hash_ctx);
  if(encoding_id__t == flea_emsa1)
  {
    FLEA_CCALL(
      THR_flea_pk_api__encode_message__emsa1(
        primitive_input__bu8,
        digest_len__alu16,
        &primitive_input_len__alu16,
        key_bit_size__alu16
      )
    );
  }
  else if(encoding_id__t == flea_pkcs1_v1_5)
  { }
  else
  {
    FLEA_THROW("invalid signature encoding id", FLEA_ERR_INV_ALGORITHM);
  }
  if(primitive_id__t == flea_ecdsa)
  {
# ifdef FLEA_HAVE_ECDSA
    const flea_u8_t* sig_r__pu8;
    const flea_u8_t* sig_s__pu8;
    flea_al_u8_t s_len__al_u8;
    flea_al_u8_t r_len__al_u8 = signature_len__alu16 / 2;
    s_len__al_u8 = r_len__al_u8;
    sig_r__pu8   = signature__pu8;
    sig_s__pu8   = signature__pu8 + r_len__al_u8;
    // concat encoding of r and s

    sig_r__pu8 = signature__pu8;
    sig_s__pu8 = signature__pu8 + r_len__al_u8;
    FLEA_CCALL(
      THR_flea_ecdsa__raw_verify(
        sig_r__pu8,
        r_len__al_u8,
        sig_s__pu8,
        s_len__al_u8,
        primitive_input__bu8,
        primitive_input_len__alu16,
        pubkey__pt->pubkey_with_params__u.ec_public_val__t.public_point_encoded__rcu8.data__pu8,
        pubkey__pt->pubkey_with_params__u.ec_public_val__t.public_point_encoded__rcu8.len__dtl,
        &pubkey__pt->pubkey_with_params__u.ec_public_val__t.dp__t
      )
    );

# else // #ifdef FLEA_HAVE_ECDSA
    FLEA_THROW("ECDSA not supported", FLEA_ERR_INV_ALGORITHM);
# endif // #else of #ifdef FLEA_HAVE_ECDSA
  }
  else if(primitive_id__t == flea_rsa_sign)
  {
# ifdef FLEA_HAVE_RSA

    FLEA_CCALL(
      THR_flea_rsa_raw_operation(
        primitive_input__bu8,
        pubkey__pt->pubkey_with_params__u.rsa_public_val__t.pub_exp__rcu8.data__pcu8,
        pubkey__pt->pubkey_with_params__u.rsa_public_val__t.pub_exp__rcu8.len__dtl,
        signature__pu8,
        signature_len__alu16,
        pubkey__pt->pubkey_with_params__u.rsa_public_val__t.mod__rcu8.data__pcu8,
        pubkey__pt->pubkey_with_params__u.rsa_public_val__t.mod__rcu8.len__dtl
      )
    );
    if(encoding_id__t == flea_pkcs1_v1_5)
    {
      FLEA_CCALL(
        THR_flea_pk_api__verify_message__pkcs1_v1_5(
          primitive_input__bu8,
          primitive_input_len__alu16,
          digest_for_rsa_ver__bu8,
          digest_len__alu16,
          key_bit_size__alu16,
          hash_id__t
        )
      );
    }
    else
    {
      FLEA_THROW("invalid RSA encoding method in RSA signature verification", FLEA_ERR_INV_ALGORITHM);
    }
# else // #ifdef FLEA_HAVE_RSA
    FLEA_THROW("scheme not supported", FLEA_ERR_INV_ALGORITHM);
# endif // #else of #ifdef FLEA_HAVE_RSA
  }
  else
  {
    FLEA_THROW("invalid signature primitive id", FLEA_ERR_INV_ALGORITHM);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(primitive_input__bu8);
    FLEA_FREE_BUF_FINAL(digest_for_rsa_ver__bu8);
  );
} /* THR_flea_pk_signer_t__final_verify */

flea_err_t THR_flea_pk_api__verify_message__pkcs1_v1_5(
  const flea_u8_t* encoded__pcu8,
  flea_al_u16_t    encoded_len__alu16,
  const flea_u8_t* digest__pu8,
  flea_al_u16_t    digest_len__alu16,
  flea_al_u16_t    bit_size__alu16,
  flea_hash_id_t   hash_id__t
)
{
  flea_al_u16_t full_size__alu16;
  flea_al_u16_t compare_val_len__alu16;

  FLEA_DECL_BUF(compare__bu8, flea_u8_t, FLEA_PK_MAX_PRIMITIVE_INPUT_LEN);

  FLEA_THR_BEG_FUNC();
  full_size__alu16 = FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(bit_size__alu16);

  // take care of the case where the leading octet is not encoded:
  if(encoded_len__alu16 == full_size__alu16)
  {
    if(encoded__pcu8[0] != 0)
    {
      FLEA_THROW("invalid format of PKCS#1 v1.5 message", FLEA_ERR_INV_SIGNATURE);
    }
    encoded__pcu8++;
    encoded_len__alu16--;
  }
  else if(encoded_len__alu16 != full_size__alu16 - 1)
  {
    FLEA_THROW("invalid format of PKCS#1 v1.5 message", FLEA_ERR_INV_SIGNATURE);
  }
  compare_val_len__alu16 = FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(bit_size__alu16);
# ifdef FLEA_USE_STACK_BUF
  if(compare_val_len__alu16 > FLEA_STACK_BUF_NB_ENTRIES(compare__bu8))
  {
    FLEA_THROW("key bit size too large", FLEA_ERR_INV_KEY_SIZE);
  }
# endif
  FLEA_ALLOC_BUF(compare__bu8, compare_val_len__alu16);
  memcpy(compare__bu8, digest__pu8, digest_len__alu16);
  FLEA_CCALL(
    THR_flea_pk_api__encode_message__pkcs1_v1_5_sign(
      compare__bu8,
      digest_len__alu16,
      &compare_val_len__alu16,
      bit_size__alu16,
      hash_id__t
    )
  );
  if(memcmp(encoded__pcu8, &compare__bu8[1], compare_val_len__alu16 - 1))
  {
    FLEA_THROW("invalid format of PKCS#1 v1.5 message", FLEA_ERR_INV_SIGNATURE);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(compare__bu8);
  );
} /* THR_flea_pk_api__verify_message__pkcs1_v1_5 */

flea_err_t THR_flea_pk_api__verify_signature(
  const flea_byte_vec_t*   message__prcu8,
  const flea_byte_vec_t*   signature__prcu8,
  const flea_public_key_t* pubkey__pt,
  flea_pk_scheme_id_t      pk_scheme_id__t,
  flea_hash_id_t           hash_id__t
)
{
  FLEA_DECL_OBJ(signer__t, flea_pk_signer_t);
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_pk_signer_t__ctor(&signer__t, hash_id__t));
  FLEA_CCALL(THR_flea_pk_signer_t__update(&signer__t, message__prcu8->data__pu8, message__prcu8->len__dtl));
  FLEA_CCALL(
    THR_flea_pk_signer_t__final_verify(
      &signer__t,
      pk_scheme_id__t,
      pubkey__pt,
      signature__prcu8->data__pu8,
      signature__prcu8->len__dtl
    )
  );
  FLEA_THR_FIN_SEC(
    flea_pk_signer_t__dtor(&signer__t);
  );
}

flea_err_t THR_flea_pk_api__sign(
  const flea_byte_vec_t*    message__prcu8,
  flea_byte_vec_t*          signature__pru8,
  const flea_private_key_t* privkey__pt,
  flea_pk_scheme_id_t       pk_scheme_id__t,
  flea_hash_id_t            hash_id__t
)
{
  FLEA_DECL_OBJ(signer__t, flea_pk_signer_t);
  FLEA_THR_BEG_FUNC();
  // flea_al_u16_t sig_len__alu16 = signature__pru8->len__dtl;
  FLEA_CCALL(THR_flea_pk_signer_t__ctor(&signer__t, hash_id__t));
  FLEA_CCALL(THR_flea_pk_signer_t__update(&signer__t, message__prcu8->data__pu8, message__prcu8->len__dtl));
  FLEA_CCALL(
    THR_flea_pk_signer_t__final_sign(
      &signer__t,
      pk_scheme_id__t,
      privkey__pt,
      // signature__pru8->data__pu8,
      signature__pru8
      // &sig_len__alu16
    )
  );
  // signature__pru8->len__dtl = sig_len__alu16;
  FLEA_THR_FIN_SEC(
    flea_pk_signer_t__dtor(&signer__t);
  );
}

/*
 * bit size = order bit size
 * output_len >= input_len, former denotes the allocated space, latter the
 * length of the input data within that space
 */
flea_err_t THR_flea_pk_api__encode_message__emsa1(
  flea_u8_t*     input_output__pcu8,
  flea_al_u16_t  input_len__alu16,
  flea_al_u16_t* output_len__palu16,
  flea_al_u16_t  bit_size
)
{
  flea_al_u16_t output_bytes__alu16;

  FLEA_THR_BEG_FUNC();

  if(8 * input_len__alu16 <= bit_size)
  {
    *output_len__palu16 = input_len__alu16;
    FLEA_THR_RETURN();
  }
  // this function never increases the length of the output, so there is no
  // error condition
  output_bytes__alu16 = FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(bit_size);
  bit_size %= 8;
  bit_size  = 8 - bit_size;
  if(bit_size)
  {
    flea_u8_t carry = 0;
    flea_al_u16_t i;
    for(i = 0; i < output_bytes__alu16; i++)
    {
      flea_u8_t x = input_output__pcu8[i];
      input_output__pcu8[i] = (x >> bit_size) | carry;
      carry = (x << (8 - bit_size));
    }
  }
  *output_len__palu16 = output_bytes__alu16;
  FLEA_THR_FIN_SEC_empty();
}

#endif // #ifdef FLEA_HAVE_ASYM_SIG

#if defined  FLEA_HAVE_ASYM_SIG || defined FLEA_HAVE_PK_CS
flea_err_t THR_flea_pk_api__decode_message__pkcs1_v1_5(
  const flea_u8_t* encoded__pcu8,
  flea_al_u16_t    encoded_len__alu16,

  /*  flea_u8_t*       output_message__pu8,
   * flea_al_u16_t*   output_message_len__palu16,*/
  flea_byte_vec_t* result_vec__pt,
  flea_al_u16_t    bit_size__alu16,
  flea_al_u16_t    enforced_decoding_result_len__alu16
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
    error__alu16 |= zero_not_found_error__alu16;
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
    encoded_len__alu16 = flea_consttime__select_u32_nz_z(
      enforced_decoding_result_len__alu16,
      encoded_len__alu16,
      error__alu16
      );
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

  /*if(encoded_len__alu16 > *output_message_len__palu16)
   * {
   * FLEA_THROW("output buffer too small for PKCS#1 v1.5 message", FLEA_ERR_BUFF_TOO_SMALL);
   * }*/
  // flea_byte_vec_t__reset(resul
  FLEA_CCALL(THR_flea_byte_vec_t__set_content(result_vec__pt, encoded__pcu8, encoded_len__alu16));
  // memcpy(output_message__pu8, encoded__pcu8, encoded_len__alu16);
  // *output_message_len__palu16 = encoded_len__alu16;
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_pk_api__decode_message__pkcs1_v1_5 */

static flea_err_t THR_flea_pk_api__encode_message__pkcs1_v1_5(
  flea_u8_t*     input_output__pu8,
  flea_al_u16_t  input_len__alu16,
  flea_al_u16_t* output_len__palu16,
  flea_al_u16_t  bit_size,
  flea_hash_id_t hash_id__t,
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
        flea_rng__randomize(&input_output__pu8[2 + i], 1);
      } while(input_output__pu8[2 + i] == 0);
    }
  }
  input_output__pu8[0] = 0x00;
  input_output__pu8[1] = second_byte_val__alu8;

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_pk_api__encode_message__pkcs1_v1_5 */

flea_err_t THR_flea_pk_api__encode_message__pkcs1_v1_5_encr(
  flea_u8_t*     input_output__pu8,
  flea_al_u16_t  input_len__alu16,
  flea_al_u16_t* output_len__palu16,
  flea_al_u16_t  bit_size,
  flea_hash_id_t hash_id__t
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

flea_err_t THR_flea_pk_api__encode_message__pkcs1_v1_5_sign(
  flea_u8_t*     input_output__pu8,
  flea_al_u16_t  input_len__alu16,
  flea_al_u16_t* output_len__palu16,
  flea_al_u16_t  bit_size,
  flea_hash_id_t hash_id__t
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

#ifdef FLEA_HAVE_PK_CS
flea_err_t THR_flea_pk_api__encrypt_message(
  flea_pk_scheme_id_t id__t,
  flea_hash_id_t      hash_id__t,
  const flea_u8_t*    message__pcu8,
  flea_al_u16_t       message_len__alu16,
  flea_byte_vec_t*    result__pt,
  const flea_u8_t*    key__pcu8,
  flea_al_u16_t       key_len__alu16,
  const flea_u8_t*    params__pcu8,
  flea_al_u16_t       params_len__alu16
)
{
  flea_al_u16_t minimal_out_len__alu16;
  flea_al_u16_t primitive_input_len__alu16;

  FLEA_THR_BEG_FUNC();
  minimal_out_len__alu16     = key_len__alu16;
  primitive_input_len__alu16 = minimal_out_len__alu16;

  /*if(minimal_out_len__alu16 > *result_len__palu16)
   * {
   * FLEA_THROW("output buffer too small in pk encryption", FLEA_ERR_BUFF_TOO_SMALL);
   * }*/
  FLEA_CCALL(THR_flea_byte_vec_t__resize(result__pt, minimal_out_len__alu16));
  if(message_len__alu16 > primitive_input_len__alu16)
  {
    FLEA_THROW("message too long of pk encryption", FLEA_ERR_INV_ARG);
  }
  memcpy(result__pt->data__pu8, message__pcu8, message_len__alu16);
  if(id__t == flea_rsa_oaep_encr)
  {
    FLEA_CCALL(
      THR_flea_pk_api__encode_message__oaep(
        // result__pu8,
        result__pt->data__pu8,
        message_len__alu16,
        &primitive_input_len__alu16,
        key_len__alu16 * 8,
        hash_id__t
      )
    );
  }
  else if(id__t == flea_rsa_pkcs1_v1_5_encr)
  {
    FLEA_CCALL(
      THR_flea_pk_api__encode_message__pkcs1_v1_5_encr(
        // result__pu8,
        result__pt->data__pu8,
        message_len__alu16,
        &primitive_input_len__alu16,
        key_len__alu16 * 8,
        hash_id__t
      )
    ); // hash-id not used
  }
  else
  {
    FLEA_THROW("unsupported pk encryption algorithm", FLEA_ERR_INV_ALGORITHM);
  }
  FLEA_CCALL(
    THR_flea_rsa_raw_operation(
      // result__pu8,
      result__pt->data__pu8,
      params__pcu8,
      params_len__alu16,
      // result__pu8,
      result__pt->data__pu8,
      primitive_input_len__alu16,
      key__pcu8,
      key_len__alu16
    )
  );
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_pk_api__encrypt_message */

#endif // #ifdef FLEA_HAVE_PK_CS

#ifdef FLEA_HAVE_PK_CS
flea_err_t THR_flea_pk_api__decrypt_message(
  flea_pk_scheme_id_t       id__t,
  flea_hash_id_t            hash_id__t,
  const flea_u8_t*          ciphertext__pcu8,
  flea_al_u16_t             ciphertext_len__alu16,

  /*flea_u8_t*                result__pu8,
   * flea_al_u16_t*            result_len__palu16,*/
  flea_byte_vec_t*          result_vec__pt,

  /*const flea_u8_t*    key__pcu8,
   * flea_al_u16_t       key_len__alu16,*/
  const flea_private_key_t* privkey__pt,
  flea_al_u16_t             enforced_decryption_result_len__alu16
)
{
  FLEA_DECL_BUF(primitive_output__bu8, flea_u8_t, FLEA_PK_MAX_PRIMITIVE_OUTPUT_LEN);

  flea_al_u16_t mod_len__alu16;

  flea_al_u16_t primitive_output_len__alu16;
  FLEA_THR_BEG_FUNC();
  // mod_len__alu16 = key_len__alu16 / 5 * 2;
  if(privkey__pt->key_type__t != flea_rsa_key)
  {
    FLEA_THROW("invalid key type for public key decryption", FLEA_ERR_INV_KEY_TYPE);
  }
  mod_len__alu16 = (privkey__pt->key_bit_size__u16 + 7) / 8;
  primitive_output_len__alu16 = mod_len__alu16;
# ifdef FLEA_USE_STACK_BUF
  if(mod_len__alu16 > FLEA_STACK_BUF_NB_ENTRIES(primitive_output__bu8))
  {
    FLEA_THROW("key length too large", FLEA_ERR_INV_KEY_SIZE);
  }
# endif
  if(ciphertext_len__alu16 > mod_len__alu16)
  {
    FLEA_THROW("ciphertext length too large", FLEA_ERR_INV_ARG);
  }
  FLEA_ALLOC_BUF(primitive_output__bu8, primitive_output_len__alu16);
  FLEA_CCALL(
    THR_flea_rsa_raw_operation_crt_private_key(
      privkey__pt,
      primitive_output__bu8,
      ciphertext__pcu8,
      ciphertext_len__alu16
      // mod_len__alu16,

      /*key__pcu8,
       * key_len__alu16*/
    )
  );
  if(id__t == flea_rsa_pkcs1_v1_5_encr)
  {
    FLEA_CCALL(
      THR_flea_pk_api__decode_message__pkcs1_v1_5(
        primitive_output__bu8,
        primitive_output_len__alu16,
        result_vec__pt,

        /*result__pu8,
         * result_len__palu16,*/
        8 * mod_len__alu16,
        enforced_decryption_result_len__alu16
      )
    );
  }
  else if(id__t == flea_rsa_oaep_encr)
  {
    FLEA_CCALL(
      THR_flea_pk_api__decode_message__oaep(

        /*result__pu8,
         * result_len__palu16,*/
        result_vec__pt,
        primitive_output__bu8,
        primitive_output_len__alu16,
        8 * mod_len__alu16,
        hash_id__t
      )
    );
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_SECRET_ARR(
      primitive_output__bu8,
      FLEA_HEAP_OR_STACK_CODE(primitive_output_len__alu16, FLEA_STACK_BUF_NB_ENTRIES(primitive_output__bu8))
    );
  );
} /* THR_flea_pk_api__decrypt_message */

#endif // #ifdef FLEA_HAVE_PK_CS
