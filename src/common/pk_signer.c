/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/pk_enc/oaep.h"
#include "flea/pk_signer.h"
#include "flea/privkey.h"
#include "flea/array_util.h"
#include "flea/util.h"
#include "flea/alloc.h"
#include "flea/error.h"
#include "flea/error_handling.h"
#include "flea/algo_config.h"
#include "flea/ecdsa.h"
#include "flea/rsa.h"
#include "flea/rsa_pub_op.h"
#include "flea/rng.h"
#include "flea/ec_dom_par.h"
#include "flea/bin_utils.h"
#include "internal/common/mask.h"
#include "internal/common/pk_key_int.h"
#include "internal/common/pk_enc/pkcs1_v1_5.h"
#include <string.h>


#ifdef FLEA_HAVE_ASYM_SIG


void flea_pk_signer_t__dtor(flea_pk_signer_t* p_destr)
{
  flea_hash_ctx_t__dtor(&p_destr->hash_ctx);
  flea_pk_signer_t__INIT(p_destr);
}

flea_err_e THR_flea_pk_signer_t__ctor(
  flea_pk_signer_t* result__pt,
  flea_hash_id_e    hash_id__t
)
{
  FLEA_THR_BEG_FUNC();
  result__pt->hash_id__t = hash_id__t;
  FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&result__pt->hash_ctx, hash_id__t));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_pk_signer_t__update(
  flea_pk_signer_t* signer__pt,
  const flea_u8_t*  message__pcu8,
  flea_al_u16_t     message_len__alu16
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_hash_ctx_t__update(&signer__pt->hash_ctx, message__pcu8, message_len__alu16));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_pk_signer_t__final_sign(
  flea_pk_signer_t*     signer__pt,
  flea_pk_scheme_id_e   id__t,
  const flea_privkey_t* privkey__pt,
  flea_byte_vec_t*      sig_vec__pt
)
{
  flea_al_u8_t digest_len__alu8;

  FLEA_DECL_BUF(digest_buf__bu8, flea_u8_t, FLEA_MAX_HASH_OUT_LEN);
  FLEA_THR_BEG_FUNC();
  digest_len__alu8 = flea_hash_ctx_t__get_output_length(&signer__pt->hash_ctx);

  FLEA_ALLOC_BUF(digest_buf__bu8, digest_len__alu8);

  FLEA_CCALL(THR_flea_hash_ctx_t__final(&signer__pt->hash_ctx, digest_buf__bu8));
  FLEA_CCALL(
    THR_flea_privkey_t__sign_digest(
      privkey__pt,
      id__t,
      signer__pt->hash_id__t,
      digest_buf__bu8,
      digest_len__alu8,
      sig_vec__pt
    )
  );
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(digest_buf__bu8);
  );
}

flea_err_e THR_flea_pk_signer_t__final_verify(
  flea_pk_signer_t*    signer__pt,
  flea_pk_scheme_id_e  id__t,
  const flea_pubkey_t* pubkey__pt,
  const flea_u8_t*     signature__pcu8,
  flea_al_u16_t        signature_len__alu16
)
{
  flea_al_u8_t digest_len__alu8;

  FLEA_DECL_BUF(digest_buf__bu8, flea_u8_t, FLEA_MAX_HASH_OUT_LEN);
  FLEA_THR_BEG_FUNC();
  digest_len__alu8 = flea_hash_ctx_t__get_output_length(&signer__pt->hash_ctx);

  FLEA_ALLOC_BUF(digest_buf__bu8, digest_len__alu8);

  FLEA_CCALL(THR_flea_hash_ctx_t__final(&signer__pt->hash_ctx, digest_buf__bu8));
  FLEA_CCALL(
    THR_flea_pubkey_t__verify_digest(
      pubkey__pt,
      id__t,
      signer__pt->hash_id__t,
      digest_buf__bu8,
      digest_len__alu8,
      signature__pcu8,
      signature_len__alu16
    )
  );
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(digest_buf__bu8);
  );
}

flea_err_e THR_flea_pk_api__verify_message__pkcs1_v1_5(
  const flea_u8_t* encoded__pcu8,
  flea_al_u16_t    encoded_len__alu16,
  const flea_u8_t* digest__pu8,
  flea_al_u16_t    digest_len__alu16,
  flea_al_u16_t    bit_size__alu16,
  flea_hash_id_e   hash_id__t
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
# ifdef FLEA_STACK_MODE
  if(compare_val_len__alu16 > FLEA_STACK_BUF_NB_ENTRIES(compare__bu8))
  {
    FLEA_THROW("key bit size too large", FLEA_ERR_INV_KEY_SIZE);
  }
# endif /* ifdef FLEA_STACK_MODE */
  FLEA_ALLOC_BUF(compare__bu8, compare_val_len__alu16);
  memcpy(compare__bu8, digest__pu8, digest_len__alu16);
  FLEA_CCALL(
    THR_flea_pk_api__enc_msg_sign_pkcs1_v1_5(
      compare__bu8,
      digest_len__alu16,
      &compare_val_len__alu16,
      bit_size__alu16,
      hash_id__t
    )
  );

  /**
   * offset by one because leading zero byte is not encoded by RSA
   * exponentiation.
   */
  if(memcmp(encoded__pcu8, &compare__bu8[1], compare_val_len__alu16 - 1))
  {
    FLEA_THROW("invalid format of PKCS#1 v1.5 message", FLEA_ERR_INV_SIGNATURE);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(compare__bu8);
  );
} /* THR_flea_pk_api__verify_message__pkcs1_v1_5 */

flea_err_e THR_flea_pk_api__enc_msg_ansi_x9_62(
  flea_u8_t*     input_output__pu8,
  flea_al_u16_t  input_len__alu16,
  flea_al_u16_t* output_len__palu16,
  flea_al_u16_t  bit_size
)
{
  flea_al_u8_t bit_shift__alu8;

  FLEA_THR_BEG_FUNC();

  if(8 * input_len__alu16 <= bit_size)
  {
    *output_len__palu16 = input_len__alu16;
    FLEA_THR_RETURN();
  }
  *output_len__palu16 = (bit_size + 7) / 8;
  bit_shift__alu8     = 8 - (bit_size % 8);
  if(bit_shift__alu8 == 8)
  {
    bit_shift__alu8 = 0;
  }
  if(bit_shift__alu8)
  {
    flea_al_u16_t j;
    flea_al_u8_t carry__alu8 = 0;
    for(j = 0; j != *output_len__palu16; ++j)
    {
      flea_al_u8_t temp__alu8 = input_output__pu8[j];
      input_output__pu8[j] = (temp__alu8 >> bit_shift__alu8) | carry__alu8;
      carry__alu8 = (temp__alu8 << (8 - bit_shift__alu8));
    }
  }
  FLEA_THR_FIN_SEC_empty();
}

#endif // #ifdef FLEA_HAVE_ASYM_SIG


#ifdef FLEA_HAVE_PK_CS
flea_err_e THR_flea_pk_api__encrypt_message(
  flea_pk_scheme_id_e id__t,
  flea_hash_id_e      hash_id__t,
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

  FLEA_CCALL(THR_flea_byte_vec_t__resize(result__pt, minimal_out_len__alu16));
  if(message_len__alu16 > primitive_input_len__alu16)
  {
    FLEA_THROW("message too long of pk encryption", FLEA_ERR_INV_ARG);
  }
  memcpy(result__pt->data__pu8, message__pcu8, message_len__alu16);
  if(id__t == flea_rsa_oaep_encr)
  {
    FLEA_CCALL(
      THR_flea_pk_api__enc_msg_oaep(
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
      THR_flea_pk_api__enc_msg_encr_pkcs1_v1_5(
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
      result__pt->data__pu8,
      params__pcu8,
      params_len__alu16,
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

flea_err_e THR_flea_privkey_t__decrypt_message(
  const flea_privkey_t* privkey__pt,
  flea_pk_scheme_id_e   id__t,
  flea_hash_id_e        hash_id__t,
  const flea_u8_t*      ciphertext__pcu8,
  flea_al_u16_t         ciphertext_len__alu16,
  flea_byte_vec_t*      result_vec__pt
)
{
  return THR_flea_privkey_t__decr_msg_secure(
    privkey__pt,
    id__t,
    hash_id__t,
    ciphertext__pcu8,
    ciphertext_len__alu16,
    result_vec__pt,
    0,
    NULL
  );
}

flea_err_e THR_flea_privkey_t__decr_msg_secure(
  const flea_privkey_t* privkey__pt,
  flea_pk_scheme_id_e   id__t,
  flea_hash_id_e        hash_id__t,
  const flea_u8_t*      ciphertext__pcu8,
  flea_al_u16_t         ciphertext_len__alu16,
  flea_byte_vec_t*      result_vec__pt,
  flea_al_u16_t         enforced_decryption_result_len__alu16,
  flea_u8_t*            silent_alarm__pu8
)
{
  FLEA_DECL_BUF(primitive_output__bu8, flea_u8_t, FLEA_PK_MAX_PRIMITIVE_OUTPUT_LEN);

  flea_al_u16_t mod_len__alu16;

  flea_al_u16_t primitive_output_len__alu16;
  FLEA_THR_BEG_FUNC();
  if(privkey__pt->key_type__t != flea_rsa_key)
  {
    FLEA_THROW("invalid key type for public key decryption", FLEA_ERR_INV_KEY_TYPE);
  }
  mod_len__alu16 = (privkey__pt->key_bit_size__u16 + 7) / 8;
  primitive_output_len__alu16 = mod_len__alu16;
# ifdef FLEA_STACK_MODE
  if(mod_len__alu16 > FLEA_STACK_BUF_NB_ENTRIES(primitive_output__bu8))
  {
    FLEA_THROW("key length too large", FLEA_ERR_INV_KEY_SIZE);
  }
# endif /* ifdef FLEA_STACK_MODE */
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
    )
  );
  if(id__t == flea_rsa_pkcs1_v1_5_encr)
  {
    FLEA_CCALL(
      THR_flea_pk_api__dec_msg__pkcs1_v1_5(
        primitive_output__bu8,
        primitive_output_len__alu16,
        result_vec__pt,
        8 * mod_len__alu16,
        enforced_decryption_result_len__alu16,
        silent_alarm__pu8
      )
    );
  }
  else if(id__t == flea_rsa_oaep_encr)
  {
    FLEA_CCALL(
      THR_flea_pk_api__dec_msg__oaep(
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
