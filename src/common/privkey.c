/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "flea/privkey.h"
#include "internal/common/pk_key_int.h"
#include "flea/ecdsa.h"
#include "flea/rsa.h"
#include "flea/error.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/x509.h"
#include "internal/common/namespace_asn1.h"
#include "internal/common/ecc_dp_int.h"
#include "flea/ec_key.h"
#include "flea/util.h"
#include "flea/bin_utils.h"
#include "flea/pk_signer.h"
#include "flea/ecc_named_curves.h"
#include "internal/common/byte_vec_int.h"
#include "internal/common/enc_ecdsa_sig.h"
#include <string.h>

#ifdef FLEA_HAVE_ASYM_ALGS

# ifdef FLEA_HAVE_ECC
flea_err_e THR_flea_private_key_t__ctor_ecc(
  flea_private_key_t*          key__pt,
  const flea_byte_vec_t*       scalar__cprcu8,
  const flea_ec_dom_par_ref_t* dp_ref__pt
)
{
  flea_al_u16_t dp_concat_len__alu16;

  FLEA_THR_BEG_FUNC();
  key__pt->key_type__t       = flea_ecc_key;
  key__pt->key_bit_size__u16 = flea__get_BE_int_bit_len(dp_ref__pt->n__ru8.data__pcu8, dp_ref__pt->n__ru8.len__dtl);
  key__pt->max_primitive_input_len__u16 = (key__pt->key_bit_size__u16 + 7) / 8;

  if(key__pt->key_bit_size__u16 > FLEA_ECC_MAX_ORDER_BIT_SIZE)
  {
    FLEA_THROW("ECC order too large", FLEA_ERR_INV_ECC_DP);
  }
  if(flea__get_BE_int_bit_len(scalar__cprcu8->data__pu8, scalar__cprcu8->len__dtl) > key__pt->key_bit_size__u16)
  {
    FLEA_THROW("ECC order too large", FLEA_ERR_INV_KEY_SIZE);
  }
#  ifdef FLEA_HEAP_MODE
  dp_concat_len__alu16 = flea_ec_dom_par_ref_t__get_concat_length(dp_ref__pt);
  FLEA_ALLOC_MEM(key__pt->privkey_with_params__u.ec_priv_key_val__t.dp_mem__bu8, dp_concat_len__alu16);
  FLEA_ALLOC_MEM(key__pt->privkey_with_params__u.ec_priv_key_val__t.priv_scalar__mem__bu8, scalar__cprcu8->len__dtl);
#  else
  dp_concat_len__alu16 = sizeof(key__pt->privkey_with_params__u.ec_priv_key_val__t.dp_mem__bu8);
#  endif /* ifdef FLEA_HEAP_MODE */
  flea_byte_vec_t__copy_content_set_ref_use_mem(
    &key__pt->privkey_with_params__u.ec_priv_key_val__t.scalar__rcu8,
    key__pt->privkey_with_params__u.ec_priv_key_val__t.priv_scalar__mem__bu8,
    scalar__cprcu8
  );

  FLEA_CCALL(
    THR_flea_ec_dom_par_ref_t__write_to_concat_array(
      &key__pt->privkey_with_params__u.ec_priv_key_val__t.dp__t,
      key__pt->privkey_with_params__u.ec_priv_key_val__t.dp_mem__bu8,
      dp_concat_len__alu16,
      dp_ref__pt
    )
  );
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_private_key_t__ctor_ecc */

# endif /* #ifdef FLEA_HAVE_ECC */
# ifdef FLEA_HAVE_RSA
flea_err_e THR_flea_private_key_t__ctor_rsa_internal_format(
  flea_private_key_t*   key__pt,
  const flea_ref_cu8_t* priv_key_enc_internal_format__prcu8,
  flea_al_u16_t         key_bit_size__alu16
)
{
  FLEA_THR_BEG_FUNC();

  const flea_u8_t* key_mem__pcu8    = priv_key_enc_internal_format__prcu8->data__pcu8;
  flea_al_u16_t key_len__alu16      = priv_key_enc_internal_format__prcu8->len__dtl;
  flea_al_u16_t half_mod_len__alu16 = key_len__alu16 / 5;
  if(key_len__alu16 % 5
#  ifdef FLEA_STACK_MODE
    || key_len__alu16 > FLEA_RSA_CRT_KEY_INTERNAL_FORMAT_MAX_BYTE_SIZE
#  endif
  )
  {
    FLEA_THROW("invalid length of RSA key in internal format", FLEA_ERR_INV_KEY_COMP_SIZE);
  }

  FLEA_CCALL(
    THR_flea_private_key_t__ctor_rsa_components(
      key__pt,
      key_bit_size__alu16,
      key_mem__pcu8,
      half_mod_len__alu16,
      key_mem__pcu8 + half_mod_len__alu16,
      half_mod_len__alu16,
      key_mem__pcu8 + 2 * half_mod_len__alu16,
      half_mod_len__alu16,
      key_mem__pcu8 + 3 * half_mod_len__alu16,
      half_mod_len__alu16,
      key_mem__pcu8 + 4 * half_mod_len__alu16,
      half_mod_len__alu16
    )
  );

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_private_key_t__ctor_rsa_internal_format */

# endif /* #ifdef FLEA_HAVE_RSA */

# ifdef FLEA_HAVE_RSA
flea_err_e THR_flea_private_key_t__ctor_rsa_components(
  flea_private_key_t* key__pt,
  flea_al_u16_t       key_bit_size__alu16,
  const flea_u8_t*    p__pcu8,
  flea_al_u16_t       p_len__alu16,
  const flea_u8_t*    q__pcu8,
  flea_al_u16_t       q_len__alu16,
  const flea_u8_t*    d1__pcu8,
  flea_al_u16_t       d1_len__alu16,
  const flea_u8_t*    d2__pcu8,
  flea_al_u16_t       d2_len__alu16,
  const flea_u8_t*    c__pcu8,
  flea_al_u16_t       c_len__alu16
)
{
  FLEA_THR_BEG_FUNC();
  flea_al_u8_t i;
  flea_u8_t* priv_key_mem__pcu8;
  const flea_u8_t* comp_ptrs__apcu8 []     = {p__pcu8, q__pcu8, d1__pcu8, d2__pcu8, c__pcu8};
  const flea_al_u16_t comp_lens__aalu16 [] = {p_len__alu16, q_len__alu16, d1_len__alu16, d2_len__alu16, c_len__alu16};

#  ifdef FLEA_HEAP_MODE
  flea_al_u16_t key_len__al_u16;
#  endif
  key__pt->key_bit_size__u16 = key_bit_size__alu16;
  key__pt->key_type__t       = flea_rsa_key;
  key__pt->max_primitive_input_len__u16 = (key_bit_size__alu16 + 7) / 8;
#  ifdef FLEA_STACK_MODE
  if(p_len__alu16 > FLEA_RSA_CRT_KEY_COMPONENT_MAX_BYTE_SIZE ||
    q_len__alu16 > FLEA_RSA_CRT_KEY_COMPONENT_MAX_BYTE_SIZE ||
    d1_len__alu16 > FLEA_RSA_CRT_KEY_COMPONENT_MAX_BYTE_SIZE ||
    d2_len__alu16 > FLEA_RSA_CRT_KEY_COMPONENT_MAX_BYTE_SIZE ||
    c_len__alu16 > FLEA_RSA_CRT_KEY_COMPONENT_MAX_BYTE_SIZE
  )
  {
    FLEA_THROW("invalid RSA private key component size", FLEA_ERR_INV_KEY_COMP_SIZE);
  }
#  endif /* ifdef FLEA_STACK_MODE */
#  ifdef FLEA_HEAP_MODE
  key_len__al_u16 = p_len__alu16 + q_len__alu16 + d1_len__alu16 + d2_len__alu16 + c_len__alu16;
  FLEA_ALLOC_MEM(key__pt->privkey_with_params__u.rsa_priv_key_val__t.priv_key_mem__bu8, key_len__al_u16);

#  endif

  priv_key_mem__pcu8 = key__pt->privkey_with_params__u.rsa_priv_key_val__t.priv_key_mem__bu8;
  for(i = 0; i < 5; i++)
  {
    const flea_u8_t* ptr__pcu8 = comp_ptrs__apcu8[i];
    flea_al_u16_t len__alu16   = comp_lens__aalu16[i];
    memcpy(priv_key_mem__pcu8, ptr__pcu8, len__alu16);
    key__pt->privkey_with_params__u.rsa_priv_key_val__t.pqd1d2c__rcu8[i].data__pu8 = priv_key_mem__pcu8;
    key__pt->privkey_with_params__u.rsa_priv_key_val__t.pqd1d2c__rcu8[i].len__dtl  = len__alu16;
    priv_key_mem__pcu8 += len__alu16;
  }


  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_private_key_t__ctor_rsa_components */

# endif /* #ifdef FLEA_HAVE_RSA */

void flea_private_key_t__dtor(flea_private_key_t* privkey__pt)
{
# ifdef FLEA_HEAP_MODE
#  ifdef FLEA_HAVE_RSA
  if(privkey__pt->key_type__t == flea_rsa_key)
  {
    FLEA_FREE_MEM_CHK_SET_NULL(privkey__pt->privkey_with_params__u.rsa_priv_key_val__t.priv_key_mem__bu8);
  }
#  endif /* ifdef FLEA_HAVE_RSA */
#  ifdef FLEA_HAVE_ECC
  if(privkey__pt->key_type__t == flea_ecc_key)
  {
    FLEA_FREE_MEM_CHK_SET_NULL(privkey__pt->privkey_with_params__u.ec_priv_key_val__t.dp_mem__bu8);
    FLEA_FREE_MEM_CHK_SET_NULL(privkey__pt->privkey_with_params__u.ec_priv_key_val__t.priv_scalar__mem__bu8);
  }
#  endif /* ifdef FLEA_HAVE_ECC */
# endif /* ifdef FLEA_HEAP_MODE */
}

# ifdef FLEA_HAVE_ASYM_SIG


flea_err_e THR_flea_private_key_t__sign(
  const flea_private_key_t* privkey__pt,
  flea_pk_scheme_id_e       pk_scheme_id__t,
  flea_hash_id_e            hash_id__t,
  const flea_byte_vec_t*    message__prcu8,
  flea_byte_vec_t*          signature__pru8
)
{
  FLEA_DECL_OBJ(signer__t, flea_pk_signer_t);
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_pk_signer_t__ctor(&signer__t, hash_id__t));
  FLEA_CCALL(THR_flea_pk_signer_t__update(&signer__t, message__prcu8->data__pu8, message__prcu8->len__dtl));
  FLEA_CCALL(
    THR_flea_pk_signer_t__final_sign(
      &signer__t,
      pk_scheme_id__t,
      privkey__pt,
      signature__pru8
    )
  );
  FLEA_THR_FIN_SEC(
    flea_pk_signer_t__dtor(&signer__t);
  );
}

flea_err_e THR_flea_private_key_t__sign_digest(
  const flea_private_key_t* privkey__pt,
  flea_pk_scheme_id_e       id__t,
  flea_hash_id_e            hash_id__e,
  const flea_u8_t*          digest__pcu8,
  flea_al_u8_t              digest_len__alu8,
  flea_byte_vec_t*          sig_vec__pt
)
{
  flea_pk_primitive_id_e primitive_id__t;
  flea_pk_encoding_id_e encoding_id__t;
  flea_al_u16_t key_bit_size__alu16;
  flea_al_u16_t primitive_input_len__alu16;

#  ifdef FLEA_HAVE_ECDSA
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(ecdsa_ws_bv__t, FLEA_ECDSA_MAX_ASN1_SIG_LEN);
#  endif
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
  if(digest_len__alu8 != flea_hash__get_output_length_by_id(hash_id__e))
  {
    FLEA_THROW("digest length does not fit to hash id", FLEA_ERR_INV_ARG);
  }
  FLEA_ALLOC_BUF(primitive_input__bu8, FLEA_MAX(primitive_input_len__alu16, FLEA_MAX_HASH_OUT_LEN));
  // get the final hash value
  if(digest_len__alu8 > FLEA_MAX_HASH_OUT_LEN)
  {
    FLEA_THROW("signature for extraneous digest length requested", FLEA_ERR_INV_ARG);
  }
  memcpy(primitive_input__bu8, digest__pcu8, digest_len__alu8);
  if((encoding_id__t == flea_emsa1_asn1) || (encoding_id__t == flea_emsa1_concat))
  {
    FLEA_CCALL(
      THR_flea_pk_api__encode_message__ansi_x9_62(
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
#  ifdef FLEA_HAVE_ECDSA
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

    if(id__t == flea_ecdsa_emsa1_asn1)
    {
      FLEA_CCALL(THR_flea_asn1_encode_ecdsa_sig(sig_r__pu8, r_len__al_u8, sig_s__pu8, s_len__al_u8, &ecdsa_ws_bv__t));
      flea_byte_vec_t__reset(sig_vec__pt);
      FLEA_CCALL(
        THR_flea_byte_vec_t__append(
          sig_vec__pt,
          flea_byte_vec_t__GET_DATA_PTR(&ecdsa_ws_bv__t),
          flea_byte_vec_t__GET_DATA_LEN(&ecdsa_ws_bv__t)
        )
      );
    }
    else
    {
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
    }

#  else // #ifdef FLEA_HAVE_ECDSA
    FLEA_THROW("ECDSA not supported", FLEA_ERR_INV_ALGORITHM);
#  endif // #else of #ifdef FLEA_HAVE_ECDSA
  }
  else if(primitive_id__t == flea_rsa_sign)
  {
#  ifdef FLEA_HAVE_RSA
    if(privkey__pt->key_type__t != flea_rsa_key)
    {
      FLEA_THROW("invalid key type for signing", FLEA_ERR_INV_KEY_TYPE);
    }
    // in RSA, input length = output length
    FLEA_CCALL(THR_flea_byte_vec_t__resize(sig_vec__pt, primitive_input_len__alu16));

    FLEA_CCALL(
      THR_flea_rsa_raw_operation_crt_private_key(
        privkey__pt,
        sig_vec__pt->data__pu8,
        primitive_input__bu8,
        primitive_input_len__alu16
      )
    );


#  else // #ifdef FLEA_HAVE_RSA
    FLEA_THROW("rsa not supported", FLEA_ERR_INV_ALGORITHM);
#  endif // #else of #ifdef FLEA_HAVE_RSA
  }
  else
  {
    FLEA_THROW("invalid signature primitive id", FLEA_ERR_INV_ALGORITHM);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(primitive_input__bu8);
    FLEA_DO_IF_HAVE_ECDSA(
      flea_byte_vec_t__dtor(&ecdsa_ws_bv__t);
    );
  );
} /* THR_flea_pk_signer_t__final_sign */

# endif /* ifdef FLEA_HAVE_ASYM_SIG */

flea_err_e THR_flea_private_key_t__get_encoded_plain(
  const flea_private_key_t* privkey__cpt,
  flea_byte_vec_t*          result__pt
)
{
  FLEA_THR_BEG_FUNC();
  if(privkey__cpt->key_type__t != flea_ecc_key)
  {
    FLEA_THROW("invalid key type for plain encoding", FLEA_ERR_INV_KEY_TYPE);
  }
# ifdef FLEA_HAVE_ECC
  FLEA_CCALL(
    THR_flea_byte_vec_t__set_content(
      result__pt,
      privkey__cpt->privkey_with_params__u.ec_priv_key_val__t.scalar__rcu8.data__pu8,
      privkey__cpt->privkey_with_params__u.ec_priv_key_val__t.scalar__rcu8.len__dtl
    )
  );
# else  /* ifdef FLEA_HAVE_ECC */
  FLEA_THROW("invalid key type for plain encoding", FLEA_ERR_INV_KEY_TYPE);
# endif /* ifdef FLEA_HAVE_ECC */

  FLEA_THR_FIN_SEC_empty();
}

#endif /* #ifdef FLEA_HAVE_ASYM_ALGS */
