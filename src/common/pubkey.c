/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "flea/pubkey.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "internal/common/namespace_asn1.h"
#include "flea/x509.h"
#include "internal/common/x509_key_int.h"
#include "flea/ec_key.h"
#include "flea/util.h"
#include "flea/bin_utils.h"
#include "flea/pk_signer.h"
#include "flea/ecc_named_curves.h"
#include "flea/ecdsa.h"
#include "flea/rsa.h"
#include "flea/rsa_pub_op.h"
#include "internal/common/oid.h"
#include "internal/common/pubkey_int.h"
#include "internal/common/pk_enc/pkcs1_v1_5.h"
#include "flea/mem_read_stream.h"
#include "flea/cert_path.h"

#ifdef FLEA_HAVE_ASYM_ALGS

void flea_public_key_t__get_encoded_plain_ref(
  const flea_public_key_t* pk,
  flea_ref_cu8_t*          result__pcu8
)
{
# ifdef FLEA_HAVE_ECC
  if(pk->key_type__t == flea_ecc_key)
  {
    result__pcu8->data__pcu8 = pk->pubkey_with_params__u.ec_public_val__t.public_point_encoded__rcu8.data__pu8;
    result__pcu8->len__dtl   = pk->pubkey_with_params__u.ec_public_val__t.public_point_encoded__rcu8.len__dtl;
  }
  else
# endif /* ifdef FLEA_HAVE_ECC */
# ifdef FLEA_HAVE_RSA
  if(pk->key_type__t == flea_rsa_key)
  {
    result__pcu8->data__pcu8 = pk->pubkey_with_params__u.rsa_public_val__t.mod__rcu8.data__pcu8;
    result__pcu8->len__dtl   = pk->pubkey_with_params__u.rsa_public_val__t.mod__rcu8.len__dtl;
  }
  else
# endif /* ifdef FLEA_HAVE_RSA */
  {
    result__pcu8->data__pcu8 = NULL;
    result__pcu8->len__dtl   = 0;
  }
}

# ifdef FLEA_HAVE_ECC


# endif /* ifdef FLEA_HAVE_ECC */


static flea_err_e THR_flea_determine_public_key_type_from_oid(
  const flea_u8_t*    oid_val__pcu8,
  flea_dtl_t          oid_val_len__dtl,
  flea_pk_key_type_e* result_key_type__pe
)
{
# ifdef FLEA_HAVE_ECC
  const flea_u8_t ec_public_key_oid__au8 [] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
# endif
# ifdef FLEA_HAVE_RSA
  const flea_u8_t rsa_public_key_oid__au8 [] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
# endif

  FLEA_THR_BEG_FUNC();
# ifdef FLEA_HAVE_RSA

  if(0 == flea_memcmp_wsize(oid_val__pcu8, oid_val_len__dtl, rsa_public_key_oid__au8, sizeof(rsa_public_key_oid__au8)))
  {
    *result_key_type__pe = flea_rsa_key;
  }
  else
# endif /* ifdef FLEA_HAVE_RSA */
# ifdef FLEA_HAVE_ECC
  if(0 == flea_memcmp_wsize(oid_val__pcu8, oid_val_len__dtl, ec_public_key_oid__au8, sizeof(ec_public_key_oid__au8)))
  {
    *result_key_type__pe = flea_ecc_key;
  }
  else
# endif /* #ifdef FLEA_HAVE_ECC */
  {
    FLEA_THROW("unsupported primitive", FLEA_ERR_X509_UNSUPP_ALGO);
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_determine_public_key_type_from_oid */

flea_err_e THR_flea_public_key_t__ctor_cert(
  flea_public_key_t*          key__pt,
  const flea_x509_cert_ref_t* cert_ref__pt
)
{
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(
    THR_flea_public_key_t__ctor_asn1(
      key__pt,
      &cert_ref__pt->subject_public_key_info__t.public_key_as_tlv__t,
      &cert_ref__pt->subject_public_key_info__t.algid__t.params_ref_as_tlv__t,
      &cert_ref__pt->subject_public_key_info__t.algid__t.oid_ref__t
    )
  );
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_public_key_t__ctor_cert */

flea_err_e THR_flea_public_key_t__ctor_asn1(
  flea_public_key_t*     key__pt,
  const flea_byte_vec_t* key_as_bit_string_tlv__prcu8,
  const flea_byte_vec_t* encoded_params__prcu8,
  const flea_byte_vec_t* alg_oid__pt
)
{
  flea_ber_dec_t key_dec__t;
  flea_rw_stream_t source__t;
  flea_mem_read_stream_help_t hlp__t;

  FLEA_THR_BEG_FUNC();
  flea_ber_dec_t__INIT(&key_dec__t);
  flea_rw_stream_t__INIT(&source__t);
  flea_byte_vec_t public_key_as_bitstr__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE;
  flea_byte_vec_t public_key_value__t     = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE; /* BIT STRING value */
  FLEA_CCALL(
    THR_flea_determine_public_key_type_from_oid(
      alg_oid__pt->data__pu8,
      alg_oid__pt->len__dtl,
      &key__pt->key_type__t
    )
  );
  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor_memory(
      &source__t,
      key_as_bit_string_tlv__prcu8->data__pu8,
      key_as_bit_string_tlv__prcu8->len__dtl,
      &hlp__t
    )
  );
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&key_dec__t, &source__t, 0, flea_decode_ref));

  FLEA_CCALL(
    THR_flea_ber_dec_t__get_ref_to_raw_cft(
      &key_dec__t,
      FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_UNIVERSAL_PRIMITIVE, FLEA_ASN1_BIT_STRING),
      &public_key_as_bitstr__t
    )
  );
  FLEA_CCALL(
    THR_flea_ber_dec__get_ref_to_bit_string_content_no_unused_bits(
      &public_key_as_bitstr__t,
      &public_key_value__t
    )
  );

# ifdef FLEA_HAVE_ECC
  if(key__pt->key_type__t == flea_ecc_key)
  {
    flea_ec_dom_par_ref_t dp_ref__t;
    FLEA_CCALL(THR_flea_x509_parse_ecc_public_params(encoded_params__prcu8, &dp_ref__t));

    FLEA_CCALL(THR_flea_public_key_t__ctor_ecc(key__pt, &public_key_value__t, &dp_ref__t));
  }
  else
# endif /* ifdef FLEA_HAVE_ECC */
# ifdef FLEA_HAVE_RSA

  if(key__pt->key_type__t == flea_rsa_key)
  {
    flea_ref_cu8_t mod__rcu8, exp__rcu8;
    FLEA_CCALL(THR_flea_x509_parse_rsa_public_key(&public_key_value__t, &mod__rcu8, &exp__rcu8));
    if(mod__rcu8.len__dtl > FLEA_RSA_MAX_MOD_BYTE_LEN || exp__rcu8.len__dtl > FLEA_RSA_MAX_PUB_EXP_BYTE_LEN)
    {
      FLEA_THROW("unsupported RSA key size", FLEA_ERR_INV_KEY_SIZE);
    }
    FLEA_CCALL(THR_flea_public_key_t__ctor_rsa(key__pt, &mod__rcu8, &exp__rcu8));
  }
  else
# endif /* ifdef FLEA_HAVE_RSA */
  {
    FLEA_THROW("key type is not supported not supported", FLEA_ERR_INV_KEY_TYPE);
  }
  FLEA_THR_FIN_SEC(
    flea_rw_stream_t__dtor(&source__t);
    flea_ber_dec_t__dtor(&key_dec__t);
  );
} /* THR_flea_public_key_t__ctor */

# ifdef FLEA_HAVE_ECC
flea_err_e THR_flea_public_key_t__ctor_ecc(
  flea_public_key_t*           key__pt,
  const flea_byte_vec_t*       public_key_value__pt,
  const flea_ec_dom_par_ref_t* dp__pt
)
{
  FLEA_THR_BEG_FUNC();

  key__pt->key_type__t = flea_ecc_key;
  FLEA_CCALL(
    THR_flea_public_key_t__create_ecdsa_key(
      &key__pt->pubkey_with_params__u.ec_public_val__t,
      public_key_value__pt,
      dp__pt
    )
  );

  key__pt->key_bit_size__u16 = flea__get_BE_int_bit_len(
    key__pt->pubkey_with_params__u.ec_public_val__t.dp__t.n__ru8.data__pcu8,
    key__pt->pubkey_with_params__u.ec_public_val__t.dp__t.n__ru8.len__dtl
    );
  key__pt->primitive_input_size__u16 = (key__pt->key_bit_size__u16 + 7) / 8;

  FLEA_THR_FIN_SEC_empty();
}

# endif /* #ifdef FLEA_HAVE_ECC */


flea_err_e THR_flea_x509_get_hash_id_and_key_type_from_oid(
  const flea_u8_t*    oid__pcu8,
  flea_al_u16_t       oid_len__alu16,
  flea_hash_id_e*     result_hash_id__pe,
  flea_pk_key_type_e* result_key_type_e
)
{
  FLEA_THR_BEG_FUNC();

# ifdef FLEA_HAVE_RSA
  if(((oid_len__alu16 == sizeof(pkcs1_oid_prefix__cau8) + 1)) &&
    !memcmp(oid__pcu8, pkcs1_oid_prefix__cau8, sizeof(pkcs1_oid_prefix__cau8)))
  {
    FLEA_CCALL(
      THR_get_hash_id_from_x509_id_for_rsa(
        oid__pcu8[sizeof(pkcs1_oid_prefix__cau8)],
        result_hash_id__pe
      )
    );

    *result_key_type_e = flea_rsa_key;
  }
  else
# endif /* ifdef FLEA_HAVE_RSA */
# ifdef FLEA_HAVE_ECC
  if(oid_len__alu16 == sizeof(ecdsa_oid_prefix__acu8) + 2 &&
    !memcmp(oid__pcu8, ecdsa_oid_prefix__acu8, sizeof(ecdsa_oid_prefix__acu8)))
  {
    FLEA_CCALL(
      THR_get_hash_id_from_x509_id_for_ecdsa(
        oid__pcu8 + sizeof(ecdsa_oid_prefix__acu8),
        result_hash_id__pe
      )
    );
    *result_key_type_e = flea_ecc_key;
  }
  else
# endif /* ifdef FLEA_HAVE_ECC */
  {
    FLEA_THROW("invalid signature algorithm", FLEA_ERR_X509_SIG_ALG_ERR);
  }


  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_x509_get_hash_id_and_scheme_type_from_oid */

flea_err_e THR_flea_public_key_t__encrypt_message(
  const flea_public_key_t* key__pt,
  flea_pk_scheme_id_e      pk_scheme_id__t,
  flea_hash_id_e           hash_id__t,
  const flea_u8_t*         message__pcu8,
  flea_al_u16_t            message_len__alu16,
  flea_byte_vec_t*         result__pt
)
{
  FLEA_THR_BEG_FUNC();
# ifdef FLEA_HAVE_RSA
  if(key__pt->key_type__t != flea_rsa_key)
  {
    FLEA_THROW("invalid public key type for encryption", FLEA_ERR_INV_KEY_TYPE);
  }
  FLEA_CCALL(
    THR_flea_pk_api__encrypt_message(
      pk_scheme_id__t,
      hash_id__t,
      message__pcu8,
      message_len__alu16,
      result__pt,
      key__pt->pubkey_with_params__u.rsa_public_val__t.mod__rcu8.data__pcu8,
      key__pt->pubkey_with_params__u.rsa_public_val__t.mod__rcu8.len__dtl,
      key__pt->pubkey_with_params__u.rsa_public_val__t.pub_exp__rcu8.data__pcu8,
      key__pt->pubkey_with_params__u.rsa_public_val__t.pub_exp__rcu8.len__dtl
    )
  );
# else /* ifdef FLEA_HAVE_RSA */
  FLEA_THROW("no public key encryption scheme (RSA) supported", FLEA_ERR_X509_UNSUPP_ALGO);
# endif /* ifdef FLEA_HAVE_RSA */
  FLEA_THR_FIN_SEC_empty();
}

# ifdef FLEA_HAVE_ASYM_SIG

/**
 * Expects a plain (concatenated) signature in case of ECDSA.
 */
static flea_err_e THR_flea_public_key_t__verify_signature_plain_format(
  const flea_public_key_t* pubkey__pt,
  flea_pk_scheme_id_e      pk_scheme_id__t,
  flea_hash_id_e           hash_id__t,
  const flea_byte_vec_t*   message__prcu8,
  const flea_byte_vec_t*   signature__prcu8
)
{
  flea_pk_signer_t signer__t;

  flea_pk_signer_t__INIT(&signer__t);
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

flea_err_e THR_flea_public_key_t__verify_signature(
  const flea_public_key_t* key__pt,
  flea_pk_scheme_id_e      pk_scheme_id__t,
  flea_hash_id_e           hash_id__t,
  const flea_byte_vec_t*   message__prcu8,
  const flea_byte_vec_t*   signature__prcu8
)
{
  FLEA_THR_BEG_FUNC();

#  ifdef FLEA_HAVE_ECDSA
  if((key__pt->key_type__t == flea_ecc_key) &&
    ((pk_scheme_id__t == flea_ecdsa_emsa1_concat) || (pk_scheme_id__t == flea_ecdsa_emsa1_asn1)))
  {
    flea_byte_vec_t concat_sig_ref__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE;
    concat_sig_ref__t.data__pu8 = signature__prcu8->data__pu8;
    concat_sig_ref__t.len__dtl  = signature__prcu8->len__dtl;

    FLEA_CCALL(
      THR_flea_public_key_t__verify_signature_plain_format(
        key__pt,
        pk_scheme_id__t,
        hash_id__t,
        message__prcu8,
        &concat_sig_ref__t
      )
    );
  }
  else
#  endif /* ifdef FLEA_HAVE_ECDSA */
#  ifdef FLEA_HAVE_RSA
  if((key__pt->key_type__t == flea_rsa_key) && (pk_scheme_id__t == flea_rsa_pkcs1_v1_5_sign))
  {
    FLEA_CCALL(
      THR_flea_public_key_t__verify_signature_plain_format(
        key__pt,
        flea_rsa_pkcs1_v1_5_sign,
        hash_id__t,
        message__prcu8,
        signature__prcu8
      )
    );
  }
  else
#  endif /* ifdef FLEA_HAVE_RSA */
  {
    FLEA_THROW("unsupported primitive", FLEA_ERR_X509_UNSUPP_ALGO);
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_public_key_t__verify_signature */

flea_err_e THR_flea_public_key_t__verify_signature_use_sigalg_id(
  const flea_public_key_t*     public_key__pt,
  const flea_x509_algid_ref_t* sigalg_id__t,
  const flea_byte_vec_t*       tbs_data__pt,
  const flea_byte_vec_t*       signature__pt,
  flea_x509_validation_flags_e cert_ver_flags__e
)
{
  const flea_byte_vec_t* oid_ref__pt = &sigalg_id__t->oid_ref__t;
  flea_hash_id_e hash_id;
  flea_pk_key_type_e key_type;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_x509_get_hash_id_and_key_type_from_oid(
      oid_ref__pt->data__pu8,
      oid_ref__pt->len__dtl,
      &hash_id,
      &key_type
    )
  );
  if(key_type != public_key__pt->key_type__t)
  {
    FLEA_THROW("key type and algorithm don't match", FLEA_ERR_INV_ALGORITHM);
  }
#  ifdef FLEA_HAVE_SHA1
  if((hash_id == flea_sha1) && !(cert_ver_flags__e & flea_x509_validation_allow_sha1))
  {
    FLEA_THROW("invalid hash algorithm", FLEA_ERR_INV_ALGORITHM);
  }
#  endif /* ifdef FLEA_HAVE_SHA1 */

#  ifdef FLEA_HAVE_RSA
  if(key_type == flea_rsa_key)
  {
    FLEA_CCALL(
      THR_flea_public_key_t__verify_signature(
        public_key__pt,
        flea_rsa_pkcs1_v1_5_sign,
        hash_id,
        tbs_data__pt,
        signature__pt
      )
    );
  }
  else
#  endif /* ifdef FLEA_HAVE_RSA */
#  ifdef FLEA_HAVE_ECC
  if(key_type == flea_ecc_key)
  {
    FLEA_CCALL(
      THR_flea_public_key_t__verify_signature(
        public_key__pt,
        flea_ecdsa_emsa1_asn1,
        hash_id,
        tbs_data__pt,
        signature__pt
      )
    );
  }
  else
#  endif /* ifdef FLEA_HAVE_ECC */
  { }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_public_key_t__verify_signature_use_sigalg_id */

flea_err_e THR_flea_public_key_t__verify_digest(
  const flea_public_key_t* pubkey__pt,
  flea_pk_scheme_id_e      id__t,
  flea_hash_id_e           hash_id__t,
  const flea_u8_t*         digest__pcu8,
  flea_al_u8_t             digest_len__alu8,
  const flea_u8_t*         signature__pu8,
  flea_al_u16_t            signature_len__alu16
)
{
  flea_pk_primitive_id_e primitive_id__t;
  flea_pk_encoding_id_e encoding_id__t;
  flea_al_u16_t digest_len__alu16;
  flea_al_u16_t key_bit_size__alu16 = 0; // avoid warning
  flea_al_u16_t primitive_input_len__alu16;

  FLEA_DECL_BUF(primitive_input__bu8, flea_u8_t, FLEA_MAX(FLEA_PK_MAX_PRIMITIVE_INPUT_LEN, FLEA_MAX_HASH_OUT_LEN));

  FLEA_DECL_BUF(digest_for_rsa_ver__bu8, flea_u8_t, FLEA_MAX_HASH_OUT_LEN);
#  ifdef FLEA_HAVE_ECDSA
  FLEA_DECL_BUF(concat_sig__bu8, flea_u8_t, FLEA_ECDSA_MAX_CONCAT_SIG_LEN);
#  endif
  FLEA_THR_BEG_FUNC();

#  ifdef FLEA_HAVE_ECDSA
  if((pubkey__pt->key_type__t == flea_ecc_key) && (id__t == flea_ecdsa_emsa1_asn1))
  {
    flea_byte_vec_t conc_sig_ref__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE;
    flea_byte_vec_t__set_as_ref(&conc_sig_ref__t, signature__pu8, signature_len__alu16);
    FLEA_ALLOC_BUF(concat_sig__bu8, signature_len__alu16);
    FLEA_CCALL(THR_flea_x509_decode_ecdsa_signature(concat_sig__bu8, &signature_len__alu16, &conc_sig_ref__t));
    signature__pu8 = concat_sig__bu8;
  }
#  endif /* ifdef FLEA_HAVE_ECDSA */

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
    memcpy(digest_for_rsa_ver__bu8, digest__pcu8, digest_len__alu8);
  }
  else
  {
    memcpy(primitive_input__bu8, digest__pcu8, digest_len__alu8);
  }
  digest_len__alu16 = digest_len__alu8;
  if((encoding_id__t == flea_emsa1_asn1) || (encoding_id__t == flea_emsa1_concat))
  {
    FLEA_CCALL(
      THR_flea_pk_api__encode_message__ansi_x9_62(
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
#  ifdef FLEA_HAVE_ECDSA
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

#  else // #ifdef FLEA_HAVE_ECDSA
    FLEA_THROW("ECDSA not supported", FLEA_ERR_INV_ALGORITHM);
#  endif // #else of #ifdef FLEA_HAVE_ECDSA
  }
  else if(primitive_id__t == flea_rsa_sign)
  {
#  ifdef FLEA_HAVE_RSA

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
#  else // #ifdef FLEA_HAVE_RSA
    FLEA_THROW("scheme not supported", FLEA_ERR_INV_ALGORITHM);
#  endif // #else of #ifdef FLEA_HAVE_RSA
  }
  else
  {
    FLEA_THROW("invalid signature primitive id", FLEA_ERR_INV_ALGORITHM);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(primitive_input__bu8);
    FLEA_FREE_BUF_FINAL(digest_for_rsa_ver__bu8);
    FLEA_DO_IF_HAVE_ECDSA(
      FLEA_FREE_BUF_FINAL(concat_sig__bu8);
    );
  );
} /* THR_flea_pk_signer_t__final_verify */

# endif /* ifdef FLEA_HAVE_ASYM_SIG */

flea_err_e THR_flea_public_key__t__get_encoded_plain(
  const flea_public_key_t* pubkey__pt,
  flea_byte_vec_t*         result__pt
)
{
  flea_ref_cu8_t ref__t;

  FLEA_THR_BEG_FUNC();
  flea_public_key_t__get_encoded_plain_ref(pubkey__pt, &ref__t);
  FLEA_CCALL(THR_flea_byte_vec_t__set_content(result__pt, ref__t.data__pcu8, ref__t.len__dtl));

  FLEA_THR_FIN_SEC_empty();
}

void flea_public_key_t__dtor(flea_public_key_t* key__pt)
{
# ifdef FLEA_HEAP_MODE
  if(key__pt->key_bit_size__u16)
  {
#  if defined FLEA_HAVE_RSA || defined FLEA_HAVE_ECC
    flea_u8_t** mem_to_free_1 = NULL, ** mem_to_free_2 = NULL;
#  endif
#  ifdef FLEA_HAVE_ECC
    if(key__pt->key_type__t == flea_ecc_key)
    {
      mem_to_free_1 = &key__pt->pubkey_with_params__u.ec_public_val__t.dp_mem__bu8;
      mem_to_free_2 = &key__pt->pubkey_with_params__u.ec_public_val__t.pub_point__mem__bu8;
    }
#  endif /* ifdef FLEA_HAVE_ECC */
#  ifdef FLEA_HAVE_RSA
    if(key__pt->key_type__t == flea_rsa_key)
    {
      mem_to_free_1 = &key__pt->pubkey_with_params__u.rsa_public_val__t.mod_mem__bu8;
      mem_to_free_2 = &key__pt->pubkey_with_params__u.rsa_public_val__t.exp_mem__bu8;
    }
#  endif /* ifdef FLEA_HAVE_RSA */
#  if defined FLEA_HAVE_RSA || defined FLEA_HAVE_ECC
    FLEA_FREE_MEM_CHK_SET_NULL(*mem_to_free_1);
    FLEA_FREE_MEM_CHK_SET_NULL(*mem_to_free_2);
#  endif
  }
# endif /* ifdef FLEA_HEAP_MODE */
}

#endif /* #ifdef FLEA_HAVE_ASYM_ALGS */
