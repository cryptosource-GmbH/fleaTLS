/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "flea/pubkey.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/namespace_asn1.h"
#include "flea/x509.h"
#include "flea/ec_key.h"
#include "flea/util.h"
#include "flea/bin_utils.h"
#include "flea/pk_api.h"
#include "flea/ecc_named_curves.h"
#include "internal/common/oid.h"
#include "flea/mem_read_stream.h"

#ifdef FLEA_HAVE_ASYM_ALGS
//
/* ANSI X9.62 Elliptic Curve Digital Signature Algorithm (ECDSA) algorithm with Secure Hash Algorithm, revision 2 (SHA2)  */
const flea_u8_t ecdsa_oid_prefix__acu8[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04};

/* subsequent octets:
 *                    3 => sha2
 *                      subsequent: specific sha2 variant
 *                    4.1 => sha1
 */

flea_err_t THR_get_hash_id_from_x509_id_for_rsa(
  flea_u8_t       cert_id__u8,
  flea_hash_id_t* result__pt
)
{
  FLEA_THR_BEG_FUNC();
  switch(cert_id__u8)
  {
      case 5:
        *result__pt = flea_sha1;
        break;
      case 14:
        *result__pt = flea_sha224;
        break;
      case 11:
        *result__pt = flea_sha256;
        break;
      case 12:
        *result__pt = flea_sha384;
        break;
      case 13:
        *result__pt = flea_sha512;
        break;
      default:
        FLEA_THROW("unrecognized hash function", FLEA_ERR_X509_UNRECOG_HASH_FUNCTION);
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_get_hash_id_from_x509_id_for_ecdsa(
  const flea_u8_t cert_id__pcu8[2],
  flea_hash_id_t* result__pt
)
{
  FLEA_THR_BEG_FUNC();
  if(cert_id__pcu8[0] == 3)
  {
    /* sha2 */
    switch(cert_id__pcu8[1])
    {
        case 1:
          *result__pt = flea_sha224;
          break;
        case 2:
          *result__pt = flea_sha256;
          break;
        case 3:
          *result__pt = flea_sha384;
          break;
        case 4:
          *result__pt = flea_sha512;
          break;
        default:
          FLEA_THROW("unsupported ECDSA variant", FLEA_ERR_X509_UNSUPP_ALGO_VARIANT);
    }
  }
  else if(cert_id__pcu8[0] == 4 && cert_id__pcu8[1] == 1)
  {
    *result__pt = flea_sha1;
  }
  else
  {
    FLEA_THROW("unsupported ECDSA variant", FLEA_ERR_X509_UNSUPP_ALGO_VARIANT);
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_get_hash_id_from_x509_id_for_ecdsa */

# ifdef FLEA_HAVE_ECC
#  if 0
static flea_err_t THR_flea_x509_verify_ecdsa_signature(
  const flea_byte_vec_t*   oid_ref__pt,
  const flea_public_key_t* ver_key__pt,
  const flea_byte_vec_t*   der_enc_signature__pt,
  const flea_byte_vec_t*   tbs_data__pt,
  flea_hash_id_t           ecdsa_hash_id__t
)
{
  // flea_hash_id_t ecdsa_hash_id__t;

  FLEA_THR_BEG_FUNC();

  /*  FLEA_CCALL(
   *  THR_get_hash_id_from_x509_id_for_ecdsa(
   *    oid_ref__pt->data__pu8 + sizeof(ecdsa_oid_prefix__acu8),
   *    &ecdsa_hash_id__t
   *  )
   * );*/
  FLEA_CCALL(
    THR_flea_public_key_t__verify_signature(
      ver_key__pt,
      flea_ecdsa_emsa1,
      tbs_data__pt,
      der_enc_signature__pt,
      ecdsa_hash_id__t
    )
  );
  // decode the signature:
  FLEA_THR_FIN_SEC(
  );
}

#  endif /* if 0 */

/* assumes that result__pu8 has sufficient length allocated */
static flea_err_t THR_flea_x509_decode_ecdsa_signature(
  flea_u8_t*             result__pu8,
  flea_al_u16_t*         result_len__palu16,
  const flea_byte_vec_t* x509_enc_sig__pt
)
{
  flea_ref_cu8_t ref_r__t;
  flea_ref_cu8_t ref_s__t;
  flea_al_u16_t r_offs, s_offs, diff, insert_offs;

  FLEA_DECL_OBJ(dec__t, flea_ber_dec_t);
  FLEA_DECL_OBJ(source__t, flea_rw_stream_t);
  flea_mem_read_stream_help_t hlp__t;
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor_memory(
      &source__t,
      x509_enc_sig__pt->data__pu8,
      x509_enc_sig__pt->len__dtl,
      &hlp__t
    )
  );
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&dec__t, &source__t, 0, flea_decode_ref));
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
  FLEA_CCALL(THR_flea_ber_dec_t__get_der_REF_to_positive_int_wo_lead_zeroes(&dec__t, &ref_r__t));
  FLEA_CCALL(THR_flea_ber_dec_t__get_der_REF_to_positive_int_wo_lead_zeroes(&dec__t, &ref_s__t));
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
  if(ref_r__t.len__dtl > ref_s__t.len__dtl)
  {
    diff        = ref_r__t.len__dtl - ref_s__t.len__dtl;
    r_offs      = 0;
    s_offs      = ref_r__t.len__dtl + diff;
    insert_offs = ref_r__t.len__dtl;
  }
  else if(ref_r__t.len__dtl < ref_s__t.len__dtl)
  {
    diff        = ref_s__t.len__dtl - ref_r__t.len__dtl;
    r_offs      = diff;
    s_offs      = ref_s__t.len__dtl;
    insert_offs = 0;
  }
  else
  {
    diff        = 0;
    r_offs      = 0;
    s_offs      = ref_r__t.len__dtl;
    insert_offs = 0; /* irrelevant */
  }
  memcpy(result__pu8 + r_offs, ref_r__t.data__pcu8, ref_r__t.len__dtl);
  memcpy(result__pu8 + s_offs, ref_s__t.data__pcu8, ref_s__t.len__dtl);
  memset(result__pu8 + insert_offs, 0, diff);
  *result_len__palu16 = ref_r__t.len__dtl + ref_s__t.len__dtl + diff;

  FLEA_THR_FIN_SEC(
    flea_rw_stream_t__dtor(&source__t);
    flea_ber_dec_t__dtor(&dec__t);

  );
} /* THR_flea_x509_decode_ecdsa_signature */

static flea_err_t THR_flea_public_key_t__create_ecdsa_key(
  flea_ec_pubkey_val_t*            ecc_key__pt,
  const flea_byte_vec_t*           public_point_encoded__pcrcu8,
  const flea_ec_gfp_dom_par_ref_t* dp_ref__pt
)
{
  flea_al_u16_t max_dp_concat_len;

  FLEA_THR_BEG_FUNC();
#  ifdef FLEA_USE_STACK_BUF
  max_dp_concat_len = sizeof(ecc_key__pt->dp_mem__bu8);
#  else
  if(dp_ref__pt->p__ru8.len__dtl > FLEA_ECC_MAX_MOD_BYTE_SIZE)
  {
    FLEA_THROW("invalid parameter length", FLEA_ERR_UNSUPP_KEY_SIZE);
  }
  max_dp_concat_len = FLEA_ECC_DP_CONCAT_BYTE_SIZE_FROM_MOD_BIT_SIZE(8 * dp_ref__pt->p__ru8.len__dtl);
  ;
  FLEA_ALLOC_MEM_ARR(ecc_key__pt->dp_mem__bu8, max_dp_concat_len);
#  endif
  FLEA_CCALL(
    THR_flea_ec_gfp_dom_par_ref_t__write_to_concat_array(
      &ecc_key__pt->dp__t,
      ecc_key__pt->dp_mem__bu8,
      max_dp_concat_len,
      dp_ref__pt
    )
  );

#  ifdef FLEA_USE_HEAP_BUF
  FLEA_ALLOC_MEM_ARR(ecc_key__pt->pub_point__mem__bu8, public_point_encoded__pcrcu8->len__dtl);
#  endif

  // flea_copy_rcu8_use_mem(
  flea_byte_vec_t__copy_content_set_ref_use_mem(
    &ecc_key__pt->public_point_encoded__rcu8,
    ecc_key__pt->pub_point__mem__bu8,
    public_point_encoded__pcrcu8
  );
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_public_key_t__create_ecdsa_key */

flea_err_t THR_flea_x509_parse_ecc_public_params(
  const flea_byte_vec_t*     encoded_parameters__pt,
  flea_ec_gfp_dom_par_ref_t* dom_par__pt
)
{
  FLEA_DECL_OBJ(source__t, flea_rw_stream_t);
  FLEA_DECL_OBJ(dec__t, flea_ber_dec_t);
  flea_mem_read_stream_help_t hlp__t;
  flea_bool_t found__b;
  FLEA_THR_BEG_FUNC();


  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor_memory(
      &source__t,
      encoded_parameters__pt->data__pu8,
      encoded_parameters__pt->len__dtl,
      &hlp__t
    )
  );
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&dec__t, &source__t, FLEA_ECC_MAX_MOD_BYTE_SIZE * 10, flea_decode_ref));
  FLEA_CCALL(
    THR_flea_ber_dec_t__open_constructed_optional_cft(
      &dec__t,
      FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONSTRUCTED, FLEA_ASN1_SEQUENCE),
      &found__b
    )
  );
  if(found__b)
  {
    flea_u32_t version__u32;
    // flea_dtl_t len__dtl;
    flea_byte_vec_t oid_ref__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE;

    const flea_u8_t prime_field_oid__acu8[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x01, 0x01};

    FLEA_CCALL(THR_flea_ber_dec_t__decode_integer_u32(&dec__t, FLEA_ASN1_INT, &version__u32));
    if(version__u32 != 1)
    {
      FLEA_THROW("invalid version in ECC parameters", FLEA_ERR_X509_INV_ECC_KEY_PARAMS);
    }
    FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
    FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_oid(&dec__t, &oid_ref__t));
    if(oid_ref__t.len__dtl != sizeof(prime_field_oid__acu8) ||
      memcmp(oid_ref__t.data__pu8, prime_field_oid__acu8, sizeof(prime_field_oid__acu8)))
    {
      FLEA_THROW("unsupported field type in ECC parameters", FLEA_ERR_X509_INV_ECC_FIELD_TYPE);
    }
    FLEA_CCALL(THR_flea_ber_dec_t__get_der_REF_to_positive_int_wo_lead_zeroes(&dec__t, &dom_par__pt->p__ru8));
    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
    FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
    FLEA_CCALL(
      THR_flea_ber_dec_t__get_REF_to_raw_cft(
        &dec__t,
        FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, FLEA_ASN1_OCTET_STRING),
        &dom_par__pt->a__ru8
      )
    );
    FLEA_CCALL(
      THR_flea_ber_dec_t__get_REF_to_raw_cft(
        &dec__t,
        FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, FLEA_ASN1_OCTET_STRING),
        &dom_par__pt->b__ru8
      )
    );
    FLEA_CCALL(
      THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(
        &dec__t,
        FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, FLEA_ASN1_BIT_STRING),
        &oid_ref__t,
        &found__b
      )
    );
    /* close the curve: */
    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
    /* the public point */
    FLEA_CCALL(
      THR_flea_ber_dec_t__get_ref_to_raw_cft(
        &dec__t,
        FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, FLEA_ASN1_OCTET_STRING),
        &oid_ref__t
      )
    );
    FLEA_CCALL(THR_flea_ec_key__decode_uncompressed_point(&oid_ref__t, &dom_par__pt->gx__ru8, &dom_par__pt->gy__ru8));

    FLEA_CCALL(THR_flea_ber_dec_t__get_der_REF_to_positive_int_wo_lead_zeroes(&dec__t, &dom_par__pt->n__ru8));
    FLEA_CCALL(THR_flea_ber_dec_t__get_der_REF_to_positive_int_wo_lead_zeroes_optional(&dec__t, &dom_par__pt->h__ru8));
    if(dom_par__pt->h__ru8.len__dtl > FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(FLEA_ECC_MAX_COFACTOR_BIT_SIZE))
    {
      FLEA_THROW("invalid cofactor size", FLEA_ERR_X509_EXCSS_COFACTOR_SIZE);
    }
    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
  }
  else
  {
    flea_byte_vec_t named_curve_oid__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE;
    flea_bool_t dummy;
    FLEA_CCALL(
      THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(
        &dec__t,
        FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, FLEA_ASN1_OID),
        &named_curve_oid__t,
        &dummy
      )
    );
    if(!FLEA_DER_REF_IS_ABSENT(&named_curve_oid__t))
    {
      FLEA_CCALL(
        THR_flea_ecc_gfp_dom_par_t__set_by_named_curve_oid(
          dom_par__pt,
          named_curve_oid__t.data__pu8,
          named_curve_oid__t.len__dtl
        )
      );
    }
    else
    {
      flea_byte_vec_t null__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE;
      FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_next_tlv_raw(&dec__t, &null__t));
      if(flea_ber_dec__is_tlv_null_vec(&null__t))
      {
        FLEA_THROW("no explicit or named ECC domain parameters provided", FLEA_ERR_X509_IMPLICT_ECC_KEY_PARAMS);
      }
      FLEA_THROW("invalidly encoded ECC domain parameters provided", FLEA_ERR_X509_INV_ECC_KEY_PARAMS);
    }
  }

  FLEA_THR_FIN_SEC(
    flea_rw_stream_t__dtor(&source__t);
    flea_ber_dec_t__dtor(&dec__t);
  );
} /* THR_flea_x509_parse_ecc_public_params */

# endif /* ifdef FLEA_HAVE_ECC */

static flea_err_t THR_flea_x509_parse_rsa_public_key(
  const flea_byte_vec_t* public_key_value__pt,
  flea_ref_cu8_t*        modulus__pt,
  flea_ref_cu8_t*        pub_exp__pt
)
{
  FLEA_DECL_OBJ(source__t, flea_rw_stream_t);
  FLEA_DECL_OBJ(dec__t, flea_ber_dec_t);
  flea_mem_read_stream_help_t hlp__t;
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor_memory(
      &source__t,
      public_key_value__pt->data__pu8,
      public_key_value__pt->len__dtl,
      &hlp__t
    )
  );
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&dec__t, &source__t, 0, flea_decode_ref));
  /* open sequence */
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
  /* decode mod */
  FLEA_CCALL(THR_flea_ber_dec_t__get_der_REF_to_positive_int_wo_lead_zeroes(&dec__t, modulus__pt));
  /* decode exp */
  FLEA_CCALL(THR_flea_ber_dec_t__get_der_REF_to_positive_int_wo_lead_zeroes(&dec__t, pub_exp__pt));
  /* close sequence */
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
  FLEA_THR_FIN_SEC(
    flea_rw_stream_t__dtor(&source__t);
    flea_ber_dec_t__dtor(&dec__t);
  );
}

# ifdef FLEA_HAVE_RSA
static flea_err_t THR_flea_public_key_t__create_rsa_key(
  flea_rsa_pubkey_val_t* key__pt,
  const flea_ref_cu8_t*  mod__pcrcu8,
  const flea_ref_cu8_t*  exp__pcrcu8
)
{
  FLEA_THR_BEG_FUNC();

#  ifdef FLEA_USE_HEAP_BUF
  FLEA_ALLOC_MEM_ARR(key__pt->mod_mem__bu8, mod__pcrcu8->len__dtl);
  FLEA_ALLOC_MEM_ARR(key__pt->exp_mem__bu8, exp__pcrcu8->len__dtl);
#  endif
  flea_copy_rcu8_use_mem(&key__pt->mod__rcu8, key__pt->mod_mem__bu8, mod__pcrcu8);
  flea_copy_rcu8_use_mem(&key__pt->pub_exp__rcu8, key__pt->exp_mem__bu8, exp__pcrcu8);

  /*flea_byte_vec_t__copy_content_set_ref_use_mem(&key__pt->mod__rcu8, key__pt->mod_mem__bu8, mod__pcrcu8);
   * flea_byte_vec_t__copy_content_set_ref_use_mem(&key__pt->pub_exp__rcu8, key__pt->exp_mem__bu8, exp__pcrcu8);*/

  FLEA_THR_FIN_SEC_empty();
}

# endif /* ifdef FLEA_HAVE_RSA */

flea_err_t THR_flea_determine_public_key_type_from_oid(
  const flea_u8_t*    oid_val__pcu8,
  flea_dtl_t          oid_val_len__dtl,
  flea_pk_key_type_t* result_key_type__pe
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

  /*if(((oid_val_len__dtl == sizeof(pkcs1_oid_prefix__cau8) + 1)) &&
   * !memcmp(oid_val__pcu8, pkcs1_oid_prefix__cau8, sizeof(pkcs1_oid_prefix__cau8)))*/

  if(0 == flea_memcmp_wsize(oid_val__pcu8, oid_val_len__dtl, rsa_public_key_oid__au8, sizeof(rsa_public_key_oid__au8)))
  {
    *result_key_type__pe = flea_rsa_key;
  }
  else
# endif /* ifdef FLEA_HAVE_RSA */
# ifdef FLEA_HAVE_ECC
  // if(oid_val_len__dtl == sizeof(ecdsa_oid_prefix__acu8) + 2 &&
  // !memcmp(oid_val__pcu8, ecdsa_oid_prefix__acu8, sizeof(ecdsa_oid_prefix__acu8)))
  if(0 == flea_memcmp_wsize(oid_val__pcu8, oid_val_len__dtl, ec_public_key_oid__au8, sizeof(ec_public_key_oid__au8)))
  {
    *result_key_type__pe = flea_ecc_key;
  }
  else
# endif /* #ifdef FLEA_HAVE_ECC */
  {
    FLEA_THROW("unsupported primitive", FLEA_ERR_X509_UNSUPP_PRIMITIVE);
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_determine_public_key_type_from_oid */

flea_err_t THR_flea_public_key_t__ctor_cert(
  flea_public_key_t*          key__pt,
  const flea_x509_cert_ref_t* cert_ref__pt
)
{
  // const flea_byte_vec_t* oid_ref__pt = &cert_ref__pt->tbs_sig_algid__t.oid_ref__t;

  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(
    THR_flea_public_key_t__ctor_asn1(
      key__pt,
      &cert_ref__pt->subject_public_key_info__t.public_key_as_tlv__t,
      &cert_ref__pt->subject_public_key_info__t.algid__t.params_ref_as_tlv__t,
      &cert_ref__pt->subject_public_key_info__t.algid__t.oid_ref__t
      // oid_ref__pt // TODO: THIS IS WRONG, NOT RELEVANT FOR PUBKEY TYPE
    )
  );
# if 0
#  ifdef FLEA_HAVE_RSA
  if(((oid_ref__pt->len__dtl == sizeof(pkcs1_oid_prefix__cau8) + 1)) &&
    !memcmp(oid_ref__pt->data__pu8, pkcs1_oid_prefix__cau8, sizeof(pkcs1_oid_prefix__cau8)))
  {
    FLEA_CCALL(
      THR_flea_public_key_t__ctor(
        key__pt,
        flea_rsa_key,
        &cert_ref__pt->subject_public_key_info__t.public_key_as_tlv__t,
        NULL
      )
    );
  }
  else
#  endif /* ifdef FLEA_HAVE_RSA */
#  ifdef FLEA_HAVE_ECC
  if(oid_ref__pt->len__dtl == sizeof(ecdsa_oid_prefix__acu8) + 2 &&
    !memcmp(oid_ref__pt->data__pu8, ecdsa_oid_prefix__acu8, sizeof(ecdsa_oid_prefix__acu8)))
  {
    FLEA_CCALL(
      THR_flea_public_key_t__ctor(
        key__pt,
        flea_ecc_key,
        &cert_ref__pt->subject_public_key_info__t.public_key_as_tlv__t,
        &cert_ref__pt->subject_public_key_info__t.algid__t.params_ref_as_tlv__t
      )
    );
  }
  else
#  endif /* #ifdef FLEA_HAVE_ECC */
  {
    FLEA_THROW("unsupported primitive", FLEA_ERR_X509_UNSUPP_PRIMITIVE);
  }
# endif /* if 0 */
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_public_key_t__ctor_cert */

flea_err_t THR_flea_public_key_t__ctor_asn1(
  flea_public_key_t*     key__pt,
  const flea_byte_vec_t* key_as_bit_string_tlv__prcu8,
  const flea_byte_vec_t* encoded_params__prcu8,
  const flea_byte_vec_t* alg_oid__pt
)
{
  FLEA_DECL_OBJ(key_dec__t, flea_ber_dec_t);
  FLEA_DECL_OBJ(source__t, flea_rw_stream_t);
  flea_mem_read_stream_help_t hlp__t;
  FLEA_THR_BEG_FUNC();
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
    flea_ec_gfp_dom_par_ref_t dp_ref__t;
    FLEA_CCALL(THR_flea_x509_parse_ecc_public_params(encoded_params__prcu8, &dp_ref__t));

    FLEA_CCALL(THR_flea_public_key_t__ctor_ecc(key__pt, &public_key_value__t, &dp_ref__t));
  }
  else
# endif
# ifdef FLEA_HAVE_RSA

  if(key__pt->key_type__t == flea_rsa_key)
  {
    /*flea_byte_vec_t mod__rcu8 = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE;
     *  flea_byte_vec_t exp__rcu8 = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE;*/
    flea_ref_cu8_t mod__rcu8, exp__rcu8;
    FLEA_CCALL(THR_flea_x509_parse_rsa_public_key(&public_key_value__t, &mod__rcu8, &exp__rcu8));
    if(mod__rcu8.len__dtl > FLEA_RSA_MAX_MOD_BYTE_LEN || exp__rcu8.len__dtl > FLEA_RSA_MAX_PUB_EXP_BYTE_LEN)
    {
      FLEA_THROW("unsupported RSA key size", FLEA_ERR_UNSUPP_KEY_SIZE);
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
flea_err_t THR_flea_public_key_t__ctor_ecc(
  flea_public_key_t*               key__pt,
  const flea_byte_vec_t*           public_key_value__pt,
  const flea_ec_gfp_dom_par_ref_t* dp__pt
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

# ifdef FLEA_HAVE_RSA
flea_err_t THR_flea_public_key_t__ctor_rsa(
  flea_public_key_t*    key__pt,
  const flea_ref_cu8_t* mod__pcrcu8,
  const flea_ref_cu8_t* pub_exp__pcrcu8
)
{
  FLEA_THR_BEG_FUNC();
  key__pt->key_type__t = flea_rsa_key;

  FLEA_CCALL(
    THR_flea_public_key_t__create_rsa_key(
      &key__pt->pubkey_with_params__u.rsa_public_val__t,
      mod__pcrcu8,
      pub_exp__pcrcu8
    )
  );
  key__pt->key_bit_size__u16 = flea__get_BE_int_bit_len(
    key__pt->pubkey_with_params__u.rsa_public_val__t.mod__rcu8.data__pcu8,
    key__pt->pubkey_with_params__u.rsa_public_val__t.mod__rcu8.len__dtl
    );
  key__pt->primitive_input_size__u16 = (key__pt->key_bit_size__u16 + 7) / 8;

  FLEA_THR_FIN_SEC_empty();
}

# endif /* ifdef FLEA_HAVE_RSA */

flea_err_t THR_flea_public_key_t__verify_signature(
  const flea_public_key_t* key__pt,
  flea_pk_scheme_id_t      pk_scheme_id__t,
  const flea_byte_vec_t*   message__prcu8,
  const flea_byte_vec_t*   signature__prcu8,
  flea_hash_id_t           hash_id__t
)
{
# ifdef FLEA_HAVE_ECDSA
  FLEA_DECL_BUF(concat_sig__bu8, flea_u8_t, FLEA_ECDSA_MAX_SIG_LEN);
# endif
  FLEA_THR_BEG_FUNC();

# ifdef FLEA_HAVE_ECDSA
  if((key__pt->key_type__t == flea_ecc_key) && (pk_scheme_id__t == flea_ecdsa_emsa1))
  {
    flea_byte_vec_t concat_sig_ref__t;
    flea_al_u16_t concat_sig_len__alu16;
    FLEA_ALLOC_BUF(concat_sig__bu8, signature__prcu8->len__dtl);
    FLEA_CCALL(THR_flea_x509_decode_ecdsa_signature(concat_sig__bu8, &concat_sig_len__alu16, signature__prcu8));
    concat_sig_ref__t.data__pu8 = concat_sig__bu8;
    concat_sig_ref__t.len__dtl  = concat_sig_len__alu16;

    FLEA_CCALL(
      THR_flea_pk_api__verify_signature(
        message__prcu8,
        &concat_sig_ref__t,
        key__pt,
        flea_ecdsa_emsa1,
        hash_id__t
      )
    );
  }
  else
# endif /* ifdef FLEA_HAVE_ECDSA */
# ifdef FLEA_HAVE_RSA
  if((key__pt->key_type__t == flea_rsa_key) && (pk_scheme_id__t == flea_rsa_pkcs1_v1_5_sign))
  {
    FLEA_CCALL(
      THR_flea_pk_api__verify_signature(
        message__prcu8,
        signature__prcu8,
        key__pt,
        flea_rsa_pkcs1_v1_5_sign,
        hash_id__t
      )
    );
  }
  else
# endif /* ifdef FLEA_HAVE_RSA */
  {
    FLEA_THROW("unsupported primitive", FLEA_ERR_X509_UNSUPP_PRIMITIVE);
  }
  FLEA_THR_FIN_SEC(
    FLEA_DO_IF_HAVE_ECDSA(
      FLEA_FREE_BUF_FINAL(concat_sig__bu8);
    );
  );
} /* THR_flea_public_key_t__verify_signature */

flea_err_t THR_flea_x509_get_hash_id_and_key_type_from_oid(
  const flea_u8_t*    oid__pcu8,
  flea_al_u16_t       oid_len__alu16,
  flea_hash_id_t*     result_hash_id__pe,
  flea_pk_key_type_t* result_key_type_e
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

flea_err_t THR_flea_public_key_t__verify_signature_use_sigalg_id(
  const flea_public_key_t*     public_key__pt,
  const flea_x509_algid_ref_t* sigalg_id__t,
  const flea_byte_vec_t*       tbs_data__pt,
  const flea_byte_vec_t*       signature__pt
)
{
  const flea_byte_vec_t* oid_ref__pt = &sigalg_id__t->oid_ref__t;
  flea_hash_id_t hash_id;
  flea_pk_key_type_t key_type;

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

# ifdef FLEA_HAVE_RSA
  if(key_type == flea_rsa_key)
  {
    FLEA_CCALL(
      THR_flea_public_key_t__verify_signature(
        public_key__pt,
        flea_rsa_pkcs1_v1_5_sign,
        tbs_data__pt,
        signature__pt,
        hash_id
      )
    );
  }
  else
# endif /* ifdef FLEA_HAVE_RSA */
# ifdef FLEA_HAVE_ECC
  if(key_type == flea_ecc_key)
  {
    FLEA_CCALL(
      THR_flea_public_key_t__verify_signature(
        public_key__pt,
        flea_ecdsa_emsa1,
        tbs_data__pt,
        signature__pt,
        hash_id
      )
    );
  }
# endif /* ifdef FLEA_HAVE_ECC */
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_public_key_t__verify_signature_use_sigalg_id */

flea_err_t THR_flea_public_key_t__encrypt_message(
  const flea_public_key_t* key__pt,
  flea_pk_scheme_id_t      pk_scheme_id__t,
  flea_hash_id_t           hash_id__t,
  const flea_u8_t*         message__pcu8,
  flea_al_u16_t            message_len__alu16,
  flea_byte_vec_t*         result__pt

  /*  flea_u8_t*               result__pu8,
   * flea_al_u16_t*           result_len__palu16*/
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

      /*result__pu8,
       * result_len__palu16,*/
      key__pt->pubkey_with_params__u.rsa_public_val__t.mod__rcu8.data__pcu8,
      key__pt->pubkey_with_params__u.rsa_public_val__t.mod__rcu8.len__dtl,
      key__pt->pubkey_with_params__u.rsa_public_val__t.pub_exp__rcu8.data__pcu8,
      key__pt->pubkey_with_params__u.rsa_public_val__t.pub_exp__rcu8.len__dtl
    )
  );
# else /* ifdef FLEA_HAVE_RSA */
  FLEA_THROW("no public key encryption scheme (RSA) supported", FLEA_ERR_X509_UNSUPP_PRIMITIVE);
# endif /* ifdef FLEA_HAVE_RSA */
  FLEA_THR_FIN_SEC_empty();
}

void flea_public_key_t__dtor(flea_public_key_t* key__pt)
{
# ifdef FLEA_USE_HEAP_BUF
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
#  endif
#  ifdef FLEA_HAVE_RSA
    if(key__pt->key_type__t == flea_rsa_key)
    {
      mem_to_free_1 = &key__pt->pubkey_with_params__u.rsa_public_val__t.mod_mem__bu8;
      mem_to_free_2 = &key__pt->pubkey_with_params__u.rsa_public_val__t.exp_mem__bu8;
    }
#  endif
#  if defined FLEA_HAVE_RSA || defined FLEA_HAVE_ECC
    FLEA_FREE_MEM_CHK_SET_NULL(*mem_to_free_1);
    FLEA_FREE_MEM_CHK_SET_NULL(*mem_to_free_2);
#  endif
  }
# endif /* ifdef FLEA_USE_HEAP_BUF */
}

#endif /* #ifdef FLEA_HAVE_ASYM_ALGS */
