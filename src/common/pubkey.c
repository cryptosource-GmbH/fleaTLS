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

/* ... rsadsi: 1.2.840.113549 */
//subsequent 2 bytes determine encoding method
// ...1 => PKCS
//    ...1 PKCS#1
const flea_u8_t pkcs1_oid_prefix__cau8[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01  };
//
//    ...7 OAEP 
// 
// the following and last byte determines the hash algorithm:
//         5 => sha1
//        14 => sha224
//        11 => sha256
//        12 => sha384
//        13 => sha512
//
/* ANSI X9.62 Elliptic Curve Digital Signature Algorithm (ECDSA) algorithm with Secure Hash Algorithm, revision 2 (SHA2)  */
const flea_u8_t ecdsa_oid_prefix__acu8[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04 };
/* subsequent octets: 
 *                    3 => sha2
 *                      subsequent: specific sha2 variant
 *                    4.1 => sha1
 */

flea_err_t THR_get_hash_id_from_x509_id_for_rsa(flea_u8_t cert_id__u8, flea_hash_id_t* result__pt)
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

flea_err_t THR_get_hash_id_from_x509_id_for_ecdsa(const flea_u8_t cert_id__pcu8[2], flea_hash_id_t* result__pt)
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
  }else if (cert_id__pcu8[0] == 4 && cert_id__pcu8[1] == 1)
  {
    *result__pt = flea_sha1;
  }
  else
  {
    FLEA_THROW("unsupported ECDSA variant", FLEA_ERR_X509_UNSUPP_ALGO_VARIANT);
  }

  FLEA_THR_FIN_SEC_empty(); 
}
#ifdef FLEA_HAVE_ECC

static flea_err_t THR_flea_x509_verify_ecdsa_signature(const flea_ref_cu8_t *oid_ref__pt, const flea_public_key_t *ver_key__pt, const flea_ref_cu8_t *der_enc_signature__pt, const flea_ref_cu8_t *tbs_data__pt)
{

  flea_hash_id_t ecdsa_hash_id__t;
  FLEA_THR_BEG_FUNC();
  /* allocating DER encoded size wastes a few bytes of RAM but saves some code */
  FLEA_CCALL(THR_get_hash_id_from_x509_id_for_ecdsa(oid_ref__pt->data__pcu8 + sizeof(ecdsa_oid_prefix__acu8), &ecdsa_hash_id__t));
  FLEA_CCALL(THR_flea_public_key_t__verify_signature(ver_key__pt, flea_ecdsa_emsa1, tbs_data__pt, der_enc_signature__pt, ecdsa_hash_id__t));
  //decode the signature:
  FLEA_THR_FIN_SEC(
      );
}
/* assumes that result__pu8 has sufficient length allocated */
static flea_err_t THR_flea_x509_decode_ecdsa_signature(flea_u8_t *result__pu8, flea_al_u16_t *result_len__palu16, const flea_ref_cu8_t *x509_enc_sig__pt  )
{
  flea_ref_cu8_t ref_r__t;
  flea_ref_cu8_t ref_s__t;
  flea_al_u16_t r_offs, s_offs, diff, insert_offs;
  FLEA_DECL_OBJ(dec__t, flea_ber_dec_t);
  FLEA_DECL_OBJ(source__t, flea_data_source_t);
  flea_data_source_mem_help_t hlp__t;
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_data_source_t__ctor_memory(&source__t, x509_enc_sig__pt->data__pcu8, x509_enc_sig__pt->len__dtl, &hlp__t));
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&dec__t, &source__t, 0)); 
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
  FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_positive_int_wo_lead_zeroes(&dec__t, &ref_r__t));
  FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_positive_int_wo_lead_zeroes(&dec__t, &ref_s__t));
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
  if(ref_r__t.len__dtl > ref_s__t.len__dtl)
  {
    diff = ref_r__t.len__dtl - ref_s__t.len__dtl;
    r_offs = 0;
    s_offs = ref_r__t.len__dtl + diff;
    insert_offs = ref_r__t.len__dtl;
  }
  else if (ref_r__t.len__dtl < ref_s__t.len__dtl)
  {
    diff = ref_s__t.len__dtl - ref_r__t.len__dtl;
    r_offs = diff;
    s_offs = ref_s__t.len__dtl;
    insert_offs = 0;
  }
  else
  {
    diff = 0;
    r_offs = 0;
    s_offs = ref_r__t.len__dtl;
    insert_offs = 0; /* irrelevant */
  }
  memcpy(result__pu8 + r_offs, ref_r__t.data__pcu8, ref_r__t.len__dtl);
  memcpy(result__pu8 + s_offs, ref_s__t.data__pcu8, ref_s__t.len__dtl);
  memset(result__pu8 + insert_offs, 0, diff);
  *result_len__palu16 = ref_r__t.len__dtl + ref_s__t.len__dtl + diff;

  FLEA_THR_FIN_SEC(
      flea_data_source_t__dtor(&source__t); 
      flea_ber_dec_t__dtor(&dec__t);

      );
}

static flea_err_t THR_flea_public_key_t__create_ecdsa_key(flea_ec_pubkey_val_t *ecc_key__pt, const flea_ref_cu8_t *key_as_bit_string_contents__prcu8, const flea_ref_cu8_t *encoded_params__prcu8, const flea_ref_cu8_t *inherited_params_mbn__cprcu8, flea_bool_t *are_keys_params_implicit)
{
  FLEA_THR_BEG_FUNC();
  flea_al_u8_t i; 
  flea_ec_gfp_dom_par_ref_t ref__t;
  flea_al_u16_t max_dp_concat_len;
  flea_err_t parse_err;
  flea_u8_t * write_pos__pu8;
  flea_ref_cu8_t *src__arcu8[7] = {&ref__t.p__ru8, &ref__t.a__ru8, &ref__t.b__ru8, &ref__t.gx__ru8, &ref__t.gy__ru8, &ref__t.n__ru8, &ref__t.h__ru8};
  flea_ref_cu8_t *trgt__arcu8[7] = {&ecc_key__pt->dp__t.p__ru8, &ecc_key__pt->dp__t.a__ru8, &ecc_key__pt->dp__t.b__ru8, &ecc_key__pt->dp__t.gx__ru8, &ecc_key__pt->dp__t.gy__ru8, &ecc_key__pt->dp__t.n__ru8, &ecc_key__pt->dp__t.h__ru8};
  parse_err = THR_flea_x509_parse_ecc_public_params(encoded_params__prcu8, &ref__t);
  *are_keys_params_implicit = FLEA_FALSE;
  if((parse_err == FLEA_ERR_X509_IMPLICT_ECC_KEY_PARAMS) && inherited_params_mbn__cprcu8)
  {
    *are_keys_params_implicit = FLEA_TRUE;
    FLEA_CCALL(THR_flea_x509_parse_ecc_public_params(inherited_params_mbn__cprcu8, &ref__t));
  }
  else if(parse_err != FLEA_ERR_FINE)
  {
    FLEA_THROW("rethrowing ecc parse error", parse_err);
  }
#ifdef FLEA_USE_STACK_BUF
  max_dp_concat_len = sizeof(ecc_key__pt->dp_mem__bu8);
#else
  if(ref__t.p__ru8.len__dtl > FLEA_ECC_MAX_MOD_BYTE_SIZE)
  {
    FLEA_THROW("invalid parameter length", FLEA_ERR_UNSUPP_KEY_SIZE);
  }
  max_dp_concat_len = FLEA_ECC_DP_CONCAT_BYTE_SIZE_FROM_MOD_BIT_SIZE(8 * ref__t.p__ru8.len__dtl);;
  FLEA_ALLOC_MEM_ARR(ecc_key__pt->dp_mem__bu8, max_dp_concat_len);
#endif
  write_pos__pu8 = ecc_key__pt->dp_mem__bu8;
  for(i = 0; i < 7; i++)
  {
    flea_ref_cu8_t *src = src__arcu8[i];
    flea_ref_cu8_t *trgt  = trgt__arcu8[i];
    if(src->len__dtl > max_dp_concat_len)
    {
      FLEA_THROW("parameters have unexpected size", FLEA_ERR_X509_INV_ECC_KEY_PARAMS);
    }
    memcpy(write_pos__pu8, src->data__pcu8, src->len__dtl);
    trgt->len__dtl = src->len__dtl;
    trgt->data__pcu8 = write_pos__pu8;
    write_pos__pu8 += src->len__dtl;
    max_dp_concat_len -= src->len__dtl;
  }

  if(key_as_bit_string_contents__prcu8->len__dtl > FLEA_ECC_MAX_ENCODED_POINT_LEN)
  {
    FLEA_THROW("excessive size of public point", FLEA_ERR_INV_KEY_SIZE);
  } 
#ifdef FLEA_USE_HEAP_BUF
  FLEA_ALLOC_MEM_ARR(ecc_key__pt->pub_point__mem__bu8, key_as_bit_string_contents__prcu8->len__dtl);
#endif

  flea_copy_rcu8_use_mem(&ecc_key__pt->public_point_encoded__rcu8, ecc_key__pt->pub_point__mem__bu8, key_as_bit_string_contents__prcu8);
  FLEA_THR_FIN_SEC_empty(); 
}

flea_err_t THR_flea_x509_parse_ecc_public_params(const flea_ref_cu8_t *encoded_parameters__pt, flea_ec_gfp_dom_par_ref_t *dom_par__pt)
{
  FLEA_DECL_OBJ(source__t, flea_data_source_t);
  FLEA_DECL_OBJ(dec__t, flea_ber_dec_t);
  flea_data_source_mem_help_t hlp__t;
  flea_bool_t found__b;
  FLEA_THR_BEG_FUNC();


  FLEA_CCALL(THR_flea_data_source_t__ctor_memory(&source__t, encoded_parameters__pt->data__pcu8, encoded_parameters__pt->len__dtl, &hlp__t));
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&dec__t, &source__t, 0));
  FLEA_CCALL(THR_flea_ber_dec_t__open_constructed_optional_cft(&dec__t, FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONSTRUCTED, FLEA_ASN1_SEQUENCE ), &found__b));
  if(found__b)
  {
    flea_u32_t version__u32;
    //flea_dtl_t len__dtl;
    flea_ref_cu8_t oid_ref__t;

    const flea_u8_t prime_field_oid__acu8[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x01, 0x01 };

    FLEA_CCALL(THR_flea_ber_dec_t__decode_integer_u32(&dec__t, FLEA_ASN1_INT, &version__u32));
    if(version__u32 != 1)
    {
      FLEA_THROW("invalid version in ECC parameters", FLEA_ERR_X509_INV_ECC_KEY_PARAMS); 
    }
    FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
    FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_oid(&dec__t, &oid_ref__t));
    if(oid_ref__t.len__dtl != sizeof(prime_field_oid__acu8) || memcmp(oid_ref__t.data__pcu8, prime_field_oid__acu8, sizeof(prime_field_oid__acu8)))
    {
      FLEA_THROW("unsupported field type in ECC parameters", FLEA_ERR_X509_INV_ECC_FIELD_TYPE); 
    }
    FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_positive_int_wo_lead_zeroes(&dec__t, &dom_par__pt->p__ru8));
    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
    FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
    FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_cft(&dec__t, FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, FLEA_ASN1_OCTET_STRING), &dom_par__pt->a__ru8));
    FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_cft(&dec__t, FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, FLEA_ASN1_OCTET_STRING), &dom_par__pt->b__ru8));
    FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(&dec__t, FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, FLEA_ASN1_BIT_STRING), &oid_ref__t, &found__b));
    /* close the curve: */
    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
    /* the public point */
    FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_cft(&dec__t, FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, FLEA_ASN1_OCTET_STRING), &oid_ref__t));
    FLEA_CCALL(THR_flea_ec_key__decode_uncompressed_point(&oid_ref__t, &dom_par__pt->gx__ru8, &dom_par__pt->gy__ru8));

    FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_positive_int_wo_lead_zeroes(&dec__t, &dom_par__pt->n__ru8));
    FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_positive_int_wo_lead_zeroes_optional(&dec__t, &dom_par__pt->h__ru8));
    if(dom_par__pt->h__ru8.len__dtl > FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(FLEA_ECC_MAX_COFACTOR_BIT_SIZE))
    {
      FLEA_THROW("invalid cofactor size", FLEA_ERR_X509_EXCSS_COFACTOR_SIZE); 
    }
    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
  }
  else
  {
    flea_ref_cu8_t named_curve_oid__t;
    flea_bool_t dummy;
    FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(&dec__t, FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, FLEA_ASN1_OID), &named_curve_oid__t, &dummy));
    if(!FLEA_DER_REF_IS_ABSENT(&named_curve_oid__t))
    {
      FLEA_CCALL(THR_flea_ecc_gfp_dom_par_t__set_by_named_curve_oid(dom_par__pt, named_curve_oid__t.data__pcu8, named_curve_oid__t.len__dtl));
    }
    else
    {
      flea_ref_cu8_t null__t;
      FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_next_tlv_raw(&dec__t, &null__t));
      if(flea_ber_dec__is_tlv_null(&null__t))
      {
        FLEA_THROW("no explicit or named ECC domain parameters provided", FLEA_ERR_X509_IMPLICT_ECC_KEY_PARAMS);
      }
      FLEA_THROW("invalidly encoded ECC domain parameters provided", FLEA_ERR_X509_INV_ECC_KEY_PARAMS);

    }

  }

  FLEA_THR_FIN_SEC(
      flea_data_source_t__dtor(&source__t); 
      flea_ber_dec_t__dtor(&dec__t);
      );
}

#endif

flea_err_t THR_flea_x509_parse_rsa_public_key(const flea_ref_cu8_t *public_key_value__pt, flea_ref_cu8_t *modulus__pt, flea_ref_cu8_t *pub_exp__pt)
{

  FLEA_DECL_OBJ(source__t, flea_data_source_t);
  FLEA_DECL_OBJ(dec__t, flea_ber_dec_t);
  flea_data_source_mem_help_t hlp__t;
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_data_source_t__ctor_memory(&source__t, public_key_value__pt->data__pcu8, public_key_value__pt->len__dtl, &hlp__t));
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&dec__t, &source__t, 0));
  /* open sequence */
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
  /* decode mod */ 
  FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_positive_int_wo_lead_zeroes(&dec__t, modulus__pt));
  /* decode exp */
  FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_positive_int_wo_lead_zeroes(&dec__t, pub_exp__pt));
  /* close sequence */
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
  FLEA_THR_FIN_SEC(
      flea_data_source_t__dtor(&source__t); 
      flea_ber_dec_t__dtor(&dec__t);
      );
}
#ifdef FLEA_HAVE_RSA
static flea_err_t THR_flea_public_key_t__create_rsa_key(flea_rsa_pubkey_val_t *key__pt, flea_ref_cu8_t *key_as_bit_string_contents__prcu8)
{
  FLEA_THR_BEG_FUNC();
  flea_ref_cu8_t mod__rcu8, exp__rcu8;

  FLEA_CCALL(THR_flea_x509_parse_rsa_public_key(key_as_bit_string_contents__prcu8, &mod__rcu8, &exp__rcu8));
  if(mod__rcu8.len__dtl > FLEA_RSA_MAX_MOD_BYTE_LEN || exp__rcu8.len__dtl > FLEA_RSA_MAX_PUB_EXP_BYTE_LEN)
  {
    FLEA_THROW("unsupported RSA key size", FLEA_ERR_UNSUPP_KEY_SIZE); 
  }
#ifdef FLEA_USE_HEAP_BUF
  FLEA_ALLOC_MEM_ARR(key__pt->mod_mem__bu8, mod__rcu8.len__dtl);
  FLEA_ALLOC_MEM_ARR(key__pt->exp_mem__bu8, exp__rcu8.len__dtl);
#endif
  flea_copy_rcu8_use_mem(&key__pt->mod__rcu8, key__pt->mod_mem__bu8, &mod__rcu8);
  flea_copy_rcu8_use_mem(&key__pt->pub_exp__rcu8, key__pt->exp_mem__bu8, &exp__rcu8);

  FLEA_THR_FIN_SEC_empty();
}
#endif
/**
 * Expects the public key as a bit string.
 *
 */
flea_err_t THR_flea_public_key_t__ctor(flea_public_key_t* key__pt, flea_pk_key_type_t key_type, const flea_ref_cu8_t *key_as_bit_string_tlv__prcu8, const flea_ref_cu8_t *encoded_params__prcu8)
{
  flea_bool_t dummy;
  return THR_flea_public_key_t__ctor_inherited_params(key__pt, key_type, key_as_bit_string_tlv__prcu8, encoded_params__prcu8, NULL, &dummy);
}

flea_err_t THR_flea_public_key_t__ctor_cert_inherited_params(flea_public_key_t* key__pt, const flea_x509_cert_ref_t *cert_ref__pt, const flea_ref_cu8_t *inherited_params_mbn__cprcu8, flea_bool_t *are_keys_params_implicit__pb)
{

  const flea_ref_cu8_t *oid_ref__pt = &cert_ref__pt->tbs_sig_algid__t.oid_ref__t;
  FLEA_THR_BEG_FUNC();

  if(((oid_ref__pt->len__dtl == sizeof(pkcs1_oid_prefix__cau8) + 1)) && !memcmp(oid_ref__pt->data__pcu8, pkcs1_oid_prefix__cau8, sizeof(pkcs1_oid_prefix__cau8)))
  {
    *are_keys_params_implicit__pb = FLEA_FALSE;
    FLEA_CCALL(THR_flea_public_key_t__ctor(key__pt, flea_rsa_key,  &cert_ref__pt->subject_public_key_info__t.public_key_as_tlv__t, NULL));
  } 
#ifdef FLEA_HAVE_ECC
  else if(oid_ref__pt->len__dtl == sizeof(ecdsa_oid_prefix__acu8) + 2 && !memcmp(oid_ref__pt->data__pcu8, ecdsa_oid_prefix__acu8, sizeof(ecdsa_oid_prefix__acu8)))
  {
    FLEA_CCALL(THR_flea_public_key_t__ctor_inherited_params(key__pt, flea_ecc_key, &cert_ref__pt->subject_public_key_info__t.public_key_as_tlv__t, &cert_ref__pt->subject_public_key_info__t.algid__t.params_ref_as_tlv__t, inherited_params_mbn__cprcu8, are_keys_params_implicit__pb));
  }
#endif /* #ifdef FLEA_HAVE_ECC */
  else
  {
    FLEA_THROW("unsupported primitive", FLEA_ERR_X509_UNSUPP_PRIMITIVE);
  }
  FLEA_THR_FIN_SEC_empty();
}
flea_err_t THR_flea_public_key_t__ctor_inherited_params(flea_public_key_t* key__pt, flea_pk_key_type_t key_type, const flea_ref_cu8_t *key_as_bit_string_tlv__prcu8, const flea_ref_cu8_t *encoded_params__prcu8, const flea_ref_cu8_t *inherited_params_mbn__cprcu8, flea_bool_t *are_keys_params_implicit__pb)
{

  FLEA_DECL_OBJ(key_dec__t, flea_ber_dec_t);
  FLEA_DECL_OBJ(source__t, flea_data_source_t);
  flea_data_source_mem_help_t hlp__t;
  FLEA_THR_BEG_FUNC();
  flea_ref_cu8_t public_key_as_bitstr__t;
  flea_ref_cu8_t public_key_value__t; /* actual representation of the public key */
  key__pt->key_type__t = key_type;
  FLEA_CCALL(THR_flea_data_source_t__ctor_memory(&source__t, key_as_bit_string_tlv__prcu8->data__pcu8, key_as_bit_string_tlv__prcu8->len__dtl, &hlp__t));
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&key_dec__t, &source__t, 0)); 

  /* valid for both ECDSA and RSA */
  FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_cft(&key_dec__t, FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_UNIVERSAL_PRIMITIVE, FLEA_ASN1_BIT_STRING), &public_key_as_bitstr__t));
  FLEA_CCALL(THR_flea_ber_dec__get_ref_to_bit_string_content_no_unused_bits(&public_key_as_bitstr__t, &public_key_value__t));
#ifdef FLEA_HAVE_ECC
  if(key_type == flea_ecc_key)
  {
    FLEA_CCALL(THR_flea_public_key_t__create_ecdsa_key(&key__pt->pubkey_with_params__u.ec_public_val__t, &public_key_value__t, encoded_params__prcu8, inherited_params_mbn__cprcu8, are_keys_params_implicit__pb));

    key__pt->key_bit_size__u16 = flea__get_BE_int_bit_len(key__pt->pubkey_with_params__u.ec_public_val__t.dp__t.n__ru8.data__pcu8, key__pt->pubkey_with_params__u.ec_public_val__t.dp__t.n__ru8.len__dtl);
  }
  else 
#endif
#ifdef FLEA_HAVE_RSA
    if(key_type == flea_rsa_key)
    {
      FLEA_CCALL(THR_flea_public_key_t__create_rsa_key(&key__pt->pubkey_with_params__u.rsa_public_val__t, &public_key_value__t));
      key__pt->key_bit_size__u16 = flea__get_BE_int_bit_len(key__pt->pubkey_with_params__u.rsa_public_val__t.mod__rcu8.data__pcu8, key__pt->pubkey_with_params__u.rsa_public_val__t.mod__rcu8.len__dtl);
    }
    else
#endif
    {
      FLEA_THROW("EC keys not supported", FLEA_ERR_X509_UNSUPP_PRIMITIVE);
    }

  FLEA_THR_FIN_SEC(
      flea_data_source_t__dtor(&source__t); 
      flea_ber_dec_t__dtor(&key_dec__t);
      ); 
}

flea_err_t THR_flea_public_key_t__verify_signature(const flea_public_key_t *key__pt, flea_pk_scheme_id_t pk_scheme_id__t, const flea_ref_cu8_t *message__prcu8, const flea_ref_cu8_t * signature__prcu8,  flea_hash_id_t hash_id__t )
{
#ifdef FLEA_HAVE_ECDSA
  FLEA_DECL_BUF(concat_sig__bu8, flea_u8_t, FLEA_ECDSA_MAX_SIG_LEN);
#endif
  flea_pub_key_param_u pk_par__u;
  FLEA_THR_BEG_FUNC();

#ifdef FLEA_HAVE_ECDSA
  if((key__pt->key_type__t == flea_ecc_key) && (pk_scheme_id__t == flea_ecdsa_emsa1))
  {

    flea_ref_cu8_t concat_sig_ref__t;
    flea_al_u16_t concat_sig_len__alu16;
    FLEA_ALLOC_BUF(concat_sig__bu8, signature__prcu8->len__dtl);
    FLEA_CCALL(THR_flea_x509_decode_ecdsa_signature(concat_sig__bu8, &concat_sig_len__alu16, signature__prcu8)); 
    concat_sig_ref__t.data__pcu8 = concat_sig__bu8;
    concat_sig_ref__t.len__dtl = concat_sig_len__alu16; 

    pk_par__u.ecc_dom_par__t = key__pt->pubkey_with_params__u.ec_public_val__t.dp__t;
    FLEA_CCALL(THR_flea_pk_api__verify_signature(
          message__prcu8,
          &concat_sig_ref__t,
          &key__pt->pubkey_with_params__u.ec_public_val__t.public_point_encoded__rcu8,
          flea_ecdsa_emsa1, 
          hash_id__t,
          &pk_par__u
          ));
  }
  else 
#endif
#ifdef FLEA_HAVE_RSA
    if((key__pt->key_type__t == flea_rsa_key) && (pk_scheme_id__t == flea_rsa_pkcs1_v1_5_sign))
    {
      pk_par__u.rsa_public_exp__ru8 = key__pt->pubkey_with_params__u.rsa_public_val__t.pub_exp__rcu8;
      FLEA_CCALL(THR_flea_pk_api__verify_signature(
            message__prcu8,
            signature__prcu8,
            &key__pt->pubkey_with_params__u.rsa_public_val__t.mod__rcu8,
            flea_rsa_pkcs1_v1_5_sign, 
            hash_id__t,
            &pk_par__u
            ));
    }
    else
#endif
    {
      FLEA_THROW("unsupported primitive", FLEA_ERR_X509_UNSUPP_PRIMITIVE);
    }
  FLEA_THR_FIN_SEC(
      FLEA_DO_IF_HAVE_ECDSA(
        FLEA_FREE_BUF_FINAL(concat_sig__bu8);
        );
      );
}

flea_err_t THR_flea_public_key_t__verify_signature_use_sigalg_id(const flea_public_key_t *public_key__pt, const flea_x509_algid_ref_t *sigalg_id__t, const flea_ref_cu8_t* tbs_data__pt, const flea_ref_cu8_t *signature__pt )
{

  const flea_ref_cu8_t *oid_ref__pt = &sigalg_id__t->oid_ref__t;
  FLEA_THR_BEG_FUNC();
#ifdef FLEA_HAVE_RSA
  if(((oid_ref__pt->len__dtl == sizeof(pkcs1_oid_prefix__cau8) + 1)) && !memcmp(oid_ref__pt->data__pcu8, pkcs1_oid_prefix__cau8, sizeof(pkcs1_oid_prefix__cau8)))
  {
    flea_hash_id_t hash_id__t; 
    if(public_key__pt->key_type__t == flea_rsa_key)
    {
      FLEA_CCALL(THR_get_hash_id_from_x509_id_for_rsa(oid_ref__pt->data__pcu8[sizeof(pkcs1_oid_prefix__cau8)], &hash_id__t));
      FLEA_CCALL(THR_flea_public_key_t__verify_signature(public_key__pt, flea_rsa_pkcs1_v1_5_sign, tbs_data__pt, signature__pt, hash_id__t));
    } 
    else
    {
      FLEA_THROW("key type and algorithm don't match", FLEA_ERR_INV_ALGORITHM);
    }
  }
  else 
#endif
#ifdef FLEA_HAVE_ECC
    if(oid_ref__pt->len__dtl == sizeof(ecdsa_oid_prefix__acu8) + 2 && !memcmp(oid_ref__pt->data__pcu8, ecdsa_oid_prefix__acu8, sizeof(ecdsa_oid_prefix__acu8)))
    {
      if(public_key__pt->key_type__t == flea_ecc_key)
      {
        FLEA_CCALL(THR_flea_x509_verify_ecdsa_signature(oid_ref__pt, public_key__pt, signature__pt, tbs_data__pt ));
      }
      else
      {
        FLEA_THROW("key type and algorithm don't match", FLEA_ERR_INV_ALGORITHM);
      }
    }
    else
#endif /* #ifdef FLEA_HAVE_ECC */
    {
      FLEA_THROW("unsupported primitive", FLEA_ERR_X509_UNSUPP_PRIMITIVE);
    }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_public_key_t__encrypt_message(const flea_public_key_t *key__pt, flea_pk_scheme_id_t pk_scheme_id__t, flea_hash_id_t hash_id__t, const flea_u8_t* message__pcu8, flea_al_u16_t message_len__alu16, flea_u8_t* result__pu8, flea_al_u16_t* result_len__palu16)
{
  FLEA_THR_BEG_FUNC();
#ifdef FLEA_HAVE_RSA
  FLEA_CCALL(THR_flea_pk_api__encrypt_message(pk_scheme_id__t, hash_id__t, message__pcu8, message_len__alu16, result__pu8, result_len__palu16, key__pt->pubkey_with_params__u.rsa_public_val__t.mod__rcu8.data__pcu8,  key__pt->pubkey_with_params__u.rsa_public_val__t.mod__rcu8.len__dtl, key__pt->pubkey_with_params__u.rsa_public_val__t.pub_exp__rcu8.data__pcu8, key__pt->pubkey_with_params__u.rsa_public_val__t.pub_exp__rcu8.len__dtl));
#else
  FLEA_THROW("no publick key encryption scheme (RSA) supported", FLEA_ERR_X509_UNSUPP_PRIMITIVE);
#endif
  FLEA_THR_FIN_SEC_empty();
}
void flea_public_key_t__dtor(flea_public_key_t *key__pt)
{
#ifdef FLEA_USE_HEAP_BUF
  if(key__pt->key_bit_size__u16)
  {
#if defined FLEA_HAVE_RSA || defined FLEA_HAVE_ECC
    flea_u8_t **mem_to_free_1 = NULL, **mem_to_free_2 = NULL;
#endif 
#ifdef FLEA_HAVE_ECC
    if(key__pt->key_type__t == flea_ecc_key)
    {
      mem_to_free_1 = &key__pt->pubkey_with_params__u.ec_public_val__t.dp_mem__bu8;
      mem_to_free_2 = &key__pt->pubkey_with_params__u.ec_public_val__t.pub_point__mem__bu8;
    }
#endif
#ifdef FLEA_HAVE_RSA
    if(key__pt->key_type__t == flea_rsa_key)
    {
      mem_to_free_1 = &key__pt->pubkey_with_params__u.rsa_public_val__t.mod_mem__bu8;
      mem_to_free_2 = &key__pt->pubkey_with_params__u.rsa_public_val__t.exp_mem__bu8;
    }
#endif
#if defined FLEA_HAVE_RSA || defined FLEA_HAVE_ECC
    FLEA_FREE_MEM_CHK_SET_NULL(*mem_to_free_1);
    FLEA_FREE_MEM_CHK_SET_NULL(*mem_to_free_2);
#endif
  }
#endif 
}
