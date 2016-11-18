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

#ifdef FLEA_HAVE_ECC

/* assumes that result__pu8 has sufficient length allocated */
static flea_err_t THR_flea_x509_decode_ecdsa_signature(flea_u8_t *result__pu8, flea_al_u16_t *result_len__palu16, const flea_der_ref_t *x509_enc_sig__pt  )
{
  flea_der_ref_t ref_r__t;
  flea_der_ref_t ref_s__t;
  flea_al_u16_t r_offs, s_offs, diff, insert_offs;
  FLEA_DECL_OBJ(dec__t, flea_ber_dec_t);
  FLEA_DECL_OBJ(source__t, flea_data_source_t);
  flea_data_source_mem_help_t hlp__t;
FLEA_THR_BEG_FUNC();
  
  FLEA_CCALL(THR_flea_data_source_t__ctor_memory(&source__t, x509_enc_sig__pt->data__pcu8, x509_enc_sig__pt->len__dtl, &hlp__t));
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&dec__t, &source__t, 0)); // TODO: SET LIMIT (ALSO ELSEWHERE)
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
//first_len__alu16 = ref__t.len__dtl;
//memcpy(result__pu8, ref__t.data__pcu8, first_len__alu16); 



 FLEA_THR_FIN_SEC(
      flea_data_source_t__dtor(&source__t); 
      flea_ber_dec_t__dtor(&dec__t);
    
    );
}


// TODO: call this function first with key's encoded params, then with the
// inherited params
static flea_err_t THR_flea_public_key_t__create_ecdsa_key(flea_ec_pubkey_val_t *ecc_key__pt, const flea_ref_cu8_t *key_as_bit_string_contents__prcu8, const flea_ref_cu8_t *encoded_params__prcu8)
{
  FLEA_THR_BEG_FUNC();
  flea_al_u8_t i; 
  flea_ec_gfp_dom_par_ref_t ref__t;
  //flea_ref_cu8_t enc_point_ref;
  flea_al_u16_t max_dp_concat_len;
  flea_u8_t * write_pos__pu8;
  flea_ref_cu8_t *src__arcu8[7] = {&ref__t.p__ru8, &ref__t.a__ru8, &ref__t.b__ru8, &ref__t.gx__ru8, &ref__t.gy__ru8, &ref__t.n__ru8, &ref__t.h__ru8};
  flea_ref_cu8_t *trgt__arcu8[7] = {&ecc_key__pt->dp__t.p__ru8, &ecc_key__pt->dp__t.a__ru8, &ecc_key__pt->dp__t.b__ru8, &ecc_key__pt->dp__t.gx__ru8, &ecc_key__pt->dp__t.gy__ru8, &ecc_key__pt->dp__t.n__ru8, &ecc_key__pt->dp__t.h__ru8};
  FLEA_CCALL(THR_flea_x509_parse_ecc_public_params(encoded_params__prcu8, &ref__t));
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
   
  if(key_as_bit_string_contents__prcu8->len__dtl > FLEA_ECC_MAX_PUBKEY_LEN)
  {
    FLEA_THROW("excessive size of public point", FLEA_ERR_INV_KEY_SIZE);
  } 
#ifdef FLEA_USE_HEAP_BUF
 FLEA_ALLOC_MEM_ARR(ecc_key__pt->pub_point__mem__bu8, key_as_bit_string_contents__prcu8->len__dtl);
#endif
 
 // MAKE FUNCTION TO COPY AND SET REF TOGETHER
 /*memcpy(ecc_key__pt->pub_point__mem__bu8, key_as_bit_string_contents__prcu8->data__pcu8, key_as_bit_string_contents__prcu8->len__dtl);
 ecc_key__pt->public_point_encoded__rcu8.data__pcu8 = ecc_key__pt->pub_point__mem__bu8;
 ecc_key__pt->public_point_encoded__rcu8.len__dtl = key_as_bit_string_contents__prcu8->len__dtl;*/
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
   // TODO: MAKE FUNCTION FOR DECODING OCTET STRING 
   FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_cft(&dec__t, FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, FLEA_ASN1_OCTET_STRING), &dom_par__pt->a__ru8));
   FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_cft(&dec__t, FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, FLEA_ASN1_OCTET_STRING), &dom_par__pt->b__ru8));
   FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(&dec__t, FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, FLEA_ASN1_BIT_STRING), &oid_ref__t, &found__b));
   /* close the curve: */
   FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
   /* the public point */
   FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_cft(&dec__t, FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, FLEA_ASN1_OCTET_STRING), &oid_ref__t));
   FLEA_CCALL(THR_flea_ec_key__decode_uncompressed_point(&oid_ref__t, &dom_par__pt->gx__ru8, &dom_par__pt->gy__ru8));

   //FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_cft(&dec__t, FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, FLEA_ASN1_OCTET_STRING), &dom_par__pt->n__ru8));
   FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_positive_int_wo_lead_zeroes(&dec__t, &dom_par__pt->n__ru8));
// TODO: restrict cofactor size to new BC var MAX_COFACTOR_BIT_SIZE bits:
   FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_positive_int_wo_lead_zeroes_optional(&dec__t, &dom_par__pt->h__ru8));
   FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
 }
else
{
  flea_der_ref_t named_curve_oid__t;
  flea_bool_t dummy;
  FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(&dec__t, FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, FLEA_ASN1_OID), &named_curve_oid__t, &dummy));
  if(!FLEA_DER_REF_IS_ABSENT(&named_curve_oid__t))
  {
     FLEA_CCALL(THR_flea_ecc_gfp_dom_par_t__set_by_named_curve_oid(dom_par__pt, named_curve_oid__t.data__pcu8, named_curve_oid__t.len__dtl));
  }
  else
  {
  /* TODO: check for implict CA*/
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

flea_err_t THR_flea_x509_parse_rsa_public_key(const flea_ref_cu8_t *public_key_value__pt, flea_ref_cu8_t *modulus__pt, flea_der_ref_t *pub_exp__pt)
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
  //memcpy(key__pt->mod_mem__bu8, mod__rcu8.data__pcu8, mod__rcu8.len__dtl);
  //memcpy(key__pt->exp_mem__bu8, exp__rcu8.data__pcu8, exp__rcu8.len__dtl);

  FLEA_THR_FIN_SEC_empty();
}
#endif
/**
 * Expects the public key as a bit string.
 *
 */
flea_err_t THR_flea_public_key_t__ctor(flea_public_key_t* key__pt, flea_pk_key_type_t key_type, const flea_ref_cu8_t *key_as_bit_string_tlv__prcu8, const flea_ref_cu8_t *encoded_params__prcu8)
{

  FLEA_DECL_OBJ(key_dec__t, flea_ber_dec_t);
  FLEA_DECL_OBJ(source__t, flea_data_source_t);
  flea_data_source_mem_help_t hlp__t;
  FLEA_THR_BEG_FUNC();
  //flea_ref_cu8_t public_key_as_bitstr_contents__t;
  flea_ref_cu8_t public_key_as_bitstr__t;
  flea_der_ref_t public_key_value__t; /* actual representation of the public key */
  //FLEA_CCALL(THR_flea_ber_dec__get_ref_to_bit_string_content_no_unused_bits(key_as_bit_string__prcu8, &public_key_as_bitstr_contents__t));
  key__pt->key_type__t = key_type;
  FLEA_CCALL(THR_flea_data_source_t__ctor_memory(&source__t, key_as_bit_string_tlv__prcu8->data__pcu8, key_as_bit_string_tlv__prcu8->len__dtl, &hlp__t));
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&key_dec__t, &source__t, 0)); // TODO: SET LIMIT (ALSO ELSEWHERE)

  /* valid for both ECDSA and RSA */
  FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_cft(&key_dec__t, FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_UNIVERSAL_PRIMITIVE, FLEA_ASN1_BIT_STRING), &public_key_as_bitstr__t));
  FLEA_CCALL(THR_flea_ber_dec__get_ref_to_bit_string_content_no_unused_bits(&public_key_as_bitstr__t, &public_key_value__t));
#ifdef FLEA_HAVE_ECC
  if(key_type == flea_ecc_key)
  {
    FLEA_CCALL(THR_flea_public_key_t__create_ecdsa_key(&key__pt->pubkey_with_params__u.ec_public_val__t, &public_key_value__t, encoded_params__prcu8));
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

//TODO: SET KEY BIT SIZE IN OBJECT
  FLEA_THR_FIN_SEC(
      flea_data_source_t__dtor(&source__t); 
      flea_ber_dec_t__dtor(&key_dec__t);
      ); 
}

// TODO: TAKE ENCODED SIGNATURE
// TODO: MAKE WRAPPER WHICH PARSES THE ALGOID TO DERIVE HASH FUCNTION
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
    
  flea_der_ref_t concat_sig_ref__t;
  flea_al_u16_t concat_sig_len__alu16;
  FLEA_ALLOC_BUF(concat_sig__bu8, signature__prcu8->len__dtl);
  FLEA_CCALL(THR_flea_x509_decode_ecdsa_signature(concat_sig__bu8, &concat_sig_len__alu16, signature__prcu8)); 
  concat_sig_ref__t.data__pcu8 = concat_sig__bu8;
  concat_sig_ref__t.len__dtl = concat_sig_len__alu16; 

  pk_par__u.ecc_dom_par__t = key__pt->pubkey_with_params__u.ec_public_val__t.dp__t;
  FLEA_CCALL(THR_flea_pk_api__verify_signature(
        message__prcu8,
        &concat_sig_ref__t,
        //public_key_value__pt,
        &key__pt->pubkey_with_params__u.ec_public_val__t.public_point_encoded__rcu8,
        flea_ecdsa_emsa1, // TODO: GENERALIZE
        hash_id__t,
        &pk_par__u
        //&key__pt->pubkey_with_params__u.ec_public_val__t.dp__t
        //&ver_key__t.pubkey_with_params__u.ec_public_val__t.dp_mem__bu8
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
          //&public_mod__t,
         &key__pt->pubkey_with_params__u.rsa_public_val__t.mod__rcu8,
          flea_rsa_pkcs1_v1_5_sign, // TODO: GENERALIZE
          hash_id__t,
          &pk_par__u
        //&key__pt->pubkey_with_params__u.rsa_public_val__t.pub_exp__rcu8
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

void flea_public_key_t__dtor(flea_public_key_t *key__pt)
{
#ifdef FLEA_USE_HEAP_BUF
  if(key__pt->key_bit_size__u16)
  {
    flea_u8_t **mem_to_free_1, **mem_to_free_2;
#ifdef FLEA_HAVE_ECC
    if(key__pt->key_type__t == flea_ecc_key)
    {
      mem_to_free_1 = &key__pt->pubkey_with_params__u.ec_public_val__t.dp_mem__bu8;
      mem_to_free_2 = &key__pt->pubkey_with_params__u.ec_public_val__t.pub_point__mem__bu8;
    }
    else
#endif
#ifdef FLEA_HAVE_RSA
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
