/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/ber_dec.h"
#include "flea/crl.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/namespace_asn1.h"
#include "flea/asn1_date.h"
#include "flea/pubkey.h"

#define DELTA_CRL_INDIC_INDIC      27
#define ISSUING_DISTR_POINT_INDIC  28

static flea_err_t THR_flea_crl__parse_extensions(flea_ber_dec_t *dec__pt, flea_bool_t is_ca_cert__b)
{
  FLEA_DECL_OBJ(cont_dec__t, flea_ber_dec_t);
  FLEA_DECL_OBJ(source__t, flea_data_source_t);
  FLEA_THR_BEG_FUNC();
  /*FLEA_CCALL(THR_flea_data_source_t__ctor_memory(&source__t, ostr__t.data__pcu8, ostr__t.len__dtl, &hlp__t));
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&cont_dec__t, &source__t, 0));*/
  /* open extensions */
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(dec__pt));
  while(flea_ber_dec_t__has_current_more_data(dec__pt))
  {
    flea_bool_t critical__b = FLEA_FALSE;
    flea_ref_cu8_t ext_oid_ref__t;
    flea_der_ref_t ostr__t;
    flea_data_source_mem_help_t hlp__t;
    /* open this extension */
    FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(dec__pt));
    FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_oid(dec__pt, &ext_oid_ref__t));
    //printf("parse_extension: before decode bool\n");
    FLEA_CCALL(THR_flea_ber_dec_t__decode_boolean_default_false(dec__pt, &critical__b));
    //printf("parse_extension: after decode bool\n");

    /* decode the extension value in the octet string */
    FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_cft(dec__pt, FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_UNIVERSAL_PRIMITIVE, FLEA_ASN1_OCTET_STRING), &ostr__t));
    /*printf("in extension with oid = "); 
      unsigned i;
      for(i = 0; i < ext_oid_ref__t.len__dtl; i++) printf("%02x ", ext_oid_ref__t.data__pcu8[i]);
      printf("\n");*/

    FLEA_CCALL(THR_flea_data_source_t__ctor_memory(&source__t, ostr__t.data__pcu8, ostr__t.len__dtl, &hlp__t));
    FLEA_CCALL(THR_flea_ber_dec_t__ctor(&cont_dec__t, &source__t, 0));
    if(!(ext_oid_ref__t.len__dtl == 3 && ext_oid_ref__t.data__pcu8[0] == 0x55 && ext_oid_ref__t.data__pcu8[1] ==  0x1D))
    {
      if(critical__b)
      {
        FLEA_THROW("unsupported critical CRL extension", FLEA_ERR_X509_UNSUPP_CRIT_CRL_EXT);
      }
      continue;
    }
    if(ext_oid_ref__t.data__pcu8[2] == DELTA_CRL_INDIC_INDIC)
    {
      FLEA_THROW("delta CRLs not supported", FLEA_ERR_X509_UNSUPP_DELTA_CRL);
    }
    else if(ext_oid_ref__t.data__pcu8[2] == ISSUING_DISTR_POINT_INDIC)
    {
      flea_bool_t only_contains_user_certs__b = FLEA_FALSE;
      flea_bool_t only_contains_ca_certs__b = FLEA_FALSE;
      flea_bool_t only_contains_attrib_certs__b = FLEA_FALSE;
      //flea_bool_t only_some_reasons = FLEA_FALSE;
      flea_bool_t indirect_crl__b = FLEA_FALSE;
      //flea_ref_cu8_t only_some_reasons__rcu8 = {NULL, 0};
      const flea_u32_t complete_reasons__u32 = 0x1FE;
      const flea_al_u8_t complete_reasons_cnt__alu8 = 9;
      flea_u32_t only_some_reasons__u32 = complete_reasons__u32;
      flea_al_u8_t nb_reason_bits__alu8 = complete_reasons_cnt__alu8;


      FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&cont_dec__t));

      while(flea_ber_dec_t__has_current_more_data(&cont_dec__t))
      {
        flea_ref_cu8_t dummy_ref__rcu8;
        flea_bool_t dummy_found__b;
        FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(&cont_dec__t, (flea_asn1_tag_t)FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONTEXT_SPECIFIC, 0), &dummy_ref__rcu8, &dummy_found__b));
        FLEA_CCALL(THR_flea_ber_dec_t__decode_boolean_default(&cont_dec__t,  &only_contains_user_certs__b));
        FLEA_CCALL(THR_flea_ber_dec_t__decode_boolean_default(&cont_dec__t,  &only_contains_ca_certs__b));
        //FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(&cont_dec__t, (flea_asn1_tag_t)FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONTEXT_SPECIFIC, 0), &only_some_reasons, &dummy_found__b));
        FLEA_CCALL(THR_flea_ber_dec_t__decode_short_bit_str_to_u32_optional(&cont_dec__t, &only_some_reasons__u32, &nb_reason_bits__alu8, &dummy_found__b));
        FLEA_CCALL(THR_flea_ber_dec_t__decode_boolean_default(&cont_dec__t,  &indirect_crl__b));
        FLEA_CCALL(THR_flea_ber_dec_t__decode_boolean_default(&cont_dec__t,  &only_contains_attrib_certs__b));

      }
      if((nb_reason_bits__alu8 != complete_reasons_cnt__alu8) || ((only_some_reasons__u32 & complete_reasons__u32) != complete_reasons__u32))
      {
        FLEA_THROW("insufficient CRL reasons", FLEA_ERR_X509_CRL_INCOMPL_REASONS);
      }
      if(is_ca_cert__b)
      {
        if(only_contains_attrib_certs__b || only_contains_user_certs__b)
        {
          FLEA_THROW("unsuitable CRL", FLEA_ERR_X509_UNSUITABLE_CRL);
        }
      }
      else if(only_contains_attrib_certs__b || only_contains_ca_certs__b)
      {
        FLEA_THROW("unsuitable CRL", FLEA_ERR_X509_UNSUITABLE_CRL);
      }
      if(indirect_crl__b)
      {
        FLEA_THROW("unsuitable CRL", FLEA_ERR_X509_UNSUPP_INDIR_CRL);
      }
      FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&cont_dec__t)); // TODO: REMOVE?
    }

    flea_ber_dec_t__dtor(&cont_dec__t); 
    flea_data_source_t__dtor(&source__t);
    /* close extension sequence */
    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_skip_remaining(dec__pt));
  } /* while(flea_ber_dec_t__has_current_more_data(dec__pt)) */
  /* close extensions sequence*/
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(dec__pt));
  FLEA_THR_FIN_SEC(
      flea_ber_dec_t__dtor(&cont_dec__t); 
      flea_data_source_t__dtor(&source__t);
      );
}

flea_err_t THR_flea_crl__check_revocation_status(const flea_x509_cert_ref_t *subject__pt, const flea_x509_cert_ref_t *issuer__pt, const flea_u8_t *crl_der__pcu8, flea_dtl_t crl_der_len__dtl, const flea_gmt_time_t *verification_date__pt, flea_bool_t is_ca_cert__b, const flea_ref_cu8_t *inherited_params_mbn__cprcu8)
{

  FLEA_DECL_OBJ(source__t, flea_data_source_t);
  FLEA_DECL_OBJ(dec__t, flea_ber_dec_t);
  FLEA_DECL_OBJ(source_tbs__t, flea_data_source_t);
  FLEA_DECL_OBJ(dec_tbs__t, flea_ber_dec_t);
  FLEA_DECL_OBJ(pubkey__t, flea_public_key_t);
  flea_data_source_mem_help_t hlp__t;
  flea_data_source_mem_help_t hlp_tbs__t;
  flea_ref_cu8_t tbs__rcu8;
  flea_u32_t enc_version__u32;
  flea_x509_algid_ref_t algid_ref_1__t; 
  flea_x509_algid_ref_t algid_ref_2__t; 
  flea_x509_dn_ref_t crl_issuer_ref__t;
  flea_gmt_time_t this_update__t;
  flea_gmt_time_t next_update__t;
  flea_bool_t have_revoked_certs__b;
  flea_bool_t is_cert_revoked = FLEA_FALSE;
  flea_bool_t have_extensions__b;
  flea_ref_cu8_t crl_signature_as_bit_string__rcu8;
  flea_ref_cu8_t sig_content__rcu8;
  flea_bool_t dummy__b;
 FLEA_THR_BEG_FUNC();
 
  FLEA_CCALL(THR_flea_data_source_t__ctor_memory(&source_tbs__t, crl_der__pcu8, crl_der_len__dtl, &hlp_tbs__t));
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&dec_tbs__t, &source_tbs__t, 0));
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec_tbs__t));
  FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_next_tlv_raw(&dec_tbs__t, &tbs__rcu8));

  FLEA_CCALL(THR_flea_data_source_t__ctor_memory(&source__t, crl_der__pcu8, crl_der_len__dtl, &hlp__t));
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&dec__t, &source__t, 0));

  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t)); // crl seq
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t)); // tbs seq
  FLEA_CCALL(THR_flea_ber_dec_t__decode_integer_u32_default(&dec__t, FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, FLEA_ASN1_INT), &enc_version__u32, 0));
  FLEA_CCALL(THR_flea_x509__parse_algid_ref(&algid_ref_1__t, &dec__t));
  FLEA_CCALL(THR_flea_x509__parse_dn(&crl_issuer_ref__t, &dec__t));
  FLEA_CCALL(THR_flea_asn1_parse_gmt_time(&dec__t, &this_update__t));
  FLEA_CCALL(THR_flea_asn1_parse_gmt_time(&dec__t, &next_update__t));

  if(1 == flea_asn1_cmp_utc_time(verification_date__pt, &next_update__t))
  {
    FLEA_THROW("CRL is not current", FLEA_ERR_X509_CRL_NEXT_UPDATE_PASSED);
  }
  
  FLEA_CCALL(THR_flea_ber_dec_t__open_constructed_optional_cft(&dec__t, FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONSTRUCTED | FLEA_ASN1_UNIVERSAL, FLEA_ASN1_SEQUENCE), &have_revoked_certs__b)); // revoked certs seq
  if(have_revoked_certs__b)
  {
    while(flea_ber_dec_t__has_current_more_data(&dec__t))
    {
      flea_ref_cu8_t serial_number__rcu8;
      //flea_gmt_time_t rev_date__t;
      FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t)); // entry seq
      FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_int(&dec__t, &serial_number__rcu8));
      FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_skip_remaining(&dec__t));
      if(!flea_rcu8_cmp(&serial_number__rcu8, &subject__pt->serial_number__t))
      {
        is_cert_revoked = FLEA_TRUE;
        break;
      }
      /*FLEA_CCALL(THR_flea_asn1_parse_gmt_time(&dec__t, &rev_date__t));
      if(enc_version__u32 == 0)
      {
        break;
      } */
    }
    /* close revokedCertificates */
    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_skip_remaining(&dec__t));
  } 
  FLEA_CCALL(THR_flea_ber_dec_t__open_constructed_optional(&dec__t, 3, FLEA_ASN1_CONSTRUCTED | FLEA_ASN1_CONTEXT_SPECIFIC, &have_extensions__b));
  if(have_extensions__b)
  {
    FLEA_CCALL(THR_flea_crl__parse_extensions(&dec__t, is_ca_cert__b));

    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
  }

  /* closing the tbs */
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));

  if(flea_rcu8_cmp(&crl_issuer_ref__t.raw_dn_complete__t, &issuer__pt->subject__t.raw_dn_complete__t) ||
      flea_rcu8_cmp(&subject__pt->issuer__t.raw_dn_complete__t, &issuer__pt->subject__t.raw_dn_complete__t))
  {
    FLEA_THROW("DN's in subject/issuer/crl do not match as required", FLEA_ERR_X509_CRL_NAMES_DONT_MATCH); 
  }
  if(issuer__pt->extensions__t.key_usage__t.is_present__u8)
  {
    if(!(issuer__pt->extensions__t.key_usage__t.purposes__u16 & FLEA_ASN1_KEY_USAGE_MASK_crl_sign))
    {
      FLEA_THROW("CRL issuer has key usage extension without the CRLSign bit set", FLEA_ERR_X509_CRL_ISSUER_WO_CRL_SIGN);
    }
  }
  
FLEA_CCALL(THR_flea_x509__parse_algid_ref(&algid_ref_2__t, &dec__t));
FLEA_CCALL(THR_flea_x509__process_alg_ids(&algid_ref_1__t, &algid_ref_2__t));
FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_cft(&dec__t, FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, BIT_STRING), &crl_signature_as_bit_string__rcu8));    
FLEA_CCALL(THR_flea_public_key_t__ctor_cert_inherited_params(&pubkey__t, issuer__pt, inherited_params_mbn__cprcu8, &dummy__b));

  FLEA_CCALL(THR_flea_ber_dec__get_ref_to_bit_string_content_no_unused_bits(&crl_signature_as_bit_string__rcu8, &sig_content__rcu8));
  FLEA_CCALL( THR_flea_public_key_t__verify_signature_use_sigalg_id(
        &pubkey__t, 
        &algid_ref_1__t,
        &tbs__rcu8,
        &sig_content__rcu8
        ));


 FLEA_THR_FIN_SEC(
      flea_data_source_t__dtor(&source__t); 
      flea_ber_dec_t__dtor(&dec__t);
      flea_public_key_t__dtor(&pubkey__t);
     );

}
