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

static flea_err_t THR_flea_crl__does_cdp_contain_distrib_point(const flea_x509_cert_ref_t *subject__pt, const flea_ref_cu8_t *dp_name_raw__cprcu8, flea_bool_t relative_to_issuer__b, flea_bool_t *result_update__pb)
{
  FLEA_DECL_OBJ(dec__t, flea_ber_dec_t); FLEA_DECL_OBJ(source__t, flea_data_source_t);
  flea_data_source_mem_help_t hlp__t;
    flea_bool_t full_name_present__b;
  FLEA_THR_BEG_FUNC();
  if(!subject__pt->extensions__t.crl_distr_point__t.is_present__u8)
  {
    FLEA_THROW("cannot process CRL with IDP when the certificate doesn't have the CDP", FLEA_ERR_X509_CRL_CDP_IDP_MISMATCH);
  }
  FLEA_CCALL(THR_flea_data_source_t__ctor_memory(&source__t, subject__pt->extensions__t.crl_distr_point__t.raw_ref__t.data__pcu8, subject__pt->extensions__t.crl_distr_point__t.raw_ref__t.len__dtl, &hlp__t));
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&dec__t, &source__t, 0));
  /* open seq of DPs */
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
  while(flea_ber_dec_t__has_current_more_data(&dec__t))
  {
    flea_bool_t distrib_point_name_found__b;
    flea_bool_t found_match__b = FLEA_FALSE;
    /* decode next DistributionPoint */

    /* open this DP's sequence */
    FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));

    /* try to open distributionPoint element of type (DistributionPointName)
     *     distributionPoint       [0]     DistributionPointName OPTIONAL */
    FLEA_CCALL(THR_flea_ber_dec_t__open_constructed_optional_cft(&dec__t, (flea_asn1_tag_t)FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONSTRUCTED | FLEA_ASN1_CONTEXT_SPECIFIC, 0), &distrib_point_name_found__b));
    /* distributionPoint          [0] DistributionPointName OPTIONAL, */
    if(!distrib_point_name_found__b)
    {
      /* close this DP's sequence */
      FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_skip_remaining(&dec__t));
      continue;
    }
    /* fullName                [0]     GeneralNames, */
    FLEA_CCALL(THR_flea_ber_dec_t__open_constructed_optional_cft(&dec__t, (flea_asn1_tag_t)FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONSTRUCTED | FLEA_ASN1_CONTEXT_SPECIFIC, 0), &full_name_present__b));
    if(!relative_to_issuer__b && full_name_present__b)
    {
      flea_ref_cu8_t raw_tlv__rcu8 = {NULL, 0};

      while(flea_ber_dec_t__has_current_more_data(&dec__t))
      {
        /* decode the raw dp name */
        FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_next_tlv_raw_optional(&dec__t, &raw_tlv__rcu8));
        if(!flea_rcu8_cmp(&raw_tlv__rcu8, dp_name_raw__cprcu8)) 
        {
          found_match__b = FLEA_TRUE; 
        }
      }
      /* close fullName */
      FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
    }
    else if(relative_to_issuer__b)
    {
      flea_ref_cu8_t raw_tlv__rcu8;
      /*      nameRelativeToCRLIssuer [1]     RelativeDistinguishedName */
      FLEA_CCALL(THR_flea_ber_dec_t__open_constructed(&dec__t, 1, (flea_asn1_tag_t)FLEA_ASN1_CONSTRUCTED | FLEA_ASN1_CONTEXT_SPECIFIC));
      /* CRL-DP must match */ 
      FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_next_tlv_raw_optional(&dec__t, &raw_tlv__rcu8));
      /* close RDN */
      FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));

      if(!flea_rcu8_cmp(&raw_tlv__rcu8, dp_name_raw__cprcu8)) 
      {
          found_match__b = FLEA_TRUE; 
      }
    }
    if(found_match__b)
    {
      /* check the CDP reasons */
      flea_bool_t reasons_found__b;
      const flea_u32_t complete_reasons__u32 = 0x1FE;
      const flea_al_u8_t complete_reasons_cnt__alu8 = 9;
      flea_u32_t only_some_reasons__u32 = complete_reasons__u32;
      flea_al_u8_t nb_reason_bits__alu8 = complete_reasons_cnt__alu8;
        FLEA_CCALL(THR_flea_ber_dec_t__decode_short_bit_str_to_u32_optional(&dec__t, &only_some_reasons__u32, &nb_reason_bits__alu8, &reasons_found__b));

      if((nb_reason_bits__alu8 != complete_reasons_cnt__alu8) || ((only_some_reasons__u32 & complete_reasons__u32) != complete_reasons__u32))
      {
        /* in this case, in principle, the cert may still be found to be revoked, which
        * in this implementation does not have priority over this exception (which causes the status
        * indeterminate) */
        FLEA_THROW("insufficient CRL reasons", FLEA_ERR_X509_CRL_INCOMPL_REASONS);
      }
      *result_update__pb = FLEA_TRUE; 
    }
    
    /* close this DP (element of Distribution Points) */ 
      FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_skip_remaining(&dec__t));
    /* else (i.e. no DP (name)) there is nothing to do */
  } /* end of loop over DPs */
  /* close seq of DPs */
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
  
  
  FLEA_THR_FIN_SEC(
      flea_ber_dec_t__dtor(&dec__t); 
      flea_data_source_t__dtor(&source__t);
      );
}

static flea_err_t THR_flea_crl__ensure_idp_cdp_general_name_match(flea_ber_dec_t *dec__pt, const flea_x509_cert_ref_t *subject__pt, flea_bool_t *match_update__pb)
{
  FLEA_THR_BEG_FUNC();
  while(flea_ber_dec_t__has_current_more_data(dec__pt))
  {
    flea_ref_cu8_t raw_tlv__rcu8;
    /* decode the raw dp name */
    FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_next_tlv_raw_optional(dec__pt, &raw_tlv__rcu8));
    FLEA_CCALL(THR_flea_crl__does_cdp_contain_distrib_point(subject__pt, &raw_tlv__rcu8, FLEA_FALSE, match_update__pb));
    if(*match_update__pb)
    {
      FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_skip_remaining(dec__pt));
      FLEA_THR_RETURN();
    }
  }
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(dec__pt));
  FLEA_THR_FIN_SEC_empty();
}
static flea_err_t THR_flea_crl__parse_and_check_crl_distribution_point(flea_ber_dec_t *dec__pt, const flea_x509_cert_ref_t *subject__pt)
{
  flea_bool_t full_name_present__b;
  flea_bool_t match_update__b = FLEA_FALSE;
  FLEA_THR_BEG_FUNC();
     /* fullName                [0]     GeneralNames, */
  FLEA_CCALL(THR_flea_ber_dec_t__open_constructed_optional_cft(dec__pt, (flea_asn1_tag_t)FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONSTRUCTED | FLEA_ASN1_CONTEXT_SPECIFIC, 0), &full_name_present__b));
  if(full_name_present__b)
  {
    FLEA_CCALL(THR_flea_crl__ensure_idp_cdp_general_name_match(dec__pt, subject__pt, &match_update__b));
    if(match_update__b)
    {
      FLEA_THR_RETURN();
    } 
    /* close constr already done in callee */
  }
  else
  {
    flea_ref_cu8_t rel_name__rcu8;
    /*      nameRelativeToCRLIssuer [1]     RelativeDistinguishedName */
    FLEA_CCALL(THR_flea_ber_dec_t__open_constructed(dec__pt, 1, (flea_asn1_tag_t)FLEA_ASN1_CONSTRUCTED | FLEA_ASN1_CONTEXT_SPECIFIC));
    FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_next_tlv_raw_optional(dec__pt, &rel_name__rcu8));
   /* CRL-DP must match */ 
    FLEA_CCALL(THR_flea_crl__does_cdp_contain_distrib_point(subject__pt, &rel_name__rcu8, FLEA_TRUE, &match_update__b));
    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(dec__pt));
    if(match_update__b)
    {
      FLEA_THR_RETURN();
    }
  }
  FLEA_THROW("no matching IDP name for CRL DP name", FLEA_ERR_X509_CRL_CDP_IDP_MISMATCH);

 /* close the distribution point element */
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(dec__pt)); 
  FLEA_THR_FIN_SEC_empty(); 
}

static flea_err_t THR_flea_crl__parse_extensions(flea_ber_dec_t *dec__pt, flea_bool_t is_ca_cert__b, const flea_x509_cert_ref_t *subject__pt)
{
  FLEA_DECL_OBJ(cont_dec__t, flea_ber_dec_t);
  FLEA_DECL_OBJ(source__t, flea_data_source_t);
  FLEA_THR_BEG_FUNC();
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
    FLEA_CCALL(THR_flea_ber_dec_t__decode_boolean_default_false(dec__pt, &critical__b));

    /* decode the extension value in the octet string */
    FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_cft(dec__pt, FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_UNIVERSAL_PRIMITIVE, FLEA_ASN1_OCTET_STRING), &ostr__t));

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
        flea_bool_t distrib_point_name_found__b;
        flea_bool_t dummy_found__b;

      flea_bool_t only_contains_user_certs__b = FLEA_FALSE;
      flea_bool_t only_contains_ca_certs__b = FLEA_FALSE;
      flea_bool_t only_contains_attrib_certs__b = FLEA_FALSE;
      flea_bool_t indirect_crl__b = FLEA_FALSE;
      const flea_u32_t complete_reasons__u32 = 0x1FE;
      const flea_al_u8_t complete_reasons_cnt__alu8 = 9;
      flea_u32_t only_some_reasons__u32 = complete_reasons__u32;
      flea_al_u8_t nb_reason_bits__alu8 = complete_reasons_cnt__alu8;


      FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&cont_dec__t));


      FLEA_CCALL(THR_flea_ber_dec_t__open_constructed_optional_cft(&cont_dec__t, (flea_asn1_tag_t)FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONSTRUCTED | FLEA_ASN1_CONTEXT_SPECIFIC, 0), &distrib_point_name_found__b));
      /* distributionPoint          [0] DistributionPointName OPTIONAL, */
      if(distrib_point_name_found__b)
      {
        FLEA_CCALL(THR_flea_crl__parse_and_check_crl_distribution_point(&cont_dec__t, subject__pt));
        FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&cont_dec__t));
      }
      FLEA_CCALL(THR_flea_ber_dec_t__decode_boolean_default(&cont_dec__t,  &only_contains_user_certs__b));
      FLEA_CCALL(THR_flea_ber_dec_t__decode_boolean_default(&cont_dec__t,  &only_contains_ca_certs__b));
      FLEA_CCALL(THR_flea_ber_dec_t__decode_short_bit_str_to_u32_optional(&cont_dec__t, &only_some_reasons__u32, &nb_reason_bits__alu8, &dummy_found__b));
      FLEA_CCALL(THR_flea_ber_dec_t__decode_boolean_default(&cont_dec__t,  &indirect_crl__b));
      FLEA_CCALL(THR_flea_ber_dec_t__decode_boolean_default(&cont_dec__t,  &only_contains_attrib_certs__b));

      if((nb_reason_bits__alu8 != complete_reasons_cnt__alu8) || ((only_some_reasons__u32 & complete_reasons__u32) != complete_reasons__u32))
      {
        /* in this case, in principle, the cert may still be found to be revoked, which
        * in this implemenation does not have priority over the exception (which causes the status
        * indeterminate) */
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
      FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&cont_dec__t));
    }
    else if(critical__b)
    {
      FLEA_THROW("unsupported critical CRL extension", FLEA_ERR_X509_UNSUPP_CRIT_CRL_EXT);
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

static flea_err_t THR_flea_crl__update_revocation_status_from_crl(const flea_x509_cert_ref_t *subject__pt, const flea_x509_cert_ref_t *issuer__pt, const flea_u8_t *crl_der__pcu8, flea_dtl_t crl_der_len__dtl, const flea_gmt_time_t *verification_date__pt, flea_bool_t is_ca_cert__b, const flea_ref_cu8_t *inherited_params_mbn__cprcu8, flea_revocation_status_e *rev_stat__pe, flea_gmt_time_t *latest_this_update__pt)
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

  if(flea_rcu8_cmp(&crl_issuer_ref__t.raw_dn_complete__t, &issuer__pt->subject__t.raw_dn_complete__t) ||
      flea_rcu8_cmp(&subject__pt->issuer__t.raw_dn_complete__t, &issuer__pt->subject__t.raw_dn_complete__t))
  {
    FLEA_THROW("DN's in subject/issuer/crl do not match as required", FLEA_ERR_X509_CRL_NAMES_DONT_MATCH); 
  }
  if(issuer__pt->extensions__t.key_usage__t.is_present__u8)
  {
    if(!(issuer__pt->extensions__t.key_usage__t.purposes__u16 & flea_ku_crl_sign))
    {
      FLEA_THROW("CRL issuer has key usage extension without the CRLSign bit set", FLEA_ERR_X509_CRL_ISSUER_WO_CRL_SIGN);
    }
  }
  if((1 == flea_asn1_cmp_utc_time(verification_date__pt, &next_update__t)) ||
    (-1 == flea_asn1_cmp_utc_time(verification_date__pt, &this_update__t)) ||
    (1 == flea_asn1_cmp_utc_time(latest_this_update__pt, &this_update__t))
    )
  {
    /* outdated (or not yet valid) revocation information is not used, no change to revocation status */
    FLEA_THR_RETURN(); 
  }
  FLEA_CCALL(THR_flea_ber_dec_t__open_constructed_optional_cft(&dec__t, FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONSTRUCTED, FLEA_ASN1_SEQUENCE), &have_revoked_certs__b)); // revoked certs seq
  if(have_revoked_certs__b)
  {
    while(flea_ber_dec_t__has_current_more_data(&dec__t))
    {
      flea_gmt_time_t revocation_date__t;
      flea_ref_cu8_t serial_number__rcu8;
      flea_bool_t have_entry_extensions__b;
      FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t)); // entry seq
      FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_int(&dec__t, &serial_number__rcu8));
      FLEA_CCALL(THR_flea_asn1_parse_gmt_time(&dec__t, &revocation_date__t));
      FLEA_CCALL(THR_flea_ber_dec_t__open_constructed_optional_cft(&dec__t, FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONSTRUCTED, FLEA_ASN1_SEQUENCE), &have_entry_extensions__b)); 
      if(have_entry_extensions__b)
      {
        while(flea_ber_dec_t__has_current_more_data(&dec__t))
        {
          flea_ref_cu8_t oid__rcu8;
          flea_bool_t critical__b;

          FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t)); // this entry ext seq
          FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_oid(&dec__t, &oid__rcu8));
          FLEA_CCALL(THR_flea_ber_dec_t__decode_boolean_default_false(&dec__t, &critical__b));
          if(critical__b)
          {
            FLEA_THROW("unsupported critical CRL entry extension", FLEA_ERR_X509_UNSUPP_CRIT_CRL_EXT);
          }
          /* close entry extension, skip the extension value */
          FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_skip_remaining(&dec__t));
        }
        /* close entry extensions */
        FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
      }
      /* close entry seq */
      FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
      if(!flea_rcu8_cmp(&serial_number__rcu8, &subject__pt->serial_number__t))
      {
        is_cert_revoked = FLEA_TRUE;
        //break;
      }
    }
    /* close revokedCertificates */
    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
  } 
  FLEA_CCALL(THR_flea_ber_dec_t__open_constructed_optional(&dec__t, 0, FLEA_ASN1_CONSTRUCTED | FLEA_ASN1_CONTEXT_SPECIFIC, &have_extensions__b));
  if(have_extensions__b)
  {
    FLEA_CCALL(THR_flea_crl__parse_extensions(&dec__t, is_ca_cert__b, subject__pt));

    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
  }

  /* closing the tbs */
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));


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
  
  *latest_this_update__pt = this_update__t;
  /* begin nothrowing section */
  if(is_cert_revoked)
  {
    *rev_stat__pe = flea_revstat_revoked;
  }
  else
  {
    *rev_stat__pe = flea_revstat_good;
  }


 FLEA_THR_FIN_SEC(
      flea_data_source_t__dtor(&source__t); 
      flea_data_source_t__dtor(&source_tbs__t); 
      flea_ber_dec_t__dtor(&dec__t);
      flea_ber_dec_t__dtor(&dec_tbs__t);
      flea_public_key_t__dtor(&pubkey__t);
     );

}

flea_err_t THR_flea_crl__check_revocation_status(const flea_x509_cert_ref_t *subject__pt, const flea_x509_cert_ref_t *issuer__pt, const flea_ref_cu8_t *crl_der__cprcu8, flea_al_u16_t nb_crls__alu16,  const flea_gmt_time_t *verification_date__pt, flea_bool_t is_ca_cert__b, const flea_ref_cu8_t *inherited_params_mbn__cprcu8)
{
  flea_al_u16_t i;
  flea_revocation_status_e revstat = flea_revstat_undetermined;
  const flea_u8_t indet_date[] = "000000000000Z";
  flea_gmt_time_t latest_this_update__t;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_asn1_parse_date(flea_asn1_utc_time, indet_date, sizeof(indet_date)-1, &latest_this_update__t));
  for(i = 0; i < nb_crls__alu16; i++)
  {
    THR_flea_crl__update_revocation_status_from_crl(subject__pt, issuer__pt, crl_der__cprcu8[i].data__pcu8,  crl_der__cprcu8[i].len__dtl, verification_date__pt, is_ca_cert__b, inherited_params_mbn__cprcu8, &revstat, &latest_this_update__t);
    /* ignore potential errors. called function does not modify the status values in
     * this case */
  }
  if(revstat == flea_revstat_revoked)
  {
    FLEA_THROW("certificate revoked", FLEA_ERR_X509_CERT_REVOKED);
  }
  else if(revstat == flea_revstat_undetermined)
  {
    FLEA_THROW("certificate's revocation status cannot be determined", FLEA_ERR_X509_CERT_REV_STAT_UNDET);
  }
  FLEA_THR_FIN_SEC_empty();
}
