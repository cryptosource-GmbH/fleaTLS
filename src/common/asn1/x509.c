/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/ber_dec.h"
#include "flea/x509.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/namespace_asn1.h"
#include "flea/asn1_date.h"

#include <string.h>

#define ID_UNSUPP_EXT_OID           0

/** id-ce **/
#define ID_CE_INDIC                (0x0100)
#define ID_CE_OID_AKI              (ID_CE_INDIC | 35)
#define ID_CE_OID_POLICIES         (ID_CE_INDIC | 32)
#define ID_CE_OID_KEY_USAGE        (ID_CE_INDIC | 15)
#define ID_CE_OID_SUBJ_KEY_ID      (ID_CE_INDIC | 14)
#define ID_CE_OID_SUBJ_ALT_NAME    (ID_CE_INDIC | 17)
#define ID_CE_OID_ISS_ALT_NAME     (ID_CE_INDIC | 18)
#define ID_CE_OID_BASIC_CONSTR     (ID_CE_INDIC | 19)
#define ID_CE_OID_NAME_CONSTR      (ID_CE_INDIC | 30)
#define ID_CE_OID_POLICY_CONSTR    (ID_CE_INDIC | 36)
#define ID_CE_OID_EXT_KEY_USAGE    (ID_CE_INDIC | 37)
#define ID_CE_OID_CRL_DISTR_POINT  (ID_CE_INDIC | 31)
#define ID_CE_OID_INHIB_ANY_POLICY (ID_CE_INDIC | 54)
#define ID_CE_OID_FRESHEST_CRL     (ID_CE_INDIC | 46)

/** id-pe**/
#define ID_PE_INDIC            (0x0200)
#define ID_PE_OID_AUTH_INF_ACC (ID_PE_INDIC | 1)
#define ID_PE_OID_SUBJ_INF_ACC (ID_PE_INDIC | 11)

const flea_u8_t id_pe__cau8 [7] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01 };

static flea_err_t THR_flea_x509_cert_parse_basic_constraints(flea_ber_dec_t *cont_dec__pt, flea_basic_constraints_t *basic_constraints__pt) 
{
  flea_u32_t x__u32; 
  flea_bool_t found__b;
  FLEA_THR_BEG_FUNC();
  basic_constraints__pt->is_present__u8 = FLEA_TRUE;
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(cont_dec__pt));
  FLEA_CCALL(THR_flea_ber_dec_t__decode_boolean_default_false(cont_dec__pt, &basic_constraints__pt->is_ca__b));

  FLEA_CCALL(THR_flea_ber_dec_t__decode_integer_u32_optional(cont_dec__pt, FLEA_ASN1_INT, &x__u32, &found__b));
  if(found__b)
  {
    if(x__u32 > 0xFFFE)
    {
      FLEA_THROW("pathlen of more than 0xFFFE not supported", FLEA_ERR_X509_BC_EXCSS_PATH_LEN);
    }
    basic_constraints__pt->path_len__u16 = x__u32;
    basic_constraints__pt->has_path_len__b = FLEA_TRUE;
  }
  else
  {
    basic_constraints__pt->path_len__u16 = 0xFFFF;
    basic_constraints__pt->has_path_len__b = FLEA_FALSE;
  }

  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(cont_dec__pt));
  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_flea_x509_cert__parse_eku(flea_ber_dec_t *cont_dec__pt, flea_ext_key_usage_t * ext_key_usage__pt )
{   
  const flea_u8_t id_kp__cau8 [] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03 };
  flea_der_ref_t oid_ref__t;
  flea_u16_t purposes__u16 = 0;
  ext_key_usage__pt->is_present__u8 = FLEA_TRUE;
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(cont_dec__pt));

  // seq of oids 
  while(flea_ber_dec_t__has_current_more_data(cont_dec__pt))
  {
    FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_oid(cont_dec__pt, &oid_ref__t));
    if((oid_ref__t.len__dtl != sizeof(id_kp__cau8) + 1)                 ||
        memcmp(oid_ref__t.data__pcu8, id_kp__cau8, sizeof(id_kp__cau8)) ||
        (oid_ref__t.data__pcu8[sizeof(id_kp__cau8)] > 15))
    {
      FLEA_THROW("unknown extended key usage purpose", FLEA_ERR_X509_EKU_VAL_ERR);
    }
    purposes__u16 |=  (1 << oid_ref__t.data__pcu8[sizeof(id_kp__cau8)]);
  }
  if(purposes__u16 & (flea_u16_t)~(
        (1 << FLEA_ASN1_EKU_BITP_server_auth      ) |
        (1 << FLEA_ASN1_EKU_BITP_client_auth      ) |
        (1 << FLEA_ASN1_EKU_BITP_code_signing     ) |
        (1 << FLEA_ASN1_EKU_BITP_email_protection ) |
        (1 << FLEA_ASN1_EKU_BITP_time_stamping    ) |
        (1 << FLEA_ASN1_EKU_BITP_ocsp_signing     )))
  {
    FLEA_THROW("unknown extended key usage purpose", FLEA_ERR_X509_EKU_VAL_ERR);
  }

  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(cont_dec__pt));
  ext_key_usage__pt->purposes__u16 = purposes__u16;
  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_flea_x509_cert__parse_key_usage(flea_ber_dec_t *cont_dec__pt, flea_key_usage_t * key_usage__pt )
{
  flea_der_ref_t bit_str_ref__t;
  flea_u16_t ku__u16;
  FLEA_THR_BEG_FUNC();
  key_usage__pt->is_present__u8 = FLEA_TRUE;
  FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_cft(cont_dec__pt, FLEA_ASN1_BIT_STRING, &bit_str_ref__t)); 
  if(bit_str_ref__t.len__dtl < 2)
  {
    FLEA_THROW("empty key usage value", FLEA_ERR_X509_KU_DEC_ERR);
  }
  ku__u16 = bit_str_ref__t.data__pcu8[1] << 8; 
  if(bit_str_ref__t.len__dtl > 2)
  {
    /* unused implicitly set to zero -- in DER unused must be zero */
    ku__u16 |= bit_str_ref__t.data__pcu8[2];
  }
  key_usage__pt->purposes__u16 = ku__u16;
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_x509__parse_algid_ref(flea_x509_algid_ref_t *algid_ref__pt, flea_ber_dec_t *dec__pt)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(dec__pt));
  FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_oid(dec__pt, &algid_ref__pt->oid_ref__t));
  FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_next_tlv_raw_optional(dec__pt, &algid_ref__pt->params_ref_as_tlv__t ));
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(dec__pt)); 
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_x509__process_alg_ids(flea_x509_algid_ref_t* tbs_ref__pt, const flea_x509_algid_ref_t* outer_ref__pt)
{
  FLEA_THR_BEG_FUNC();

  if(!flea_ber_dec__are_der_refs_equal(&outer_ref__pt->oid_ref__t, &tbs_ref__pt->oid_ref__t))
  {
    FLEA_THROW("the two signature algorithm identifiers in the certificate do not match", FLEA_ERR_X509_SIG_ALG_ERR );
  }
  if(flea_ber_dec__is_tlv_null(&tbs_ref__pt->params_ref_as_tlv__t))
  {
    // take params from outer
    tbs_ref__pt->params_ref_as_tlv__t = outer_ref__pt->params_ref_as_tlv__t;
  }
  FLEA_THR_FIN_SEC_empty();
}

/*
   id-pkix  OBJECT IDENTIFIER  ::=
   { iso(1) identified-organization(3) dod(6) internet(1)
   security(5) mechanisms(5) pkix(7) }

   id-pe  OBJECT IDENTIFIER  ::=  { id-pkix 1 }
   */
static flea_err_t THR_flea_x509_cert_ref__t__parse_extensions(flea_x509_ext_ref_t *ext_ref__pt, flea_ber_dec_t *dec__pt)
{
  flea_bool_t have_extensions__b;
  flea_der_ref_t ext_oid_ref__t;
  flea_bool_t critical__b;
  FLEA_DECL_OBJ(cont_dec__t, flea_ber_dec_t);
  FLEA_DECL_OBJ(source__t, flea_data_source_t);
  FLEA_THR_BEG_FUNC();
  /* open implicit */
  FLEA_CCALL(THR_flea_ber_dec_t__open_constructed_optional(dec__pt, 3, FLEA_ASN1_CONSTRUCTED | FLEA_ASN1_CONTEXT_SPECIFIC, &have_extensions__b));
  if(!have_extensions__b)
  {
    FLEA_THR_RETURN();
  }
  /* open extensions */
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(dec__pt));
  //printf("parse_extension: before more data\n");
  while(flea_ber_dec_t__has_current_more_data(dec__pt))
  {
    flea_al_u8_t ext_indic_pos__alu8;
    flea_der_ref_t ostr__t;
    flea_al_u16_t oid_indicator__alu16 = 0;
    flea_data_source_mem_help_t hlp__t;
    /* open this extension */
    FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(dec__pt));
    FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_oid(dec__pt, &ext_oid_ref__t));
    FLEA_CCALL(THR_flea_ber_dec_t__decode_boolean_default_false(dec__pt, &critical__b));

    /* decode the extension value in the octet string */
    FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_cft(dec__pt, FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_UNIVERSAL_PRIMITIVE, FLEA_ASN1_OCTET_STRING), &ostr__t));

    /* open 'octet string' sequence */
    if(ext_oid_ref__t.len__dtl == 3 && ext_oid_ref__t.data__pcu8[0] == 0x55 && ext_oid_ref__t.data__pcu8[1] ==  0x1D)
    {
      oid_indicator__alu16 = ID_CE_INDIC;
      ext_indic_pos__alu8 = 2;
      oid_indicator__alu16 |= ext_oid_ref__t.data__pcu8[ext_indic_pos__alu8];
    }
    else if((ext_oid_ref__t.len__dtl == sizeof(id_pe__cau8) + 1 ) && (!memcmp(ext_oid_ref__t.data__pcu8, id_pe__cau8, sizeof(id_pe__cau8))))
    {
      oid_indicator__alu16 = ID_PE_INDIC;
      ext_indic_pos__alu8 = sizeof(id_pe__cau8);
      oid_indicator__alu16 |= ext_oid_ref__t.data__pcu8[ext_indic_pos__alu8];
    }
    else
    {
      if(critical__b)
      {
        FLEA_THROW("unsupported critical extension", FLEA_ERR_X509_ERR_UNSUP_CRIT_EXT );
      }
      oid_indicator__alu16 = ID_UNSUPP_EXT_OID; 
    }
    /* standard extension */
    FLEA_CCALL(THR_flea_data_source_t__ctor_memory(&source__t, ostr__t.data__pcu8, ostr__t.len__dtl, &hlp__t));
    FLEA_CCALL(THR_flea_ber_dec_t__ctor(&cont_dec__t, &source__t, 0));
    switch (oid_indicator__alu16)
    {
      flea_bool_t found__b;
      case ID_CE_OID_AKI:
      {
        /* authority key identifier */
        ext_ref__pt->auth_key_id__t.is_present__u8 = FLEA_TRUE;

        FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&cont_dec__t));
        FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(&cont_dec__t, (flea_asn1_tag_t)FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONTEXT_SPECIFIC, 0), &ext_ref__pt->auth_key_id__t.key_id__t, &found__b));
        FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_implicit_universal_optional(&cont_dec__t, 1, FLEA_ASN1_CONTEXT_SPECIFIC | FLEA_ASN1_CONSTRUCTED, &ext_ref__pt->auth_key_id__t.auth_cert_serial_number__t));
        /* this value is not used, the above is just for parsing */
        ext_ref__pt->auth_key_id__t.auth_cert_serial_number__t.data__pcu8 = NULL;

        /* decode serial number component */
        FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(&cont_dec__t, (flea_asn1_tag_t)FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONTEXT_SPECIFIC, 2), &ext_ref__pt->auth_key_id__t.auth_cert_serial_number__t, &found__b));


        FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&cont_dec__t));
        break;
      }
#if 0
      case ID_CE_OID_POLICIES: 
      {
        break;
      }
#endif
      case ID_CE_OID_KEY_USAGE:
      {
        FLEA_CCALL(THR_flea_x509_cert__parse_key_usage(&cont_dec__t, &ext_ref__pt->key_usage__t));
        break;
      }
      case ID_CE_OID_SUBJ_KEY_ID:  
      {
        FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_cft(&cont_dec__t, FLEA_ASN1_OCTET_STRING, &ext_ref__pt->subj_key_id__t));
        break;
      }
      case ID_CE_OID_SUBJ_ALT_NAME:
      {
        ext_ref__pt->san__t.is_present__u8 = FLEA_TRUE;
        FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_next_tlv_raw(&cont_dec__t, &ext_ref__pt->san__t.san_raw__t));
        break; 
      }

      case ID_CE_OID_ISS_ALT_NAME:
      {
        // nothing to do, flea does not process it
        break;
      }
      case ID_CE_OID_BASIC_CONSTR:
      {
        FLEA_CCALL(THR_flea_x509_cert_parse_basic_constraints(&cont_dec__t, &ext_ref__pt->basic_constraints__t));
        break;
      }
#if 0
      case ID_CE_OID_NAME_CONSTR:
      {
        break;
      }
      case ID_CE_OID_POLICY_CONSTR:
      {
        break;
      }
#endif
      case ID_CE_OID_EXT_KEY_USAGE:
      {
        FLEA_CCALL(THR_flea_x509_cert__parse_eku(&cont_dec__t, &ext_ref__pt->ext_key_usage__t));
        break;
      }
      case ID_CE_OID_CRL_DISTR_POINT:
      {
        ext_ref__pt->crl_distr_point__t.is_present__u8 = FLEA_TRUE;
        FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_next_tlv_raw(&cont_dec__t, &ext_ref__pt->crl_distr_point__t.raw_ref__t));
        break;
      }
#if 0
      case ID_CE_OID_INHIB_ANY_POLICY:
      {
        break;
      }
#endif
      case ID_CE_OID_FRESHEST_CRL:
      {
        ext_ref__pt->freshest_crl__t.is_present__u8 = FLEA_TRUE;
        FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_next_tlv_raw(&cont_dec__t, &ext_ref__pt->freshest_crl__t.raw_ref__t));

        break;
      }
      case ID_PE_OID_AUTH_INF_ACC:
      {
        ext_ref__pt->auth_inf_acc__t.is_present__u8 = FLEA_TRUE;
        FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_next_tlv_raw(&cont_dec__t, &ext_ref__pt->auth_inf_acc__t.raw_ref__t));
        break;
      }
#if 0
      case ID_PE_OID_SUBJ_INF_ACC:
      {
        break;
      }
#endif
      default:
      if(critical__b)
      {
        FLEA_THROW("unsupported critical extension", FLEA_ERR_X509_ERR_UNSUP_CRIT_EXT );
      }

    }


    flea_ber_dec_t__dtor(&cont_dec__t);
    flea_data_source_t__dtor(&source__t);
    /* close extension sequence */
    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(dec__pt));
  } /* while(flea_ber_dec_t__has_current_more_data(dec__pt)) */

  /* close extensions sequence*/
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(dec__pt));

  /* close implicit */
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(dec__pt));
  FLEA_THR_FIN_SEC(
      flea_ber_dec_t__dtor(&cont_dec__t); 
      flea_data_source_t__dtor(&source__t);
      );
}


flea_err_t THR_flea_x509__parse_dn(flea_x509_dn_ref_t *dn_ref__pt, flea_ber_dec_t *dec__pt)
{

  FLEA_DECL_OBJ(source__t, flea_data_source_t);
  FLEA_DECL_OBJ(dec__t, flea_ber_dec_t);
  flea_data_source_mem_help_t hlp__t;
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_next_tlv_raw(dec__pt, &dn_ref__pt->raw_dn_complete__t));

  FLEA_CCALL(THR_flea_data_source_t__ctor_memory(&source__t, dn_ref__pt->raw_dn_complete__t.data__pcu8, dn_ref__pt->raw_dn_complete__t.len__dtl, &hlp__t));
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&dec__t, &source__t, 0));

  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
  while(flea_ber_dec_t__has_current_more_data(&dec__t))
  {
    flea_x509_ref_t *entry_ref__pt = NULL;
    flea_der_ref_t entry_ref__t;
    flea_asn1_str_type_t str_type__t;
    FLEA_CCALL(THR_flea_ber_dec_t__open_set(&dec__t));
    FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
    FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_oid(&dec__t, &entry_ref__t));
    if(entry_ref__t.len__dtl != 3 || entry_ref__t.data__pcu8[0] != FLEA_ASN1_OID_FIRST_BYTE(2,5) || entry_ref__t.data__pcu8[1] != 4)
    {
      FLEA_THROW("invalid oid for distinguished name component", FLEA_ERR_X509_DN_ERROR);
    }
    switch (entry_ref__t.data__pcu8[2])
    {
      case 6:
        entry_ref__pt = &dn_ref__pt->country__t;
        break;
      case 10:
        entry_ref__pt = &dn_ref__pt->org__t;
        break;
      case 11:
        entry_ref__pt = &dn_ref__pt->org_unit__t;
        break;
      case 46:
        entry_ref__pt = &dn_ref__pt->dn_qual__t;
        break;
      case 8:
        entry_ref__pt = &dn_ref__pt->state_or_province_name__t;
        break;
      case 3:
        entry_ref__pt = &dn_ref__pt->common_name__t;
        break;
      case 5:
        entry_ref__pt = &dn_ref__pt->serial_number__t;
        break;
      case 7:
        entry_ref__pt = &dn_ref__pt->locality_name__t;
        break;
      default: 
        FLEA_THROW("unsupported distinguished name component", FLEA_ERR_X509_DN_ERROR); 
    }
    if(entry_ref__pt == NULL)
    {
      FLEA_THROW("unknown component in distinguished name", FLEA_ERR_X509_DN_ERROR);
    }
    FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_string(&dec__t, &str_type__t, &entry_ref__pt->data__pcu8, &entry_ref__pt->len__dtl));
    // close the sequence
    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
    // close the set -- multivalued RDNs are not supported
    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
  } 
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
  FLEA_THR_FIN_SEC(
      flea_data_source_t__dtor(&source__t); 
      flea_ber_dec_t__dtor(&dec__t);
      ); 
}

flea_err_t THR_flea_x509_cert_ref_t__ctor(flea_x509_cert_ref_t *cert_ref__pt, const flea_u8_t* der_encoded_cert__pu8, flea_x509_len_t der_encoded_cert_len__x5l)
{

  FLEA_DECL_OBJ(source__t, flea_data_source_t);
  FLEA_DECL_OBJ(source_tbs__t, flea_data_source_t);
  FLEA_DECL_OBJ(dec__t, flea_ber_dec_t);
  FLEA_DECL_OBJ(dec_tbs__t, flea_ber_dec_t);
  flea_data_source_mem_help_t hlp__t;
  flea_data_source_mem_help_t hlp_tbs__t;
  flea_bool_t found_tag__b;
  flea_x509_algid_ref_t outer_sig_algid__t;

  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_data_source_t__ctor_memory(&source_tbs__t, der_encoded_cert__pu8, der_encoded_cert_len__x5l, &hlp_tbs__t));
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&dec_tbs__t, &source_tbs__t, 0));
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec_tbs__t));
  FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_next_tlv_raw(&dec_tbs__t, &cert_ref__pt->tbs_ref__t));


  FLEA_CCALL(THR_flea_data_source_t__ctor_memory(&source__t, der_encoded_cert__pu8, der_encoded_cert_len__x5l, &hlp__t));
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&dec__t, &source__t, 0));

  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
  FLEA_CCALL(THR_flea_ber_dec_t__open_constructed_optional(&dec__t, 0, FLEA_ASN1_CONSTRUCTED | FLEA_ASN1_CONTEXT_SPECIFIC, &found_tag__b));
  if(found_tag__b)
  {
    flea_dtl_t version_len__dtl = 1;
    flea_u8_t version__u8;
    FLEA_CCALL(THR_flea_ber_dec_t__read_value_raw(&dec__t, FLEA_ASN1_INT, 0, &version__u8, &version_len__dtl));
    if(version_len__dtl == 0)
    {
      FLEA_THROW("x.509 version of length 0", FLEA_ERR_X509_VERSION_ERROR);
    } 
    cert_ref__pt->version__u8 = version__u8 + 1;
    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
  }
  else
  {
    cert_ref__pt->version__u8 = 1;
  } 
  FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_int(&dec__t, &cert_ref__pt->serial_number__t));


  FLEA_CCALL(THR_flea_x509__parse_algid_ref(&cert_ref__pt->tbs_sig_algid__t, &dec__t));
  FLEA_CCALL(THR_flea_x509__parse_dn(&cert_ref__pt->issuer__t, &dec__t));
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));

  FLEA_CCALL(THR_flea_asn1_parse_gmt_time(&dec__t, &cert_ref__pt->not_before__t));
  FLEA_CCALL(THR_flea_asn1_parse_gmt_time(&dec__t, &cert_ref__pt->not_after__t));
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));

  FLEA_CCALL(THR_flea_x509__parse_dn(&cert_ref__pt->subject__t, &dec__t));

  /* enter subject public key info */
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
  FLEA_CCALL(THR_flea_x509__parse_algid_ref(&cert_ref__pt->subject_public_key_info__t.algid__t, &dec__t));

  FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_next_tlv_raw(&dec__t, &cert_ref__pt->subject_public_key_info__t.public_key_as_tlv__t));

  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
  FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_implicit_universal_optional_with_inner(&dec__t, 1, FLEA_ASN1_BIT_STRING, &cert_ref__pt->issuer_unique_id_as_bitstr__t));
  FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_implicit_universal_optional_with_inner(&dec__t, 2, FLEA_ASN1_BIT_STRING, &cert_ref__pt->subject_unique_id_as_bitstr__t));
  FLEA_CCALL(THR_flea_x509_cert_ref__t__parse_extensions(&cert_ref__pt->extensions__t, &dec__t));

  /* closing the tbs */
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));

  FLEA_CCALL(THR_flea_x509__parse_algid_ref(&outer_sig_algid__t, &dec__t));
  FLEA_CCALL(THR_flea_x509__process_alg_ids(&cert_ref__pt->tbs_sig_algid__t, &outer_sig_algid__t));
  FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_cft(&dec__t, FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, BIT_STRING), &cert_ref__pt->cert_signature_as_bit_string__t));    
  FLEA_THR_FIN_SEC(
      flea_data_source_t__dtor(&source__t); 
      flea_data_source_t__dtor(&source_tbs__t); 
      flea_ber_dec_t__dtor(&dec__t);
      flea_ber_dec_t__dtor(&dec_tbs__t);
      );
}

flea_bool_t flea_x509_has_key_usages(flea_x509_cert_ref_t *cert_ref__pt, flea_u16_t check_usages__u16)
{
  flea_u16_t ku_val__u16 = cert_ref__pt->extensions__t.key_usage__t.purposes__u16;
  if(!cert_ref__pt->extensions__t.key_usage__t.is_present__u8)
  {
    return FLEA_FALSE;
  }
  if((ku_val__u16 & check_usages__u16) == check_usages__u16)
  {
    return FLEA_TRUE; 
  }
  return FLEA_FALSE;
}

