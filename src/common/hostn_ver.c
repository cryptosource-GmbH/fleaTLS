/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "flea/hostn_ver.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "internal/common/ber_dec.h"
#include "flea/alloc.h"
#include "flea/util.h"
#include "flea/x509.h"


static flea_bool_t is_ascii_string(const flea_u8_t *s__pcu8, flea_al_u16_t s_len__sz)
{
  flea_al_u16_t i;

  for(i = 0; i < s_len__sz; i++)
  {
    if((s__pcu8[i] & 0x80) || s__pcu8[i] == 0)
    {
      return FLEA_FALSE;
    }
  }
  return FLEA_TRUE;
}

/**
 * s_len__sz is assumed to be greater than 0
 *
 * returns 0 if not found
 */
static flea_al_u16_t offs_of_second_label(const flea_u8_t *s__pcu8, flea_al_u16_t s_len__sz)
{
  flea_al_u16_t i;

  /* look for first '.' */
  for(i = 0; i < (s_len__sz - 1); i++)
  {
    if(s__pcu8[i] == '.')
    {
      return i;
    }
  }
  return 0;
}

static flea_u8_t to_lower_case(flea_u8_t byte)
{
  if((byte >= 65) && (byte <= 90))
  {
    byte += 32;
  }
  return byte;
}

static flea_bool_t are_strings_equal_case_insensitive(const flea_u8_t *s1__pcu8, const flea_u8_t *s2__pcu8, flea_al_u16_t s12_len__alu8)
{
  flea_al_u16_t i;

  for(i = 0; i < s12_len__alu8; i++)
  {
    if(to_lower_case(s1__pcu8[i]) != to_lower_case(s2__pcu8[i]))
    {
      return FLEA_FALSE;
    }
  }
  return FLEA_TRUE;
}

static flea_err_t THR_flea_x509__verify_host_name(const flea_ref_cu8_t *user_host_name__pcrcu8, const flea_ref_cu8_t *cert_dns_name__pcrcu8, flea_bool_t allow_wildcard__b, flea_bool_t *result__pb)
{
  *result__pb = FLEA_FALSE;
  flea_al_u16_t cert_cmp_len__alu16, user_cmp_len__alu16;
  flea_al_u16_t second_label_offset_user = 0;
  flea_al_u16_t second_label_offset_cert = 0;
  FLEA_THR_BEG_FUNC();

  if((user_host_name__pcrcu8->len__dtl > 0xFFFF) || !user_host_name__pcrcu8->len__dtl || !is_ascii_string(user_host_name__pcrcu8->data__pcu8, user_host_name__pcrcu8->len__dtl))
  {
    FLEA_THROW("invalid user hostname of size 0", FLEA_ERR_X509_INVALID_USER_HOSTN);
  }
  if((cert_dns_name__pcrcu8->len__dtl == 0) || cert_dns_name__pcrcu8->len__dtl > FLEA_X509_NAME_COMPONENT_MAX_BYTE_LEN)
  {
    FLEA_THR_RETURN();
  }
  user_cmp_len__alu16 = user_host_name__pcrcu8->len__dtl;
  cert_cmp_len__alu16 = cert_dns_name__pcrcu8->len__dtl;
  if((cert_dns_name__pcrcu8->len__dtl >= 3) && (cert_dns_name__pcrcu8->data__pcu8[0] == '*') && allow_wildcard__b)
  {
    second_label_offset_cert = offs_of_second_label(cert_dns_name__pcrcu8->data__pcu8, cert_dns_name__pcrcu8->len__dtl);
    second_label_offset_user = offs_of_second_label((const flea_u8_t *) user_host_name__pcrcu8->data__pcu8, user_host_name__pcrcu8->len__dtl);
    if((second_label_offset_cert != 1) || (second_label_offset_user == 0))
    {
      FLEA_THR_RETURN();
    }
    user_cmp_len__alu16 = user_cmp_len__alu16 - second_label_offset_user;
    cert_cmp_len__alu16 = cert_cmp_len__alu16 - second_label_offset_cert;
  }
  if(user_cmp_len__alu16 != cert_cmp_len__alu16)
  {
    FLEA_THR_RETURN();
  }
  if(are_strings_equal_case_insensitive((const flea_u8_t *) user_host_name__pcrcu8->data__pcu8 + second_label_offset_user, cert_dns_name__pcrcu8->data__pcu8 + second_label_offset_cert, user_cmp_len__alu16))
  {
    *result__pb = FLEA_TRUE;
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_x509__verify_host_name */

flea_err_t THR_flea_x509__verify_tls_server_id_cstr(const char *user_id__cs, flea_host_id_type_e host_type, const flea_x509_cert_ref_t *server_cert__pt)
{
  flea_ref_cu8_t user_id__rcu8;

  user_id__rcu8.data__pcu8 = (const flea_u8_t *) user_id__cs;
  user_id__rcu8.len__dtl   = strlen(user_id__cs);
  return THR_flea_x509__verify_tls_server_id(&user_id__rcu8, host_type, server_cert__pt);
}

flea_err_t THR_flea_x509__verify_tls_server_id(const flea_ref_cu8_t *user_id__pcrcu8, flea_host_id_type_e host_type, const flea_x509_cert_ref_t *server_cert__pt)
{
  FLEA_DECL_OBJ(cont_dec__t, flea_ber_dec_t);
  FLEA_DECL_OBJ(source__t, flea_data_source_t);

  const flea_x509_dn_ref_t *cert_subject_dn__pcrcu8 = &server_cert__pt->subject__t;
  flea_bool_t contains_dnsname__b = FLEA_FALSE;
  flea_bool_t contains_ipaddr__b  = FLEA_FALSE;
  flea_data_source_mem_help_t hlp__t;
  FLEA_THR_BEG_FUNC();

  if(server_cert__pt->extensions__t.san__t.is_present__u8)
  {
    const flea_ref_cu8_t *general_names_raw__pcrcu8 = &server_cert__pt->extensions__t.san__t.san_raw__t;
    FLEA_CCALL(THR_flea_data_source_t__ctor_memory(&source__t, general_names_raw__pcrcu8->data__pcu8, general_names_raw__pcrcu8->len__dtl, &hlp__t));
    FLEA_CCALL(THR_flea_ber_dec_t__ctor(&cont_dec__t, &source__t, 0));
    FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&cont_dec__t));

    while(flea_ber_dec_t__has_current_more_data(&cont_dec__t))
    {
      flea_ref_cu8_t dummy_ref__t;
      flea_bool_t found__b, found_any__b = FLEA_FALSE;
      flea_ref_cu8_t dec_name__rcu8;

      /*GeneralName ::= CHOICE {
       * otherName                 [0]  AnotherName,*/
      FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(&cont_dec__t, (flea_asn1_tag_t) FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONTEXT_SPECIFIC, 0), &dummy_ref__t, &found__b));
      found_any__b |= found__b;
      /*rfc822Name                [1]  IA5String, */
      FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(&cont_dec__t, (flea_asn1_tag_t) FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONTEXT_SPECIFIC, 1), &dummy_ref__t, &found__b));
      found_any__b |= found__b;
      /*dNSName                   [2]  IA5String,         supported */
      FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(&cont_dec__t, (flea_asn1_tag_t) FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONTEXT_SPECIFIC, 2), &dec_name__rcu8, &found__b));
      if(found__b && (host_type == flea_host_dnsname))
      {
        flea_bool_t names_match__b;
        FLEA_CCALL(THR_flea_x509__verify_host_name(user_id__pcrcu8, &dec_name__rcu8, FLEA_TRUE, &names_match__b));
        if(names_match__b)
        {
          FLEA_THR_RETURN();
        }
      }
      contains_dnsname__b |= found__b;
      found_any__b        |= found__b;
      /*    x400Address               [3]  ORAddress, */
      FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(&cont_dec__t, (flea_asn1_tag_t) FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONTEXT_SPECIFIC, 3), &dummy_ref__t, &found__b));
      found_any__b |= found__b;
      /* directoryName             [4]  Name,              binary only*/
      FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_implicit_universal_optional(&cont_dec__t, 4, /*dummy*/ 0, &dummy_ref__t));
      found_any__b |= found__b;
      /*ediPartyName              [5]  EDIPartyName,*/
      FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(&cont_dec__t, (flea_asn1_tag_t) FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONTEXT_SPECIFIC, 5), &dummy_ref__t, &found__b));
      found_any__b |= found__b;
      /*uniformResourceIdentifier [6]  IA5String,         binary only */
      FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(&cont_dec__t, (flea_asn1_tag_t) FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONTEXT_SPECIFIC, 6), &dec_name__rcu8, &found__b));
      /* URI not yet supported by flea */
      found_any__b |= found__b;
      /* iPAddress                 [7]  OCTET STRING,      supported */
      FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(&cont_dec__t, (flea_asn1_tag_t) FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONTEXT_SPECIFIC, 7), &dec_name__rcu8, &found__b));
      if(found__b && (host_type == flea_host_ipaddr))
      {
        if((dec_name__rcu8.len__dtl != 4) && (dec_name__rcu8.len__dtl != 16))
        {
          FLEA_THROW("invalid ip address format", FLEA_ERR_X509_SAN_DEC_ERR);
        }
        if(!flea_rcu8_cmp(&dec_name__rcu8, user_id__pcrcu8))
        {
          FLEA_THR_RETURN();
        }
      }
      contains_ipaddr__b |= found__b;
      found_any__b       |= found__b;
      /* registeredID              [8]  OBJECT IDENTIFIER  supported */
      FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(&cont_dec__t, (flea_asn1_tag_t) FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONTEXT_SPECIFIC, 7), &dummy_ref__t, &found__b));
      found_any__b |= found__b;
      /*}*/
      if(!found_any__b)
      {
        FLEA_THROW("invalid element in SAN", FLEA_ERR_X509_SAN_DEC_ERR);
      }
    }
  }
  if(!contains_ipaddr__b && !contains_dnsname__b && (host_type == flea_host_dnsname))
  {
    /* as specified in RFC 6125, only use CN if no appropirate SAN elements were
     * found */
    flea_bool_t names_match__b;
    FLEA_CCALL(THR_flea_x509__verify_host_name(user_id__pcrcu8, &cert_subject_dn__pcrcu8->common_name__t, FLEA_TRUE, &names_match__b));
    if(names_match__b)
    {
      FLEA_THR_RETURN();
    }
  }
  FLEA_THROW("TLS server id does not match server certificate", FLEA_ERR_X509_TLS_SERVER_ID_NO_MATCH);
  FLEA_THR_FIN_SEC(
    flea_ber_dec_t__dtor(&cont_dec__t);
    flea_data_source_t__dtor(&source__t);
  );
} /* THR_flea_x509__verify_tls_server_id */
