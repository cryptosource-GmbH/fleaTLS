/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/hostn_ver.h"
#include "internal/common/hostn_ver_int.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "internal/common/ber_dec.h"
#include "flea/alloc.h"
#include "flea/util.h"
#include "flea/x509.h"
#include "flea/mem_read_stream.h"


static flea_bool_e is_ascii_string(
  const flea_u8_t* s__pcu8,
  flea_al_u16_t    s_len__sz
)
{
  flea_al_u16_t i;

  for(i = 0; i < s_len__sz; i++)
  {
    if((s__pcu8[i] & 0x80) || s__pcu8[i] == 0)
    {
      return flea_false;
    }
  }
  return flea_true;
}

/**
 * s_len__sz is assumed to be greater than 0
 *
 * returns 0 if not found
 */
static flea_al_u16_t offs_of_second_label(
  const flea_u8_t* s__pcu8,
  flea_al_u16_t    s_len__sz
)
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

static flea_bool_e are_strings_equal_case_insensitive(
  const flea_u8_t* s1__pcu8,
  const flea_u8_t* s2__pcu8,
  flea_al_u16_t    s12_len__alu8
)
{
  flea_al_u16_t i;

  for(i = 0; i < s12_len__alu8; i++)
  {
    if(to_lower_case(s1__pcu8[i]) != to_lower_case(s2__pcu8[i]))
    {
      return flea_false;
    }
  }
  return flea_true;
}

flea_err_e THR_flea_x509__verify_host_name(
  const flea_ref_cu8_t*  user_host_name__pcrcu8,
  const flea_byte_vec_t* cert_dns_name__pcrcu8,
  flea_bool_e            allow_wildcard__b,
  flea_bool_e*           result__pb
)
{
  *result__pb = flea_false;
  flea_al_u16_t cert_cmp_len__alu16, user_cmp_len__alu16;
  flea_al_u16_t second_label_offset_user = 0;
  flea_al_u16_t second_label_offset_cert = 0;
  FLEA_THR_BEG_FUNC();

  if(
#ifdef FLEA_HAVE_DTL_32BIT
    (user_host_name__pcrcu8->len__dtl > 0xFFFF) ||
#endif
    !user_host_name__pcrcu8->len__dtl ||
    !is_ascii_string(user_host_name__pcrcu8->data__pcu8, user_host_name__pcrcu8->len__dtl))
  {
    FLEA_THROW("invalid user hostname of size 0", FLEA_ERR_X509_INVALID_USER_HOSTN);
  }
  if((cert_dns_name__pcrcu8->len__dtl == 0) || cert_dns_name__pcrcu8->len__dtl > FLEA_X509_NAME_COMPONENT_MAX_BYTE_LEN)
  {
    FLEA_THR_RETURN();
  }
  user_cmp_len__alu16 = user_host_name__pcrcu8->len__dtl;
  cert_cmp_len__alu16 = cert_dns_name__pcrcu8->len__dtl;
  if((cert_dns_name__pcrcu8->len__dtl >= 3) && (cert_dns_name__pcrcu8->data__pu8[0] == '*') && allow_wildcard__b)
  {
    second_label_offset_cert = offs_of_second_label(cert_dns_name__pcrcu8->data__pu8, cert_dns_name__pcrcu8->len__dtl);
    second_label_offset_user = offs_of_second_label(
      (const flea_u8_t*) user_host_name__pcrcu8->data__pcu8,
      user_host_name__pcrcu8->len__dtl
      );
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
  if(are_strings_equal_case_insensitive(
      (const flea_u8_t*) user_host_name__pcrcu8->data__pcu8
      + second_label_offset_user,
      cert_dns_name__pcrcu8->data__pu8 + second_label_offset_cert,
      user_cmp_len__alu16
    ))
  {
    *result__pb = flea_true;
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_x509__verify_host_name */

flea_err_e THR_flea_x509__verify_tls_server_id_cstr(
  const char*                 user_id__cs,
  flea_host_id_type_e         host_type,
  const flea_x509_cert_ref_t* server_cert__pt
)
{
  flea_byte_vec_t user_id__rcu8;

  user_id__rcu8.data__pu8 = (flea_u8_t*) user_id__cs;
  user_id__rcu8.len__dtl  = strlen(user_id__cs);
  return THR_flea_x509__verify_tls_server_id(&user_id__rcu8, host_type, server_cert__pt);
}

flea_err_e THR_flea_x509__verify_tls_server_id(
  const flea_byte_vec_t*      user_id_vec__pt,
  flea_host_id_type_e         host_type,
  const flea_x509_cert_ref_t* server_cert__pt
)
{
  FLEA_DECL_OBJ(cont_dec__t, flea_ber_dec_t);
  FLEA_DECL_OBJ(source__t, flea_rw_stream_t);
  const flea_x509_dn_ref_t* cert_subject_dn__pcrcu8 = &server_cert__pt->subject__t;
  const flea_ref_cu8_t user_id__crcu8 = {.data__pcu8 = user_id_vec__pt->data__pu8, .len__dtl = user_id_vec__pt->len__dtl};
  flea_mem_read_stream_help_t hlp__t;

  flea_hostn_match_info_t match_info__t;
  match_info__t.contains_dnsname__b = flea_false;
  match_info__t.contains_ipaddr__b  = flea_false;
  match_info__t.id_matched__b       = flea_false;

  flea_byte_vec_t work_spc__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE;

  FLEA_THR_BEG_FUNC();

  if(server_cert__pt->extensions__t.san__t.is_present__u8)
  {
    const flea_byte_vec_t* general_names_raw__pcrcu8 = &server_cert__pt->extensions__t.san__t.san_raw__t;
    FLEA_CCALL(
      THR_flea_rw_stream_t__ctor_memory(
        &source__t,
        general_names_raw__pcrcu8->data__pu8,
        general_names_raw__pcrcu8->len__dtl,
        &hlp__t
      )
    );

    FLEA_CCALL(THR_flea_ber_dec_t__ctor(&cont_dec__t, &source__t, 0, flea_decode_ref));
    FLEA_CCALL(
      THR_flea_x509__parse_san_and_validate_hostn(
        &user_id__crcu8,
        host_type,
        &cont_dec__t,
        &work_spc__t,
        &match_info__t
      )
    );

    if(match_info__t.id_matched__b == flea_true)
    {
      FLEA_THR_RETURN();
    }
  }
  if((!match_info__t.contains_dnsname__b && (host_type == flea_host_dnsname)))
  {
    /* as specified in RFC 6125, only use CN if no appropirate SAN elements were
     * found */
    flea_bool_e names_match__b;
    FLEA_CCALL(
      THR_flea_x509__verify_host_name(
        &user_id__crcu8,
        &cert_subject_dn__pcrcu8->common_name__t,
        flea_true,
        &names_match__b
      )
    );
    if(names_match__b)
    {
      FLEA_THR_RETURN();
    }
  }
  FLEA_THROW("TLS server id does not match server certificate", FLEA_ERR_X509_TLS_SERVER_ID_NO_MATCH);
  FLEA_THR_FIN_SEC(
    flea_ber_dec_t__dtor(&cont_dec__t);
    flea_byte_vec_t__dtor(&work_spc__t);
    flea_rw_stream_t__dtor(&source__t);
  );
} /* THR_flea_x509__verify_tls_server_id */

flea_err_e THR_flea_x509__parse_san_and_validate_hostn(
  const flea_ref_cu8_t*    user_id__pcrcu8,
  flea_host_id_type_e      host_type,
  flea_ber_dec_t*          cont_dec__pt,
  flea_byte_vec_t*         work_spc__pt,
  flea_hostn_match_info_t* match_info__pt
)
{
  FLEA_THR_BEG_FUNC();
  match_info__pt->id_matched__b       = flea_false;
  match_info__pt->contains_ipaddr__b  = flea_false;
  match_info__pt->contains_dnsname__b = flea_false;
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(cont_dec__pt));

  while(flea_ber_dec_t__has_current_more_data(cont_dec__pt))
  {
    flea_bool_e found__b, found_any__b = flea_false;

    /*GeneralName ::= CHOICE {
     * otherName                 [0]  AnotherName,*/
    FLEA_CCALL(
      THR_flea_ber_dec_t__decode_value_raw_cft_optional(
        cont_dec__pt,
        (flea_asn1_tag_t) FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONTEXT_SPECIFIC, 0),
        work_spc__pt,
        &found__b
      )
    );
    found_any__b |= found__b;
    /*rfc822Name                [1]  IA5String, */
    FLEA_CCALL(
      THR_flea_ber_dec_t__decode_value_raw_cft_optional(
        cont_dec__pt,
        (flea_asn1_tag_t) FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONTEXT_SPECIFIC, 1),
        work_spc__pt,
        &found__b
      )
    );
    found_any__b |= found__b;
    /*dNSName                   [2]  IA5String,         supported */
    FLEA_CCALL(
      THR_flea_ber_dec_t__decode_value_raw_cft_optional(
        cont_dec__pt,
        (flea_asn1_tag_t) FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONTEXT_SPECIFIC, 2),
        work_spc__pt,
        &found__b
      )
    );
    if(found__b && (host_type == flea_host_dnsname))
    {
      flea_bool_e names_match__b;
      FLEA_CCALL(THR_flea_x509__verify_host_name(user_id__pcrcu8, work_spc__pt, flea_true, &names_match__b));
      if(names_match__b)
      {
        match_info__pt->id_matched__b = flea_true;
        break;
      }
    }
    match_info__pt->contains_dnsname__b |= found__b;
    found_any__b |= found__b;
    /*    x400Address               [3]  ORAddress, */
    FLEA_CCALL(
      THR_flea_ber_dec_t__decode_value_raw_cft_optional(
        cont_dec__pt,
        (flea_asn1_tag_t) FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONTEXT_SPECIFIC, 3),
        work_spc__pt,
        &found__b
      )
    );
    found_any__b |= found__b;
    /* directoryName             [4]  Name,              binary only*/
    FLEA_CCALL(
      THR_flea_ber_dec_t__decode_implicit_universal_optional(
        cont_dec__pt,
        4, /*dummy*/
        0,
        work_spc__pt
      )
    );
    found_any__b |= found__b;
    /*ediPartyName              [5]  EDIPartyName,*/
    FLEA_CCALL(
      THR_flea_ber_dec_t__decode_value_raw_cft_optional(
        cont_dec__pt,
        (flea_asn1_tag_t) FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONTEXT_SPECIFIC, 5),
        work_spc__pt,
        &found__b
      )
    );
    found_any__b |= found__b;
    /*uniformResourceIdentifier [6]  IA5String,         binary only */
    FLEA_CCALL(
      THR_flea_ber_dec_t__decode_value_raw_cft_optional(
        cont_dec__pt,
        (flea_asn1_tag_t) FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONTEXT_SPECIFIC, 6),
        work_spc__pt,
        &found__b
      )
    );
    /* URI not yet supported by flea */
    found_any__b |= found__b;
    /* iPAddress                 [7]  OCTET STRING,      supported */
    FLEA_CCALL(
      THR_flea_ber_dec_t__decode_value_raw_cft_optional(
        cont_dec__pt,
        (flea_asn1_tag_t) FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONTEXT_SPECIFIC, 7),
        work_spc__pt,
        &found__b
      )
    );
    if(found__b && (host_type == flea_host_ipaddr))
    {
      if((work_spc__pt->len__dtl != 4) && (work_spc__pt->len__dtl != 16))
      {
        FLEA_THROW("invalid ip address format", FLEA_ERR_X509_SAN_DEC_ERR);
      }
      if(!flea_byte_vec_t__cmp_with_cref(work_spc__pt, user_id__pcrcu8))
      {
        match_info__pt->id_matched__b = flea_true;
        break;
      }
    }
    match_info__pt->contains_ipaddr__b |= found__b;
    found_any__b |= found__b;
    /* registeredID              [8]  OBJECT IDENTIFIER  supported */
    FLEA_CCALL(
      THR_flea_ber_dec_t__decode_value_raw_cft_optional(
        cont_dec__pt,
        (flea_asn1_tag_t) FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONTEXT_SPECIFIC, 7),
        work_spc__pt,
        &found__b
      )
    );
    found_any__b |= found__b;
    if(!found_any__b)
    {
      FLEA_THROW("invalid element in SAN", FLEA_ERR_X509_SAN_DEC_ERR);
    }
  } /* while(flea_ber_dec_t__has_current_more_data(cont_dec__pt)) */
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_skip_remaining(cont_dec__pt));

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_x509__verify_tls_server_id */
