/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/alloc.h"
#include "flea/cert_verify.h"
#include "flea/byte_vec.h"
#include "flea/error_handling.h"
#include "internal/common/ber_dec.h"
#include "flea/x509.h"
#include "internal/common/x509_int.h"
#include "flea/x509_key.h"
#include "flea/pk_api.h"
#include "flea/asn1_date.h"
#include "flea/tls.h"
#include "internal/common/namespace_asn1.h"
#include "flea/rw_stream.h"
#include "flea/cert_store.h"
#include "internal/common/cert_path_int.h"
#include "internal/common/tls/handsh_reader.h"
#include "internal/common/lib_int.h"
#include "internal/common/tls/tls_cert_path.h"
#include "flea/hostn_ver.h"
#include "internal/common/hostn_ver_int.h"
#include "flea/crl.h"
#include "flea/mem_read_stream.h"
#include "internal/common/tls/tls_int.h"

#ifdef FLEA_HAVE_TLS

# define FLEA_TLS_CERT_PATH_MAX_LEN 20

/**
 * Used in stack mode for back-buffering during certificate processing until the signature hash algorithm is
 * known. This size must be sufficient for a buffer to hold all data of an
 * X.509 certificate up to and including the first SignatureAlgorithm.
 */
# define FLEA_X509_CERT_PRE_SIGALGID_BUFFER_SIZE 70


typedef struct
{
  flea_hostn_match_info_t match_info__t;
  flea_host_id_type_e     host_type_id__e;
  const flea_ref_cu8_t*   user_id__pct;
} hostn_validation_info_t;

static flea_err_e THR_flea_tls_check_cert_validity_time(
  flea_ber_dec_t*        dec__pt,
  const flea_gmt_time_t* compare_time__pt
)
{
  flea_gmt_time_t not_after__t;
  flea_gmt_time_t not_before__t;

  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(dec__pt));


  FLEA_CCALL(THR_flea_asn1_parse_gmt_time(dec__pt, &not_before__t));
  FLEA_CCALL(THR_flea_asn1_parse_gmt_time(dec__pt, &not_after__t));

  if(1 == flea_asn1_cmp_utc_time(&not_before__t, compare_time__pt))
  {
    FLEA_THROW("certificate not yet valid", FLEA_ERR_X509_CERT_NOT_YET_VALID);
  }
  if(-1 == flea_asn1_cmp_utc_time(&not_after__t, compare_time__pt))
  {
    FLEA_THROW("certificate expired", FLEA_ERR_X509_CERT_EXPIRED);
  }
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(dec__pt));
  FLEA_THR_FIN_SEC_empty();
}

static flea_err_e THR_flea_tls_cert_path__parse_san_and_validate_hostname(
  const flea_ref_cu8_t*    user_id__pt,
  flea_host_id_type_e      host_id_type,
  flea_ber_dec_t*          cont_dec__pt,
  flea_hostn_match_info_t* result_match_info__pt
)
{
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(work_spc__t, FLEA_STKMD_X509_SAN_ELEMENT_MAX_LEN);

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_x509__parse_san_and_validate_hostn(
      user_id__pt,
      host_id_type,
      cont_dec__pt,
      &work_spc__t,
      result_match_info__pt
    )
  );


  FLEA_THR_FIN_SEC(
    flea_byte_vec_t__dtor(&work_spc__t);
  );
}

static flea_err_e THR_flea_tls_cert_validation__parse_extensions(
  flea_ber_dec_t*           dec__pt,
  flea_key_usage_t*         key_usage__pt,
  flea_key_usage_t*         extd_key_usage__pt,
  flea_basic_constraints_t* basic_constr__pt,
  hostn_validation_info_t*  hostn_valid_info_mbn__pt,
  flea_byte_vec_t*          crl_dp_raw__pt,
  flea_bool_e*              have_extensions__pb
)
{
  flea_bool_e false__b = FLEA_FALSE;

  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(ext_oid__t, 30);
  flea_bool_e critical__b;

  FLEA_THR_BEG_FUNC();
  /* open implicit */
  FLEA_CCALL(
    THR_flea_ber_dec_t__open_constructed_optional(
      dec__pt,
      3,
      FLEA_ASN1_CONSTRUCTED | FLEA_ASN1_CONTEXT_SPECIFIC,
      have_extensions__pb
    )
  );
  if(!*have_extensions__pb)
  {
    FLEA_THR_RETURN();
  }
  /* open extensions */
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(dec__pt));
  while(flea_ber_dec_t__has_current_more_data(dec__pt))
  {
    flea_al_u8_t ext_indic_pos__alu8;
    flea_al_u16_t oid_indicator__alu16 = 0;
    /* open this extension */
    FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(dec__pt));
    FLEA_CCALL(
      THR_flea_ber_dec_t__decode_value_raw_cft(
        dec__pt,
        FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, OID),
        &ext_oid__t
      )
    );
    FLEA_CCALL(THR_flea_ber_dec_t__decode_boolean_default_false(dec__pt, &critical__b));

    /* decode the extension value in the octet string */
    FLEA_CCALL(
      THR_flea_ber_dec_t__open_constructed(
        dec__pt,
        FLEA_ASN1_OCTET_STRING,
        FLEA_ASN1_UNIVERSAL_PRIMITIVE
      )
    );


    /* open 'octet string' sequence */
    if(ext_oid__t.len__dtl == 3 && ext_oid__t.data__pu8[0] == 0x55 && ext_oid__t.data__pu8[1] == 0x1D)
    {
      oid_indicator__alu16  = ID_CE_INDIC;
      ext_indic_pos__alu8   = 2;
      oid_indicator__alu16 |= ext_oid__t.data__pu8[ext_indic_pos__alu8];
    }
    else if((ext_oid__t.len__dtl == sizeof(id_pe__cau8) + 1) &&
      (!memcmp(ext_oid__t.data__pu8, id_pe__cau8, sizeof(id_pe__cau8))))
    {
      oid_indicator__alu16  = ID_PE_INDIC;
      ext_indic_pos__alu8   = sizeof(id_pe__cau8);
      oid_indicator__alu16 |= ext_oid__t.data__pu8[ext_indic_pos__alu8];
    }
    else
    {
      if(critical__b)
      {
        FLEA_THROW("unsupported critical extension", FLEA_ERR_X509_ERR_UNSUP_CRIT_EXT);
      }
      oid_indicator__alu16 = ID_UNSUPP_EXT_OID;
    }
    /* standard extension */
    switch(oid_indicator__alu16)
    {
        // flea_bool_e found__b;
        case ID_CE_OID_AKI:
        {
          /* authority key identifier */
          break;
        }
        case ID_CE_OID_KEY_USAGE:
        {
          FLEA_CCALL(THR_flea_x509_cert__parse_key_usage(dec__pt, key_usage__pt));
          break;
        }
        case ID_CE_OID_SUBJ_KEY_ID:
        {
          break;
        }
        case ID_CE_OID_SUBJ_ALT_NAME:
        {
          if(hostn_valid_info_mbn__pt && (hostn_valid_info_mbn__pt->user_id__pct->data__pcu8 != NULL))
          {
            FLEA_CCALL(
              THR_flea_tls_cert_path__parse_san_and_validate_hostname(
                hostn_valid_info_mbn__pt->user_id__pct,
                hostn_valid_info_mbn__pt->host_type_id__e,
                dec__pt,
                &hostn_valid_info_mbn__pt->match_info__t
              )
            );
          }
          break;
        }

        case ID_CE_OID_ISS_ALT_NAME:
        {
          /* nothing to do, flea does not process it */
          break;
        }
        case ID_CE_OID_POLICIES:
        {
          // nothing to do, flea does not process it
          break;
        }
        case ID_CE_OID_BASIC_CONSTR:
        {
          FLEA_CCALL(THR_flea_x509_cert_parse_basic_constraints(dec__pt, basic_constr__pt));
          break;
        }
        case ID_CE_OID_EXT_KEY_USAGE:
        {
          FLEA_CCALL(THR_flea_x509_cert__parse_eku(dec__pt, extd_key_usage__pt));
          break;
        }
        case ID_CE_OID_CRL_DISTR_POINT:
        {
          FLEA_CCALL(
            THR_flea_ber_dec_t__decode_tlv_raw_optional(
              dec__pt,
              crl_dp_raw__pt,
              &false__b
            )
          );
          break;
        }
        default:
          if(critical__b)
          {
            FLEA_THROW("unsupported critical extension", FLEA_ERR_X509_ERR_UNSUP_CRIT_EXT);
          }
    }
    /* close conceptual constructed of extension octet string */
    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_skip_remaining(dec__pt));
    /* close the extension */
    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(dec__pt));
  }
  /* close extensions */
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(dec__pt));
  /* close implicit */
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(dec__pt));
  FLEA_THR_FIN_SEC(
    flea_byte_vec_t__dtor(&ext_oid__t);
  );
} /* THR_flea_tls_cert_validation__parse_extensions */

typedef enum { validate_server_cert, validate_client_cert, validate_ca_cert } cert_validation_type_e;

static flea_err_e THR_flea_tls__validate_cert(
  flea_tls_ctx_t*                    tls_ctx__pt,
  flea_rw_stream_t*                  rd_strm__pt,
  flea_u32_t                         new_cert_len__u32,
  flea_public_key_t*                 pubkey_out__pt,
  flea_byte_vec_t*                   signature_in_out__pt,
  flea_byte_vec_t*                   tbs_hash_in_out__pt,
  flea_hash_id_e*                    tbs_hash_id__pe,
  flea_bool_e                        have_precursor_to_verify__b,
  flea_byte_vec_t*                   issuer_dn__pt, // previous issuer on input, gets updated to validated cert's subject
  const flea_gmt_time_t*             compare_time__pt,
  flea_al_u16_t*                     cnt_non_self_issued_in_path__palu16,
  flea_tls_cert_path_params_t const* cert_path_params__pct,
  const flea_ref_cu8_t*              crl_der__cprcu8,
  flea_al_u16_t                      nb_crls__alu16,
  flea_bool_e                        validate_crl_for_issued_by_current__b,
  flea_byte_vec_t*                   prev_sn_buffer__pt,
  flea_byte_vec_t*                   previous_crldp__pt
)
{
  flea_al_u8_t version__u8;

  FLEA_DECL_OBJ(dec__t, flea_ber_dec_t);
  FLEA_DECL_OBJ(hash__t, flea_hash_ctx_t);
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(
    back_buffer__t,
    FLEA_X509_CERT_PRE_SIGALGID_BUFFER_SIZE
  );
  FLEA_DECL_byte_vec_t__CONSTR_STACK_BUF_EMPTY_NOT_ALLOCATABLE(version_vec__t, 1);

  /* for SN, subject:
   */
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(sn_buffer__t, FLEA_X509_MAX_SERIALNUMBER_LEN);
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(local_issuer__t, 200);
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(local_subject__t, 200);
# ifdef FLEA_USE_STACK_BUF
  flea_u8_t sigalg_oid__au8[10];
  flea_u8_t sigalg_params__au8[10];
  flea_u8_t outer_sigalg_oid__au8[10];
  flea_u8_t outer_sigalg_params__au8[10];
  flea_u8_t pubkey_oid__au8[10];
  flea_u8_t pubkey_params__au8[FLEA_STKMD_TLS_CERT_PATH_VLD_PUBKEY_PARAMS_BUF_SIZE];

  flea_x509_algid_ref_t sigalg_id__t         = {.oid_ref__t = flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK_BUF(sigalg_oid__au8), .params_ref_as_tlv__t = flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK_BUF(sigalg_params__au8)};
  flea_x509_algid_ref_t outer_sigalg_id__t   = {.oid_ref__t = flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK_BUF(outer_sigalg_oid__au8), .params_ref_as_tlv__t = flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK_BUF(outer_sigalg_params__au8)};
  flea_x509_algid_ref_t public_key_alg_id__t = {.oid_ref__t = flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK_BUF(pubkey_oid__au8), .params_ref_as_tlv__t = flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK_BUF(pubkey_params__au8)};
# else /* ifdef FLEA_USE_STACK_BUF */
  flea_x509_algid_ref_t sigalg_id__t         = flea_x509_algid_ref_t__CONSTR_EMPTY_ALLOCATABLE;
  flea_x509_algid_ref_t outer_sigalg_id__t   = flea_x509_algid_ref_t__CONSTR_EMPTY_ALLOCATABLE;
  flea_x509_algid_ref_t public_key_alg_id__t = flea_x509_algid_ref_t__CONSTR_EMPTY_ALLOCATABLE;
# endif /* ifdef FLEA_USE_STACK_BUF */
  flea_bool_e optional_found__b;
  flea_basic_constraints_t basic_constraints__t = {0};
  flea_key_usage_t key_usage__t      = {0};
  flea_key_usage_t extd_key_usage__t = {0};
  flea_hash_id_e sigalg_hash_id;
  flea_pk_key_type_e key_type;
  flea_bool_e optional__b;
  hostn_validation_info_t hostn_valid_info__t         = {.match_info__t = {.id_matched__b = 0, .contains_ipaddr__b = 0, .contains_dnsname__b = 0}, .host_type_id__e = 0, .user_id__pct = NULL};
  hostn_validation_info_t* hostn_valid_params_mbn__pt = &hostn_valid_info__t;
  flea_bool_e do_validate_host_name__b = (cert_path_params__pct->hostn_valid_params__pt != NULL) && (cert_path_params__pct->hostn_valid_params__pt->host_id__ct.data__pcu8 != NULL);

  const flea_al_u16_t previous_non_self_issued_cnt__calu16 = *cnt_non_self_issued_in_path__palu16;
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(
    public_key_value__t,
    __FLEA_COMPUTED_PK_MAX_ASYM_PUBKEY_X509_LEN + 1
  );
  flea_tls_client_cert_type_e cert_type__e;
  FLEA_THR_BEG_FUNC();
  if(do_validate_host_name__b)
  {
    hostn_valid_info__t.host_type_id__e = cert_path_params__pct->hostn_valid_params__pt->host_id_type__e;
    hostn_valid_info__t.user_id__pct    = &cert_path_params__pct->hostn_valid_params__pt->host_id__ct;
  }
  else
  {
    hostn_valid_params_mbn__pt = NULL;
  }
  flea_public_key_t__dtor(pubkey_out__pt);
  FLEA_CCALL(
    THR_flea_ber_dec_t__ctor_hash_support(
      &dec__t,
      rd_strm__pt,
      new_cert_len__u32,
      flea_decode_copy,
      &back_buffer__t,
      &hash__t
    )
  );

  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
  flea_ber_dec_t__activate_hashing(&dec__t);
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
  FLEA_CCALL(
    THR_flea_ber_dec_t__open_constructed_optional(
      &dec__t,
      0,
      FLEA_ASN1_CONSTRUCTED | FLEA_ASN1_CONTEXT_SPECIFIC,
      &optional_found__b
    )
  );
  if(optional_found__b)
  {
    FLEA_CCALL(THR_flea_ber_dec_t__read_value_raw(&dec__t, FLEA_ASN1_INT, 0, &version_vec__t));
    if(version_vec__t.len__dtl != 1)
    {
      FLEA_THROW("x.509 version of invalid length", FLEA_ERR_X509_VERSION_ERROR);
    }
    version__u8 = version_vec__t.data__pu8[0] + 1;
    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
  }
  else
  {
    version__u8 = 1;
  }
  if(version__u8 > 3)
  {
    FLEA_THROW("x.509 version invalid", FLEA_ERR_X509_VERSION_ERROR);
  }

  FLEA_CCALL(THR_flea_ber_dec_t__decode_int(&dec__t, &sn_buffer__t));

  FLEA_CCALL(THR_flea_x509__decode_algid_ref(&sigalg_id__t, &dec__t));
  FLEA_CCALL(
    THR_flea_x509_get_hash_id_and_key_type_from_oid(
      sigalg_id__t.oid_ref__t.data__pu8,
      sigalg_id__t.oid_ref__t.len__dtl,
      &sigalg_hash_id,
      &key_type
    )
  );
  FLEA_CCALL(THR_flea_ber_dec_t__set_hash_id(&dec__t, sigalg_hash_id));
  optional__b = FLEA_FALSE;
  FLEA_CCALL(
    THR_flea_ber_dec_t__decode_tlv_raw_optional(
      &dec__t,
      &local_issuer__t,
      &optional__b
    )
  );

  FLEA_CCALL(THR_flea_tls_check_cert_validity_time(&dec__t, compare_time__pt));
  optional__b = FLEA_FALSE;
  FLEA_CCALL(
    THR_flea_ber_dec_t__decode_tlv_raw_optional(
      &dec__t,
      &local_subject__t,
      &optional__b
    )
  );
  if(have_precursor_to_verify__b && flea_byte_vec_t__cmp(issuer_dn__pt, &local_subject__t))
  {
    FLEA_THROW("name chaining failed", FLEA_ERR_X509_DN_ERROR);
  }
  if(flea_byte_vec_t__cmp(&local_issuer__t, &local_subject__t))
  {
    (*cnt_non_self_issued_in_path__palu16)++;
  }
  /* enter subject public key info */
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
  FLEA_CCALL(THR_flea_x509__decode_algid_ref(&public_key_alg_id__t, &dec__t));

  optional_found__b = FLEA_FALSE;
  FLEA_CCALL(
    THR_flea_ber_dec_t__decode_tlv_raw_optional(
      &dec__t,
      &public_key_value__t,
      &optional_found__b
    )
  );

  FLEA_CCALL(
    THR_flea_public_key_t__ctor_asn1(
      pubkey_out__pt,
      &public_key_value__t,
      &public_key_alg_id__t.params_ref_as_tlv__t,
      &public_key_alg_id__t.oid_ref__t
    )
  );
  flea_byte_vec_t__dtor(&public_key_value__t);
  if(have_precursor_to_verify__b)
  {
    flea_pk_scheme_id_e scheme_id;
    flea_bool_e sig_alg_allowed__b = FLEA_FALSE;
    flea_dtl_t i;
    if(pubkey_out__pt->key_type__t == flea_rsa_key)
    {
      scheme_id = flea_rsa_pkcs1_v1_5_sign;
    }
    else
    {
      scheme_id = flea_ecdsa_emsa1;
    }

    // only for tls client (for server the sig_algs member is null):
    if(cert_path_params__pct->allowed_sig_algs_mbn__pe)
    {
      for(i = 0; i < cert_path_params__pct->nb_allowed_sig_algs__alu16; i += 1)
      {
        if(((cert_path_params__pct->allowed_sig_algs_mbn__pe[i] >> 8) == *tbs_hash_id__pe) &&
          ((cert_path_params__pct->allowed_sig_algs_mbn__pe[i] & 0xFF) == scheme_id))
        {
          sig_alg_allowed__b = FLEA_TRUE;
          break;
        }
      }

      if(!sig_alg_allowed__b)
      {
        FLEA_THROW("signature algorithm not allowed", FLEA_ERR_TLS_CERT_VER_FAILED);
      }
    }

# ifdef FLEA_HAVE_SHA1
    /* MD5 is generally not supported in flea certificate verification */
    if(!(tls_ctx__pt->cfg_flags__e & flea_tls_flag__sha1_cert_sigalg__allow) && (*tbs_hash_id__pe == flea_sha1))
    {
      FLEA_THROW("SHA1 not supported", FLEA_ERR_X509_UNRECOG_HASH_FUNCTION);
    }
# endif /* ifdef FLEA_HAVE_SHA1 */
    FLEA_CCALL(
      THR_flea_public_key_t__verify_digest_plain_format(
        pubkey_out__pt,
        scheme_id,
        *tbs_hash_id__pe,
        tbs_hash_in_out__pt->data__pu8,
        tbs_hash_in_out__pt->len__dtl,
        signature_in_out__pt->data__pu8,
        signature_in_out__pt->len__dtl
      )
    );

    if(validate_crl_for_issued_by_current__b)
    {
      FLEA_CCALL(
        THR_flea_crl__check_revocation_status(
          crl_der__cprcu8,
          nb_crls__alu16,
          compare_time__pt,
          have_precursor_to_verify__b,
          &local_subject__t,
          prev_sn_buffer__pt,
          previous_crldp__pt,
          pubkey_out__pt,
          tls_ctx__pt->cfg_flags__e & flea_tls_flag__sha1_cert_sigalg__allow ? flea_x509_validation_allow_sha1 : flea_x509_validation_empty_flags
        )
      );
    }
  }

  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));

  // issuer unique ID
  FLEA_CCALL(
    THR_flea_ber_dec_t__decode_implicit_universal_optional_with_inner(
      &dec__t,
      1,
      FLEA_ASN1_BIT_STRING,
      NULL
    )
  );
  // subject unique ID
  FLEA_CCALL(
    THR_flea_ber_dec_t__decode_implicit_universal_optional_with_inner(
      &dec__t,
      2,
      FLEA_ASN1_BIT_STRING,
      NULL
    )
  );
  FLEA_CCALL(
    THR_flea_tls_cert_validation__parse_extensions(
      &dec__t,
      &key_usage__t,
      &extd_key_usage__t,
      &basic_constraints__t,
      hostn_valid_params_mbn__pt, //  have_precursor_to_verify__b ? NULL : &hostn_valid_info__t,
      previous_crldp__pt,
      &optional_found__b
    )
  );

  if(optional_found__b && (version__u8 != 3))
  {
    FLEA_THROW("x.509 version does not support extensions", FLEA_ERR_X509_VERSION_ERROR);
  }
  /** flea does check the TA to be a CA **/
  if(have_precursor_to_verify__b)
  {
    if(!basic_constraints__t.is_present__u8 || !basic_constraints__t.is_ca__b)
    {
      FLEA_THROW("basic constraints missing", FLEA_ERR_CERT_INTERMED_IS_NOT_CA_CERT);
    }
    if(basic_constraints__t.has_path_len__b)
    {
      if(previous_non_self_issued_cnt__calu16 > basic_constraints__t.path_len__u16 + 1)
      {
        FLEA_THROW("path len violated", FLEA_ERR_X509_BC_EXCSS_PATH_LEN);
      }
    }
    if(key_usage__t.is_present__u8 &&
      !(key_usage__t.purposes__u16 & flea_ku_key_cert_sign))
    {
      FLEA_THROW("key usage cert sign missing", FLEA_ERR_CERT_INTERMED_IS_NOT_CA_CERT);
    }

    if(validate_crl_for_issued_by_current__b && key_usage__t.is_present__u8)
    {
      if(!(key_usage__t.purposes__u16 & flea_ku_crl_sign))
      {
        FLEA_THROW(
          "CRL issuer has key usage extension without the CRLSign bit set",
          FLEA_ERR_X509_CRL_ISSUER_WO_CRL_SIGN
        );
      }
    }
  }
  else
  {
    /* this is the EE certificate */
    if(cert_path_params__pct->validate_server_or_client__e == FLEA_TLS_SERVER)
    {
      FLEA_CCALL(
        THR_flea_tls__check_key_usage_of_tls_server(
          &key_usage__t,
          &extd_key_usage__t,
          cert_path_params__pct->kex_type__e
        )
      );
    }
    else if(cert_path_params__pct->validate_server_or_client__e == FLEA_TLS_CLIENT)
    {
      // see what kind of public key type we got and then check if it is one of the
      // expected ones. Then check the key usage
      if(pubkey_out__pt->key_type__t == flea_rsa_key)
      {
        cert_type__e = flea_tls_cl_cert__rsa_sign;
      }
      else if(pubkey_out__pt->key_type__t == flea_ecc_key)
      {
        cert_type__e = flea_tls_cl_cert__ecdsa_sign;
      }
      else
      {
        FLEA_THROW("invalid value of cert type", FLEA_ERR_INV_ARG);
      }

      if(cert_path_params__pct->client_cert_type_mask__u8 & cert_type__e)
      {
        FLEA_CCALL(
          THR_flea_tls__check_key_usage_of_tls_client(
            &key_usage__t,
            &extd_key_usage__t,
            cert_type__e
          )
        );
      }
      else
      {
        FLEA_THROW("invalid certificate type, expected other", FLEA_ERR_TLS_CERT_VER_FAILED);
      }
    }


    if(do_validate_host_name__b && !hostn_valid_info__t.match_info__t.id_matched__b)
    {
      /* host name needs to be matched and wasn't so yet (in SAN) */

      if((!hostn_valid_info__t.match_info__t.contains_dnsname__b && (hostn_valid_info__t.host_type_id__e == flea_host_dnsname)))
      {
        /* as specified in RFC 6125, only use CN if no appropirate SAN elements were
         * found, which is the case now. */

        flea_x509_dn_ref_t dn_ref__t = {.common_name__t = {.data__pu8 = 0}};

        flea_bool_e names_match__b;

        FLEA_CCALL(THR_flea_x509__decode_dn_ref_elements(&dn_ref__t, local_subject__t.data__pu8, local_subject__t.len__dtl, FLEA_TRUE));
        FLEA_CCALL(
          THR_flea_x509__verify_host_name(
            &cert_path_params__pct->hostn_valid_params__pt->host_id__ct,
            &dn_ref__t.common_name__t,
            FLEA_TRUE,
            &names_match__b
          )
        );
        if(!names_match__b)
        {
          FLEA_THROW("TLS hostname verification failed", FLEA_ERR_X509_TLS_SERVER_ID_NO_MATCH);
        }
      }
      else
      {
        /* SAN contained the applicable fields, but they did not match, or IP
         * address was not found in SAN */
        FLEA_THROW("TLS hostname verification failed", FLEA_ERR_X509_TLS_SERVER_ID_NO_MATCH);
      }
    }
  }
  /* closing the tbs */
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));

  *tbs_hash_id__pe = sigalg_hash_id;
  FLEA_CCALL(THR_flea_hash_ctx_t__final_byte_vec(&hash__t, tbs_hash_in_out__pt));

  FLEA_CCALL(THR_flea_x509__decode_algid_ref(&outer_sigalg_id__t, &dec__t));
  FLEA_CCALL(THR_flea_x509__process_alg_ids(&sigalg_id__t, &outer_sigalg_id__t));

  /** starting to update the cycling fields */
  FLEA_CCALL(
    THR_flea_ber_dec_t__read_value_raw_cft(
      &dec__t,
      FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, BIT_STRING),
      signature_in_out__pt
    )
  );

  FLEA_CCALL(
    THR_flea_byte_vec_t__set_content(
      issuer_dn__pt,
      local_issuer__t.data__pu8,
      local_issuer__t.len__dtl
    )
  );
  FLEA_CCALL(THR_flea_byte_vec_t__set_content(prev_sn_buffer__pt, sn_buffer__t.data__pu8, sn_buffer__t.len__dtl));
  FLEA_THR_FIN_SEC(
    flea_ber_dec_t__dtor(&dec__t);
    flea_byte_vec_t__dtor(&public_key_value__t);
    flea_byte_vec_t__dtor(&local_subject__t);
    flea_byte_vec_t__dtor(&sn_buffer__t);
    flea_byte_vec_t__dtor(&local_issuer__t);
    flea_byte_vec_t__dtor(&back_buffer__t);
    flea_byte_vec_t__dtor(&sigalg_id__t.oid_ref__t);
    flea_byte_vec_t__dtor(&sigalg_id__t.params_ref_as_tlv__t);
    flea_byte_vec_t__dtor(&outer_sigalg_id__t.oid_ref__t);
    flea_byte_vec_t__dtor(&outer_sigalg_id__t.params_ref_as_tlv__t);
    flea_byte_vec_t__dtor(&public_key_alg_id__t.oid_ref__t);
    flea_byte_vec_t__dtor(&public_key_alg_id__t.params_ref_as_tlv__t);
  );
} /* THR_flea_tls__validate_cert */

flea_err_e THR_flea_tls__cert_path_validation(
  flea_tls_ctx_t*                    tls_ctx__pt,
  flea_tls_handsh_reader_t*          hs_rdr__pt,
  const flea_cert_store_t*           trust_store__pt,
  flea_public_key_t*                 pubkey_to_construct__pt,
  flea_tls_cert_path_params_t const* cert_path_params__pct
)
{
  flea_bool_e finished__b = FLEA_FALSE;
  flea_gmt_time_t compare_time__t;
  flea_al_u16_t cert_count__alu16     = 0;
  flea_al_u16_t iter__alu16           = 0;
  flea_public_key_t cycling_pubkey__t = flea_public_key_t__INIT_VALUE;
  flea_al_u16_t cnt_non_self_issued_in_path__alu16 = 0;
  flea_rw_stream_t* rd_strm__pt;
  flea_rw_stream_t mem_rd_strm__t = flea_rw_stream_t__INIT_VALUE;

  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(sn_buffer__t, FLEA_X509_MAX_SERIALNUMBER_LEN);
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(previous_crldp__t, FLEA_X509_STCKMD_MAX_CRLDP_LEN);

  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(
    cycling_signature__t,
    FLEA_PK_MAX_SIGNATURE_LEN + 10
  );
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(cycling_tbs_hash__t, FLEA_MAX_HASH_OUT_LEN);
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(cycling_issuer_dn, FLEA_X509_MAX_ISSUER_DN_RAW_BYTE_LEN);
  flea_hash_id_e cycling_hash_id;
  flea_public_key_t* pubkey_ptr__pt = pubkey_to_construct__pt;
  const flea_ref_cu8_t* trusted__prcu8;
  flea_mem_read_stream_help_t mem_hlp__t;
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_lib__get_gmt_time_now(&compare_time__t));

  do
  {
    flea_bool_e is_cert_trusted__b;
    flea_u32_t new_cert_len__u32;
    rd_strm__pt = flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt);
    flea_al_u16_t trusted_idx__alu16;
    if(!flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt))
    {
      FLEA_THROW("no trusted certificate found in TLS path validation", FLEA_ERR_CERT_PATH_NO_TRUSTED_CERTS);
    }
    if(iter__alu16)
    {
      pubkey_ptr__pt = &cycling_pubkey__t;
    }
    if(++cert_count__alu16 > FLEA_TLS_CERT_PATH_MAX_LEN)
    {
      FLEA_THROW("maximal cert path size for TLS exceeded", FLEA_ERR_CERT_PATH_NO_TRUSTED_CERTS);
    }

    FLEA_CCALL(THR_flea_rw_stream_t__read_int_be(rd_strm__pt, &new_cert_len__u32, 3));
# ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF
    if(iter__alu16 == 0)
    {
      if(new_cert_len__u32 > (flea_dtl_t) -1)
      {
        FLEA_THROW("excessive certificate size", FLEA_ERR_ASN1_DER_EXCSS_LEN);
      }
      FLEA_CCALL(THR_flea_byte_vec_t__resize(&tls_ctx__pt->peer_ee_cert_data__t, new_cert_len__u32));
      FLEA_CCALL(THR_flea_rw_stream_t__read_full(rd_strm__pt, tls_ctx__pt->peer_ee_cert_data__t.data__pu8, tls_ctx__pt->peer_ee_cert_data__t.len__dtl));

      FLEA_CCALL(THR_flea_rw_stream_t__ctor_memory(&mem_rd_strm__t, tls_ctx__pt->peer_ee_cert_data__t.data__pu8, tls_ctx__pt->peer_ee_cert_data__t.len__dtl, &mem_hlp__t));
      rd_strm__pt = &mem_rd_strm__t;
    }
# endif /* ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF */
    FLEA_CCALL(
      THR_flea_tls__validate_cert(
        tls_ctx__pt,
        rd_strm__pt,
        new_cert_len__u32,
        pubkey_ptr__pt,
        &cycling_signature__t,
        &cycling_tbs_hash__t,
        &cycling_hash_id,
        iter__alu16,
        &cycling_issuer_dn,
        &compare_time__t,
        &cnt_non_self_issued_in_path__alu16,
        cert_path_params__pct,
        tls_ctx__pt->rev_chk_cfg__t.crl_der__pt,
        tls_ctx__pt->rev_chk_cfg__t.nb_crls__u16,
        tls_ctx__pt->rev_chk_cfg__t.rev_chk_mode__e == flea_rev_chk_none ? FLEA_FALSE : (tls_ctx__pt->rev_chk_cfg__t.rev_chk_mode__e == flea_rev_chk_only_ee ? ((iter__alu16 == 1) ? FLEA_TRUE : FLEA_FALSE) : (iter__alu16 > 0)),
        &sn_buffer__t,
        &previous_crldp__t
      )
    );
# ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF
    flea_rw_stream_t__dtor(&mem_rd_strm__t);
# endif

    if(iter__alu16)
    {
      flea_public_key_t__dtor(&cycling_pubkey__t);
    }
    FLEA_CCALL(
      THR_flea_cert_store_t__is_tbs_hash_trusted(
        trust_store__pt,
        cycling_hash_id,
        cycling_tbs_hash__t.data__pu8,
        cycling_tbs_hash__t.len__dtl,
        &is_cert_trusted__b,
        &trusted_idx__alu16
      )
    );
    iter__alu16++;
    if(is_cert_trusted__b)
    {
      finished__b = FLEA_TRUE;
# ifdef FLEA_TLS_HAVE_PEER_ROOT_CERT_REF
      trusted__prcu8 = flea_cert_store_t__GET_PTR_TO_ENC_CERT_RCU8(trust_store__pt, trusted_idx__alu16);
# endif
    }
    else if(flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt) < 4)
    {
      /* no trusted cert found and no more following. check whether the trusted
       * root was omitted, i.e. try all possible trusted roots */
      flea_al_u16_t i;
      for(i = 0; i < flea_cert_store_t__GET_NB_CERTS(trust_store__pt); i++)
      {
        trusted__prcu8 = flea_cert_store_t__GET_PTR_TO_ENC_CERT_RCU8(trust_store__pt, i);
        if(!flea_cert_store_t__is_cert_trusted(trust_store__pt, i))
        {
          continue;
        }
        FLEA_CCALL(THR_flea_rw_stream_t__ctor_memory(&mem_rd_strm__t, trusted__prcu8->data__pcu8, trusted__prcu8->len__dtl, &mem_hlp__t));

        if(FLEA_ERR_FINE == THR_flea_tls__validate_cert(
            tls_ctx__pt,
            &mem_rd_strm__t,
            trusted__prcu8->len__dtl,
            pubkey_ptr__pt,
            &cycling_signature__t,
            &cycling_tbs_hash__t,
            &cycling_hash_id,
            iter__alu16,
            &cycling_issuer_dn,
            &compare_time__t,
            &cnt_non_self_issued_in_path__alu16,
            cert_path_params__pct,
            tls_ctx__pt->rev_chk_cfg__t.crl_der__pt,
            tls_ctx__pt->rev_chk_cfg__t.nb_crls__u16,
            tls_ctx__pt->rev_chk_cfg__t.rev_chk_mode__e == flea_rev_chk_none ? FLEA_FALSE : (tls_ctx__pt->rev_chk_cfg__t.rev_chk_mode__e == flea_rev_chk_only_ee ? ((iter__alu16 == 1) ? FLEA_TRUE : FLEA_FALSE) : (iter__alu16 > 0)),
            &sn_buffer__t,
            &previous_crldp__t
          ))
        {
          finished__b = FLEA_TRUE;
        }
        flea_rw_stream_t__dtor(&mem_rd_strm__t);
      }
    }
  } while(!finished__b);

# ifdef FLEA_TLS_HAVE_PEER_ROOT_CERT_REF
  /* if finished, then a trusted cert was found */
  FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(&tls_ctx__pt->peer_root_cert_ref__t, trusted__prcu8->data__pcu8, trusted__prcu8->len__dtl));
  tls_ctx__pt->peer_root_cert_set__u8 = FLEA_TRUE;
# endif
# ifdef FLEA_TLS_HAVE_PEER_EE_CERT_REF
  FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(&tls_ctx__pt->peer_ee_cert_ref__t, tls_ctx__pt->peer_ee_cert_data__t.data__pu8, tls_ctx__pt->peer_ee_cert_data__t.len__dtl));
# endif

  FLEA_THR_FIN_SEC(
    flea_public_key_t__dtor(&cycling_pubkey__t);
    flea_byte_vec_t__dtor(&cycling_signature__t);
    flea_byte_vec_t__dtor(&cycling_issuer_dn);
    flea_byte_vec_t__dtor(&cycling_tbs_hash__t);
    flea_byte_vec_t__dtor(&sn_buffer__t);
    flea_byte_vec_t__dtor(&previous_crldp__t);
    flea_rw_stream_t__dtor(&mem_rd_strm__t);
  );
} /* THR_flea_tls__cert_path_validation */

#endif /* ifdef FLEA_HAVE_TLS */
