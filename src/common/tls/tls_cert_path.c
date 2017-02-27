/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/alloc.h"
#include "flea/cert_verify.h"
#include "flea/error_handling.h"
#include "internal/common/ber_dec.h"
#include "flea/x509.h"
#include "flea/pk_api.h"
#include "flea/asn1_date.h"
#include "flea/namespace_asn1.h"
#include "flea/tls.h"
#include "flea/rw_stream.h"
#include "flea/cert_store.h"
#include "internal/common/cert_path_int.h"
#include "internal/common/tls/handsh_reader.h"
#include "internal/pltf_if/time.h"

#define FLEA_TLS_CERT_BUF_SIZE                  1536
#define FLEA_TLS_CERT_PATH_MAX_LEN              20
#define FLEA_X509_CERT_PRE_SIGALGID_BUFFER_SIZE 70

flea_err_t THR_flea_tls__cert_path_validation(
  flea_tls_ctx_t*          tls_ctx__pt,
  // flea_tls_handsh_reader_t* hs_rdr__pt,
  flea_rw_stream_t*        rd_strm__pt,
  const flea_cert_store_t* trust_store__pt,
  flea_public_key_t*       pubkey_to_construct__pt
)
{
  flea_u8_t enc_len__au8[3];
  // flea_rw_stream_t* rd_strm__pt;
  flea_bool_t finished__b = FLEA_FALSE;
  flea_bool_t even__b     = FLEA_TRUE;
  flea_bool_t first__b    = FLEA_TRUE;
  flea_gmt_time_t compare_time__t;
  flea_al_u16_t cert_count__alu16 = 0;

  FLEA_DECL_BUF(cert_buf_1__bu8, flea_u8_t, FLEA_TLS_CERT_BUF_SIZE);
  flea_al_u16_t buf_1_len__alu16     = 0;
  flea_x509_cert_ref_t cert_ref_1__t = flea_x509_cert_ref_t__INIT_VALUE;
  FLEA_DECL_BUF(cert_buf_2__bu8, flea_u8_t, FLEA_TLS_CERT_BUF_SIZE);
  flea_al_u16_t buf_2_len__alu16     = 0;
  flea_x509_cert_ref_t cert_ref_2__t = flea_x509_cert_ref_t__INIT_VALUE;
  flea_u32_t prev_cert_len__u32      = 0;

  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_pltfif_time__get_current_time(&compare_time__t));

  // rd_strm__pt = flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt);
  do
  {
    flea_u32_t new_cert_len__u32;
    flea_u8_t* new_cert__pu8;
    flea_x509_cert_ref_t* new_cert_ref__pt;
    flea_u8_t* prev_cert__pu8;
    // flea_x509_cert_ref_t* prev_cert_ref__pt;
    flea_bool_t is_new_cert_trusted__b;
    flea_u16_t path_len__u16;
    flea_basic_constraints_t* basic_constraints__pt;

    if(++cert_count__alu16 > FLEA_TLS_CERT_PATH_MAX_LEN)
    {
      FLEA_THROW("maximal cert path size for TLS exceeded", FLEA_ERR_INV_ARG);
    }

    FLEA_CCALL(THR_flea_rw_stream_t__force_read(rd_strm__pt, enc_len__au8, sizeof(enc_len__au8)));
    new_cert_len__u32 = ((flea_u32_t) enc_len__au8[0] << 16) | (enc_len__au8[1] << 8) | (enc_len__au8[2]);
    if(even__b)
    {
      FLEA_FREE_BUF(cert_buf_1__bu8);
      if(buf_1_len__alu16 < new_cert_len__u32)
      {
        FLEA_FREE_BUF(cert_buf_1__bu8);
        FLEA_ALLOC_BUF(cert_buf_1__bu8, new_cert_len__u32);
        buf_1_len__alu16 = new_cert_len__u32;
      }
      // TODO: STACK BUF LIMIT CHECK
      new_cert__pu8    = cert_buf_1__bu8;
      new_cert_ref__pt = &cert_ref_1__t;
      even__b = FLEA_FALSE;

      prev_cert__pu8 = cert_buf_2__bu8;
      // prev_cert_ref__pt = &cert_ref_2__t;
    }
    else
    {
      /*FLEA_FREE_BUF(cert_buf_2__bu8);
       * FLEA_ALLOC_BUF(cert_buf_2__bu8, new_cert_len__u32);*/

      if(buf_2_len__alu16 < new_cert_len__u32)
      {
        // TODO: STACK BUF LIMIT CHECK
        FLEA_FREE_BUF(cert_buf_2__bu8);
        FLEA_ALLOC_BUF(cert_buf_2__bu8, new_cert_len__u32);
        buf_2_len__alu16 = new_cert_len__u32;
      }
      new_cert__pu8    = cert_buf_2__bu8;
      new_cert_ref__pt = &cert_ref_2__t;
      even__b = FLEA_TRUE;

      prev_cert__pu8 = cert_buf_1__bu8;
      // prev_cert_ref__pt = &cert_ref_1__t;
    }
    FLEA_CCALL(THR_flea_rw_stream_t__force_read(rd_strm__pt, new_cert__pu8, new_cert_len__u32));

    FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(new_cert_ref__pt, new_cert__pu8, new_cert_len__u32));

    basic_constraints__pt = &new_cert_ref__pt->extensions__t.basic_constraints__t;
    FLEA_CCALL(
      THR_flea_cert_store_t__is_cert_trusted(
        trust_store__pt,
        new_cert__pu8,
        new_cert_len__u32,
        &is_new_cert_trusted__b
      )
    );

    if(!flea_x509_is_cert_self_issued(new_cert_ref__pt) && !first__b)
    {
      if(basic_constraints__pt->is_present__u8)
      {
        if(basic_constraints__pt->has_path_len__b)
        {
          if(path_len__u16 > basic_constraints__pt->path_len__u16)
          {
            FLEA_THROW("path len constraint exceeded", FLEA_ERR_CERT_PATH_LEN_CONSTR_EXCEEDED);
          }
        }
      }
      path_len__u16++;
    }


    FLEA_CCALL(
      THR_flea_cert_path__validate_single_cert(
        new_cert_ref__pt,
        is_new_cert_trusted__b,
        first__b,
        &compare_time__t
      )
    );

    if(!first__b)
    {
      FLEA_CCALL(
        THR_flea_x509_verify_cert_signature(
          prev_cert__pu8,
          prev_cert_len__u32,
          new_cert__pu8,
          new_cert_len__u32
        )
      );
    }
    else
    {
      // TODO: VALIDATED CERT KEY USAGE FOR TLS
      FLEA_CCALL(THR_flea_public_key_t__ctor_cert(pubkey_to_construct__pt, new_cert_ref__pt));
    }
    if(is_new_cert_trusted__b)
    {
      break;
    }
    first__b = FLEA_FALSE;
    prev_cert_len__u32 = new_cert_len__u32;
  } while(!finished__b);
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(cert_buf_1__bu8);
    FLEA_FREE_BUF_FINAL(cert_buf_2__bu8);
  );
} /* THR_flea_tls__cert_path_validation */

static flea_err_t THR_flea_tls_chec_cert_validity_time(
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
    FLEA_THROW("certificate not yet valid", FLEA_ERR_CERT_NOT_YET_VALID);
  }
  if(-1 == flea_asn1_cmp_utc_time(&not_after__t, compare_time__pt))
  {
    FLEA_THROW("certificate not yet valid", FLEA_ERR_CERT_NOT_YET_VALID);
  }
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(dec__pt));
  FLEA_THR_FIN_SEC_empty();
}

// TODO: USE DECODE FUNCTIONS EVERYWHERE, THEN UNITE THIS WITH X.509 CERT REF
// CTOR?
static flea_err_t THR_flea_tls_cert_validation__parse_extensions(
  flea_ber_dec_t*             dec__pt,
  flea_key_usage_t*           key_usage__pt,
  flea_key_usage_t*           extd_key_usage__pt,
  flea_x509_subj_alt_names_t* subj_alt_names_mbn__pt,
  flea_basic_constraints_t*   basic_constr__pt
)
{
  flea_bool_t have_extensions__b;

  // flea_byte_vec_t ext_oid_ref__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE;
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(ext_oid__t, 30); // TODO: MAKE TYPEDEF FOR VALUE
  // FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(ext_oid__t, 30); // TODO: MAKE TYPEDEF FOR VALUE
  flea_bool_t critical__b;
  // flea_bool_t optional__b;

  /*FLEA_DECL_OBJ(cont_dec__t, flea_ber_dec_t);
   *  FLEA_DECL_OBJ(source__t, flea_rw_stream_t);*/
  FLEA_THR_BEG_FUNC();
  /* open implicit */
  FLEA_CCALL(
    THR_flea_ber_dec_t__open_constructed_optional(
      dec__pt,
      3,
      FLEA_ASN1_CONSTRUCTED | FLEA_ASN1_CONTEXT_SPECIFIC,
      &have_extensions__b
    )
  );
  if(!have_extensions__b)
  {
    FLEA_THR_RETURN();
  }
  /* open extensions */
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(dec__pt));
  // printf("parse_extension: before more data\n");
  while(flea_ber_dec_t__has_current_more_data(dec__pt))
  {
    flea_al_u8_t ext_indic_pos__alu8;
    // flea_byte_vec_t ostr__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE;
    flea_al_u16_t oid_indicator__alu16 = 0;
    // flea_mem_read_stream_help_t hlp__t;
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
        // flea_bool_t found__b;
        case ID_CE_OID_AKI:
        {
          /* authority key identifier */
#if 0
          ext_ref__pt->auth_key_id__t.is_present__u8 = FLEA_TRUE;

          FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&cont_dec__t));
          FLEA_CCALL(
            THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(
              &cont_dec__t,
              (flea_asn1_tag_t) FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_CONTEXT_SPECIFIC, 0),
              &ext_ref__pt->auth_key_id__t.key_id__t,
              &found__b
            )
          );

#endif /* if 0 */
          break;
        }
        case ID_CE_OID_KEY_USAGE:
        {
          FLEA_CCALL(THR_flea_x509_cert__parse_key_usage(dec__pt, key_usage__pt));
          break;
        }
        case ID_CE_OID_SUBJ_KEY_ID:
        {
#if 0
          FLEA_CCALL(
            THR_flea_ber_dec_t__get_ref_to_raw_cft(
              &cont_dec__t,
              FLEA_ASN1_OCTET_STRING,
              &ext_ref__pt->subj_key_id__t
            )
          );
#endif
          break;
        }
        case ID_CE_OID_SUBJ_ALT_NAME:
        {
          if(subj_alt_names_mbn__pt)
          {
            subj_alt_names_mbn__pt->is_present__u8 = FLEA_TRUE;
            FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_next_tlv_raw(dec__pt, &subj_alt_names_mbn__pt->san_raw__t));
          }
          break;
        }

        case ID_CE_OID_ISS_ALT_NAME:
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
          // TODO: CRL PARSING IN TLS
#if 0
          ext_ref__pt->crl_distr_point__t.is_present__u8 = FLEA_TRUE;
          FLEA_CCALL(
            THR_flea_ber_dec_t__get_ref_to_next_tlv_raw(
              &cont_dec__t,
              &ext_ref__pt->crl_distr_point__t.raw_ref__t
            )
          );
          break;
#endif
        }
        case ID_CE_OID_FRESHEST_CRL:
        {
#if 0
          ext_ref__pt->freshest_crl__t.is_present__u8 = FLEA_TRUE;
          FLEA_CCALL(
            THR_flea_ber_dec_t__get_ref_to_next_tlv_raw(
              &cont_dec__t,
              &ext_ref__pt->freshest_crl__t.raw_ref__t
            )
          );
#endif
          break;
        }
        case ID_PE_OID_AUTH_INF_ACC:
        {
#if 0
          ext_ref__pt->auth_inf_acc__t.is_present__u8 = FLEA_TRUE;
          FLEA_CCALL(
            THR_flea_ber_dec_t__get_ref_to_next_tlv_raw(
              &cont_dec__t,
              &ext_ref__pt->auth_inf_acc__t.raw_ref__t
            )
          );
          break;
#endif
        }
        default:
          if(critical__b)
          {
            FLEA_THROW("unsupported critical extension", FLEA_ERR_X509_ERR_UNSUP_CRIT_EXT);
          }
    }
    // close conceptual constructed of extension octet string
    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_skip_remaining(dec__pt));
  }
  FLEA_THR_FIN_SEC(
    flea_byte_vec_t__dtor(&ext_oid__t);
  );
} /* THR_flea_tls_cert_validation__parse_extensions */

static flea_err_t THR_flea_tls__validate_cert(
  flea_rw_stream_t*           rd_strm__pt,
  flea_public_key_t*          pubkey_out__pt,
  flea_byte_vec_t*            signature_in_out__pt,
  flea_byte_vec_t*            tbs_hash_in_out__pt,
  flea_bool_t                 have_precursor_to_verify__b,
  flea_byte_vec_t*            issuer_dn__pt, // previous issuer on input, gets updated to validated cert's subject
  const flea_gmt_time_t*      compare_time__pt,
  flea_key_usage_t*           key_usage__pt,
  flea_key_usage_t*           extd_key_usage__pt,
  flea_x509_subj_alt_names_t* subj_alt_names_mbn__pt,
  flea_basic_constraints_t*   basic_constr__pt
)
{
  FLEA_DECL_OBJ(dec__t, flea_ber_dec_t);
  FLEA_DECL_OBJ(hash__t, flea_hash_ctx_t);
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(back_buffer__t, FLEA_X509_CERT_PRE_SIGALGID_BUFFER_SIZE);
  FLEA_DECL_byte_vec_t__CONSTR_STACK_BUF_EMPTY_NOT_ALLOCATABLE(version_vec__t, 1);

  /* for SN, subject:
   */
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(var_buffer__t, 200);
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(local_issuer__t, 200);
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(local_subject__t, 200);
  flea_bool_t found_tag__b;
  flea_x509_algid_ref_t sigalg_id__t         = flea_x509_algid_ref_t__CONSTR_EMPTY_ALLOCATABLE;
  flea_x509_algid_ref_t outer_sigalg_id__t   = flea_x509_algid_ref_t__CONSTR_EMPTY_ALLOCATABLE;
  flea_x509_algid_ref_t public_key_alg_id__t = flea_x509_algid_ref_t__CONSTR_EMPTY_ALLOCATABLE;
  ;
  flea_hash_id_t sigalg_hash_id;
  flea_pk_key_type_t key_type;
  // FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(public_key_alg_id__t, 50); // TODO: VERIFY THIS SIZE
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(
    public_key_value__t,
    __FLEA_COMPUTED_PK_MAX_ASYM_PUBKEY_LEN
  ); // TODO: VERIFY THIS SIZE
     // flea_x509_public_key_info_t  = flea_x509_public_key_info_t__

  FLEA_THR_BEG_FUNC();

  flea_public_key_t__dtor(pubkey_out__pt);
  FLEA_CCALL(
    THR_flea_ber_dec_t__ctor_hash_support(
      &dec__t,
      rd_strm__pt,
      0,
      flea_decode_copy,
      &back_buffer__t,
      &hash__t
    )
  );

  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
  FLEA_CCALL(
    THR_flea_ber_dec_t__open_constructed_optional(
      &dec__t,
      0,
      FLEA_ASN1_CONSTRUCTED | FLEA_ASN1_CONTEXT_SPECIFIC,
      &found_tag__b
    )
  );
  if(found_tag__b)
  {
    // flea_dtl_t version_len__dtl = 1;
    // flea_u8_t version__u8;
    // FLEA_CCALL(THR_flea_ber_dec_t__read_value_raw(&dec__t, FLEA_ASN1_INT, 0, &version__u8, &version_len__dtl));
    FLEA_CCALL(THR_flea_ber_dec_t__read_value_raw(&dec__t, FLEA_ASN1_INT, 0, &version_vec__t));
    // if(version_len__dtl != 1)
    if(version_vec__t.len__dtl != 1)
    {
      FLEA_THROW("x.509 version of invalid length", FLEA_ERR_X509_VERSION_ERROR);
    }
    // cert_ref__pt->version__u8 = version__u8 + 1;
    // cert_ref__pt->version__u8 = version_vec__t.data__pu8[0] + 1;
    version_vec__t.data__pu8[0] += 1;
    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
  }
  else
  {
    FLEA_CCALL(THR_flea_byte_vec_t__push_back(&version_vec__t, 1));
  }
  // TODO: USE SN FOR CRL CHECK
  FLEA_CCALL(THR_flea_ber_dec_t__decode_int(&dec__t, &var_buffer__t));

  FLEA_CCALL(THR_flea_x509__decode_algid_ref(&sigalg_id__t, &dec__t));
  FLEA_CCALL(
    THR_flea_x509_get_hash_id_and_key_type_from_oid(
      sigalg_id__t.oid_ref__t.data__pu8,
      sigalg_id__t.oid_ref__t.len__dtl,
      &sigalg_hash_id,
      &key_type
    )
  );
  FLEA_CCALL(THR_flea_ber_dec_t__activate_hashing(&dec__t, sigalg_hash_id));
  // CANT'T BE CALLED, ASSUMES MEM SRC:
  // FLEA_CCALL(THR_flea_x509__parse_dn(&local_dn__t, &dec__t));
  FLEA_CCALL(
    THR_flea_ber_dec_t__read_value_raw_cft(
      &dec__t,
      FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, SEQUENCE),
      &local_issuer__t
    )
  );

  FLEA_CCALL(THR_flea_tls_chec_cert_validity_time(&dec__t, compare_time__pt));

  // TODO: IMPLEMENT COMPARE WITH STREAM
  // FLEA_CCALL(THR_flea_x509__parse_dn(&cert_ref__pt->subject__t, &dec__t));
  FLEA_CCALL(
    THR_flea_ber_dec_t__read_value_raw_cft(
      &dec__t,
      FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, SEQUENCE),
      &local_subject__t
    )
  );
  if(have_precursor_to_verify__b && flea_byte_vec_t__cmp(issuer_dn__pt, &local_issuer__t))
  {
    FLEA_THROW("name chaining failed", FLEA_ERR_X509_DN_ERROR);
  }
  /* enter subject public key info */
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
  FLEA_CCALL(THR_flea_x509__decode_algid_ref(&public_key_alg_id__t, &dec__t));

  FLEA_CCALL(
    THR_flea_ber_dec_t__get_ref_to_next_tlv_raw(
      &dec__t,
      &public_key_value__t
    )
  );
  if(have_precursor_to_verify__b)
  {
    flea_hash_id_t hash_id;
    flea_pk_key_type_t key_type;
    flea_pk_scheme_id_t scheme_id;

    FLEA_CCALL(
      THR_flea_x509_get_hash_id_and_key_type_from_oid(
        public_key_alg_id__t.oid_ref__t.data__pu8,
        public_key_alg_id__t.oid_ref__t.len__dtl,
        &hash_id,
        &key_type
      )
    );
    if(key_type == flea_rsa_key)
    {
      scheme_id = flea_rsa_pkcs1_v1_5_sign;
    }
    else
    {
      scheme_id = flea_ecdsa_emsa1;
    }

    FLEA_CCALL(
      THR_flea_public_key_t__ctor_asn1(
        pubkey_out__pt,
        &public_key_value__t,
        &public_key_alg_id__t.params_ref_as_tlv__t,
        &public_key_alg_id__t.oid_ref__t
      )
    );

    FLEA_CCALL(
      THR_flea_pk_api__verify_digest(
        tbs_hash_in_out__pt->data__pu8,
        tbs_hash_in_out__pt->len__dtl,
        hash_id,
        scheme_id,
        pubkey_out__pt,
        signature_in_out__pt->data__pu8,
        signature_in_out__pt->len__dtl
      )
    );
  }

  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));

  // TODO: skip decode this:
  FLEA_CCALL(
    THR_flea_ber_dec_t__get_ref_to_implicit_universal_optional_with_inner(
      &dec__t,
      1,
      FLEA_ASN1_BIT_STRING,
      &var_buffer__t
    )
  );
  FLEA_CCALL(
    THR_flea_ber_dec_t__get_ref_to_implicit_universal_optional_with_inner(
      &dec__t,
      2,
      FLEA_ASN1_BIT_STRING,
      &var_buffer__t
    )
  );
  FLEA_CCALL(
    THR_flea_tls_cert_validation__parse_extensions(
      &dec__t,
      key_usage__pt,
      extd_key_usage__pt,
      subj_alt_names_mbn__pt,
      basic_constr__pt
    )
  );

  /* closing the tbs */
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));

  FLEA_CCALL(THR_flea_x509__decode_algid_ref(&outer_sigalg_id__t, &dec__t));
  // TODO: THIS FUNCTION DOES A DANGEROUS REF-ASSIGNMENT OF THE PARAMS FROM ONE
  // SIGALG ID TO THE OTHER!
  FLEA_CCALL(THR_flea_x509__process_alg_ids(&sigalg_id__t, &outer_sigalg_id__t));
  FLEA_CCALL(
    THR_flea_ber_dec_t__get_ref_to_raw_cft(
      &dec__t,
      FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, BIT_STRING),
      signature_in_out__pt
    )
  );

  FLEA_THR_FIN_SEC(
    flea_ber_dec_t__dtor(&dec__t);
  );
} /* THR_flea_x509_cert_ref_t__ctor */
