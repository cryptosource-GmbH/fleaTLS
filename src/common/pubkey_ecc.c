/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "flea/pubkey.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "internal/common/namespace_asn1.h"
#include "flea/x509.h"
#include "internal/common/x509_key_int.h"
#include "flea/ec_key.h"
#include "flea/ecdsa.h"
#include "internal/common/pubkey_int.h"
#include "flea/mem_read_stream.h"
#include "flea/ecc_named_curves.h"
#include "flea/ecka.h"

#ifdef FLEA_HAVE_ECC

/* ANSI X9.62 Elliptic Curve Digital Signature Algorithm (ECDSA) algorithm with Secure Hash Algorithm, revision 2 (SHA2)  */
const flea_u8_t ecdsa_oid_prefix__acu8[6] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04};

/* subsequent octets:
 *                    3 => sha2
 *                      subsequent: specific sha2 variant
 *                    4.1 => sha1
 */


flea_err_e THR_get_hash_id_from_x509_id_for_ecdsa(
  const flea_u8_t cert_id__pcu8[2],
  flea_hash_id_e* result__pt
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
# ifdef FLEA_HAVE_SHA384_512
        case 3:
          *result__pt = flea_sha384;
          break;
        case 4:
          *result__pt = flea_sha512;
          break;
# endif /* ifdef FLEA_HAVE_SHA384_512 */
        default:
          FLEA_THROW("unsupported ECDSA variant", FLEA_ERR_X509_UNSUPP_ALGO_VARIANT);
    }
  }
# ifdef FLEA_HAVE_SHA1
  else if(cert_id__pcu8[0] == 4 && cert_id__pcu8[1] == 1)
  {
    *result__pt = flea_sha1;
  }
# endif /* ifdef FLEA_HAVE_SHA1 */
  else
  {
    FLEA_THROW("unsupported ECDSA variant", FLEA_ERR_X509_UNSUPP_ALGO_VARIANT);
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_get_hash_id_from_x509_id_for_ecdsa */

/* assumes that result__pu8 has sufficient length allocated */
flea_err_e THR_flea_x509_decode_ecdsa_signature(
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

flea_err_e THR_flea_public_key_t__create_ecdsa_key(
  flea_ec_pubkey_val_t*            ecc_key__pt,
  const flea_byte_vec_t*           public_point_encoded__pcrcu8,
  const flea_ec_gfp_dom_par_ref_t* dp_ref__pt
)
{
  flea_al_u16_t max_dp_concat_len;

  FLEA_THR_BEG_FUNC();
# ifdef FLEA_USE_STACK_BUF
  max_dp_concat_len = sizeof(ecc_key__pt->dp_mem__bu8);
# else
  if(dp_ref__pt->p__ru8.len__dtl > FLEA_ECC_MAX_MOD_BYTE_SIZE)
  {
    FLEA_THROW("invalid parameter length", FLEA_ERR_INV_KEY_SIZE);
  }
  max_dp_concat_len = FLEA_ECC_DP_CONCAT_BYTE_SIZE_FROM_MOD_BIT_SIZE(8 * dp_ref__pt->p__ru8.len__dtl);
  ;
  FLEA_ALLOC_MEM_ARR(ecc_key__pt->dp_mem__bu8, max_dp_concat_len);
# endif /* ifdef FLEA_USE_STACK_BUF */
  FLEA_CCALL(
    THR_flea_ec_gfp_dom_par_ref_t__write_to_concat_array(
      &ecc_key__pt->dp__t,
      ecc_key__pt->dp_mem__bu8,
      max_dp_concat_len,
      dp_ref__pt
    )
  );

# ifdef FLEA_USE_HEAP_BUF
  FLEA_ALLOC_MEM_ARR(ecc_key__pt->pub_point__mem__bu8, public_point_encoded__pcrcu8->len__dtl);
# endif

  flea_byte_vec_t__copy_content_set_ref_use_mem(
    &ecc_key__pt->public_point_encoded__rcu8,
    ecc_key__pt->pub_point__mem__bu8,
    public_point_encoded__pcrcu8
  );
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_public_key_t__create_ecdsa_key */

flea_err_e THR_flea_x509_parse_ecc_public_params(
  const flea_byte_vec_t*     encoded_parameters__pt,
  flea_ec_gfp_dom_par_ref_t* dom_par__pt
)
{
  FLEA_DECL_OBJ(source__t, flea_rw_stream_t);
  FLEA_DECL_OBJ(dec__t, flea_ber_dec_t);
  flea_mem_read_stream_help_t hlp__t;
  flea_bool_e found__b;
  FLEA_THR_BEG_FUNC();


  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor_memory(
      &source__t,
      encoded_parameters__pt->data__pu8,
      encoded_parameters__pt->len__dtl,
      &hlp__t
    )
  );
  FLEA_CCALL(
    THR_flea_ber_dec_t__ctor(
      &dec__t,
      &source__t,
      FLEA_ECC_MAX_MOD_BYTE_SIZE * 10,
      flea_decode_ref
    )
  );
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
    FLEA_CCALL(THR_flea_ecc_key__decode_uncompressed_point(&oid_ref__t, &dom_par__pt->gx__ru8, &dom_par__pt->gy__ru8));

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
    flea_bool_e dummy;
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

#endif /* ifdef FLEA_HAVE_ECC */
