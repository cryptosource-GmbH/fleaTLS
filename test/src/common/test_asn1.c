/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "internal/common/ber_dec.h"
#include "test_data_x509_certs.h"
#include "flea/mem_read_stream.h"
#include "test_data_pkcs8.h"
#include "self_test.h"

#include <stdio.h>
#include <string.h>

flea_err_t THR_flea_test_ber_dec_basic()
{
  FLEA_DECL_OBJ(source__t, flea_rw_stream_t);
  FLEA_DECL_OBJ(dec__t, flea_ber_dec_t);
  // FLEA_DECL_BUF(version_buf__bu8, flea_u8_t, 10);
  // flea_dtl_t version_len__dtl = 10;
  // flea_ref_cu8_t oid_ref__t;
  flea_byte_vec_t oid_vec__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE;
  flea_mem_read_stream_help_t hlp__t;
  // const flea_u8_t* oid__pu8;
  flea_bool_t found_tag__b;
  FLEA_DECL_byte_vec_t__CONSTR_STACK_BUF_EMPTY_NOT_ALLOCATABLE(version_vec__t, 10);
  FLEA_THR_BEG_FUNC();
  // FLEA_ALLOC_BUF(version_buf__bu8, 10);
  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor_memory(
      &source__t,
      flea_test_cert_1__au8,
      sizeof(flea_test_cert_1__au8),
      &hlp__t
    )
  );
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&dec__t, &source__t, 0, flea_decode_ref));
  FLEA_CCALL(
    THR_flea_ber_dec_t__get_ref_to_raw_optional(
      &dec__t,
      FLEA_ASN1_OID,
      0,

      /*&oid__pu8,
       * &version_len__dtl,*/
      &oid_vec__t,
      &found_tag__b
    )
  );
  if(found_tag__b)
  {
    FLEA_THROW("optional decoding of missing element", FLEA_ERR_FAILED_TEST);
  }

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
    FLEA_THROW("optional opening of missing constructed", FLEA_ERR_FAILED_TEST);
  }
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
    FLEA_THROW("optional opening of missing constructed", FLEA_ERR_FAILED_TEST);
  }
  // version_len__dtl = 10;
  FLEA_CCALL(
    THR_flea_ber_dec_t__open_constructed_optional(
      &dec__t,
      FLEA_ASN1_SEQUENCE,
      FLEA_ASN1_CONSTRUCTED,
      &found_tag__b
    )
  );
  if(!found_tag__b)
  {
    FLEA_THROW("optional opening of existing constructed", FLEA_ERR_FAILED_TEST);
  }

  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
  // decode integer serial number
  FLEA_CCALL(THR_flea_ber_dec_t__open_constructed(&dec__t, 0, FLEA_ASN1_CONSTRUCTED | FLEA_ASN1_CONTEXT_SPECIFIC));

  FLEA_CCALL(
    THR_flea_ber_dec_t__read_value_raw_cft(
      &dec__t,
      FLEA_ASN1_CFT_MAKE3(0, 0, FLEA_ASN1_INT),
      // version_buf__bu8,
      &version_vec__t
      // &version_len__dtl
    )
  );
  // if(version_len__dtl != 1 || version_buf__bu8[0] != 1)
  if(version_vec__t.len__dtl != 1 || version_vec__t.data__pu8[0] != 1)
  {
    FLEA_THROW("invalid decoded version number", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_skip_remaining(&dec__t));
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
  // decode the OID
  // version_len__dtl = 10;
  // version_vec__t.len__dtl = 10;
  // FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_cft(&dec__t, FLEA_ASN1_CFT_MAKE2(0, FLEA_ASN1_OID), &oid_ref__t));
  FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_cft(&dec__t, FLEA_ASN1_CFT_MAKE2(0, FLEA_ASN1_OID), &oid_vec__t));
  // if(oid_ref__t.len__dtl != 9)
  if(oid_vec__t.len__dtl != 9)
  {
    FLEA_THROW("invalid decoded OID length", FLEA_ERR_FAILED_TEST);
  }
  // if(oid_ref__t.data__pcu8[0] != 0x2A || oid_ref__t.data__pcu8[8] != 0x0B)
  if(oid_vec__t.data__pu8[0] != 0x2A || oid_vec__t.data__pu8[8] != 0x0B)
  {
    FLEA_THROW("invalid decoded OID", FLEA_ERR_FAILED_TEST);
  }
  if(FLEA_ERR_ASN1_DER_DEC_ERR != THR_flea_ber_dec_t__close_constructed_at_end(&dec__t))
  {
    FLEA_THROW("skipping remaining bytes when requiring constructed to be finished", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_skip_remaining(&dec__t));
  FLEA_THR_FIN_SEC(
    flea_rw_stream_t__dtor(&source__t);
    flea_ber_dec_t__dtor(&dec__t);
  );
} /* THR_flea_test_ber_dec_basic */

typedef enum { dec_func_default, dec_func_ref,
               dec_func_cpy /*, dec_func_cpy_tlv__only_for_first_function*/ } dec_func_e;

static flea_err_t THR_flea_test_ber_dec_opt_and_ref_and_cpy_inner(
  flea_bool_t              is_fake_gen_strm__b,
  flea_asn1_dec_val_hndg_e dec_val_hndg__e,
  dec_func_e               first_dec_func__e,
  dec_func_e               second_dec_func__e,
  flea_err_t               dec_ctor_exp_err_code,
  flea_err_t               first_func_exp_err_code,
  flea_err_t               second_func_exp_err_code
)
{
  FLEA_DECL_OBJ(strm__t, flea_rw_stream_t);
  FLEA_DECL_OBJ(dec__t, flea_ber_dec_t);
  flea_mem_read_stream_help_t hlp__t;
  // FLEA_DECL_byte_vec_t__CONSTR_STACK_BUF_EMPTY_NOT_ALLOCATABLE(cp_pkcs8_vec__t, sizeof(flea_testd_pkcs8_ecc_key_secp384r1_implicit_params__au8));
#ifdef FLEA_USE_STACK_BUF
  FLEA_DECL_byte_vec_t__CONSTR_STACK_BUF_EMPTY_NOT_ALLOCATABLE(dec_vec__t, 1000);
#else
  flea_byte_vec_t dec_vec__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE;
#endif
  // flea_ref_cu8_t ref__rcu8;
  flea_err_t err__t;
  flea_asn1_tag_t false_cft         = FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_UNIVERSAL_PRIMITIVE, FLEA_ASN1_SET);
  flea_u8_t exp_version_tlv__au8 [] = {0x02, 0x01, 0x00};
  flea_bool_t optional_found__b     = FLEA_TRUE;
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor_memory(
      &strm__t,
      flea_testd_pkcs8_ecc_key_secp384r1_implicit_params__au8,
      sizeof(flea_testd_pkcs8_ecc_key_secp384r1_implicit_params__au8),
      &hlp__t
    )
  );
  if(is_fake_gen_strm__b)
  {
    strm__t.strm_type__e = flea_strm_type_generic;
  }
  err__t = THR_flea_ber_dec_t__ctor(&dec__t, &strm__t, 0, dec_val_hndg__e);
  if(err__t != dec_ctor_exp_err_code)
  {
    FLEA_THROW("unexpected ctor err code", FLEA_ERR_FAILED_TEST);
  }
  if(err__t)
  {
    FLEA_THR_RETURN();
  }


  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));

  if(first_dec_func__e == dec_func_cpy)
  {
    optional_found__b = FLEA_TRUE;
    err__t = THR_flea_ber_dec_t__read_value_raw_cft_opt(&dec__t, false_cft, &dec_vec__t, &optional_found__b);
#if 0
    if(err__t != first_func_exp_err_code)
    {
      FLEA_THROW("unexpected error code", FLEA_ERR_FAILED_TEST);
    }
    if(!err__t && optional_found__b)
    {
      FLEA_THROW("invalid decoding result", FLEA_ERR_FAILED_TEST);
    }
#endif
  }
  else if(first_dec_func__e == dec_func_ref)
  {
    // flea_bool_t found__b;
    optional_found__b = FLEA_TRUE;
    // TODO: EMPLOY REF HERE INSTEAD OF VEC
    err__t = THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(&dec__t, false_cft, &dec_vec__t, &optional_found__b);
#if 0
#endif
  }
  else if(first_dec_func__e == dec_func_default)
  {
    printf("test case not yet implemented\n");
    FLEA_THROW("test case not yet implemented", FLEA_ERR_INT_ERR);
  }

  /*else if(first_dec_func__e == dec_func_cpy_tlv__only_for_first_function)
   * {
   *
   * optional_found__b = FLEA_TRUE;
   * err__t = THR_flea_ber_dec_t__read_tlv_raw_optional(&dec__t, &dec_vec__t, &optional_found__b);
   * }*/
  if(err__t != first_func_exp_err_code)
  {
    FLEA_THROW("unexpected error code", FLEA_ERR_FAILED_TEST);
  }
  if(!err__t && optional_found__b)
  {
    FLEA_THROW("invalid decoding result", FLEA_ERR_FAILED_TEST);
  }

  if(second_dec_func__e == dec_func_cpy)
  {
    // err__t = THR_flea_ber_dec_t__read_value_raw(&dec__t, FLEA_ASN1_INT, FLEA_ASN1_UNIVERSAL_PRIMITIVE, &dec_vec__t);

    /*  printf("test case not yet implemented\n");
     * FLEA_THROW("test case not yet implemented", FLEA_ERR_FAILED_TEST);*/
#if 0
    err__t =
      THR_flea_ber_dec_t__read_value_raw_cft(
      &dec__t,
      FLEA_ASN1_CFT_MAKE2(
        FLEA_ASN1_UNIVERSAL_PRIMITIVE,
        FLEA_ASN1_INT
      ),
      &dec_vec__t
      );
    if(err__t != second_func_exp_err_code)
    {
      FLEA_THROW("unexpected error code", FLEA_ERR_FAILED_TEST);
    }
    if(!err__t && ((dec_vec__t.len__dtl != 1) || (dec_vec__t.data__pu8[0] != 0)))
    {
      FLEA_THROW("invalid decoded value for second function", FLEA_ERR_FAILED_TEST);
    }
#else /* if 0 */
    flea_bool_t optional_false__b = FLEA_FALSE;
    err__t = THR_flea_ber_dec_t__read_tlv_raw_optional(&dec__t, &dec_vec__t, &optional_false__b);

    if(err__t != second_func_exp_err_code)
    {
      FLEA_THROW("unexpected error code", FLEA_ERR_FAILED_TEST);
    }
# if 0
    if(!err__t)
    {
      if(dec_vec__t.len__dtl != sizeof(exp_version_tlv__au8))
      {
        FLEA_THROW("PKCS#8 version of invalid length", FLEA_ERR_FAILED_TEST);
      }
      if(memcmp(exp_version_tlv__au8, dec_vec__t.data__pu8, sizeof(exp_version_tlv__au8)))
      {
        FLEA_THROW("PKCS#8 version of invalid content", FLEA_ERR_FAILED_TEST);
      }
    }
# endif /* if 0 */
#endif  /* if 0 */
  }
  else if(second_dec_func__e == dec_func_ref)
  {
    // TODO: EMPLOY REF HERE INSTEAD OF VEC
    err__t = THR_flea_ber_dec_t__get_ref_to_next_tlv_raw(&dec__t, &dec_vec__t);

#if 0
    if(err__t != second_func_exp_err_code)
    {
      FLEA_THROW("unexpected error code", FLEA_ERR_FAILED_TEST);
    }
    if(!err__t)
    {
      if(dec_vec__t.len__dtl != sizeof(exp_version_tlv__au8))
      {
        FLEA_THROW("PKCS#8 version of invalid length", FLEA_ERR_FAILED_TEST);
      }
      if(memcmp(exp_version_tlv__au8, dec_vec__t.data__pu8, sizeof(exp_version_tlv__au8)))
      {
        FLEA_THROW("PKCS#8 version of invalid content", FLEA_ERR_FAILED_TEST);
      }
    }
#endif /* if 0 */
  }
  else if(second_dec_func__e == dec_func_default)
  {
    flea_bool_t optional_false__b = FLEA_FALSE;
    err__t = THR_flea_ber_dec_t__decode_tlv_raw_optional(&dec__t, &dec_vec__t, &optional_false__b);

#if 0
    if(err__t != second_func_exp_err_code)
    {
      FLEA_THROW("unexpected error code", FLEA_ERR_FAILED_TEST);
    }
    if(!err__t)
    {
      if(dec_vec__t.len__dtl != sizeof(exp_version_tlv__au8))
      {
        FLEA_THROW("PKCS#8 version of invalid length", FLEA_ERR_FAILED_TEST);
      }
      if(memcmp(exp_version_tlv__au8, dec_vec__t.data__pu8, sizeof(exp_version_tlv__au8)))
      {
        FLEA_THROW("PKCS#8 version of invalid content", FLEA_ERR_FAILED_TEST);
      }
    }
#endif /* if 0 */
  }
  else
  {
    FLEA_THROW("unexpected test config", FLEA_ERR_INT_ERR);
  }

  if(err__t != second_func_exp_err_code)
  {
    FLEA_THROW("unexpected error code", FLEA_ERR_FAILED_TEST);
  }
  if(!err__t)
  {
    if(dec_vec__t.len__dtl != sizeof(exp_version_tlv__au8))
    {
      FLEA_THROW("PKCS#8 version of invalid length", FLEA_ERR_FAILED_TEST);
    }
    if(memcmp(exp_version_tlv__au8, dec_vec__t.data__pu8, sizeof(exp_version_tlv__au8)))
    {
      FLEA_THROW("PKCS#8 version of invalid content", FLEA_ERR_FAILED_TEST);
    }
  }


  FLEA_THR_FIN_SEC(
    flea_rw_stream_t__dtor(&strm__t);
    flea_ber_dec_t__dtor(&dec__t);
    flea_byte_vec_t__dtor(&dec_vec__t);
  );
} /* THR_flea_test_ber_dec_opt_and_ref_and_cpy_inner */

flea_err_t THR_flea_test_ber_dec_opt_and_ref_and_cpy()
{
  // FLEA_DECL_BUF(version_buf__bu8, flea_u8_t, 10);
  // flea_dtl_t version_len__dtl = 10;
  // flea_ref_cu8_t oid_ref__t;
  // flea_byte_vec_t oid_vec__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_test_ber_dec_opt_and_ref_and_cpy_inner(
      /* normal mem rd stream */ FLEA_FALSE,
      flea_decode_ref,
      dec_func_cpy,
      dec_func_ref,
      FLEA_ERR_FINE,
      FLEA_ERR_FINE,
      FLEA_ERR_FINE
    )
  );

  /* construction of a decoder using ref decoding as default may not work */
  FLEA_CCALL(
    THR_flea_test_ber_dec_opt_and_ref_and_cpy_inner(
      FLEA_TRUE /* apparent generic rd stream */,
      flea_decode_ref,
      dec_func_cpy,
      dec_func_ref,
      FLEA_ERR_INV_ARG, /*N/A*/
      FLEA_ERR_FINE,    /*N/A*/
      FLEA_ERR_FINE
    )
  );

  FLEA_CCALL(
    // TODO:fails
    THR_flea_test_ber_dec_opt_and_ref_and_cpy_inner(
      FLEA_TRUE /* apparent generic rd stream */,
      flea_decode_copy,
      dec_func_cpy,
      dec_func_cpy,
      FLEA_ERR_FINE,
      FLEA_ERR_FINE,
      FLEA_ERR_FINE
    )
  );

  FLEA_CCALL(
    THR_flea_test_ber_dec_opt_and_ref_and_cpy_inner(
      FLEA_FALSE /* normal mem rd stream */,
      flea_decode_copy,
      dec_func_cpy,
      dec_func_cpy,
      FLEA_ERR_FINE,
      FLEA_ERR_FINE,
      FLEA_ERR_FINE
    )
  );

  /* calling a decode-ref function when the underlying read stream doesn't support
   * static memory pointers, decoding should fail
   */
  FLEA_CCALL(
    THR_flea_test_ber_dec_opt_and_ref_and_cpy_inner(
      FLEA_TRUE /* apparent generic rd stream */,
      flea_decode_copy,
      dec_func_ref,
      dec_func_cpy,
      FLEA_ERR_FINE,
      FLEA_ERR_INV_STATE,
      FLEA_ERR_FINE
    )
  );

  FLEA_CCALL(
    THR_flea_test_ber_dec_opt_and_ref_and_cpy_inner(
      FLEA_TRUE /* apparent generic rd stream */,
      flea_decode_copy,
      dec_func_cpy,
      dec_func_ref, /* this is invalid for a generic stream */
      FLEA_ERR_FINE,
      FLEA_ERR_FINE,
      FLEA_ERR_INV_STATE
    )
  );

  FLEA_CCALL(
    THR_flea_test_ber_dec_opt_and_ref_and_cpy_inner(
      FLEA_TRUE /* apparent generic rd stream */,
      flea_decode_copy,
      dec_func_cpy,
      dec_func_default,
      FLEA_ERR_FINE,
      FLEA_ERR_FINE,
      FLEA_ERR_FINE
    )
  );


  // TODO: ALSO MAKE CALLS WITH DEC_FUNC_DEFAULT
  FLEA_THR_FIN_SEC_empty(
  );
} /* THR_flea_test_ber_dec_opt_and_ref_and_cpy */
