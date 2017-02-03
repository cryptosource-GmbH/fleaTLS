/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "flea/data_source.h"
#include "internal/common/ber_dec.h"
#include "test_data_x509_certs.h"

#include <string.h>

flea_err_t THR_flea_test_ber_dec_basic()
{
  FLEA_DECL_OBJ(source__t, flea_data_source_t);
  FLEA_DECL_OBJ(dec__t, flea_ber_dec_t);
  FLEA_DECL_BUF(version_buf__bu8, flea_u8_t, 10);
  flea_dtl_t version_len__dtl = 10;
  flea_ref_cu8_t oid_ref__t;
  flea_data_source_mem_help_t hlp__t;
  const flea_u8_t *oid__pu8;
  flea_bool_t found_tag__b;
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(version_buf__bu8, 10);
  FLEA_CCALL(THR_flea_data_source_t__ctor_memory(&source__t, flea_test_cert_1__au8, sizeof(flea_test_cert_1__au8), &hlp__t));
  FLEA_CCALL(THR_flea_ber_dec_t__ctor(&dec__t, &source__t, 0));
  FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_optional(&dec__t, FLEA_ASN1_OID, 0, &oid__pu8, &version_len__dtl, &found_tag__b));
  if(found_tag__b)
  {
    FLEA_THROW("optional decoding of missing element", FLEA_ERR_FAILED_TEST);
  }

  FLEA_CCALL(THR_flea_ber_dec_t__open_constructed_optional(&dec__t, 0, FLEA_ASN1_CONSTRUCTED | FLEA_ASN1_CONTEXT_SPECIFIC, &found_tag__b));
  if(found_tag__b)
  {
    FLEA_THROW("optional opening of missing constructed", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CCALL(THR_flea_ber_dec_t__open_constructed_optional(&dec__t, 0, FLEA_ASN1_CONSTRUCTED | FLEA_ASN1_CONTEXT_SPECIFIC, &found_tag__b));
  if(found_tag__b)
  {
    FLEA_THROW("optional opening of missing constructed", FLEA_ERR_FAILED_TEST);
  }
  version_len__dtl = 10;
  FLEA_CCALL(THR_flea_ber_dec_t__open_constructed_optional(&dec__t, FLEA_ASN1_SEQUENCE, FLEA_ASN1_CONSTRUCTED, &found_tag__b));
  if(!found_tag__b)
  {
    FLEA_THROW("optional opening of existing constructed", FLEA_ERR_FAILED_TEST);
  }

  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
  // decode integer serial number
  FLEA_CCALL(THR_flea_ber_dec_t__open_constructed(&dec__t, 0, FLEA_ASN1_CONSTRUCTED | FLEA_ASN1_CONTEXT_SPECIFIC));

  FLEA_CCALL(THR_flea_ber_dec_t__read_value_raw_cft(&dec__t, FLEA_ASN1_CFT_MAKE3(0, 0, FLEA_ASN1_INT), version_buf__bu8, &version_len__dtl));
  if(version_len__dtl != 1 || version_buf__bu8[0] != 1)
  {
    FLEA_THROW("invalid decoded version number", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(&dec__t));
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_skip_remaining(&dec__t));
  FLEA_CCALL(THR_flea_ber_dec_t__open_sequence(&dec__t));
  // decode the OID
  version_len__dtl = 10;
  FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_raw_cft(&dec__t, FLEA_ASN1_CFT_MAKE2(0, FLEA_ASN1_OID), &oid_ref__t));
  if(oid_ref__t.len__dtl != 9)
  {
    FLEA_THROW("invalid decoded OID length", FLEA_ERR_FAILED_TEST);
  }
  if(oid_ref__t.data__pcu8[0] != 0x2A || oid_ref__t.data__pcu8[8] != 0x0B)
  {
    FLEA_THROW("invalid decoded OID", FLEA_ERR_FAILED_TEST);
  }
  if(FLEA_ERR_ASN1_DER_DEC_ERR != THR_flea_ber_dec_t__close_constructed_at_end(&dec__t))
  {
    FLEA_THROW("skipping remaining bytes when requiring constructed to be finished", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_skip_remaining(&dec__t));
  FLEA_THR_FIN_SEC(
    flea_data_source_t__dtor(&source__t);
    flea_ber_dec_t__dtor(&dec__t);
    FLEA_FREE_BUF_FINAL(version_buf__bu8);
  );
} /* THR_flea_test_ber_dec_basic */
