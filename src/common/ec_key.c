/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/ec_key.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "internal/common/ber_dec.h"

#define FLEA_X509_ECC_POINT_FORMAT_UNCOMPRESSED 0x04

flea_al_u8_t flea_ecc_key__get_coordinate_len_from_encoded_point(const flea_ref_cu8_t *encoded__pt)
{
  if(!(encoded__pt->len__dtl % 2) || encoded__pt->len__dtl > FLEA_ECC_MAX_ENCODED_POINT_LEN || encoded__pt->data__pcu8[0] != FLEA_X509_ECC_POINT_FORMAT_UNCOMPRESSED)
  {
    return 0;
  }
  return (encoded__pt->len__dtl - 1) / 2;
}

flea_err_t THR_flea_ec_key__decode_uncompressed_point(const flea_ref_cu8_t *encoded__pt, flea_ref_cu8_t *x__pt, flea_ref_cu8_t *y__pt)
{
  flea_dtl_t len__dtl;

  FLEA_THR_BEG_FUNC();
  if(0 == (len__dtl = flea_ecc_key__get_coordinate_len_from_encoded_point(encoded__pt)))
  {
    FLEA_THROW("error with encoded public point", FLEA_ERR_X509_INV_ECC_POINT_ENCODING);
  }
  x__pt->data__pcu8 = &encoded__pt->data__pcu8[1];
  x__pt->len__dtl   = len__dtl;
  y__pt->data__pcu8 = &encoded__pt->data__pcu8[1 + len__dtl];
  y__pt->len__dtl   = len__dtl;
  FLEA_THR_FIN_SEC_empty();
}
