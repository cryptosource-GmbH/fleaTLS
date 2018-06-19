/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "internal/common/pubkey_int2.h"
#include "flea/pubkey.h"

#ifdef FLEA_HAVE_ASYM_ALGS
flea_err_e THR_flea_pk_ensure_key_strength(
  flea_pk_sec_lev_e  required_strength__e,
  flea_al_u16_t      key_bit_size__alu16,
  flea_pk_key_type_e key_type
)
{
  FLEA_THR_BEG_FUNC();
  if(key_type == flea_ecc_key)
  {
    if(((flea_al_u16_t) (required_strength__e) * 4) > key_bit_size__alu16)
    {
      FLEA_THROW("public/private EC key size does not meet required security level", FLEA_ERR_PUBKEY_SEC_LEV_NOT_MET);
    }
  }
  else if(key_type == flea_rsa_key)
  {
    if(((required_strength__e == flea_pubkey_80bit) && (key_bit_size__alu16 < 1024)) ||
      ((required_strength__e == flea_pubkey_112bit) && (key_bit_size__alu16 < 2048)) ||
      ((required_strength__e == flea_pubkey_128bit) && (key_bit_size__alu16 < 3072)) ||
      ((required_strength__e == flea_pubkey_192bit) && (key_bit_size__alu16 < 7680)) ||
      ((required_strength__e == flea_pubkey_256bit) && (key_bit_size__alu16 < 15360)))
    {
      FLEA_THROW("public/private RSA key size does not meet required security level", FLEA_ERR_PUBKEY_SEC_LEV_NOT_MET);
    }
  }
  FLEA_THR_FIN_SEC_empty();
}

#endif /* ifdef FLEA_HAVE_ASYM_ALGS */
