/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "flea/privkey.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/namespace_asn1.h"
#include "flea/x509.h"
#include "flea/ec_key.h"
#include "flea/util.h"
#include "flea/bin_utils.h"
#include "flea/pk_api.h"
#include "flea/ecc_named_curves.h"

flea_err_t THR_flea_private_key_t__ctor_internal_format(flea_private_key_t *key__pt, flea_pk_key_type_t key_type, const flea_ref_cu8_t* priv_key_enc_internal_format__prcu8, const flea_ref_cu8_t *flea_)
{

  FLEA_THR_BEG_FUNC();
#ifdef FLEA_HAVE_ECC
  if(key_type == flea_ecc_key)
  {
    
  }
  else
#endif
#ifdef FLEA_HAVE_RSA
  if(key_type == flea_rsa_key)
  {

  }
  else
#endif
  {  
    FLEA_THROW("construction of private key failed, key type not supported", FLEA_ERR_X509_UNSUPP_PRIMITIVE);
  }

   
  FLEA_THR_FIN_SEC_empty();
}

// decrypt: only RSA exists => params not needed at all
//
// sign: pk_signer-final already works with param_u

