/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "flea/asn1_date.h"
#include "flea/cert_chain.h"
#include "flea/ber_dec.h"
#include "test_data_x509_certs.h"

#include <string.h>

#ifdef FLEA_HAVE_RSA
flea_err_t THR_flea_test_cert_chain_correct_chain_of_two()
{
  FLEA_DECL_OBJ(cert_chain__t, flea_cert_chain_t);
  FLEA_DECL_OBJ(subject, flea_x509_cert_ref_t);
  FLEA_DECL_OBJ(issuer, flea_x509_cert_ref_t);
  const flea_u8_t date_str[] = "170228200000Z";
  flea_gmt_time_t time__t;
flea_err_t err;
FLEA_THR_BEG_FUNC();
FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(&subject, test_cert_tls_server_1, sizeof(test_cert_tls_server_1) ));
FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(&issuer, flea_test_cert_issuer_of_tls_server_1__cau8, sizeof(flea_test_cert_issuer_of_tls_server_1__cau8) ));

FLEA_CCALL(THR_flea_cert_chain_t__ctor(&cert_chain__t, &subject));
FLEA_CCALL(THR_flea_cert_chain_t__add_trust_anchor_cert(&cert_chain__t, &issuer));
FLEA_CCALL(THR_flea_asn1_parse_utc_time(date_str, sizeof(date_str) -1, &time__t));
 err = THR_flea_cert_chain__build_and_verify_cert_chain(&cert_chain__t, &time__t);
#if (defined FLEA_HAVE_RSA) && (FLEA_RSA_MAX_KEY_BIT_SIZE >= 4096)
 if(err)
 {
  FLEA_THROW("error when verifying RSA signed cert chain", err);
 }
#else 
 if(!err)
 {
   // TODO: not yet consistent that this must cause an error
  //FLEA_THROW("no error when verifying RSA signed cert chain but missing algo / key size support", FLEA_ERR_FAILED_TEST);
 }
#endif
FLEA_THR_FIN_SEC(
   flea_cert_chain_t__dtor(&cert_chain__t); 
    );

}

#endif /*  #ifdef FLEA_HAVE_RSA*/
