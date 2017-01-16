/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/x509.h"
#include "internal/common/tls_key_usage.h"

flea_err_t THR_flea_tls__check_key_usage_for_tls_server(const flea_x509_cert_ref_t *server_cert__pt, flea_tls_kex_kex_e kex_type)
{ 
  flea_key_usage_e required_ku_t = 0;
  flea_key_usage_e required_eku_t =  flea_eku_any_ext_ku | flea_eku_server_auth;
  FLEA_THR_BEG_FUNC();
  switch (kex_type)
  {
    case flea_tls_kex__rsa:
    case flea_tls_kex__psa_psk:
      required_ku_t = flea_ku_key_encipherment;
      break;
    case flea_tls_kex__ecdh_ecdsa:
    case flea_tls_kex__ecdh_rsa:
      required_ku_t = flea_ku_key_agreement;
      break;
    case flea_tls_kex__ecdhe_rsa:
    case flea_tls_kex__ecdhe_ecdsa:
      required_ku_t = flea_ku_digital_signature;
      break;
    default:
      break;
  }
  
  if(!flea_x509_has_key_usages(server_cert__pt, flea_key_usage_extension, required_ku_t, flea_key_usage_implicit ) ||
      !flea_x509_has_key_usages(server_cert__pt, flea_extended_key_usage_extension,  required_eku_t, flea_key_usage_implicit))
  {
    FLEA_THROW("invalid key usage for TLS server certificate", FLEA_ERR_TLS_PEER_CERT_INVALID_KEY_USAGE);
  }
  FLEA_THR_FIN_SEC_empty();
}


flea_err_t THR_flea_tls__check_key_usage_for_tls_client(const flea_x509_cert_ref_t *client_cert__pt, flea_tls_client_cert_type_e cert_type)
{

  flea_key_usage_e required_ku__e = 0;
  flea_key_usage_e required_eku__e =  flea_eku_any_ext_ku | flea_eku_client_auth;
  FLEA_THR_BEG_FUNC();
  switch (cert_type)
  {
    case flea_tls_cl_cert__rsa_sign:
    case flea_tls_cl_cert__ecdsa_sign:
      required_ku__e = flea_ku_digital_signature;
      break;
    default:
      break;
  }
  if(!flea_x509_has_key_usages(client_cert__pt, flea_key_usage_extension, required_ku__e, flea_key_usage_implicit ) ||
      !flea_x509_has_key_usages(client_cert__pt, flea_extended_key_usage_extension,  required_eku__e, flea_key_usage_implicit))
  {
    FLEA_THROW("invalid key usage for TLS client certificate", FLEA_ERR_TLS_PEER_CERT_INVALID_KEY_USAGE);
  }
  FLEA_THR_FIN_SEC_empty();
}
