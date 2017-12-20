/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_kex_key_usage__H_
#define _flea_tls_kex_key_usage__H_

#include "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { flea_tls_kex__rsa, flea_tls_kex__psa_psk, flea_tls_kex__ecdh_ecdsa, flea_tls_kex__ecdh_rsa,
               flea_tls_kex__ecdhe_rsa, flea_tls_kex__ecdhe_ecdsa } flea_tls_kex_e;

typedef enum { flea_tls_cl_cert__rsa_sign       = 1, flea_tls_cl_cert__ecdsa_sign = 2,
               flea_tls_cl_cert__rsa_fixed_ecdh = 4,
               flea_tls_cl_cert__ecdsa_fixed_e  = 8 } flea_tls_client_cert_type_e;

flea_err_e THR_flea_tls__check_key_usage_of_tls_server(
  flea_key_usage_t const* key_usage__pt,
  flea_key_usage_t const* extended_key_usage__pt,
  flea_tls_kex_e          kex_type
);

flea_err_e THR_flea_tls__check_key_usage_of_tls_client(
  flea_key_usage_t const*     key_usage__pt,
  flea_key_usage_t const*     extended_key_usage__pt,
  flea_tls_client_cert_type_e cert_type
);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
