/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_kex_key_usage__H_
#define _flea_tls_kex_key_usage__H_

#include "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { flea_tls_kex__rsa, flea_tls_kex__psa_psk, flea_tls_kex__ecdh_ecdsa, flea_tls_kex__ecdh_rsa, flea_tls_kex__ecdhe_rsa, flea_tls_kex__ecdhe_ecdsa } flea_tls_kex_kex_e;

typedef enum { flea_tls_cl_cert__rsa_sign, flea_tls_cl_cert__ecdsa_sign, flea_tls_cl_cert__rsa_fixed_ecdh, flea_tls_cl_cert__ecdsa_fixed_e } flea_tls_client_cert_type_e;

flea_err_t
THR_flea_tls__check_key_usage_for_tls_server(const flea_x509_cert_ref_t *server_cert__pt, flea_tls_kex_kex_e kex_type);

flea_err_t
THR_flea_tls__check_key_usage_for_tls_client(const flea_x509_cert_ref_t *client_cert__pt, flea_tls_client_cert_type_e cert_type);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
