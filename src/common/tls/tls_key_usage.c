/* fleaTLS cryptographic library
Copyright (C) 2015-2019 cryptosource GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/x509.h"
#include "internal/common/tls/tls_key_usage.h"
#include "internal/common/x509_int.h"

flea_err_e THR_flea_tls__chck_key_usg_of_server(
  flea_key_usage_t const* key_usage__pt,
  flea_key_usage_t const* extended_key_usage__pt,
  flea_tls_kex_e          kex_type
)
{
  flea_key_usage_e required_ku_t      = 0;
  flea_ext_key_usage_e required_eku_t = flea_eku_server_auth;

  FLEA_THR_BEG_FUNC();
  switch(kex_type)
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

  if(!flea_x509_has_key_usages(key_usage__pt, required_ku_t, flea_key_usage_implicit) ||
    !flea_x509_has_extended_key_usages(
      extended_key_usage__pt,
      required_eku_t,
      flea_key_usage_implicit
    ))
  {
    FLEA_THROW("invalid key usage for TLS server certificate", FLEA_ERR_TLS_PEER_CERT_INVALID_KEY_USAGE);
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__check_key_usage_for_tls_server */

flea_err_e THR_flea_tls__chck_key_usg_of_client(
  flea_key_usage_t const*     key_usage__pt,
  flea_key_usage_t const*     extended_key_usage__pt,
  flea_tls_client_cert_type_e cert_type
)
{
  flea_key_usage_e required_ku__e      = 0;
  flea_ext_key_usage_e required_eku__e = flea_eku_client_auth;

  FLEA_THR_BEG_FUNC();
  switch(cert_type)
  {
      case flea_tls_cl_cert__rsa_sign:
      case flea_tls_cl_cert__ecdsa_sign:
        required_ku__e = flea_ku_digital_signature;
        break;
      default:
        break;
  }
  if(!flea_x509_has_key_usages(key_usage__pt, required_ku__e, flea_key_usage_implicit) ||
    !flea_x509_has_extended_key_usages(extended_key_usage__pt, required_eku__e, flea_key_usage_implicit))
  {
    FLEA_THROW("invalid key usage for TLS client certificate", FLEA_ERR_TLS_PEER_CERT_INVALID_KEY_USAGE);
  }
  FLEA_THR_FIN_SEC_empty();
}
