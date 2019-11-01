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

#ifndef _flea_tls_kex_key_usage__H_
# define _flea_tls_kex_key_usage__H_

# include "flea/types.h"

# ifdef __cplusplus
extern "C" {
# endif

typedef enum { flea_tls_kex__rsa, flea_tls_kex__psa_psk, flea_tls_kex__ecdh_ecdsa, flea_tls_kex__ecdh_rsa,
               flea_tls_kex__ecdhe_rsa, flea_tls_kex__ecdhe_ecdsa } flea_tls_kex_e;

typedef enum { flea_tls_cl_cert__rsa_sign       = 1, flea_tls_cl_cert__ecdsa_sign = 2,
               flea_tls_cl_cert__rsa_fixed_ecdh = 4,
               flea_tls_cl_cert__ecdsa_fixed_e  = 8 } flea_tls_client_cert_type_e;

flea_err_e THR_flea_tls__chck_key_usg_of_server(
  flea_key_usage_t const* key_usage__pt,
  flea_key_usage_t const* extended_key_usage__pt,
  flea_tls_kex_e          kex_type
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_tls__chck_key_usg_of_client(
  flea_key_usage_t const*     key_usage__pt,
  flea_key_usage_t const*     extended_key_usage__pt,
  flea_tls_client_cert_type_e cert_type
) FLEA_ATTRIB_UNUSED_RESULT;

# ifdef __cplusplus
}
# endif

#endif /* h-guard */
