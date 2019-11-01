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

#ifndef _flea_cert_info__H_
#define _flea_cert_info__H_

#include "flea/x509.h"


#ifdef __cplusplus
extern "C" {
#endif


typedef struct
{
  flea_x509_cert_ref_t cert_ref__t;
  flea_byte_vec_t      ref_to_raw_der__rcu8;
  flea_byte_vec_t      ref_to_tbs__rcu8;
  flea_bool_t          is_trusted__b;
} flea_x509_cert_info_t;

#define flea_x509_cert_info_t__INIT(__p) memset(__p, 0, sizeof(*(__p)))

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
