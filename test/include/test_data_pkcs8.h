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


#ifndef _flea_test_data_pkcs8__H_
#define _flea_test_data_pkcs8__H_

#include "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif


extern const flea_u8_t flea_testd_pkcs8_rsa_key_2048_crt__au8[1217];

extern const flea_u8_t flea_testd_pkcs8_ecc_key_secp192r1_explicit_params__au8 [308];

extern const flea_u8_t flea_testd_pkcs8_ecc_key_secp384r1_implicit_params__au8 [185];


#ifdef __cplusplus
}
#endif

#endif /* h-guard */
