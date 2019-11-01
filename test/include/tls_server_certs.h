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

#ifndef _flea_tls_server_certs__H_
#define _flea_tls_server_certs__H_

#include "flea/types.h"
#ifdef __cplusplus
extern "C" {
#endif

extern const flea_u8_t trust_anchor_2048__au8[899];

extern const flea_u8_t server_cert_2048__au8[815];

extern const flea_u8_t server_key_2048__au8[1218];

extern const flea_u8_t trust_anchor_1024__au8[560];

extern const flea_u8_t server_cert_1024__au8[554];

extern const flea_u8_t server_key_1024__au8[635];

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
