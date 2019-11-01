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

#include "internal/common/default.h"
#include "internal/common/oid.h"

/* ... rsadsi: 1.2.840.113549 */
// subsequent 2 bytes determine encoding method
// ...1 => PKCS
//    ...1 PKCS#1
const flea_u8_t pkcs1_oid_prefix__cau8[8] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01};
//
//    ...7 OAEP
//
// the following and last byte determines the hash algorithm:
//         5 => sha1
//        14 => sha224
//        11 => sha256
//        12 => sha384
//        13 => sha512
