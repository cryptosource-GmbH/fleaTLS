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
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "flea/asn1_date.h"
#include "flea/cert_path.h"
#include "internal/common/ber_dec.h"
#include "flea/cert_store.h"
#include "test_data_x509_certs.h"
#include "self_test.h"

#include <string.h>

#ifdef FLEA_HAVE_ASYM_SIG

const flea_u8_t tls_cert_chain__acu8 [] = {
  0x00, 0x05, 0x40, 0x30, 0x82, 0x05, 0x3c, 0x30, 0x82, 0x04, 0x24, 0xa0, 0x03, 0x02, 0x01, 0x02,
  0x02, 0x10, 0x52, 0x43, 0x4d, 0x90, 0x5e, 0x3f, 0x4f, 0x0b, 0x80, 0x37, 0x45, 0x77, 0xa9, 0x8f,
  0x70, 0xd8, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
  0x00, 0x30, 0x81, 0x90, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x47,
  0x42, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x12, 0x47, 0x72, 0x65, 0x61,
  0x74, 0x65, 0x72, 0x20, 0x4d, 0x61, 0x6e, 0x63, 0x68, 0x65, 0x73, 0x74, 0x65, 0x72, 0x31, 0x10,
  0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x53, 0x61, 0x6c, 0x66, 0x6f, 0x72, 0x64,
  0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x11, 0x43, 0x4f, 0x4d, 0x4f, 0x44,
  0x4f, 0x20, 0x43, 0x41, 0x20, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x65, 0x64, 0x31, 0x36, 0x30, 0x34,
  0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x2d, 0x43, 0x4f, 0x4d, 0x4f, 0x44, 0x4f, 0x20, 0x52, 0x53,
  0x41, 0x20, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x20, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74,
  0x69, 0x6f, 0x6e, 0x20, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65,
  0x72, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x35, 0x31, 0x30, 0x30, 0x31, 0x30, 0x30,
  0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x31, 0x37, 0x31, 0x32, 0x32, 0x39, 0x32, 0x33, 0x35,
  0x39, 0x35, 0x39, 0x5a, 0x30, 0x4c, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13,
  0x18, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x20,
  0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x64, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55,
  0x04, 0x0b, 0x13, 0x0b, 0x50, 0x6f, 0x73, 0x69, 0x74, 0x69, 0x76, 0x65, 0x53, 0x53, 0x4c, 0x31,
  0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x08, 0x68, 0x65, 0x69, 0x73, 0x65, 0x2e,
  0x64, 0x65, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
  0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82,
  0x01, 0x01, 0x00, 0xb8, 0xe3, 0x3a, 0xd9, 0xdb, 0x88, 0xc6, 0xde, 0x9d, 0x7e, 0xbf, 0xcc, 0x5a,
  0x53, 0xfc, 0x45, 0x01, 0x9a, 0x29, 0x19, 0xaf, 0xf3, 0xc1, 0x4b, 0xad, 0x20, 0x1b, 0xc3, 0xb3,
  0xa1, 0x26, 0x61, 0x51, 0xf6, 0x6c, 0xec, 0x54, 0x9d, 0xf8, 0x8e, 0xd0, 0xc4, 0x9f, 0x07, 0x33,
  0x18, 0x68, 0x12, 0x9f, 0x8a, 0xbd, 0xc8, 0xf7, 0xf7, 0xce, 0xd9, 0x0e, 0x87, 0x8c, 0xec, 0xeb,
  0x22, 0x06, 0x51, 0x29, 0xd6, 0x84, 0xd5, 0x2c, 0x7b, 0x52, 0xed, 0x9f, 0xd3, 0x9d, 0x5f, 0x25,
  0x38, 0xdf, 0x23, 0x2c, 0x46, 0x13, 0x1c, 0xa8, 0x35, 0xf2, 0xb2, 0xf3, 0x4b, 0xd8, 0x1b, 0x5b,
  0x89, 0x31, 0x3c, 0xb9, 0x2d, 0xe7, 0xb7, 0x34, 0x06, 0xeb, 0x5a, 0xe4, 0xd3, 0xe5, 0xd8, 0xe5,
  0xa2, 0xc1, 0x9f, 0xe2, 0xef, 0x15, 0x2a, 0xa8, 0xd5, 0x54, 0xce, 0x68, 0xbe, 0xd6, 0xe1, 0x3c,
  0x2d, 0x19, 0xc8, 0x8b, 0xa0, 0x4e, 0x65, 0x41, 0x68, 0x46, 0x1a, 0x24, 0x7d, 0xb6, 0x9c, 0x01,
  0x22, 0x79, 0x14, 0x31, 0x10, 0xac, 0xa8, 0x88, 0x88, 0xea, 0x62, 0x7a, 0x9f, 0xc7, 0x7d, 0x74,
  0x93, 0x9c, 0x17, 0x58, 0x6e, 0x96, 0x6f, 0xbb, 0x3d, 0x50, 0x8c, 0xeb, 0x15, 0x95, 0xa1, 0x14,
  0x2f, 0xfc, 0x8e, 0xfb, 0xf8, 0x0b, 0x5a, 0xa2, 0x53, 0xe0, 0x08, 0x17, 0x80, 0x16, 0xfd, 0xa1,
  0x3f, 0xc0, 0xc9, 0x36, 0xd1, 0xd2, 0x8b, 0x46, 0xc7, 0xf5, 0x98, 0xbd, 0xf9, 0x99, 0xb6, 0x17,
  0xd9, 0xb3, 0xf2, 0xec, 0xa5, 0x49, 0xf1, 0x31, 0xd3, 0x02, 0x34, 0x00, 0x0d, 0xff, 0xd3, 0x67,
  0xc1, 0xf0, 0x21, 0x05, 0x74, 0xd6, 0x54, 0x38, 0x49, 0xb7, 0x7a, 0x3a, 0x11, 0x47, 0x40, 0x59,
  0x6b, 0xc1, 0x03, 0x9e, 0x67, 0x32, 0x29, 0xcb, 0xd1, 0xcc, 0xa3, 0x9a, 0xb8, 0x93, 0xaa, 0x6c,
  0x2b, 0x17, 0xa1, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x82, 0x01, 0xd3, 0x30, 0x82, 0x01, 0xcf,
  0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x90, 0xaf, 0x6a,
  0x3a, 0x94, 0x5a, 0x0b, 0xd8, 0x90, 0xea, 0x12, 0x56, 0x73, 0xdf, 0x43, 0xb4, 0x3a, 0x28, 0xda,
  0xe7, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xda, 0xfb, 0x9f, 0xef,
  0x75, 0x37, 0xed, 0x4b, 0xed, 0x75, 0x50, 0x87, 0x07, 0xd5, 0x6a, 0x38, 0xca, 0xd8, 0x28, 0x20,
  0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0,
  0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x1d,
  0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
  0x07, 0x03, 0x01, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x30, 0x4f, 0x06,
  0x03, 0x55, 0x1d, 0x20, 0x04, 0x48, 0x30, 0x46, 0x30, 0x3a, 0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04,
  0x01, 0xb2, 0x31, 0x01, 0x02, 0x02, 0x07, 0x30, 0x2b, 0x30, 0x29, 0x06, 0x08, 0x2b, 0x06, 0x01,
  0x05, 0x05, 0x07, 0x02, 0x01, 0x16, 0x1d, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x73,
  0x65, 0x63, 0x75, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6f, 0x64, 0x6f, 0x2e, 0x63, 0x6f, 0x6d,
  0x2f, 0x43, 0x50, 0x53, 0x30, 0x08, 0x06, 0x06, 0x67, 0x81, 0x0c, 0x01, 0x02, 0x01, 0x30, 0x54,
  0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x4d, 0x30, 0x4b, 0x30, 0x49, 0xa0, 0x47, 0xa0, 0x45, 0x86,
  0x43, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x72, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x6f,
  0x64, 0x6f, 0x63, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x43, 0x4f, 0x4d, 0x4f, 0x44, 0x4f, 0x52,
  0x53, 0x41, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69,
  0x6f, 0x6e, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x43, 0x41,
  0x2e, 0x63, 0x72, 0x6c, 0x30, 0x81, 0x85, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01,
  0x01, 0x04, 0x79, 0x30, 0x77, 0x30, 0x4f, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30,
  0x02, 0x86, 0x43, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x72, 0x74, 0x2e, 0x63, 0x6f,
  0x6d, 0x6f, 0x64, 0x6f, 0x63, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x43, 0x4f, 0x4d, 0x4f, 0x44,
  0x4f, 0x52, 0x53, 0x41, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61,
  0x74, 0x69, 0x6f, 0x6e, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72,
  0x43, 0x41, 0x2e, 0x63, 0x72, 0x74, 0x30, 0x24, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
  0x30, 0x01, 0x86, 0x18, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x63, 0x73, 0x70, 0x2e,
  0x63, 0x6f, 0x6d, 0x6f, 0x64, 0x6f, 0x63, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x21, 0x06, 0x03,
  0x55, 0x1d, 0x11, 0x04, 0x1a, 0x30, 0x18, 0x82, 0x08, 0x68, 0x65, 0x69, 0x73, 0x65, 0x2e, 0x64,
  0x65, 0x82, 0x0c, 0x77, 0x77, 0x77, 0x2e, 0x68, 0x65, 0x69, 0x73, 0x65, 0x2e, 0x64, 0x65, 0x30,
  0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82,
  0x01, 0x01, 0x00, 0x7f, 0xf6, 0xe8, 0xaa, 0x1b, 0x75, 0x96, 0xee, 0xd6, 0xd9, 0xe9, 0xac, 0x0c,
  0x46, 0xee, 0xea, 0x93, 0x20, 0x54, 0xfd, 0xa0, 0xb1, 0x0d, 0x60, 0xc4, 0x92, 0xfa, 0x81, 0x2d,
  0x61, 0xd7, 0xb5, 0x8e, 0x10, 0x0e, 0x4a, 0xe3, 0xe7, 0x6f, 0x24, 0xab, 0x37, 0xab, 0xc8, 0x17,
  0x3c, 0xb0, 0xac, 0x3c, 0x45, 0x50, 0xc8, 0x9b, 0xac, 0x78, 0x70, 0x8c, 0xec, 0x59, 0x0d, 0x55,
  0x83, 0xa1, 0xef, 0x2f, 0x46, 0x15, 0x96, 0x96, 0x05, 0xae, 0x5f, 0x25, 0x15, 0x81, 0xfc, 0xb7,
  0x1c, 0xde, 0xda, 0x0d, 0x17, 0x3d, 0xe0, 0x07, 0x02, 0xa3, 0x8d, 0x19, 0xa2, 0xce, 0x9a, 0x54,
  0x43, 0x6a, 0xc5, 0x43, 0xf8, 0x7c, 0x67, 0x5b, 0x65, 0xa3, 0x8a, 0xfd, 0x50, 0xcb, 0x73, 0x4b,
  0x37, 0x76, 0xec, 0xab, 0x99, 0x8b, 0x03, 0x8f, 0x3b, 0xb6, 0x13, 0xa4, 0xb6, 0x01, 0x6c, 0xde,
  0xb8, 0x2a, 0xf2, 0x2d, 0xd2, 0x89, 0xf4, 0x7d, 0x4f, 0xda, 0x0b, 0x9c, 0x40, 0x49, 0xf3, 0xc6,
  0xe8, 0x4e, 0x5b, 0xe2, 0xa8, 0x25, 0x09, 0xd0, 0x50, 0x3f, 0xa1, 0x23, 0x1b, 0x58, 0xa7, 0x86,
  0x40, 0x69, 0xd2, 0x8f, 0x3a, 0x22, 0x62, 0xbd, 0xda, 0x0b, 0x23, 0xb9, 0x2c, 0xa0, 0xfa, 0x65,
  0x73, 0x01, 0x9c, 0x33, 0xf5, 0x56, 0x8f, 0x16, 0xd0, 0x25, 0x1f, 0x96, 0xc8, 0xeb, 0xc5, 0x66,
  0xc9, 0x5c, 0xdd, 0x0b, 0xe3, 0x29, 0xa5, 0xc6, 0x35, 0x89, 0xcb, 0xfb, 0x4f, 0xef, 0x87, 0x6e,
  0xe0, 0x57, 0x13, 0x01, 0x13, 0x93, 0x09, 0xe4, 0x9c, 0xe1, 0xd5, 0x3b, 0x7f, 0x1d, 0x53, 0xa3,
  0xc7, 0x27, 0xab, 0xb9, 0x44, 0xf5, 0x3a, 0x4c, 0x54, 0x4d, 0xbc, 0x21, 0x8b, 0xd1, 0xb3, 0x76,
  0x7e, 0xa3, 0x11, 0x1d, 0x86, 0x1c, 0x66, 0x44, 0xf1, 0xff, 0x68, 0xb1, 0x0c, 0x1a, 0x4c, 0x2b,
  0xc2, 0x03, 0xa2, 0x00, 0x06, 0x0c, 0x30, 0x82, 0x06, 0x08, 0x30, 0x82, 0x03, 0xf0, 0xa0, 0x03,
  0x02, 0x01, 0x02, 0x02, 0x10, 0x2b, 0x2e, 0x6e, 0xea, 0xd9, 0x75, 0x36, 0x6c, 0x14, 0x8a, 0x6e,
  0xdb, 0xa3, 0x7c, 0x8c, 0x07, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
  0x01, 0x0c, 0x05, 0x00, 0x30, 0x81, 0x85, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
  0x13, 0x02, 0x47, 0x42, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x12, 0x47,
  0x72, 0x65, 0x61, 0x74, 0x65, 0x72, 0x20, 0x4d, 0x61, 0x6e, 0x63, 0x68, 0x65, 0x73, 0x74, 0x65,
  0x72, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x53, 0x61, 0x6c, 0x66,
  0x6f, 0x72, 0x64, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x11, 0x43, 0x4f,
  0x4d, 0x4f, 0x44, 0x4f, 0x20, 0x43, 0x41, 0x20, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x65, 0x64, 0x31,
  0x2b, 0x30, 0x29, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x22, 0x43, 0x4f, 0x4d, 0x4f, 0x44, 0x4f,
  0x20, 0x52, 0x53, 0x41, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69,
  0x6f, 0x6e, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x30, 0x1e, 0x17, 0x0d,
  0x31, 0x34, 0x30, 0x32, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32,
  0x39, 0x30, 0x32, 0x31, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x81, 0x90, 0x31,
  0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x47, 0x42, 0x31, 0x1b, 0x30, 0x19,
  0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x12, 0x47, 0x72, 0x65, 0x61, 0x74, 0x65, 0x72, 0x20, 0x4d,
  0x61, 0x6e, 0x63, 0x68, 0x65, 0x73, 0x74, 0x65, 0x72, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55,
  0x04, 0x07, 0x13, 0x07, 0x53, 0x61, 0x6c, 0x66, 0x6f, 0x72, 0x64, 0x31, 0x1a, 0x30, 0x18, 0x06,
  0x03, 0x55, 0x04, 0x0a, 0x13, 0x11, 0x43, 0x4f, 0x4d, 0x4f, 0x44, 0x4f, 0x20, 0x43, 0x41, 0x20,
  0x4c, 0x69, 0x6d, 0x69, 0x74, 0x65, 0x64, 0x31, 0x36, 0x30, 0x34, 0x06, 0x03, 0x55, 0x04, 0x03,
  0x13, 0x2d, 0x43, 0x4f, 0x4d, 0x4f, 0x44, 0x4f, 0x20, 0x52, 0x53, 0x41, 0x20, 0x44, 0x6f, 0x6d,
  0x61, 0x69, 0x6e, 0x20, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x53,
  0x65, 0x63, 0x75, 0x72, 0x65, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x43, 0x41, 0x30,
  0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
  0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00,
  0x8e, 0xc2, 0x02, 0x19, 0xe1, 0xa0, 0x59, 0xa4, 0xeb, 0x38, 0x35, 0x8d, 0x2c, 0xfd, 0x01, 0xd0,
  0xd3, 0x49, 0xc0, 0x64, 0xc7, 0x0b, 0x62, 0x05, 0x45, 0x16, 0x3a, 0xa8, 0xa0, 0xc0, 0x0c, 0x02,
  0x7f, 0x1d, 0xcc, 0xdb, 0xc4, 0xa1, 0x6d, 0x77, 0x03, 0xa3, 0x0f, 0x86, 0xf9, 0xe3, 0x06, 0x9c,
  0x3e, 0x0b, 0x81, 0x8a, 0x9b, 0x49, 0x1b, 0xad, 0x03, 0xbe, 0xfa, 0x4b, 0xdb, 0x8c, 0x20, 0xed,
  0xd5, 0xce, 0x5e, 0x65, 0x8e, 0x3e, 0x0d, 0xaf, 0x4c, 0xc2, 0xb0, 0xb7, 0x45, 0x5e, 0x52, 0x2f,
  0x34, 0xde, 0x48, 0x24, 0x64, 0xb4, 0x41, 0xae, 0x00, 0x97, 0xf7, 0xbe, 0x67, 0xde, 0x9e, 0xd0,
  0x7a, 0xa7, 0x53, 0x80, 0x3b, 0x7c, 0xad, 0xf5, 0x96, 0x55, 0x6f, 0x97, 0x47, 0x0a, 0x7c, 0x85,
  0x8b, 0x22, 0x97, 0x8d, 0xb3, 0x84, 0xe0, 0x96, 0x57, 0xd0, 0x70, 0x18, 0x60, 0x96, 0x8f, 0xee,
  0x2d, 0x07, 0x93, 0x9d, 0xa1, 0xba, 0xca, 0xd1, 0xcd, 0x7b, 0xe9, 0xc4, 0x2a, 0x9a, 0x28, 0x21,
  0x91, 0x4d, 0x6f, 0x92, 0x4f, 0x25, 0xa5, 0xf2, 0x7a, 0x35, 0xdd, 0x26, 0xdc, 0x46, 0xa5, 0xd0,
  0xac, 0x59, 0x35, 0x8c, 0xff, 0x4e, 0x91, 0x43, 0x50, 0x3f, 0x59, 0x93, 0x1e, 0x6c, 0x51, 0x21,
  0xee, 0x58, 0x14, 0xab, 0xfe, 0x75, 0x50, 0x78, 0x3e, 0x4c, 0xb0, 0x1c, 0x86, 0x13, 0xfa, 0x6b,
  0x98, 0xbc, 0xe0, 0x3b, 0x94, 0x1e, 0x85, 0x52, 0xdc, 0x03, 0x93, 0x24, 0x18, 0x6e, 0xcb, 0x27,
  0x51, 0x45, 0xe6, 0x70, 0xde, 0x25, 0x43, 0xa4, 0x0d, 0xe1, 0x4a, 0xa5, 0xed, 0xb6, 0x7e, 0xc8,
  0xcd, 0x6d, 0xee, 0x2e, 0x1d, 0x27, 0x73, 0x5d, 0xdc, 0x45, 0x30, 0x80, 0xaa, 0xe3, 0xb2, 0x41,
  0x0b, 0xaf, 0xbd, 0x44, 0x87, 0xda, 0xb9, 0xe5, 0x1b, 0x9d, 0x7f, 0xae, 0xe5, 0x85, 0x82, 0xa5,
  0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x82, 0x01, 0x65, 0x30, 0x82, 0x01, 0x61, 0x30, 0x1f, 0x06,
  0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xbb, 0xaf, 0x7e, 0x02, 0x3d, 0xfa,
  0xa6, 0xf1, 0x3c, 0x84, 0x8e, 0xad, 0xee, 0x38, 0x98, 0xec, 0xd9, 0x32, 0x32, 0xd4, 0x30, 0x1d,
  0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x90, 0xaf, 0x6a, 0x3a, 0x94, 0x5a, 0x0b,
  0xd8, 0x90, 0xea, 0x12, 0x56, 0x73, 0xdf, 0x43, 0xb4, 0x3a, 0x28, 0xda, 0xe7, 0x30, 0x0e, 0x06,
  0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x12, 0x06,
  0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01,
  0x00, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2b, 0x06,
  0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
  0x30, 0x1b, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x14, 0x30, 0x12, 0x30, 0x06, 0x06, 0x04, 0x55,
  0x1d, 0x20, 0x00, 0x30, 0x08, 0x06, 0x06, 0x67, 0x81, 0x0c, 0x01, 0x02, 0x01, 0x30, 0x4c, 0x06,
  0x03, 0x55, 0x1d, 0x1f, 0x04, 0x45, 0x30, 0x43, 0x30, 0x41, 0xa0, 0x3f, 0xa0, 0x3d, 0x86, 0x3b,
  0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x72, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x6f, 0x64,
  0x6f, 0x63, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x43, 0x4f, 0x4d, 0x4f, 0x44, 0x4f, 0x52, 0x53,
  0x41, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x41, 0x75,
  0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x71, 0x06, 0x08, 0x2b,
  0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x65, 0x30, 0x63, 0x30, 0x3b, 0x06, 0x08, 0x2b,
  0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f,
  0x63, 0x72, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x6f, 0x64, 0x6f, 0x63, 0x61, 0x2e, 0x63, 0x6f, 0x6d,
  0x2f, 0x43, 0x4f, 0x4d, 0x4f, 0x44, 0x4f, 0x52, 0x53, 0x41, 0x41, 0x64, 0x64, 0x54, 0x72, 0x75,
  0x73, 0x74, 0x43, 0x41, 0x2e, 0x63, 0x72, 0x74, 0x30, 0x24, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
  0x05, 0x07, 0x30, 0x01, 0x86, 0x18, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x63, 0x73,
  0x70, 0x2e, 0x63, 0x6f, 0x6d, 0x6f, 0x64, 0x6f, 0x63, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x0d,
  0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x05, 0x00, 0x03, 0x82, 0x02,
  0x01, 0x00, 0x4e, 0x2b, 0x76, 0x4f, 0x92, 0x1c, 0x62, 0x36, 0x89, 0xba, 0x77, 0xc1, 0x27, 0x05,
  0xf4, 0x1c, 0xd6, 0x44, 0x9d, 0xa9, 0x9a, 0x3e, 0xaa, 0xd5, 0x66, 0x66, 0x01, 0x3e, 0xea, 0x49,
  0xe6, 0xa2, 0x35, 0xbc, 0xfa, 0xf6, 0xdd, 0x95, 0x8e, 0x99, 0x35, 0x98, 0x0e, 0x36, 0x18, 0x75,
  0xb1, 0xdd, 0xdd, 0x50, 0x72, 0x7c, 0xae, 0xdc, 0x77, 0x88, 0xce, 0x0f, 0xf7, 0x90, 0x20, 0xca,
  0xa3, 0x67, 0x2e, 0x1f, 0x56, 0x7f, 0x7b, 0xe1, 0x44, 0xea, 0x42, 0x95, 0xc4, 0x5d, 0x0d, 0x01,
  0x50, 0x46, 0x15, 0xf2, 0x81, 0x89, 0x59, 0x6c, 0x8a, 0xdd, 0x8c, 0xf1, 0x12, 0xa1, 0x8d, 0x3a,
  0x42, 0x8a, 0x98, 0xf8, 0x4b, 0x34, 0x7b, 0x27, 0x3b, 0x08, 0xb4, 0x6f, 0x24, 0x3b, 0x72, 0x9d,
  0x63, 0x74, 0x58, 0x3c, 0x1a, 0x6c, 0x3f, 0x4f, 0xc7, 0x11, 0x9a, 0xc8, 0xa8, 0xf5, 0xb5, 0x37,
  0xef, 0x10, 0x45, 0xc6, 0x6c, 0xd9, 0xe0, 0x5e, 0x95, 0x26, 0xb3, 0xeb, 0xad, 0xa3, 0xb9, 0xee,
  0x7f, 0x0c, 0x9a, 0x66, 0x35, 0x73, 0x32, 0x60, 0x4e, 0xe5, 0xdd, 0x8a, 0x61, 0x2c, 0x6e, 0x52,
  0x11, 0x77, 0x68, 0x96, 0xd3, 0x18, 0x75, 0x51, 0x15, 0x00, 0x1b, 0x74, 0x88, 0xdd, 0xe1, 0xc7,
  0x38, 0x04, 0x43, 0x28, 0xe9, 0x16, 0xfd, 0xd9, 0x05, 0xd4, 0x5d, 0x47, 0x27, 0x60, 0xd6, 0xfb,
  0x38, 0x3b, 0x6c, 0x72, 0xa2, 0x94, 0xf8, 0x42, 0x1a, 0xdf, 0xed, 0x6f, 0x06, 0x8c, 0x45, 0xc2,
  0x06, 0x00, 0xaa, 0xe4, 0xe8, 0xdc, 0xd9, 0xb5, 0xe1, 0x73, 0x78, 0xec, 0xf6, 0x23, 0xdc, 0xd1,
  0xdd, 0x6c, 0x8e, 0x1a, 0x8f, 0xa5, 0xea, 0x54, 0x7c, 0x96, 0xb7, 0xc3, 0xfe, 0x55, 0x8e, 0x8d,
  0x49, 0x5e, 0xfc, 0x64, 0xbb, 0xcf, 0x3e, 0xbd, 0x96, 0xeb, 0x69, 0xcd, 0xbf, 0xe0, 0x48, 0xf1,
  0x62, 0x82, 0x10, 0xe5, 0x0c, 0x46, 0x57, 0xf2, 0x33, 0xda, 0xd0, 0xc8, 0x63, 0xed, 0xc6, 0x1f,
  0x94, 0x05, 0x96, 0x4a, 0x1a, 0x91, 0xd1, 0xf7, 0xeb, 0xcf, 0x8f, 0x52, 0xae, 0x0d, 0x08, 0xd9,
  0x3e, 0xa8, 0xa0, 0x51, 0xe9, 0xc1, 0x87, 0x74, 0xd5, 0xc9, 0xf7, 0x74, 0xab, 0x2e, 0x53, 0xfb,
  0xbb, 0x7a, 0xfb, 0x97, 0xe2, 0xf8, 0x1f, 0x26, 0x8f, 0xb3, 0xd2, 0xa0, 0xe0, 0x37, 0x5b, 0x28,
  0x3b, 0x31, 0xe5, 0x0e, 0x57, 0x2d, 0x5a, 0xb8, 0xad, 0x79, 0xac, 0x5e, 0x20, 0x66, 0x1a, 0xa5,
  0xb9, 0xa6, 0xb5, 0x39, 0xc1, 0xf5, 0x98, 0x43, 0xff, 0xee, 0xf9, 0xa7, 0xa7, 0xfd, 0xee, 0xca,
  0x24, 0x3d, 0x80, 0x16, 0xc4, 0x17, 0x8f, 0x8a, 0xc1, 0x60, 0xa1, 0x0c, 0xae, 0x5b, 0x43, 0x47,
  0x91, 0x4b, 0xd5, 0x9a, 0x17, 0x5f, 0xf9, 0xd4, 0x87, 0xc1, 0xc2, 0x8c, 0xb7, 0xe7, 0xe2, 0x0f,
  0x30, 0x19, 0x37, 0x86, 0xac, 0xe0, 0xdc, 0x42, 0x03, 0xe6, 0x94, 0xa8, 0x9d, 0xae, 0xfd, 0x0f,
  0x24, 0x51, 0x94, 0xce, 0x92, 0x08, 0xd1, 0xfc, 0x50, 0xf0, 0x03, 0x40, 0x7b, 0x88, 0x59, 0xed,
  0x0e, 0xdd, 0xac, 0xd2, 0x77, 0x82, 0x34, 0xdc, 0x06, 0x95, 0x02, 0xd8, 0x90, 0xf9, 0x2d, 0xea,
  0x37, 0xd5, 0x1a, 0x60, 0xd0, 0x67, 0x20, 0xd7, 0xd8, 0x42, 0x0b, 0x45, 0xaf, 0x82, 0x68, 0xde,
  0xdd, 0x66, 0x24, 0x37, 0x90, 0x29, 0x94, 0x19, 0x46, 0x19, 0x25, 0xb8, 0x80, 0xd7, 0xcb, 0xd4,
  0x86, 0x28, 0x6a, 0x44, 0x70, 0x26, 0x23, 0x62, 0xa9, 0x9f, 0x86, 0x6f, 0xbf, 0xba, 0x90, 0x70,
  0xd2, 0x56, 0x77, 0x85, 0x78, 0xef, 0xea, 0x25, 0xa9, 0x17, 0xce, 0x50, 0x72, 0x8c, 0x00, 0x3a,
  0xaa, 0xe3, 0xdb, 0x63, 0x34, 0x9f, 0xf8, 0x06, 0x71, 0x01, 0xe2, 0x82, 0x20, 0xd4, 0xfe, 0x6f,
  0xbd, 0xb1, 0x00, 0x05, 0x78, 0x30, 0x82, 0x05, 0x74, 0x30, 0x82, 0x04, 0x5c, 0xa0, 0x03, 0x02,
  0x01, 0x02, 0x02, 0x10, 0x27, 0x66, 0xee, 0x56, 0xeb, 0x49, 0xf3, 0x8e, 0xab, 0xd7, 0x70, 0xa2,
  0xfc, 0x84, 0xde, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
  0x0c, 0x05, 0x00, 0x30, 0x6f, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
  0x53, 0x45, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0b, 0x41, 0x64, 0x64,
  0x54, 0x72, 0x75, 0x73, 0x74, 0x20, 0x41, 0x42, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55, 0x04,
  0x0b, 0x13, 0x1d, 0x41, 0x64, 0x64, 0x54, 0x72, 0x75, 0x73, 0x74, 0x20, 0x45, 0x78, 0x74, 0x65,
  0x72, 0x6e, 0x61, 0x6c, 0x20, 0x54, 0x54, 0x50, 0x20, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
  0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x19, 0x41, 0x64, 0x64, 0x54, 0x72,
  0x75, 0x73, 0x74, 0x20, 0x45, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x20, 0x43, 0x41, 0x20,
  0x52, 0x6f, 0x6f, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x30, 0x30, 0x30, 0x35, 0x33, 0x30, 0x31, 0x30,
  0x34, 0x38, 0x33, 0x38, 0x5a, 0x17, 0x0d, 0x32, 0x30, 0x30, 0x35, 0x33, 0x30, 0x31, 0x30, 0x34,
  0x38, 0x33, 0x38, 0x5a, 0x30, 0x81, 0x85, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
  0x13, 0x02, 0x47, 0x42, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x12, 0x47,
  0x72, 0x65, 0x61, 0x74, 0x65, 0x72, 0x20, 0x4d, 0x61, 0x6e, 0x63, 0x68, 0x65, 0x73, 0x74, 0x65,
  0x72, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x53, 0x61, 0x6c, 0x66,
  0x6f, 0x72, 0x64, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x11, 0x43, 0x4f,
  0x4d, 0x4f, 0x44, 0x4f, 0x20, 0x43, 0x41, 0x20, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x65, 0x64, 0x31,
  0x2b, 0x30, 0x29, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x22, 0x43, 0x4f, 0x4d, 0x4f, 0x44, 0x4f,
  0x20, 0x52, 0x53, 0x41, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69,
  0x6f, 0x6e, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x30, 0x82, 0x02, 0x22,
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03,
  0x82, 0x02, 0x0f, 0x00, 0x30, 0x82, 0x02, 0x0a, 0x02, 0x82, 0x02, 0x01, 0x00, 0x91, 0xe8, 0x54,
  0x92, 0xd2, 0x0a, 0x56, 0xb1, 0xac, 0x0d, 0x24, 0xdd, 0xc5, 0xcf, 0x44, 0x67, 0x74, 0x99, 0x2b,
  0x37, 0xa3, 0x7d, 0x23, 0x70, 0x00, 0x71, 0xbc, 0x53, 0xdf, 0xc4, 0xfa, 0x2a, 0x12, 0x8f, 0x4b,
  0x7f, 0x10, 0x56, 0xbd, 0x9f, 0x70, 0x72, 0xb7, 0x61, 0x7f, 0xc9, 0x4b, 0x0f, 0x17, 0xa7, 0x3d,
  0xe3, 0xb0, 0x04, 0x61, 0xee, 0xff, 0x11, 0x97, 0xc7, 0xf4, 0x86, 0x3e, 0x0a, 0xfa, 0x3e, 0x5c,
  0xf9, 0x93, 0xe6, 0x34, 0x7a, 0xd9, 0x14, 0x6b, 0xe7, 0x9c, 0xb3, 0x85, 0xa0, 0x82, 0x7a, 0x76,
  0xaf, 0x71, 0x90, 0xd7, 0xec, 0xfd, 0x0d, 0xfa, 0x9c, 0x6c, 0xfa, 0xdf, 0xb0, 0x82, 0xf4, 0x14,
  0x7e, 0xf9, 0xbe, 0xc4, 0xa6, 0x2f, 0x4f, 0x7f, 0x99, 0x7f, 0xb5, 0xfc, 0x67, 0x43, 0x72, 0xbd,
  0x0c, 0x00, 0xd6, 0x89, 0xeb, 0x6b, 0x2c, 0xd3, 0xed, 0x8f, 0x98, 0x1c, 0x14, 0xab, 0x7e, 0xe5,
  0xe3, 0x6e, 0xfc, 0xd8, 0xa8, 0xe4, 0x92, 0x24, 0xda, 0x43, 0x6b, 0x62, 0xb8, 0x55, 0xfd, 0xea,
  0xc1, 0xbc, 0x6c, 0xb6, 0x8b, 0xf3, 0x0e, 0x8d, 0x9a, 0xe4, 0x9b, 0x6c, 0x69, 0x99, 0xf8, 0x78,
  0x48, 0x30, 0x45, 0xd5, 0xad, 0xe1, 0x0d, 0x3c, 0x45, 0x60, 0xfc, 0x32, 0x96, 0x51, 0x27, 0xbc,
  0x67, 0xc3, 0xca, 0x2e, 0xb6, 0x6b, 0xea, 0x46, 0xc7, 0xc7, 0x20, 0xa0, 0xb1, 0x1f, 0x65, 0xde,
  0x48, 0x08, 0xba, 0xa4, 0x4e, 0xa9, 0xf2, 0x83, 0x46, 0x37, 0x84, 0xeb, 0xe8, 0xcc, 0x81, 0x48,
  0x43, 0x67, 0x4e, 0x72, 0x2a, 0x9b, 0x5c, 0xbd, 0x4c, 0x1b, 0x28, 0x8a, 0x5c, 0x22, 0x7b, 0xb4,
  0xab, 0x98, 0xd9, 0xee, 0xe0, 0x51, 0x83, 0xc3, 0x09, 0x46, 0x4e, 0x6d, 0x3e, 0x99, 0xfa, 0x95,
  0x17, 0xda, 0x7c, 0x33, 0x57, 0x41, 0x3c, 0x8d, 0x51, 0xed, 0x0b, 0xb6, 0x5c, 0xaf, 0x2c, 0x63,
  0x1a, 0xdf, 0x57, 0xc8, 0x3f, 0xbc, 0xe9, 0x5d, 0xc4, 0x9b, 0xaf, 0x45, 0x99, 0xe2, 0xa3, 0x5a,
  0x24, 0xb4, 0xba, 0xa9, 0x56, 0x3d, 0xcf, 0x6f, 0xaa, 0xff, 0x49, 0x58, 0xbe, 0xf0, 0xa8, 0xff,
  0xf4, 0xb8, 0xad, 0xe9, 0x37, 0xfb, 0xba, 0xb8, 0xf4, 0x0b, 0x3a, 0xf9, 0xe8, 0x43, 0x42, 0x1e,
  0x89, 0xd8, 0x84, 0xcb, 0x13, 0xf1, 0xd9, 0xbb, 0xe1, 0x89, 0x60, 0xb8, 0x8c, 0x28, 0x56, 0xac,
  0x14, 0x1d, 0x9c, 0x0a, 0xe7, 0x71, 0xeb, 0xcf, 0x0e, 0xdd, 0x3d, 0xa9, 0x96, 0xa1, 0x48, 0xbd,
  0x3c, 0xf7, 0xaf, 0xb5, 0x0d, 0x22, 0x4c, 0xc0, 0x11, 0x81, 0xec, 0x56, 0x3b, 0xf6, 0xd3, 0xa2,
  0xe2, 0x5b, 0xb7, 0xb2, 0x04, 0x22, 0x52, 0x95, 0x80, 0x93, 0x69, 0xe8, 0x8e, 0x4c, 0x65, 0xf1,
  0x91, 0x03, 0x2d, 0x70, 0x74, 0x02, 0xea, 0x8b, 0x67, 0x15, 0x29, 0x69, 0x52, 0x02, 0xbb, 0xd7,
  0xdf, 0x50, 0x6a, 0x55, 0x46, 0xbf, 0xa0, 0xa3, 0x28, 0x61, 0x7f, 0x70, 0xd0, 0xc3, 0xa2, 0xaa,
  0x2c, 0x21, 0xaa, 0x47, 0xce, 0x28, 0x9c, 0x06, 0x45, 0x76, 0xbf, 0x82, 0x18, 0x27, 0xb4, 0xd5,
  0xae, 0xb4, 0xcb, 0x50, 0xe6, 0x6b, 0xf4, 0x4c, 0x86, 0x71, 0x30, 0xe9, 0xa6, 0xdf, 0x16, 0x86,
  0xe0, 0xd8, 0xff, 0x40, 0xdd, 0xfb, 0xd0, 0x42, 0x88, 0x7f, 0xa3, 0x33, 0x3a, 0x2e, 0x5c, 0x1e,
  0x41, 0x11, 0x81, 0x63, 0xce, 0x18, 0x71, 0x6b, 0x2b, 0xec, 0xa6, 0x8a, 0xb7, 0x31, 0x5c, 0x3a,
  0x6a, 0x47, 0xe0, 0xc3, 0x79, 0x59, 0xd6, 0x20, 0x1a, 0xaf, 0xf2, 0x6a, 0x98, 0xaa, 0x72, 0xbc,
  0x57, 0x4a, 0xd2, 0x4b, 0x9d, 0xbb, 0x10, 0xfc, 0xb0, 0x4c, 0x41, 0xe5, 0xed, 0x1d, 0x3d, 0x5e,
  0x28, 0x9d, 0x9c, 0xcc, 0xbf, 0xb3, 0x51, 0xda, 0xa7, 0x47, 0xe5, 0x84, 0x53, 0x02, 0x03, 0x01,
  0x00, 0x01, 0xa3, 0x81, 0xf4, 0x30, 0x81, 0xf1, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04,
  0x18, 0x30, 0x16, 0x80, 0x14, 0xad, 0xbd, 0x98, 0x7a, 0x34, 0xb4, 0x26, 0xf7, 0xfa, 0xc4, 0x26,
  0x54, 0xef, 0x03, 0xbd, 0xe0, 0x24, 0xcb, 0x54, 0x1a, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,
  0x04, 0x16, 0x04, 0x14, 0xbb, 0xaf, 0x7e, 0x02, 0x3d, 0xfa, 0xa6, 0xf1, 0x3c, 0x84, 0x8e, 0xad,
  0xee, 0x38, 0x98, 0xec, 0xd9, 0x32, 0x32, 0xd4, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01,
  0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
  0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x11, 0x06, 0x03, 0x55, 0x1d, 0x20,
  0x04, 0x0a, 0x30, 0x08, 0x30, 0x06, 0x06, 0x04, 0x55, 0x1d, 0x20, 0x00, 0x30, 0x44, 0x06, 0x03,
  0x55, 0x1d, 0x1f, 0x04, 0x3d, 0x30, 0x3b, 0x30, 0x39, 0xa0, 0x37, 0xa0, 0x35, 0x86, 0x33, 0x68,
  0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x72, 0x6c, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x74, 0x72,
  0x75, 0x73, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x41, 0x64, 0x64, 0x54, 0x72, 0x75, 0x73, 0x74,
  0x45, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x43, 0x41, 0x52, 0x6f, 0x6f, 0x74, 0x2e, 0x63,
  0x72, 0x6c, 0x30, 0x35, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x29,
  0x30, 0x27, 0x30, 0x25, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x19,
  0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x63, 0x73, 0x70, 0x2e, 0x75, 0x73, 0x65, 0x72,
  0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
  0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x64, 0xbf, 0x83,
  0xf1, 0x5f, 0x9a, 0x85, 0xd0, 0xcd, 0xb8, 0xa1, 0x29, 0x57, 0x0d, 0xe8, 0x5a, 0xf7, 0xd1, 0xe9,
  0x3e, 0xf2, 0x76, 0x04, 0x6e, 0xf1, 0x52, 0x70, 0xbb, 0x1e, 0x3c, 0xff, 0x4d, 0x0d, 0x74, 0x6a,
  0xcc, 0x81, 0x82, 0x25, 0xd3, 0xc3, 0xa0, 0x2a, 0x5d, 0x4c, 0xf5, 0xba, 0x8b, 0xa1, 0x6d, 0xc4,
  0x54, 0x09, 0x75, 0xc7, 0xe3, 0x27, 0x0e, 0x5d, 0x84, 0x79, 0x37, 0x40, 0x13, 0x77, 0xf5, 0xb4,
  0xac, 0x1c, 0xd0, 0x3b, 0xab, 0x17, 0x12, 0xd6, 0xef, 0x34, 0x18, 0x7e, 0x2b, 0xe9, 0x79, 0xd3,
  0xab, 0x57, 0x45, 0x0c, 0xaf, 0x28, 0xfa, 0xd0, 0xdb, 0xe5, 0x50, 0x95, 0x88, 0xbb, 0xdf, 0x85,
  0x57, 0x69, 0x7d, 0x92, 0xd8, 0x52, 0xca, 0x73, 0x81, 0xbf, 0x1c, 0xf3, 0xe6, 0xb8, 0x6e, 0x66,
  0x11, 0x05, 0xb3, 0x1e, 0x94, 0x2d, 0x7f, 0x91, 0x95, 0x92, 0x59, 0xf1, 0x4c, 0xce, 0xa3, 0x91,
  0x71, 0x4c, 0x7c, 0x47, 0x0c, 0x3b, 0x0b, 0x19, 0xf6, 0xa1, 0xb1, 0x6c, 0x86, 0x3e, 0x5c, 0xaa,
  0xc4, 0x2e, 0x82, 0xcb, 0xf9, 0x07, 0x96, 0xba, 0x48, 0x4d, 0x90, 0xf2, 0x94, 0xc8, 0xa9, 0x73,
  0xa2, 0xeb, 0x06, 0x7b, 0x23, 0x9d, 0xde, 0xa2, 0xf3, 0x4d, 0x55, 0x9f, 0x7a, 0x61, 0x45, 0x98,
  0x18, 0x68, 0xc7, 0x5e, 0x40, 0x6b, 0x23, 0xf5, 0x79, 0x7a, 0xef, 0x8c, 0xb5, 0x6b, 0x8b, 0xb7,
  0x6f, 0x46, 0xf4, 0x7b, 0xf1, 0x3d, 0x4b, 0x04, 0xd8, 0x93, 0x80, 0x59, 0x5a, 0xe0, 0x41, 0x24,
  0x1d, 0xb2, 0x8f, 0x15, 0x60, 0x58, 0x47, 0xdb, 0xef, 0x6e, 0x46, 0xfd, 0x15, 0xf5, 0xd9, 0x5f,
  0x9a, 0xb3, 0xdb, 0xd8, 0xb8, 0xe4, 0x40, 0xb3, 0xcd, 0x97, 0x39, 0xae, 0x85, 0xbb, 0x1d, 0x8e,
  0xbc, 0xdc, 0x87, 0x9b, 0xd1, 0xa6, 0xef, 0xf1, 0x3b, 0x6f, 0x10, 0x38, 0x6f
};

flea_err_e THR_flea_test_cert_path_valid_init()
{
  flea_cpv_t cert_chain__t;
  flea_cert_store_t cert_store__t;

  FLEA_THR_BEG_FUNC();
  flea_cpv_t__INIT(&cert_chain__t);
  flea_cert_store_t__INIT(&cert_store__t);

  FLEA_THR_FIN_SEC(
    flea_cert_store_t__dtor(&cert_store__t);
    flea_cpv_t__dtor(&cert_chain__t);
  );
}

# ifdef FLEA_HAVE_RSA
flea_err_e THR_flea_test_cert_chain_correct_chain_of_two()
{
/* ! [cert_validation_1] */
  flea_cpv_t cert_chain__t;

  flea_cpv_t__INIT(&cert_chain__t);
  const flea_u8_t date_str[] = "170228200000Z";
  flea_gmt_time_t time__t;
  flea_err_e err;
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(
    THR_flea_cpv_t__ctor_cert(
      &cert_chain__t,
      test_cert_tls_server_1,
      sizeof(test_cert_tls_server_1),
      flea_rev_chk_none,
      flea_x509_validation_empty_flags
    )
  );
  FLEA_CCALL(
    THR_flea_cpv_t__add_trust_anchor_cert(
      &cert_chain__t,
      flea_test_cert_issuer_of_tls_server_1__cau8,
      sizeof(flea_test_cert_issuer_of_tls_server_1__cau8)
    )
  );
  FLEA_CCALL(THR_flea_asn1_parse_utc_time(date_str, sizeof(date_str) - 1, &time__t));
  err = THR_flea_cpv_t__validate(&cert_chain__t, &time__t);
/* ! [cert_validation_1] */
#  if (defined FLEA_HAVE_RSA) && (FLEA_RSA_MAX_KEY_BIT_SIZE >= 4096)
  if(err)
  {
    FLEA_THROW("error when verifying RSA signed cert chain", err);
  }
#  else /* if (defined FLEA_HAVE_RSA) && (FLEA_RSA_MAX_KEY_BIT_SIZE >= 4096) */
  if(!err)
  {
    FLEA_THROW(
      "no error when verifying RSA signed cert chain but missing algo / key size support",
      FLEA_ERR_FAILED_TEST
    );
  }
#  endif /* if (defined FLEA_HAVE_RSA) && (FLEA_RSA_MAX_KEY_BIT_SIZE >= 4096) */
  FLEA_THR_FIN_SEC(
    flea_cpv_t__dtor(&cert_chain__t);
  );
} /* THR_flea_test_cert_chain_correct_chain_of_two */

flea_err_e THR_flea_test_cert_chain_correct_chain_of_two_using_cert_store()
{
  const flea_u8_t date_str[] = "170228200000Z";
  flea_gmt_time_t time__t;
  flea_err_e err;
  flea_u16_t nb_trusted_certs;
  flea_dtl_t i;

  flea_cpv_t cert_chain__t;
  flea_cert_store_t trusted_store__t;

  FLEA_THR_BEG_FUNC();
  flea_cpv_t__INIT(&cert_chain__t);
  flea_cert_store_t__INIT(&trusted_store__t);
  FLEA_CCALL(THR_flea_cert_store_t__ctor(&trusted_store__t));
  FLEA_CCALL(
    THR_flea_cpv_t__ctor_cert(
      &cert_chain__t,
      test_cert_tls_server_1,
      sizeof(test_cert_tls_server_1),
      flea_rev_chk_none,
      flea_x509_validation_empty_flags
    )
  );
  nb_trusted_certs = (FLEA_MAX_CERT_COLLECTION_SIZE ? (FLEA_MAX_CERT_COLLECTION_SIZE - 1) : 1);
  for(i = 0; i < nb_trusted_certs; i++)
  {
    FLEA_CCALL(
      THR_flea_cert_store_t__add_trusted_cert(
        &trusted_store__t,
        flea_test_cert_issuer_of_tls_server_1__cau8,
        sizeof(flea_test_cert_issuer_of_tls_server_1__cau8)
      )
    );
  }
  FLEA_CCALL(THR_flea_cert_store_t__add_my_trusted_certs_to_path_validator(&trusted_store__t, &cert_chain__t));
  FLEA_CCALL(THR_flea_asn1_parse_utc_time(date_str, sizeof(date_str) - 1, &time__t));

  err = THR_flea_cpv_t__validate(&cert_chain__t, &time__t);
#  if (defined FLEA_HAVE_RSA) && (FLEA_RSA_MAX_KEY_BIT_SIZE >= 4096)
  if(err)
  {
    FLEA_THROW("error when verifying RSA signed cert chain", err);
  }
#  else /* if (defined FLEA_HAVE_RSA) && (FLEA_RSA_MAX_KEY_BIT_SIZE >= 4096) */
  if(!err)
  {
    FLEA_THROW(
      "no error when verifying RSA signed cert chain but missing algo / key size support",
      FLEA_ERR_FAILED_TEST
    );
  }
#  endif /* if (defined FLEA_HAVE_RSA) && (FLEA_RSA_MAX_KEY_BIT_SIZE >= 4096) */

  /* fill up to the maximal capacity */
  FLEA_CCALL(
    THR_flea_cert_store_t__add_trusted_cert(
      &trusted_store__t,
      flea_test_cert_issuer_of_tls_server_1__cau8,
      sizeof(flea_test_cert_issuer_of_tls_server_1__cau8)
    )
  );

  if(FLEA_MAX_CERT_COLLECTION_SIZE &&
    FLEA_ERR_BUFF_TOO_SMALL !=
    THR_flea_cert_store_t__add_trusted_cert(
      &trusted_store__t,
      flea_test_cert_issuer_of_tls_server_1__cau8,
      sizeof(flea_test_cert_issuer_of_tls_server_1__cau8)
    ))
  {
    FLEA_THROW("max cert store capacity not respected", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    flea_cpv_t__dtor(&cert_chain__t);
    flea_cert_store_t__dtor(&trusted_store__t);
  );
} /* THR_flea_test_cert_chain_correct_chain_of_two_using_cert_store */

/**
 * Testing the a cert chain as it is supplied with TLS.
 */
flea_err_e THR_flea_test_tls_cert_chain()
{
  flea_cpv_t cert_chain__t;
  const flea_u8_t date_str[] = "170228200000Z";
  flea_gmt_time_t time__t;
  flea_bool_t first__b = FLEA_TRUE;
  flea_err_e err;
  const flea_u8_t* ptr = tls_cert_chain__acu8;
  flea_al_u16_t len    = sizeof(tls_cert_chain__acu8);

  FLEA_THR_BEG_FUNC();

  flea_cpv_t__INIT(&cert_chain__t);
  while(len > 3)
  {
    /* testing a certificate chain as it is used in the TLS protocol with a length
     * field before each certificate
     */
    flea_u32_t new_len = ((flea_u32_t) ptr[0] << 16) | (ptr[1] << 8) | (ptr[2]);
    ptr += 3;
    len -= 3;
    if(new_len > len)
    {
      FLEA_THROW("invalid cert chain length", FLEA_ERR_INV_ARG);
    }
    if(first__b)
    {
      FLEA_CCALL(
        THR_flea_cpv_t__ctor_cert(
          &cert_chain__t,
          ptr,
          new_len,
          flea_rev_chk_none,
          flea_x509_validation_empty_flags
        )
      );
      first__b = FLEA_FALSE;
    }
    else
    {
      FLEA_CCALL(THR_flea_cpv_t__add_cert_without_trust_status(&cert_chain__t, ptr, new_len));
    }
    ptr += new_len;
    len -= new_len;
  }

  FLEA_CCALL(THR_flea_asn1_parse_utc_time(date_str, sizeof(date_str) - 1, &time__t));
  err = THR_flea_cpv_t__validate(&cert_chain__t, &time__t);

  if(!err)
  {
    FLEA_THROW("no error when verifying untrusted cert", FLEA_ERR_FAILED_TEST);
  }

  FLEA_THR_FIN_SEC(
    flea_cpv_t__dtor(&cert_chain__t);
  );
} /* THR_flea_test_tls_cert_chain */

# endif /*  #ifdef FLEA_HAVE_RSA*/

#endif /* ifdef FLEA_HAVE_ASYM_SIG */
