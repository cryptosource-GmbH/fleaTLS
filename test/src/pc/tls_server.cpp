/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h> // Linux specific

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h> // inet_addr
#include <unistd.h>    // for close

#include "pc/test_util.h"
#include "flea/tls.h"
#include "pc/test_pc.h"
#include "pltf_support/tcpip_stream.h"

flea_err_t THR_flea_start_tls_server(property_set_t const& cmdl_args)
{
  flea_rw_stream_t rw_stream__t;


  // TODO: MISSING INIT OF CTX
  flea_tls_ctx_t tls_ctx;

  // char app_data_www[] = "GET index.html HTTP/1.1\nHost: 127.0.0.1";


  #define SERVER_CERT_1024

  const flea_u8_t trust_anchor_2048__au8[] =
  {0x30, 0x82, 0x03, 0x7f, 0x30, 0x82, 0x02, 0x67, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00, 0xfe, 0x12, 0x36,
   0x42, 0xa1, 0xb6, 0xf7, 0x11, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
   0x00, 0x30, 0x56, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30,
   0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31,
   0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20,
   0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x31, 0x0f, 0x30, 0x0d,
   0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, 0x72, 0x6f, 0x6f, 0x74, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x36,
   0x31, 0x31, 0x30, 0x31, 0x30, 0x38, 0x33, 0x39, 0x31, 0x33, 0x5a, 0x17, 0x0d, 0x31, 0x39, 0x30, 0x38, 0x32, 0x32,
   0x30, 0x38, 0x33, 0x39, 0x31, 0x33, 0x5a, 0x30, 0x56, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
   0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d,
   0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74,
   0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c,
   0x74, 0x64, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, 0x72, 0x6f, 0x6f, 0x74, 0x43, 0x41,
   0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
   0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xcf, 0xa5, 0x70, 0x42, 0x71,
   0x64, 0xdf, 0xfa, 0x98, 0x43, 0x8a, 0x13, 0x5f, 0xe3, 0x7d, 0xed, 0x27, 0xff, 0x52, 0x3a, 0x6b, 0x7f, 0x0f, 0xd6,
   0x80, 0xaa, 0xfd, 0x2e, 0xf9, 0xb7, 0xcf, 0x6b, 0x46, 0x72, 0x91, 0x95, 0x39, 0x44, 0xc1, 0xbf, 0x69, 0x9e, 0x65,
   0xab, 0xbd, 0xa7, 0xe6, 0x3c, 0xfd, 0x12, 0x09, 0xa6, 0xda, 0x1e, 0xf4, 0x12, 0x9b, 0x0d, 0xd6, 0x5c, 0x6c, 0xdf,
   0x64, 0x77, 0xfe, 0x35, 0x2d, 0xd9, 0xad, 0x99, 0xc1, 0x47, 0x31, 0xef, 0x95, 0x23, 0x38, 0x48, 0xd7, 0xa6, 0x84,
   0x69, 0x6c, 0x4d, 0x37, 0xe8, 0x29, 0xd3, 0xb4, 0x68, 0x03, 0x19, 0xdc, 0xb1, 0xd1, 0xfd, 0xfb, 0x97, 0x61, 0x50,
   0xe7, 0x2a, 0xa0, 0xfd, 0x7c, 0x8f, 0x51, 0x88, 0x0b, 0x5d, 0x74, 0xce, 0xb6, 0xa5, 0x65, 0x53, 0xb2, 0x0d, 0xdf,
   0xb5, 0x7a, 0xe1, 0x3c, 0x98, 0x6e, 0x29, 0xa7, 0x90, 0x75, 0x13, 0xac, 0x22, 0x92, 0xdb, 0xe6, 0x8c, 0x6f, 0x32,
   0xa7, 0x42, 0xa4, 0xa4, 0x5c, 0x04, 0xdb, 0x04, 0x95, 0x34, 0x13, 0xe0, 0xa1, 0x47, 0x00, 0x21, 0xf6, 0xa1, 0xa7,
   0xaa, 0x0e, 0x97, 0xc5, 0x2b, 0x64, 0x00, 0x74, 0xdd, 0x57, 0xe3, 0x03, 0xe0, 0xb8, 0xc5, 0x4e, 0xe3, 0x3e, 0xf0,
   0x33, 0x7d, 0x5e, 0x82, 0xda, 0xaa, 0x04, 0x0d, 0xdc, 0x80, 0x14, 0xaf, 0x30, 0x10, 0x9c, 0x5b, 0xb8, 0xd2, 0xb6,
   0x76, 0x6c, 0x10, 0x27, 0xfd, 0x6e, 0xaa, 0xc2, 0x70, 0x7e, 0x0d, 0x37, 0x2c, 0x28, 0x81, 0x26, 0xc8, 0xeb, 0x7c,
   0x4b, 0x8f, 0xda, 0x7b, 0x02, 0xb0, 0x51, 0x92, 0x3d, 0x3d, 0x5e, 0x53, 0xfa, 0xcb, 0x43, 0x4f, 0xef, 0x1e, 0x61,
   0xe5, 0xb9, 0x2c, 0x08, 0x77, 0xff, 0x65, 0x77, 0x13, 0x4d, 0xd4, 0xcb, 0x2e, 0x7f, 0x9d, 0xe2, 0x1a, 0xc3, 0x19,
   0x84, 0xb1, 0x52, 0x9d, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x50, 0x30, 0x4e, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
   0x0e, 0x04, 0x16, 0x04, 0x14, 0xb7, 0x52, 0x9d, 0x67, 0xd2, 0x32, 0x3f, 0x0c, 0x4d, 0xe3, 0xa2, 0xe8, 0x95, 0xfe,
   0x23, 0x83, 0xbf, 0xaa, 0x17, 0x66, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
   0xb7, 0x52, 0x9d, 0x67, 0xd2, 0x32, 0x3f, 0x0c, 0x4d, 0xe3, 0xa2, 0xe8, 0x95, 0xfe, 0x23, 0x83, 0xbf, 0xaa, 0x17,
   0x66, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09,
   0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x7b, 0x18, 0xad,
   0x25, 0x86, 0x17, 0x93, 0x93, 0xcb, 0x01, 0xe1, 0x07, 0xce, 0xfa, 0x37, 0x96, 0x5f, 0x17, 0x95, 0x1d, 0x76, 0xf3,
   0x04, 0x36, 0x81, 0x64, 0x78, 0x2a, 0xc2, 0xcc, 0xbd, 0x77, 0xf7, 0x59, 0xeb, 0x9a, 0xf7, 0xb3, 0xfc, 0x1a, 0x30,
   0xfe, 0x6f, 0x6e, 0x02, 0xc6, 0x2d, 0x4d, 0x79, 0x25, 0xaf, 0x98, 0xb4, 0xab, 0x3e, 0x25, 0xfc, 0xef, 0x98, 0x26,
   0x0f, 0x6a, 0x0a, 0x74, 0x5b, 0x4f, 0x3a, 0x6c, 0xd6, 0x42, 0x56, 0xd9, 0x25, 0x0a, 0x1e, 0x3a, 0x4c, 0x74, 0xe9,
   0x28, 0xcf, 0x7d, 0xe9, 0x48, 0xdc, 0xd6, 0xf4, 0x23, 0xf7, 0x2e, 0xc9, 0x50, 0xb7, 0xad, 0x22, 0x9b, 0xdf, 0x60,
   0xcf, 0x2f, 0x4b, 0x98, 0x79, 0x3d, 0x56, 0xf0, 0x03, 0xfd, 0xe1, 0x61, 0x12, 0xed, 0x44, 0xe8, 0x22, 0xce, 0x4d,
   0x41, 0xe7, 0xd4, 0x9c, 0xf9, 0x12, 0x57, 0x12, 0xb0, 0x20, 0xb3, 0xfa, 0xf5, 0x09, 0x8b, 0xc6, 0x38, 0xc2, 0x31,
   0x41, 0xe8, 0xf3, 0x1c, 0x9a, 0xb7, 0x87, 0x73, 0x64, 0x29, 0xc5, 0x0f, 0x8e, 0x2d, 0x80, 0xbd, 0x54, 0x16, 0x6d,
   0xc2, 0xcd, 0x5f, 0x0c, 0x12, 0xe0, 0xd2, 0x6b, 0xce, 0x99, 0x53, 0x7b, 0xa8, 0x38, 0x4e, 0x17, 0xea, 0xc1, 0x70,
   0x9b, 0x33, 0x39, 0xc2, 0x83, 0x11, 0xba, 0xbd, 0x9b, 0x79, 0x09, 0xc5, 0x01, 0xea, 0x2d, 0xc6, 0x56, 0xf2, 0x9a,
   0x14, 0x68, 0x37, 0xb2, 0x28, 0xb0, 0x60, 0xf0, 0xc6, 0xf4, 0xa6, 0x1e, 0xeb, 0x2b, 0x1d, 0x0e, 0xa0, 0x58, 0xfc,
   0xd8, 0x2c, 0x01, 0xa3, 0xcf, 0xae, 0xa8, 0x3b, 0x49, 0x9e, 0xad, 0x51, 0xe7, 0x08, 0x65, 0x8c, 0x5c, 0x33, 0x54,
   0x04, 0x14, 0x48, 0xf1, 0x79, 0xab, 0x33, 0xf5, 0xd4, 0xe0, 0xef, 0x1a, 0x62, 0x13, 0x48, 0xda, 0x52, 0x3e, 0x02,
   0x8f, 0x64, 0xba, 0x8e, 0xf1, 0x88};


  const flea_u8_t server_cert_2048__au8[] =
  {0x30, 0x82, 0x03, 0x2b, 0x30, 0x82, 0x02, 0x13, 0x02, 0x09, 0x00, 0xa5, 0x7b, 0x1a, 0x50,
   0xfa, 0x22, 0x11, 0x33,
   0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
   0x01, 0x0d, 0x05, 0x00, 0x30, 0x56, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
   0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a,
   0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06,
   0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20,
   0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64,
   0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, 0x72, 0x6f, 0x6f, 0x74,
   0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x36, 0x31, 0x31, 0x30, 0x31, 0x30, 0x38, 0x34,
   0x36, 0x33, 0x32, 0x5a, 0x17, 0x0d, 0x32, 0x36, 0x31, 0x30, 0x33, 0x30, 0x30, 0x38, 0x34,
   0x36, 0x33, 0x32, 0x5a, 0x30, 0x59, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
   0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a,
   0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06,
   0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20,
   0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64,
   0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x09, 0x6c, 0x6f, 0x63, 0x61,
   0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
   0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30,
   0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xd0, 0x62, 0xb0, 0x10, 0x9b, 0x46, 0xa6,
   0xe1, 0x07, 0x87, 0xbc, 0x97, 0x8e, 0x52, 0x12, 0xac, 0xfc, 0xfe, 0x65, 0x85, 0x7c, 0xfc,
   0x55, 0xf9, 0x54, 0x87, 0x5d, 0x4b, 0x67, 0x23, 0x63, 0xe7, 0xd1, 0x64, 0x18, 0xa1, 0x20,
   0xa9, 0x80, 0x99, 0x52, 0xd9, 0x8d, 0xef, 0x70, 0x91, 0x83, 0xc6, 0xd6, 0x11, 0x71, 0x6f,
   0x6d, 0x27, 0xe0, 0xb0, 0x81, 0xcb, 0xc9, 0x70, 0x19, 0x36, 0x50, 0x2d, 0x9b, 0xab, 0xb6,
   0xeb, 0x7b, 0x85, 0xcf, 0xd2, 0x13, 0x13, 0x19, 0xf3, 0xbc, 0xc0, 0x99, 0x8b, 0x05, 0x40,
   0xa3, 0xb1, 0xaa, 0x76, 0x7f, 0x01, 0x43, 0x3c, 0xca, 0x45, 0xdd, 0x82, 0xa8, 0x99, 0x70,
   0xe0, 0x7c, 0x2d, 0x0a, 0xe7, 0x23, 0xa3, 0x60, 0x37, 0x87, 0xf0, 0xda, 0xc1, 0x95, 0x7b,
   0x93, 0xd9, 0xb9, 0xfd, 0xe7, 0x6c, 0x1a, 0x30, 0x5e, 0xb9, 0x5e, 0xa3, 0x7f, 0x6a, 0x9b,
   0x83, 0x21, 0x37, 0xe4, 0x78, 0x5a, 0xbc, 0x98, 0xb3, 0xe4, 0xa7, 0xe1, 0xfe, 0x2d, 0xc2,
   0xb2, 0x3d, 0x0d, 0xfd, 0xf2, 0x0b, 0xc3, 0x06, 0x97, 0xa2, 0x65, 0xd9, 0x7e, 0x49, 0x06,
   0x39, 0xcd, 0xdb, 0xef, 0xfb, 0xff, 0xf0, 0xcd, 0x38, 0x72, 0xbb, 0x23, 0xdc, 0xaf, 0x22,
   0x13, 0x9b, 0x91, 0x9d, 0x35, 0x55, 0x16, 0xaf, 0xb3, 0x36, 0x43, 0xd1, 0x44, 0xfd, 0xc8,
   0x60, 0x22, 0x32, 0xf5, 0x41, 0xa1, 0x82, 0x56, 0x8c, 0xc4, 0x41, 0x84, 0xcb, 0xb9, 0xa8,
   0x07, 0x4f, 0x6d, 0x7f, 0x4d, 0x5c, 0x54, 0x5d, 0x1f, 0xea, 0x84, 0x7f, 0x6d, 0x2c, 0x1e,
   0x6c, 0xea, 0x63, 0xfd, 0x1b, 0x3f, 0x54, 0xe6, 0xa7, 0x03, 0x19, 0x90, 0x86, 0x36, 0x3e,
   0xd3, 0x59, 0xaa, 0x08, 0xff, 0xcd, 0x0d, 0x09, 0x5c, 0xf4, 0x2e, 0x91, 0x7b, 0x34, 0x34,
   0x22, 0x8f, 0x6f, 0xf2, 0x12, 0x93, 0x18, 0x30, 0x4f, 0x02, 0x03, 0x01, 0x00, 0x01, 0x30,
   0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x05, 0x00, 0x03,
   0x82, 0x01, 0x01, 0x00, 0xab, 0xc0, 0xfc, 0x33, 0x7d, 0xb3, 0xf7, 0x5a, 0x5c, 0x29, 0x7f,
   0xa3, 0x8b, 0x00, 0xc0, 0x1e, 0x1c, 0x2d, 0x4e, 0xe9, 0x69, 0x44, 0xe6, 0xfc, 0xa7, 0xaf,
   0xb9, 0x3c, 0x02, 0x07, 0xb7, 0x2f, 0xcb, 0x59, 0x8f, 0x59, 0xb6, 0xe1, 0xfc, 0x0d, 0x0c,
   0xea, 0xee, 0x69, 0x66, 0xa6, 0x0c, 0xec, 0x22, 0x75, 0x7d, 0xb9, 0x85, 0x6b, 0xfd, 0x34,
   0x60, 0x8f, 0x9a, 0xb1, 0x9f, 0x8d, 0x7b, 0xd1, 0x98, 0x9e, 0xef, 0x89, 0x85, 0xa8, 0x58,
   0x68, 0xf5, 0xd9, 0x50, 0xcd, 0x5f, 0x1a, 0xe4, 0x87, 0xf8, 0x85, 0xc0, 0xcc, 0x8d, 0xf1,
   0xde, 0x2d, 0xc9, 0x68, 0x7a, 0x6c, 0xbd, 0xf9, 0x18, 0xce, 0x3d, 0xdd, 0xa5, 0xe3, 0x7f,
   0xa6, 0x32, 0x64, 0x89, 0x87, 0x20, 0x88, 0x46, 0x72, 0x5e, 0x07, 0xc1, 0xc1, 0x53, 0x11,
   0xcc, 0x96, 0x5a, 0x04, 0x2f, 0x6e, 0x7f, 0x8c, 0x8a, 0xda, 0x61, 0x5f, 0xee, 0x63, 0xef,
   0xa6, 0xff, 0x05, 0xf1, 0x83, 0xef, 0x46, 0xd6, 0x79, 0xa8, 0x9a, 0x12, 0x81, 0x7a, 0xd2,
   0xf8, 0xc1, 0xd7, 0xd3, 0x46, 0x2a, 0x52, 0x39, 0xcc, 0x1f, 0x00, 0x95, 0x88, 0x2e, 0x99,
   0xb5, 0xff, 0x27, 0x85, 0xd8, 0xd1, 0x40, 0xe5, 0xb1, 0x48, 0xb9, 0x61, 0xcf, 0x94, 0x89,
   0x3a, 0x41, 0xca, 0x2a, 0xd4, 0xee, 0x47, 0x18, 0xe2, 0x0b, 0xd7, 0xd3, 0x78, 0x53, 0x7a,
   0xe7, 0x84, 0x01, 0x4d, 0xb0, 0x19, 0xc9, 0x2e, 0xee, 0xd2, 0x4c, 0xb2, 0x1a, 0x40, 0x10,
   0x2d, 0xc0, 0xb8, 0xf3, 0x15, 0x6a, 0x14, 0x15, 0x7f, 0xfd, 0x42, 0x12, 0xd8, 0x6b, 0x70,
   0xb1, 0x30, 0xf5, 0x7b, 0x84, 0x49, 0x3c, 0x9b, 0x9e, 0xad, 0x9a, 0xbf, 0x22, 0x2e, 0xe0,
   0x68, 0xe8, 0xca, 0x6a, 0x25, 0xc6, 0x9f, 0xb4, 0xd7, 0x83, 0xbe, 0xec, 0xf4, 0x36, 0x34,
   0x83, 0x2b, 0xce, 0xed, 0xc7};


  const flea_u8_t server_key_2048__au8[] =
  {0x30, 0x82, 0x04, 0xbe, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
   0xf7, 0x0d, 0x01, 0x01,
   0x01, 0x05, 0x00, 0x04, 0x82, 0x04, 0xa8, 0x30, 0x82, 0x04, 0xa4,
   0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xd0, 0x62, 0xb0, 0x10, 0x9b, 0x46, 0xa6,
   0xe1, 0x07, 0x87, 0xbc, 0x97, 0x8e, 0x52, 0x12, 0xac, 0xfc, 0xfe, 0x65, 0x85, 0x7c, 0xfc,
   0x55, 0xf9, 0x54, 0x87, 0x5d, 0x4b, 0x67, 0x23, 0x63, 0xe7, 0xd1, 0x64, 0x18, 0xa1, 0x20,
   0xa9, 0x80, 0x99, 0x52, 0xd9, 0x8d, 0xef, 0x70, 0x91, 0x83, 0xc6, 0xd6, 0x11, 0x71, 0x6f,
   0x6d, 0x27, 0xe0, 0xb0, 0x81, 0xcb, 0xc9, 0x70, 0x19, 0x36, 0x50, 0x2d, 0x9b, 0xab, 0xb6,
   0xeb, 0x7b, 0x85, 0xcf, 0xd2, 0x13, 0x13, 0x19, 0xf3, 0xbc, 0xc0, 0x99, 0x8b, 0x05, 0x40,
   0xa3, 0xb1, 0xaa, 0x76, 0x7f, 0x01, 0x43, 0x3c, 0xca, 0x45, 0xdd, 0x82, 0xa8, 0x99, 0x70,
   0xe0, 0x7c, 0x2d, 0x0a, 0xe7, 0x23, 0xa3, 0x60, 0x37, 0x87, 0xf0, 0xda, 0xc1, 0x95, 0x7b,
   0x93, 0xd9, 0xb9, 0xfd, 0xe7, 0x6c, 0x1a, 0x30, 0x5e, 0xb9, 0x5e, 0xa3, 0x7f, 0x6a, 0x9b,
   0x83, 0x21, 0x37, 0xe4, 0x78, 0x5a, 0xbc, 0x98, 0xb3, 0xe4, 0xa7, 0xe1, 0xfe, 0x2d, 0xc2,
   0xb2, 0x3d, 0x0d, 0xfd, 0xf2, 0x0b, 0xc3, 0x06, 0x97, 0xa2, 0x65, 0xd9, 0x7e, 0x49, 0x06,
   0x39, 0xcd, 0xdb, 0xef, 0xfb, 0xff, 0xf0, 0xcd, 0x38, 0x72, 0xbb, 0x23, 0xdc, 0xaf, 0x22,
   0x13, 0x9b, 0x91, 0x9d, 0x35, 0x55, 0x16, 0xaf, 0xb3, 0x36, 0x43, 0xd1, 0x44, 0xfd, 0xc8,
   0x60, 0x22, 0x32, 0xf5, 0x41, 0xa1, 0x82, 0x56, 0x8c, 0xc4, 0x41, 0x84, 0xcb, 0xb9, 0xa8,
   0x07, 0x4f, 0x6d, 0x7f, 0x4d, 0x5c, 0x54, 0x5d, 0x1f, 0xea, 0x84, 0x7f, 0x6d, 0x2c, 0x1e,
   0x6c, 0xea, 0x63, 0xfd, 0x1b, 0x3f, 0x54, 0xe6, 0xa7, 0x03, 0x19, 0x90, 0x86, 0x36, 0x3e,
   0xd3, 0x59, 0xaa, 0x08, 0xff, 0xcd, 0x0d, 0x09, 0x5c, 0xf4, 0x2e, 0x91, 0x7b, 0x34, 0x34,
   0x22, 0x8f, 0x6f, 0xf2, 0x12, 0x93, 0x18, 0x30, 0x4f, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02,
   0x82, 0x01, 0x01, 0x00, 0x89, 0x7a, 0xa2, 0x57, 0xc2, 0x69, 0x81, 0x4d, 0x72, 0xef, 0x5d,
   0x3f, 0xcb, 0xb8, 0x5f, 0xf3, 0xda, 0xd1, 0x67, 0x5f, 0x03, 0x0f, 0x63, 0x15, 0x24, 0x6c,
   0x4d, 0xe3, 0xa2, 0x3e, 0xd9, 0xf9, 0xa5, 0xce, 0x58, 0xe5, 0x6c, 0xac, 0x07, 0x58, 0xa0,
   0x2d, 0x41, 0x93, 0xd7, 0x7b, 0x59, 0x2a, 0x04, 0x2e, 0xeb, 0xdc, 0xac, 0x72, 0x23, 0xad,
   0xaf, 0x64, 0x28, 0x18, 0x99, 0xb9, 0x98, 0x7a, 0x0e, 0x7a, 0xe2, 0x2a, 0x47, 0x8b, 0x07,
   0x89, 0xbb, 0xe5, 0xdd, 0x38, 0x4d, 0xad, 0xef, 0x5e, 0xa5, 0x6f, 0x78, 0xcf, 0x8c, 0xfb,
   0xb2, 0x5c, 0xbd, 0xe4, 0x4c, 0x3a, 0x7d, 0xa2, 0x66, 0xe3, 0x1c, 0x72, 0x2d, 0xda, 0x75,
   0x97, 0xfa, 0x8e, 0x1d, 0xbb, 0x65, 0x27, 0x44, 0xdb, 0x74, 0x68, 0x5c, 0x29, 0xc7, 0xa8,
   0x38, 0x56, 0xbc, 0x8c, 0x6e, 0xe1, 0xf3, 0x0b, 0x00, 0xd3, 0xef, 0x96, 0x08, 0x8d, 0x1c,
   0xcd, 0x80, 0x0f, 0x9b, 0x1f, 0xd7, 0xf0, 0xb8, 0x02, 0xde, 0xdd, 0xb5, 0x53, 0x4d, 0x14,
   0xa6, 0x5c, 0x78, 0x76, 0x3b, 0xfc, 0x78, 0xd0, 0xb6, 0x37, 0xf6, 0x4c, 0x1e, 0x4e, 0x17,
   0xd3, 0xc3, 0x8c, 0x79, 0x61, 0x6b, 0xe8, 0xc2, 0x50, 0xa1, 0x0c, 0x3d, 0x54, 0x46, 0x2b,
   0x8b, 0x95, 0xf0, 0xbe, 0x8d, 0x29, 0x00, 0x69, 0xb9, 0xe3, 0xc1, 0xe1, 0x22, 0x5e, 0x7b,
   0xab, 0x80, 0xcf, 0x02, 0x84, 0xdd, 0xfc, 0x1e, 0x8f, 0x1a, 0x80, 0x4b, 0x86, 0x90, 0x39,
   0x2d, 0x26, 0x59, 0xf3, 0x34, 0xe2, 0x76, 0xd0, 0x73, 0xa4, 0x1b, 0x1f, 0x31, 0xb0, 0x57,
   0x06, 0xbd, 0x26, 0x5b, 0xcc, 0xbd, 0x1a, 0x02, 0x6a, 0x66, 0x19, 0x1b, 0xc9, 0xb3, 0x8b,
   0x1f, 0x21, 0xc7, 0x6d, 0xcc, 0xfd, 0x68, 0xa2, 0xdc, 0xb1, 0xeb, 0x3c, 0xe1, 0xca, 0x02,
   0xc6, 0x29, 0xf3, 0x95, 0x71, 0x02, 0x81, 0x81, 0x00, 0xfc, 0x67, 0x63, 0xa5, 0x0d, 0x44,
   0x0f, 0xb0, 0x52, 0xeb, 0xcb, 0x78, 0x2e, 0xf5, 0xbc, 0x8f, 0xc1, 0x56, 0x32, 0xa3, 0x93,
   0xcf, 0x8e, 0x1b, 0x8d, 0xf7, 0xee, 0x60, 0x87, 0xb6, 0xb5, 0xe0, 0x8d, 0x76, 0xca, 0x9e,
   0x1c, 0x39, 0xa7, 0x19, 0x6f, 0xc5, 0xa7, 0x1a, 0xee, 0x69, 0xf2, 0x63, 0x09, 0x52, 0xf6,
   0xbb, 0xeb, 0x00, 0x0d, 0x5a, 0xb6, 0xa0, 0x81, 0x2f, 0x0c, 0x20, 0x88, 0x8e, 0x8e, 0xc3,
   0x62, 0x13, 0xf2, 0x6d, 0x49, 0xc4, 0x8e, 0x32, 0x2e, 0xd8, 0xee, 0xa2, 0xa7, 0xb9, 0x5a,
   0xac, 0xd1, 0x6c, 0x84, 0xcc, 0xc9, 0xa3, 0x58, 0x44, 0xe8, 0xff, 0x4d, 0x3a, 0x46, 0x09,
   0xed, 0x24, 0x9e, 0xfc, 0x4d, 0x31, 0x51, 0x26, 0xfd, 0xb0, 0x6e, 0xbd, 0xc3, 0x58, 0xc9,
   0x15, 0x42, 0x28, 0x45, 0x0a, 0xc3, 0x1f, 0xd7, 0x46, 0x99, 0x7b, 0x75, 0x4c, 0xbe, 0xcb,
   0xb5, 0x97, 0x02, 0x81, 0x81, 0x00, 0xd3, 0x5a, 0xbf, 0x46, 0x63, 0x17, 0xda, 0x3b, 0xcb,
   0x17, 0xb6, 0xa7, 0xc6, 0x46, 0xd6, 0xde, 0xe5, 0x62, 0x4e, 0x26, 0xf3, 0x12, 0x9c, 0x05,
   0xb2, 0xe2, 0xf2, 0x8a, 0x2a, 0x7e, 0xa3, 0x3b, 0xb9, 0xda, 0x92, 0xac, 0xfc, 0x1e, 0xa5,
   0xde, 0x0c, 0x29, 0x0e, 0xe7, 0x1d, 0xfd, 0xb4, 0x78, 0xea, 0xa9, 0xb1, 0xe4, 0x7b, 0xaf,
   0xf7, 0x3f, 0x6c, 0xdc, 0x7e, 0xb4, 0xd1, 0x5e, 0x5f, 0x05, 0xbc, 0xc4, 0x22, 0x3f, 0x2e,
   0xdd, 0x0e, 0x2b, 0x98, 0x31, 0xc9, 0x01, 0x1d, 0xb8, 0x50, 0x7f, 0x5d, 0xe2, 0x4f, 0x28,
   0x42, 0xbd, 0x7a, 0x29, 0x76, 0x26, 0xe3, 0x34, 0xa4, 0x17, 0x04, 0xb0, 0x9f, 0xca, 0x40,
   0xc9, 0x3b, 0x2e, 0x9e, 0x94, 0x21, 0xbd, 0x3f, 0x81, 0x31, 0xdf, 0xca, 0x6f, 0xb7, 0xc1,
   0xd4, 0xca, 0x30, 0xef, 0xf4, 0xae, 0xd6, 0x77, 0xf3, 0x62, 0x5c, 0x4d, 0x62, 0x09, 0x02,
   0x81, 0x80, 0x3c, 0x46, 0xe8, 0x9a, 0x0b, 0x1f, 0xfc, 0xeb, 0x2b, 0xf2, 0x59, 0xc6, 0x1a,
   0xd8, 0xde, 0xae, 0x2a, 0x0a, 0xce, 0xcf, 0x17, 0xc6, 0x92, 0x76, 0x6c, 0x22, 0x10, 0x90,
   0x86, 0xf8, 0x90, 0x58, 0xcf, 0x0f, 0xd6, 0x75, 0x89, 0xe2, 0x0e, 0xd0, 0xd9, 0x4b, 0x87,
   0x8b, 0xbb, 0xf2, 0x1b, 0x4b, 0xa1, 0x77, 0x69, 0xab, 0x19, 0x05, 0x0b, 0x2b, 0x65, 0xbf,
   0xd0, 0xfa, 0x0e, 0x58, 0x5a, 0xa4, 0x48, 0xdd, 0xca, 0x37, 0x5f, 0x46, 0xd0, 0x3e, 0x1b,
   0x83, 0x4a, 0x82, 0xce, 0x02, 0x94, 0x31, 0x84, 0xc1, 0x0e, 0xc6, 0x6e, 0xb4, 0x85, 0x56,
   0xf8, 0x06, 0x84, 0xea, 0x2b, 0x64, 0x46, 0x43, 0xaa, 0x99, 0x7b, 0x4a, 0x5f, 0x98, 0xee,
   0x7b, 0x74, 0x4c, 0x45, 0x36, 0x16, 0x47, 0xc6, 0xc5, 0xc7, 0xe5, 0xdc, 0x0f, 0x24, 0xe8,
   0x1e, 0xbe, 0x22, 0x7b, 0x44, 0x59, 0x0e, 0x9b, 0x91, 0x83, 0x02, 0x81, 0x81, 0x00, 0xc0,
   0xbc, 0x9c, 0x79, 0x1f, 0x9c, 0x7c, 0xd2, 0xd2, 0x1d, 0xc9, 0xdf, 0xad, 0x9c, 0xa4, 0x0d,
   0x97, 0xb8, 0xd1, 0xf4, 0x0a, 0xee, 0x09, 0x81, 0xd8, 0xe3, 0xc4, 0xb1, 0xe2, 0x96, 0xa1,
   0x5c, 0xb1, 0xdb, 0x74, 0xae, 0x73, 0x2b, 0xaf, 0xae, 0x92, 0x00, 0x4f, 0x2a, 0xcb, 0xda,
   0xb4, 0x5d, 0x20, 0x01, 0xa7, 0xcb, 0xe8, 0x4f, 0x4b, 0x75, 0x77, 0x5c, 0x8b, 0xdf, 0x70,
   0x9e, 0x52, 0xa0, 0xf4, 0xc7, 0x17, 0x43, 0xef, 0x04, 0x7f, 0x0b, 0x9a, 0x3a, 0xac, 0x46,
   0x6c, 0x47, 0xcc, 0x80, 0x99, 0xa8, 0xea, 0xee, 0x98, 0x0e, 0x19, 0xfc, 0xfd, 0x55, 0xf1,
   0x13, 0xec, 0x1f, 0x61, 0x93, 0x7f, 0xe3, 0xfc, 0xb8, 0x85, 0x53, 0xba, 0x20, 0xf3, 0xb3,
   0x94, 0xd9, 0xc8, 0x15, 0x80, 0x91, 0xe8, 0x4c, 0xc6, 0x33, 0xab, 0xf4, 0xe6, 0x79, 0x19,
   0xf3, 0x40, 0xeb, 0x8d, 0xa8, 0xb3, 0xa1, 0x02, 0x81, 0x80, 0x7a, 0x25, 0xd2, 0x9d, 0x82,
   0x1b, 0x59, 0xaa, 0xb1, 0x04, 0x2a, 0x7c, 0x48, 0xf4, 0xa6, 0xba, 0x26, 0x83, 0xf4, 0x02,
   0x6c, 0x1a, 0x61, 0xf9, 0xf2, 0x3e, 0x38, 0x0a, 0x77, 0xf8, 0x39, 0x42, 0xab, 0x25, 0x74,
   0x8f, 0xb5, 0x7b, 0xf7, 0x50, 0x0d, 0x1a, 0x13, 0xb4, 0x27, 0x7b, 0xf0, 0x54, 0xd2, 0x44,
   0xd8, 0xa9, 0x43, 0xdd, 0xca, 0x2d, 0xbc, 0x70, 0xa4, 0x2d, 0x7d, 0x10, 0x21, 0xc1, 0x11,
   0x41, 0x2c, 0xf1, 0x0d, 0x99, 0xbe, 0x8f, 0x63, 0xcb, 0x32, 0xcb, 0x15, 0x05, 0x2e, 0x65,
   0x35, 0x5e, 0x80, 0x18, 0xaa, 0xc0, 0x67, 0x6d, 0xec, 0x07, 0xfd, 0xee, 0xd6, 0xe2, 0x2c,
   0x95, 0x78, 0xa9, 0xd5, 0xd6, 0xbf, 0xb0, 0xb3, 0xcf, 0x64, 0x5d, 0xa0, 0x25, 0xa4, 0xd8,
   0xa2, 0xe5, 0x89, 0xda, 0x1d, 0x09, 0x10, 0x7f, 0x65, 0x40, 0xaf, 0x63, 0x95, 0xbe, 0xdf,
   0x00, 0xb9, 0x97};

  const flea_u8_t trust_anchor_1024__au8[] = {
    0x30, 0x82, 0x02, 0x1c, 0x30, 0x82, 0x01, 0x85, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00, 0xf9, 0x6f, 0x13,
    0x78, 0xf9, 0x59, 0x92, 0xca, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x47, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
    0x06, 0x13, 0x02, 0x47, 0x42, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03,
    0x55, 0x04, 0x08, 0x0c, 0x07, 0x45, 0x6e, 0x67, 0x6c, 0x61, 0x6e, 0x64, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55,
    0x04, 0x0a, 0x0c, 0x09, 0x41, 0x6c, 0x69, 0x63, 0x65, 0x20, 0x4c,
    0x74, 0x64, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68,
    0x6f, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x37, 0x30, 0x32,
    0x32, 0x37, 0x31, 0x30, 0x35, 0x31, 0x33, 0x36, 0x5a, 0x17, 0x0d, 0x33, 0x37, 0x30, 0x32, 0x32, 0x32, 0x31, 0x30,
    0x35, 0x31, 0x33, 0x36, 0x5a, 0x30, 0x47, 0x31, 0x0b, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x47, 0x42, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c,
    0x07, 0x45, 0x6e, 0x67, 0x6c, 0x61, 0x6e, 0x64, 0x31, 0x12, 0x30,
    0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x09, 0x41, 0x6c, 0x69, 0x63, 0x65, 0x20, 0x4c, 0x74, 0x64, 0x31, 0x12,
    0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x09, 0x6c, 0x6f,
    0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30,
    0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xb9, 0x2e, 0x00, 0x73, 0xaf, 0x56, 0x90, 0xcf, 0x61, 0xb4, 0xd7, 0xd0, 0xee,
    0x3e, 0x8d, 0x4b, 0x4a, 0xcb, 0xe5, 0xe2, 0x07, 0xf6, 0x4a, 0xd1,
    0x8e, 0x55, 0x6f, 0x38, 0x0b, 0x3f, 0x91, 0x49, 0xf9, 0x70, 0x23, 0x0d, 0xbe, 0x1d, 0xda, 0xd6, 0x2c, 0xe5, 0xea,
    0xc7, 0x16, 0x22, 0xd1, 0x9f, 0xc3, 0x11, 0x11, 0x8c, 0x9c, 0x4c,
    0x04, 0x78, 0xde, 0xe5, 0xd5, 0x63, 0x09, 0x11, 0x70, 0xbe, 0x56, 0x6c, 0x19, 0xbf, 0x94, 0xd8, 0xfc, 0xb9, 0x1d,
    0xb2, 0x2d, 0x63, 0xe4, 0xd5, 0x3e, 0x5c, 0xdf, 0xea, 0xc0, 0x4c,
    0x89, 0x81, 0x9c, 0x26, 0x2a, 0x91, 0x2a, 0xc0, 0xee, 0x43, 0xd0, 0x30, 0x60, 0x0c, 0x7c, 0xb1, 0x28, 0x6c, 0x60,
    0x1e, 0xf7, 0xb9, 0x36, 0x97, 0x61, 0x9b, 0x61, 0x80, 0x76, 0x2a,
    0x22, 0x15, 0xb9, 0xa9, 0x6a, 0x9b, 0xcf, 0x70, 0x88, 0x89, 0x43, 0xfe, 0xe9, 0x1b, 0x02, 0x03, 0x01, 0x00, 0x01,
    0xa3, 0x10, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13,
    0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x0b, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00, 0x63, 0xd8, 0xcf, 0xbc,
    0x26, 0x18, 0xb6, 0xae, 0x4a, 0x05, 0x31, 0xd6, 0x43, 0xb5, 0xef, 0xaa, 0x76, 0xad, 0x8b, 0x96, 0x85, 0xab, 0x32,
    0xa1, 0x94, 0xa7, 0xc0, 0xe2, 0x31, 0x2e, 0x37, 0x43, 0xf5, 0x7b,
    0xf0, 0x3c, 0x26, 0x65, 0x63, 0x21, 0xb7, 0xcf, 0xec, 0xbf, 0x5e, 0x00, 0xc2, 0x3f, 0x00, 0xc7, 0x8e, 0xb9, 0x84,
    0xc2, 0x9f, 0x35, 0x3d, 0xd1, 0x26, 0xce, 0xa6, 0x15, 0x82, 0xc3,
    0x8e, 0x5c, 0x32, 0xb7, 0xf1, 0x25, 0xef, 0x27, 0xc0, 0x9e, 0x84, 0xf3, 0x98, 0x1e, 0xcf, 0xdc, 0xc7, 0x9a, 0x81,
    0x8c, 0xb6, 0x4f, 0xd1, 0xd9, 0xe1, 0xe7, 0xed, 0x02, 0x06, 0xdc,
    0x45, 0x20, 0x2a, 0x7b, 0xb7, 0x0a, 0xfc, 0xba, 0x05, 0xd8, 0x52, 0x8c, 0x55, 0x58, 0x47, 0x9a, 0x9e, 0x4e, 0x57,
    0xd2, 0x13, 0x46, 0x5c, 0xb4, 0x19, 0x78, 0x37, 0xd8, 0x37, 0x82,
    0x7d, 0x2b, 0xf0, 0xbb
  };

  const flea_u8_t server_cert_1024__au8[] = {
    0x30, 0x82, 0x02, 0x17, 0x30, 0x82, 0x01, 0x80, 0x02, 0x09, 0x00, 0x8f, 0x13, 0xd6, 0x60, 0xf0, 0x11, 0xf2, 0x1c,
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x01, 0x0b, 0x05, 0x00, 0x30, 0x47, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x47, 0x42,
    0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x07,
    0x45, 0x6e, 0x67, 0x6c, 0x61, 0x6e, 0x64, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x09, 0x41,
    0x6c, 0x69, 0x63, 0x65, 0x20, 0x4c, 0x74, 0x64, 0x31, 0x12, 0x30,
    0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x1e,
    0x17, 0x0d, 0x31, 0x37, 0x30, 0x32, 0x32, 0x37, 0x31, 0x31, 0x30,
    0x38, 0x33, 0x31, 0x5a, 0x17, 0x0d, 0x31, 0x37, 0x30, 0x33, 0x32, 0x39, 0x31, 0x31, 0x30, 0x38, 0x33, 0x31, 0x5a,
    0x30, 0x59, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
    0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65,
    0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06,
    0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67,
    0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64,
    0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73,
    0x74, 0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00,
    0x93, 0x26, 0x83, 0x7d, 0xe9, 0x88, 0xac, 0xfa, 0x26, 0x65, 0x05,
    0x23, 0x53, 0x1e, 0x44, 0x5d, 0x92, 0x32, 0x94, 0x6e, 0xcb, 0xb2, 0xc4, 0xc4, 0x09, 0x67, 0x75, 0x60, 0xeb, 0x14,
    0xab, 0xa8, 0x57, 0xc9, 0xd4, 0x1e, 0xcb, 0xf6, 0xc9, 0xcd, 0x62,
    0xd2, 0x07, 0x34, 0x86, 0x2a, 0xdd, 0x4f, 0x20, 0xd8, 0x60, 0x1f, 0xbb, 0xc7, 0xf7, 0xf1, 0x5e, 0x61, 0x02, 0x82,
    0x7f, 0x4d, 0xfd, 0xeb, 0xad, 0xc8, 0x3c, 0xb5, 0xed, 0x21, 0x50,
    0x36, 0xc4, 0x85, 0xe2, 0xab, 0x80, 0x12, 0x15, 0x4e, 0x72, 0xf6, 0xa4, 0x0a, 0xfe, 0x43, 0x33, 0x34, 0xbd, 0x42,
    0x0a, 0xbb, 0x5e, 0xa3, 0xda, 0xe7, 0x4b, 0xda, 0xdb, 0x40, 0x9c,
    0x73, 0x09, 0xdf, 0x7d, 0x3e, 0x58, 0x12, 0xa8, 0x97, 0x57, 0x36, 0x82, 0xe4, 0xd7, 0x8e, 0x18, 0x1f, 0x01, 0x4b,
    0x1a, 0xdc, 0x28, 0x19, 0xef, 0x9e, 0x0f, 0xcf, 0x02, 0x03, 0x01,
    0x00, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x81,
    0x81, 0x00, 0x90, 0x6f, 0x35, 0x7a, 0xf6, 0x76, 0x96, 0x63, 0xe2,
    0x3d, 0xdf, 0x6d, 0x1f, 0x1c, 0x66, 0x2a, 0x79, 0xcf, 0xe8, 0x8c, 0xea, 0x8f, 0x3c, 0x1b, 0x03, 0xc7, 0x67, 0x42,
    0x47, 0xad, 0x31, 0x36, 0x71, 0x66, 0xa9, 0xc3, 0x3f, 0x05, 0x5b,
    0x56, 0x46, 0xcd, 0x2e, 0x34, 0xee, 0xb9, 0x33, 0x48, 0xc9, 0xe4, 0x2e, 0x66, 0xf7, 0x12, 0x56, 0x85, 0x0b, 0xc6,
    0xef, 0xc2, 0x85, 0x10, 0x26, 0x77, 0xce, 0xdc, 0x74, 0xa7, 0x5f,
    0xf9, 0xad, 0xfd, 0x4e, 0x61, 0x41, 0xcd, 0x3a, 0xbc, 0xaa, 0x66, 0xc0, 0x8e, 0xee, 0x87, 0xe0, 0x65, 0xcb, 0xa3,
    0x43, 0x99, 0xec, 0x60, 0xe1, 0x7c, 0x87, 0x6b, 0x20, 0x0f, 0x03,
    0x57, 0x79, 0xde, 0x74, 0xfe, 0xf8, 0xa3, 0x77, 0x25, 0xee, 0x56, 0x6a, 0x0c, 0x52, 0xd0, 0x36, 0x21, 0xd2, 0xd5,
    0x49, 0x6d, 0xb4, 0x94, 0x50, 0xce, 0x4c, 0xf3, 0xb2, 0xbd
  };

  const flea_u8_t server_key_1024__au8[] = {
    0x30, 0x82, 0x02, 0x76, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x04, 0x82, 0x02, 0x60, 0x30, 0x82, 0x02, 0x5c,
    0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0x93, 0x26, 0x83, 0x7d, 0xe9, 0x88, 0xac, 0xfa, 0x26, 0x65, 0x05, 0x23,
    0x53, 0x1e, 0x44, 0x5d, 0x92, 0x32, 0x94, 0x6e, 0xcb, 0xb2, 0xc4,
    0xc4, 0x09, 0x67, 0x75, 0x60, 0xeb, 0x14, 0xab, 0xa8, 0x57, 0xc9, 0xd4, 0x1e, 0xcb, 0xf6, 0xc9, 0xcd, 0x62, 0xd2,
    0x07, 0x34, 0x86, 0x2a, 0xdd, 0x4f, 0x20, 0xd8, 0x60, 0x1f, 0xbb,
    0xc7, 0xf7, 0xf1, 0x5e, 0x61, 0x02, 0x82, 0x7f, 0x4d, 0xfd, 0xeb, 0xad, 0xc8, 0x3c, 0xb5, 0xed, 0x21, 0x50, 0x36,
    0xc4, 0x85, 0xe2, 0xab, 0x80, 0x12, 0x15, 0x4e, 0x72, 0xf6, 0xa4,
    0x0a, 0xfe, 0x43, 0x33, 0x34, 0xbd, 0x42, 0x0a, 0xbb, 0x5e, 0xa3, 0xda, 0xe7, 0x4b, 0xda, 0xdb, 0x40, 0x9c, 0x73,
    0x09, 0xdf, 0x7d, 0x3e, 0x58, 0x12, 0xa8, 0x97, 0x57, 0x36, 0x82,
    0xe4, 0xd7, 0x8e, 0x18, 0x1f, 0x01, 0x4b, 0x1a, 0xdc, 0x28, 0x19, 0xef, 0x9e, 0x0f, 0xcf, 0x02, 0x03, 0x01, 0x00,
    0x01, 0x02, 0x81, 0x80, 0x2c, 0xe6, 0x3a, 0x87, 0x07, 0xe4, 0x11,
    0x4b, 0xbe, 0xbd, 0x62, 0x44, 0xf6, 0x0e, 0xad, 0x33, 0x93, 0xf1, 0x65, 0x03, 0x2d, 0x9a, 0x5d, 0x99, 0xa7, 0x78,
    0xef, 0x02, 0xe4, 0x98, 0x09, 0x0c, 0xb3, 0xc4, 0xbc, 0xb9, 0xac,
    0xe8, 0x9f, 0x88, 0xd0, 0xd7, 0x5f, 0x25, 0x72, 0xae, 0xcf, 0x9a, 0x5e, 0x5e, 0x47, 0x6e, 0x47, 0x60, 0xeb, 0xd1,
    0xb5, 0x47, 0x8a, 0x79, 0x81, 0x18, 0xae, 0x1a, 0x6e, 0x19, 0x68,
    0x50, 0xde, 0xbc, 0x56, 0x5e, 0xa6, 0xe3, 0x2a, 0xb8, 0xe2, 0x74, 0xf7, 0x6f, 0x92, 0xdf, 0x23, 0xe8, 0x83, 0x9a,
    0xa2, 0x35, 0xa7, 0x6c, 0xfa, 0xb4, 0x3e, 0x87, 0x9d, 0x05, 0x9a,
    0x7d, 0x62, 0x09, 0xb8, 0xc5, 0xf3, 0x32, 0xf9, 0x69, 0x5a, 0x6d, 0xb2, 0x84, 0x25, 0x2a, 0x91, 0xd1, 0x7e, 0x5b,
    0x27, 0xd4, 0xd2, 0x2e, 0xb3, 0xb5, 0x1a, 0xe8, 0x95, 0x23, 0x74,
    0x61, 0x02, 0x41, 0x00, 0xc2, 0x42, 0x86, 0x20, 0x34, 0x9c, 0xe3, 0xd4, 0xcc, 0x96, 0xce, 0x95, 0x51, 0x0d, 0x40,
    0xac, 0x9b, 0x3f, 0xef, 0xf6, 0x8b, 0xb6, 0xa2, 0xab, 0xa0, 0xec,
    0x42, 0xab, 0xe3, 0xb3, 0x5d, 0x5f, 0xf3, 0xb4, 0xe7, 0x02, 0xe9, 0x9a, 0x7b, 0x00, 0x87, 0x2a, 0x3a, 0x0c, 0xee,
    0xb5, 0x87, 0xd6, 0x01, 0x66, 0xf3, 0x54, 0x3a, 0xf8, 0xde, 0x8f,
    0x66, 0x80, 0x0b, 0x1d, 0x11, 0x28, 0x6b, 0x11, 0x02, 0x41, 0x00, 0xc1, 0xeb, 0x0c, 0x43, 0xb9, 0x4b, 0xa8, 0x86,
    0xb8, 0x32, 0x09, 0x99, 0xe9, 0xc3, 0x2b, 0xc1, 0x51, 0x90, 0xe6,
    0xf5, 0x89, 0x7c, 0xfc, 0xae, 0xba, 0x36, 0x8b, 0x0b, 0x2d, 0x00, 0xce, 0x44, 0x83, 0x02, 0x5e, 0xeb, 0x06, 0xb7,
    0x2b, 0xc8, 0xf8, 0xf7, 0xb6, 0x3c, 0x8e, 0xb4, 0x05, 0x8b, 0xa9,
    0x4a, 0xc8, 0xb4, 0xd6, 0x32, 0xa4, 0x9a, 0x1d, 0x1b, 0x8b, 0x96, 0x6a, 0x24, 0x0c, 0xdf, 0x02, 0x40, 0x62, 0x7a,
    0x24, 0xd2, 0x58, 0xb9, 0x9c, 0x09, 0xb9, 0x79, 0x4d, 0xda, 0x86,
    0x0f, 0x28, 0xd5, 0x17, 0x92, 0xcf, 0x0b, 0xf6, 0x01, 0xac, 0xef, 0x42, 0x91, 0xe2, 0xae, 0x8e, 0xac, 0xd3, 0xce,
    0x1b, 0x96, 0x7e, 0x71, 0x8c, 0x88, 0xe2, 0x87, 0xfe, 0xfd, 0x5a,
    0x16, 0x4a, 0x40, 0xbe, 0x4e, 0xaf, 0xc1, 0x47, 0xe3, 0x50, 0x4d, 0xef, 0x4d, 0x54, 0xd1, 0xde, 0x50, 0x6a, 0xed,
    0x49, 0x71, 0x02, 0x41, 0x00, 0x84, 0xc6, 0x74, 0xa2, 0x56, 0x58,
    0x38, 0x6e, 0xed, 0xe5, 0xcc, 0xef, 0x26, 0xc0, 0xec, 0xcf, 0xb4, 0x12, 0x9c, 0x21, 0x18, 0xdf, 0x8c, 0x7f, 0xf2,
    0x9e, 0x6f, 0xfb, 0xd9, 0xf7, 0x88, 0x44, 0x1e, 0xd3, 0xdb, 0xbb,
    0xde, 0xe0, 0x42, 0x49, 0x9c, 0x36, 0xb7, 0xff, 0xa4, 0xd2, 0x1c, 0x4d, 0xf1, 0x3f, 0x74, 0x47, 0x65, 0xb6, 0x4d,
    0x3f, 0xfc, 0x98, 0x24, 0xae, 0x7b, 0xc4, 0x6d, 0x4f, 0x02, 0x40,
    0x7b, 0xf7, 0xc0, 0x98, 0xa7, 0xa5, 0x15, 0xd0, 0x77, 0xf7, 0x7d, 0xd2, 0x94, 0x98, 0xe6, 0x73, 0x97, 0x1b, 0xfb,
    0x95, 0x8b, 0x03, 0x08, 0xe1, 0x8f, 0x19, 0x75, 0xbe, 0xf6, 0x8d,
    0xf0, 0xb2, 0xb3, 0x99, 0xc2, 0xe1, 0x5e, 0x4c, 0xd6, 0x22, 0x56, 0xd0, 0x7e, 0x7a, 0x39, 0x54, 0x39, 0x99, 0xbe,
    0xbd, 0x61, 0xaa, 0x8c, 0x5e, 0x71, 0xf3, 0x07, 0x24, 0x99, 0xe0,
    0x03, 0x9b, 0x71, 0xca
  };

  flea_ref_cu8_t cert_chain[2];
  flea_ref_cu8_t server_key__t;
#ifdef SERVER_CERT_1024
  cert_chain[1].data__pcu8 = trust_anchor_1024__au8;
  cert_chain[1].len__dtl   = sizeof(trust_anchor_1024__au8);
  cert_chain[0].data__pcu8 = server_cert_1024__au8;
  cert_chain[0].len__dtl   = sizeof(server_cert_1024__au8);
  server_key__t.data__pcu8 = server_key_1024__au8;
  server_key__t.len__dtl   = sizeof(server_key_1024__au8);

#else
  cert_chain[1].data__pcu8 = trust_anchor_2048__au8;
  cert_chain[1].len__dtl   = sizeof(trust_anchor_2048__au8);
  cert_chain[0].data__pcu8 = server_cert_2048__au8;
  cert_chain[0].len__dtl   = sizeof(server_cert_2048__au8);
  server_key__t.data__pcu8 = server_key_2048__au8;
  server_key__t.len__dtl   = sizeof(server_key_2048__au8);


#endif // ifdef SERVER_CERT_1024

  // now read data and echo it back
  flea_u8_t buf[1000];
  flea_al_u16_t buf_len = sizeof(buf);
  FLEA_THR_BEG_FUNC();
  flea_tls_ctx_t__INIT(&tls_ctx);
  FLEA_CCALL(THR_flea_pltfif_tcpip__create_rw_stream_server(&rw_stream__t));
  FLEA_CCALL(flea_tls_ctx_t__ctor(&tls_ctx, &rw_stream__t, NULL, 0));
  FLEA_CCALL(THR_flea_tls__server_handshake(&tls_ctx, &rw_stream__t, cert_chain, 2, &server_key__t));

  while(1)
  {
    flea_err_t retval = THR_flea_tls__read_app_data(&tls_ctx, buf, &buf_len, flea_read_blocking);
    if(retval == FLEA_ERR_TLS_SESSION_CLOSED)
    {
      FLEA_THR_RETURN();
    }
    else if(retval)
    {
      FLEA_THROW("rethrowing error from read_app_data", retval);
    }
    printf("before read_app_data\n");
    buf[buf_len] = 0;
    printf("received data: %s\n", buf);
    printf("read_app_data returned\n");
    FLEA_CCALL(THR_flea_tls__send_app_data(&tls_ctx, buf, buf_len));
    buf_len = sizeof(buf);
  }
  // FLEA_CCALL(THR_flea_tls__send_app_data(&tls_ctx, (flea_u8_t *) app_data_www, strlen(app_data_www)));
  // FLEA_CCALL(THR_flea_tls__send_alert(&tls_ctx, FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY, FLEA_TLS_ALERT_LEVEL_WARNING));


  FLEA_THR_FIN_SEC(
    flea_rw_stream_t__dtor(&rw_stream__t);
    flea_tls_ctx_t__dtor(&tls_ctx);
  );
} // THR_flea_start_tls_server

int flea_start_tls_server(property_set_t const& cmdl_args)
{
  flea_err_t err;

  if((err = THR_flea_start_tls_server(cmdl_args)))
  {
    FLEA_PRINTF_TEST_OUTP_2_SWITCHED("error %04x during tls server test\n", err);
    return 1;
  }
  else
  {
    FLEA_PRINTF_TEST_OUTP_1_SWITCHED("tls test passed\n");
    return 0;
  }
}
