/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/tls_rec_prot.h"
#include "flea/alloc.h"
#include "flea/error_handling.h"
#include "flea/mem_read_stream.h"

flea_u8_t some_record__au8 [] = {
  0x16, 0x03, 0x03, 0x00, 0x4a, 0x02, 0x00, 0x00, 0x46, 0x03, 0x03, 0xb7, 0xe7, 0x2c, 0x6b, 0x04,
  0x6f, 0x40, 0xb4, 0x28, 0x0b, 0x0a, 0xce, 0x23, 0x1b, 0x39, 0xdf, 0x1a, 0x6d, 0xeb, 0x84, 0x43,
  0xb5, 0x49, 0x13, 0x25, 0x00, 0xee, 0xaa, 0xfc, 0x69, 0x83, 0xb5, 0x20, 0x34, 0x28, 0xf4, 0xae,
  0x86, 0x2d, 0x67, 0x6c, 0x45, 0x70, 0xe7, 0x14, 0x54, 0x33, 0x32, 0xe5, 0x95, 0xfb, 0x7d, 0xaa,
  0x37, 0x7a, 0x9c, 0xa6, 0xdc, 0x5f, 0x34, 0x03, 0xb9, 0x4c, 0x6e, 0xb5, 0x00, 0x3d, 0x00, 0x16,
  0x03, 0x03, 0x06, 0xbf, 0x0b, 0x00, 0x06, 0xbb, 0x00, 0x06, 0xb8, 0x00, 0x03, 0x2f, 0x30, 0x82,
  0x03, 0x2b, 0x30, 0x82, 0x02, 0x13, 0x02, 0x09, 0x00, 0xa5, 0x7b, 0x1a, 0x50, 0xfa, 0x22, 0x11,
  0x33, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x05, 0x00,
  0x30, 0x56, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31,
  0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53,
  0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49,
  0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20,
  0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03,
  0x0c, 0x06, 0x72, 0x6f, 0x6f, 0x74, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x36, 0x31, 0x31,
  0x30, 0x31, 0x30, 0x38, 0x34, 0x36, 0x33, 0x32, 0x5a, 0x17, 0x0d, 0x32, 0x36, 0x31, 0x30, 0x33,
  0x30, 0x30, 0x38, 0x34, 0x36, 0x33, 0x32, 0x5a, 0x30, 0x59, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
  0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08,
  0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f,
  0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20,
  0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x31,
  0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68,
  0x6f, 0x73, 0x74, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
  0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02,
  0x82, 0x01, 0x01, 0x00, 0xd0, 0x62, 0xb0, 0x10, 0x9b, 0x46, 0xa6, 0xe1, 0x07, 0x87, 0xbc, 0x97,
  0x8e, 0x52, 0x12, 0xac, 0xfc, 0xfe, 0x65, 0x85, 0x7c, 0xfc, 0x55, 0xf9, 0x54, 0x87, 0x5d, 0x4b,
  0x67, 0x23, 0x63, 0xe7, 0xd1, 0x64, 0x18, 0xa1, 0x20, 0xa9, 0x80, 0x99, 0x52, 0xd9, 0x8d, 0xef,
  0x70, 0x91, 0x83, 0xc6, 0xd6, 0x11, 0x71, 0x6f, 0x6d, 0x27, 0xe0, 0xb0, 0x81, 0xcb, 0xc9, 0x70,
  0x19, 0x36, 0x50, 0x2d, 0x9b, 0xab, 0xb6, 0xeb, 0x7b, 0x85, 0xcf, 0xd2, 0x13, 0x13, 0x19, 0xf3,
  0xbc, 0xc0, 0x99, 0x8b, 0x05, 0x40, 0xa3, 0xb1, 0xaa, 0x76, 0x7f, 0x01, 0x43, 0x3c, 0xca, 0x45,
  0xdd, 0x82, 0xa8, 0x99, 0x70, 0xe0, 0x7c, 0x2d, 0x0a, 0xe7, 0x23, 0xa3, 0x60, 0x37, 0x87, 0xf0,
  0xda, 0xc1, 0x95, 0x7b, 0x93, 0xd9, 0xb9, 0xfd, 0xe7, 0x6c, 0x1a, 0x30, 0x5e, 0xb9, 0x5e, 0xa3,
  0x7f, 0x6a, 0x9b, 0x83, 0x21, 0x37, 0xe4, 0x78, 0x5a, 0xbc, 0x98, 0xb3, 0xe4, 0xa7, 0xe1, 0xfe,
  0x2d, 0xc2, 0xb2, 0x3d, 0x0d, 0xfd, 0xf2, 0x0b, 0xc3, 0x06, 0x97, 0xa2, 0x65, 0xd9, 0x7e, 0x49,
  0x06, 0x39, 0xcd, 0xdb, 0xef, 0xfb, 0xff, 0xf0, 0xcd, 0x38, 0x72, 0xbb, 0x23, 0xdc, 0xaf, 0x22,
  0x13, 0x9b, 0x91, 0x9d, 0x35, 0x55, 0x16, 0xaf, 0xb3, 0x36, 0x43, 0xd1, 0x44, 0xfd, 0xc8, 0x60,
  0x22, 0x32, 0xf5, 0x41, 0xa1, 0x82, 0x56, 0x8c, 0xc4, 0x41, 0x84, 0xcb, 0xb9, 0xa8, 0x07, 0x4f,
  0x6d, 0x7f, 0x4d, 0x5c, 0x54, 0x5d, 0x1f, 0xea, 0x84, 0x7f, 0x6d, 0x2c, 0x1e, 0x6c, 0xea, 0x63,
  0xfd, 0x1b, 0x3f, 0x54, 0xe6, 0xa7, 0x03, 0x19, 0x90, 0x86, 0x36, 0x3e, 0xd3, 0x59, 0xaa, 0x08,
  0xff, 0xcd, 0x0d, 0x09, 0x5c, 0xf4, 0x2e, 0x91, 0x7b, 0x34, 0x34, 0x22, 0x8f, 0x6f, 0xf2, 0x12,
  0x93, 0x18, 0x30, 0x4f, 0x02, 0x03, 0x01, 0x00, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
  0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0xab, 0xc0, 0xfc,
  0x33, 0x7d, 0xb3, 0xf7, 0x5a, 0x5c, 0x29, 0x7f, 0xa3, 0x8b, 0x00, 0xc0, 0x1e, 0x1c, 0x2d, 0x4e,
  0xe9, 0x69, 0x44, 0xe6, 0xfc, 0xa7, 0xaf, 0xb9, 0x3c, 0x02, 0x07, 0xb7, 0x2f, 0xcb, 0x59, 0x8f,
  0x59, 0xb6, 0xe1, 0xfc, 0x0d, 0x0c, 0xea, 0xee, 0x69, 0x66, 0xa6, 0x0c, 0xec, 0x22, 0x75, 0x7d,
  0xb9, 0x85, 0x6b, 0xfd, 0x34, 0x60, 0x8f, 0x9a, 0xb1, 0x9f, 0x8d, 0x7b, 0xd1, 0x98, 0x9e, 0xef,
  0x89, 0x85, 0xa8, 0x58, 0x68, 0xf5, 0xd9, 0x50, 0xcd, 0x5f, 0x1a, 0xe4, 0x87, 0xf8, 0x85, 0xc0,
  0xcc, 0x8d, 0xf1, 0xde, 0x2d, 0xc9, 0x68, 0x7a, 0x6c, 0xbd, 0xf9, 0x18, 0xce, 0x3d, 0xdd, 0xa5,
  0xe3, 0x7f, 0xa6, 0x32, 0x64, 0x89, 0x87, 0x20, 0x88, 0x46, 0x72, 0x5e, 0x07, 0xc1, 0xc1, 0x53,
  0x11, 0xcc, 0x96, 0x5a, 0x04, 0x2f, 0x6e, 0x7f, 0x8c, 0x8a, 0xda, 0x61, 0x5f, 0xee, 0x63, 0xef,
  0xa6, 0xff, 0x05, 0xf1, 0x83, 0xef, 0x46, 0xd6, 0x79, 0xa8, 0x9a, 0x12, 0x81, 0x7a, 0xd2, 0xf8,
  0xc1, 0xd7, 0xd3, 0x46, 0x2a, 0x52, 0x39, 0xcc, 0x1f, 0x00, 0x95, 0x88, 0x2e, 0x99, 0xb5, 0xff,
  0x27, 0x85, 0xd8, 0xd1, 0x40, 0xe5, 0xb1, 0x48, 0xb9, 0x61, 0xcf, 0x94, 0x89, 0x3a, 0x41, 0xca,
  0x2a, 0xd4, 0xee, 0x47, 0x18, 0xe2, 0x0b, 0xd7, 0xd3, 0x78, 0x53, 0x7a, 0xe7, 0x84, 0x01, 0x4d,
  0xb0, 0x19, 0xc9, 0x2e, 0xee, 0xd2, 0x4c, 0xb2, 0x1a, 0x40, 0x10, 0x2d, 0xc0, 0xb8, 0xf3, 0x15,
  0x6a, 0x14, 0x15, 0x7f, 0xfd, 0x42, 0x12, 0xd8, 0x6b, 0x70, 0xb1, 0x30, 0xf5, 0x7b, 0x84, 0x49,
  0x3c, 0x9b, 0x9e, 0xad, 0x9a, 0xbf, 0x22, 0x2e, 0xe0, 0x68, 0xe8, 0xca, 0x6a, 0x25, 0xc6, 0x9f,
  0xb4, 0xd7, 0x83, 0xbe, 0xec, 0xf4, 0x36, 0x34, 0x83, 0x2b, 0xce, 0xed, 0xc7, 0x00, 0x03, 0x83,
  0x30, 0x82, 0x03, 0x7f, 0x30, 0x82, 0x02, 0x67, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00,
  0xfe, 0x12, 0x36, 0x42, 0xa1, 0xb6, 0xf7, 0x11, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
  0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x56, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
  0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c,
  0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06,
  0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57,
  0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x31, 0x0f,
  0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, 0x72, 0x6f, 0x6f, 0x74, 0x43, 0x41, 0x30,
  0x1e, 0x17, 0x0d, 0x31, 0x36, 0x31, 0x31, 0x30, 0x31, 0x30, 0x38, 0x33, 0x39, 0x31, 0x33, 0x5a,
  0x17, 0x0d, 0x31, 0x39, 0x30, 0x38, 0x32, 0x32, 0x30, 0x38, 0x33, 0x39, 0x31, 0x33, 0x5a, 0x30,
  0x56, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13,
  0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74,
  0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e,
  0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50,
  0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
  0x06, 0x72, 0x6f, 0x6f, 0x74, 0x43, 0x41, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a,
  0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30,
  0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xcf, 0xa5, 0x70, 0x42, 0x71, 0x64, 0xdf, 0xfa,
  0x98, 0x43, 0x8a, 0x13, 0x5f, 0xe3, 0x7d, 0xed, 0x27, 0xff, 0x52, 0x3a, 0x6b, 0x7f, 0x0f, 0xd6,
  0x80, 0xaa, 0xfd, 0x2e, 0xf9, 0xb7, 0xcf, 0x6b, 0x46, 0x72, 0x91, 0x95, 0x39, 0x44, 0xc1, 0xbf,
  0x69, 0x9e, 0x65, 0xab, 0xbd, 0xa7, 0xe6, 0x3c, 0xfd, 0x12, 0x09, 0xa6, 0xda, 0x1e, 0xf4, 0x12,
  0x9b, 0x0d, 0xd6, 0x5c, 0x6c, 0xdf, 0x64, 0x77, 0xfe, 0x35, 0x2d, 0xd9, 0xad, 0x99, 0xc1, 0x47,
  0x31, 0xef, 0x95, 0x23, 0x38, 0x48, 0xd7, 0xa6, 0x84, 0x69, 0x6c, 0x4d, 0x37, 0xe8, 0x29, 0xd3,
  0xb4, 0x68, 0x03, 0x19, 0xdc, 0xb1, 0xd1, 0xfd, 0xfb, 0x97, 0x61, 0x50, 0xe7, 0x2a, 0xa0, 0xfd,
  0x7c, 0x8f, 0x51, 0x88, 0x0b, 0x5d, 0x74, 0xce, 0xb6, 0xa5, 0x65, 0x53, 0xb2, 0x0d, 0xdf, 0xb5,
  0x7a, 0xe1, 0x3c, 0x98, 0x6e, 0x29, 0xa7, 0x90, 0x75, 0x13, 0xac, 0x22, 0x92, 0xdb, 0xe6, 0x8c,
  0x6f, 0x32, 0xa7, 0x42, 0xa4, 0xa4, 0x5c, 0x04, 0xdb, 0x04, 0x95, 0x34, 0x13, 0xe0, 0xa1, 0x47,
  0x00, 0x21, 0xf6, 0xa1, 0xa7, 0xaa, 0x0e, 0x97, 0xc5, 0x2b, 0x64, 0x00, 0x74, 0xdd, 0x57, 0xe3,
  0x03, 0xe0, 0xb8, 0xc5, 0x4e, 0xe3, 0x3e, 0xf0, 0x33, 0x7d, 0x5e, 0x82, 0xda, 0xaa, 0x04, 0x0d,
  0xdc, 0x80, 0x14, 0xaf, 0x30, 0x10, 0x9c, 0x5b, 0xb8, 0xd2, 0xb6, 0x76, 0x6c, 0x10, 0x27, 0xfd,
  0x6e, 0xaa, 0xc2, 0x70, 0x7e, 0x0d, 0x37, 0x2c, 0x28, 0x81, 0x26, 0xc8, 0xeb, 0x7c, 0x4b, 0x8f,
  0xda, 0x7b, 0x02, 0xb0, 0x51, 0x92, 0x3d, 0x3d, 0x5e, 0x53, 0xfa, 0xcb, 0x43, 0x4f, 0xef, 0x1e,
  0x61, 0xe5, 0xb9, 0x2c, 0x08, 0x77, 0xff, 0x65, 0x77, 0x13, 0x4d, 0xd4, 0xcb, 0x2e, 0x7f, 0x9d,
  0xe2, 0x1a, 0xc3, 0x19, 0x84, 0xb1, 0x52, 0x9d, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x50, 0x30,
  0x4e, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xb7, 0x52, 0x9d, 0x67,
  0xd2, 0x32, 0x3f, 0x0c, 0x4d, 0xe3, 0xa2, 0xe8, 0x95, 0xfe, 0x23, 0x83, 0xbf, 0xaa, 0x17, 0x66,
  0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xb7, 0x52, 0x9d,
  0x67, 0xd2, 0x32, 0x3f, 0x0c, 0x4d, 0xe3, 0xa2, 0xe8, 0x95, 0xfe, 0x23, 0x83, 0xbf, 0xaa, 0x17,
  0x66, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30,
  0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82,
  0x01, 0x01, 0x00, 0x7b, 0x18, 0xad, 0x25, 0x86, 0x17, 0x93, 0x93, 0xcb, 0x01, 0xe1, 0x07, 0xce,
  0xfa, 0x37, 0x96, 0x5f, 0x17, 0x95, 0x1d, 0x76, 0xf3, 0x04, 0x36, 0x81, 0x64, 0x78, 0x2a, 0xc2,
  0xcc, 0xbd, 0x77, 0xf7, 0x59, 0xeb, 0x9a, 0xf7, 0xb3, 0xfc, 0x1a, 0x30, 0xfe, 0x6f, 0x6e, 0x02,
  0xc6, 0x2d, 0x4d, 0x79, 0x25, 0xaf, 0x98, 0xb4, 0xab, 0x3e, 0x25, 0xfc, 0xef, 0x98, 0x26, 0x0f,
  0x6a, 0x0a, 0x74, 0x5b, 0x4f, 0x3a, 0x6c, 0xd6, 0x42, 0x56, 0xd9, 0x25, 0x0a, 0x1e, 0x3a, 0x4c,
  0x74, 0xe9, 0x28, 0xcf, 0x7d, 0xe9, 0x48, 0xdc, 0xd6, 0xf4, 0x23, 0xf7, 0x2e, 0xc9, 0x50, 0xb7,
  0xad, 0x22, 0x9b, 0xdf, 0x60, 0xcf, 0x2f, 0x4b, 0x98, 0x79, 0x3d, 0x56, 0xf0, 0x03, 0xfd, 0xe1,
  0x61, 0x12, 0xed, 0x44, 0xe8, 0x22, 0xce, 0x4d, 0x41, 0xe7, 0xd4, 0x9c, 0xf9, 0x12, 0x57, 0x12,
  0xb0, 0x20, 0xb3, 0xfa, 0xf5, 0x09, 0x8b, 0xc6, 0x38, 0xc2, 0x31, 0x41, 0xe8, 0xf3, 0x1c, 0x9a,
  0xb7, 0x87, 0x73, 0x64, 0x29, 0xc5, 0x0f, 0x8e, 0x2d, 0x80, 0xbd, 0x54, 0x16, 0x6d, 0xc2, 0xcd,
  0x5f, 0x0c, 0x12, 0xe0, 0xd2, 0x6b, 0xce, 0x99, 0x53, 0x7b, 0xa8, 0x38, 0x4e, 0x17, 0xea, 0xc1,
  0x70, 0x9b, 0x33, 0x39, 0xc2, 0x83, 0x11, 0xba, 0xbd, 0x9b, 0x79, 0x09, 0xc5, 0x01, 0xea, 0x2d,
  0xc6, 0x56, 0xf2, 0x9a, 0x14, 0x68, 0x37, 0xb2, 0x28, 0xb0, 0x60, 0xf0, 0xc6, 0xf4, 0xa6, 0x1e,
  0xeb, 0x2b, 0x1d, 0x0e, 0xa0, 0x58, 0xfc, 0xd8, 0x2c, 0x01, 0xa3, 0xcf, 0xae, 0xa8, 0x3b, 0x49,
  0x9e, 0xad, 0x51, 0xe7, 0x08, 0x65, 0x8c, 0x5c, 0x33, 0x54, 0x04, 0x14, 0x48, 0xf1, 0x79, 0xab,
  0x33, 0xf5, 0xd4, 0xe0, 0xef, 0x1a, 0x62, 0x13, 0x48, 0xda, 0x52, 0x3e, 0x02, 0x8f, 0x64, 0xba,
  0x8e, 0xf1, 0x88, 0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00,
  0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03, 0x03, 0x00, 0x50, 0xcd, 0x64, 0x9c, 0x34, 0xb4,
  0xb9, 0x63, 0xde, 0x33, 0x8f, 0xf8, 0xfc, 0x20, 0xbc, 0xe1, 0x2f, 0x77, 0xe2, 0x21, 0xd7, 0xfb,
  0xf4, 0x63, 0xf4, 0x6c, 0xf8, 0x8e, 0xdf, 0xfd, 0xf4, 0x9e, 0x51, 0x22, 0x3b, 0x69, 0xae, 0x7b,
  0xa5, 0x2b, 0x0f, 0x88, 0xf6, 0x80, 0x63, 0xdb, 0x69, 0xa2, 0xa1, 0x28, 0x99, 0xc1, 0x1f, 0xd4,
  0xa0, 0x5d, 0x95, 0xdb, 0xcc, 0xc0, 0x13, 0xfc, 0x1f, 0x93, 0x1f, 0x09, 0xf7, 0x3e, 0xfe, 0x48,
  0x04, 0xde, 0xf6, 0xed, 0xb7, 0x0d, 0x4e, 0x61, 0x63, 0x8a, 0x5a
};

flea_err_t flea_test_tls_record_protocol_basic()
{
  FLEA_DECL_BUF(read_buf__bu8, flea_u8_t, 3000);
  FLEA_DECL_BUF(stream_buf__bu8, flea_u8_t, 16384);  // TODO: vary length!
  const flea_al_u16_t stream_buf_len__alu16 = 16384; // TODO: vary length!
  FLEA_DECL_OBJ(mem_read_stream__t, flea_rw_stream_t);
  flea_mem_read_stream_help_t mem_hlp__t;
  FLEA_DECL_OBJ(rec_prot__t, flea_tls_rec_prot_t);
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(read_buf__bu8, 3000);
  FLEA_ALLOC_BUF(stream_buf__bu8, 16384);
  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor_memory(
      &mem_read_stream__t,
      some_record__au8,
      sizeof(some_record__au8),
      &mem_hlp__t
    )
  );

  // FLEA_CCALL(THR_flea_tls_rec_prot_t__ctor(&rec_prot__t, stream_buf__bu8, stream_buf_len__alu16,

  FLEA_THR_FIN_SEC(
    flea_tls_rec_prot_t__dtor(&rec_prot__t);
    flea_rw_stream_t__dtor(&mem_read_stream__t);
    FLEA_FREE_BUF(read_buf__bu8);
    FLEA_FREE_BUF(stream_buf__bu8);
  );
}
