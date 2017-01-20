

#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/privkey.h"
#include "flea/pkcs8.h"
#include "flea/pk_api.h"
#include "internal/common/math/mpi.h"
#include  "flea/rsa.h"
#include "self_test.h"
#include "flea/alloc.h"
#include <string.h>
#if defined FLEA_HAVE_RSA && FLEA_RSA_MAX_KEY_BIT_SIZE >= 2048
static const flea_u8_t pkcs8_rsa_key_2048_crt [] = {
/*
 *
    <30 82 04 BD 02 01 00 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00 04 82>
   0 1213: SEQUENCE {
    <02 01 00>
   4    1:   INTEGER 0
    <30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00>
   7   13:   SEQUENCE {
    <06 09 2A 86 48 86 F7 0D 01 01 01>
   9    9:     OBJECT IDENTIFIER rsaEncryption (1 2 840 113549 1 1 1)
    <05 00>
  20    0:     NULL
         :     }
    <04 82 04 A7 30 82 04 A3 02 01 00 02 82 01 01 00 CE 2E BA 32 EB 19 74 C3>
  22 1191:   OCTET STRING, encapsulates {
    <30 82 04 A3 02 01 00 02 82 01 01 00 CE 2E BA 32 EB 19 74 C3 D3 A8 EA 59>
  26 1187:     SEQUENCE {
    <02 01 00>
  30    1:       INTEGER 0
    <02 82 01 01 00 CE 2E BA 32 EB 19 74 C3 D3 A8 EA 59 A9 9C 60 C6 0D 70 2A>
  33  257:       INTEGER
         :         00 CE 2E BA 32 EB 19 74 C3 D3 A8 EA 59 A9 9C 60
         :         C6 0D 70 2A 88 71 9D 20 D5 00 45 FB ED C2 46 92
         :         DA 2C 5E 0C 23 CC A9 BE BF 0F 77 D0 87 32 BC A7
         :         81 9B 56 19 03 79 0C D7 9A 37 6C F5 4E D9 98 B6
         :         6D 26 66 16 AD B7 A9 4A 40 B1 9D 08 5E 83 9A B9
         :         63 DE 2D 7A 64 5B D4 C7 36 03 B9 8C D5 1E FE 8F
         :         0D B5 52 C1 1E 5C C4 64 8C F8 94 2E F6 AC A4 F4
         :         4F 78 36 04 B6 2D 7B 6B 07 D9 F6 8A 12 11 E9 DC
         :                 [ Another 129 bytes skipped ]
    <02 03 01 00 01>
 294    3:       INTEGER 65537
    <02 82 01 00 35 9F D7 93 A8 AB BD 3F B5 4C 08 6F 7B 7A 8D 7C D5 3F E8 00>
 299  256:       INTEGER
         :         35 9F D7 93 A8 AB BD 3F B5 4C 08 6F 7B 7A 8D 7C
         :         D5 3F E8 00 06 B4 9C 36 69 D4 C9 DA 23 9E 21 51
         :         97 1A 7A C3 D0 D6 11 23 36 0D AE 71 8B 53 9F A9
         :         48 D2 52 BD 21 7D A2 91 9C 7A BD 2E 5D CF A7 1A
         :         AA 53 00 F0 FB 84 8F 28 56 49 86 44 B6 AB C6 2D
         :         E0 3A 29 CB F2 4A 5B E9 83 7C 7D D1 6C 37 3E D3
         :         8C E6 52 0D E8 88 B7 B2 26 70 BB EA 32 2A D0 D3
         :         DE 6B 06 3C AF 85 9A E7 B6 DB B5 3B 4F E7 68 0A
         :                 [ Another 128 bytes skipped ]
    <02 81 81 00 F7 D2 A8 B2 64 79 8C D3 A1 8E 92 2B 7C 17 C9 35 7B D5 E6 52>
 559  129:       INTEGER
         :         00 F7 D2 A8 B2 64 79 8C D3 A1 8E 92 2B 7C 17 C9
         :         35 7B D5 E6 52 BD E9 D9 BB D3 59 FC 0B 69 8A 3D
         :         E9 E1 8F A2 59 12 F3 1C 64 59 AC 9D 11 A1 2E 91
         :         11 D3 DA 05 85 94 CE 58 7B 77 42 F5 ED 3C 18 B8
         :         B4 71 52 09 CB 2A 59 90 30 B9 0B 26 93 7C 3D 04
         :         06 B1 8D 9D A9 3F 0A 51 07 F8 2D 51 E8 0C BE 20
         :         CA FD 6F B2 0C 1B A3 FC EE 40 A2 EC 76 F1 B1 14
         :         DA D2 EB C8 BB 71 FF 70 DE A7 12 FB 2F DF AC CF
         :         5B
    <02 81 81 00 D4 FC 55 DF 50 56 A5 89 40 29 8A 68 4C 24 9E C0 4C A8 EF 96>
 691  129:       INTEGER
         :         00 D4 FC 55 DF 50 56 A5 89 40 29 8A 68 4C 24 9E
         :         C0 4C A8 EF 96 F7 97 0E EC 05 96 80 00 20 33 24
         :         10 4D 86 8D D2 FB BB A3 F9 14 3F 35 A3 59 F3 88
         :         3A 66 25 20 1C B7 FF FE D6 EB ED 29 D2 A7 87 5F
         :         26 A7 42 86 93 90 2B 4C 37 C7 9F 13 44 EC 76 DC
         :         79 A2 73 DF 08 3D 7C 08 73 CF 76 F5 1E 01 E1 92
         :         CC D4 0E F7 B0 6A D2 52 E5 44 19 5B ED 2C 29 41
         :         C8 20 76 F2 AE 3C D6 9C BD F6 15 CF 27 CD 66 D1
         :         3B
    <02 81 81 00 E2 2A AC AE 71 A7 C4 6F F7 87 07 BB 0B BB 21 73 E0 1A 2B E2>
 823  129:       INTEGER
         :         00 E2 2A AC AE 71 A7 C4 6F F7 87 07 BB 0B BB 21
         :         73 E0 1A 2B E2 E3 53 21 D4 9A 64 0A F3 D7 53 C4
         :         81 47 CB 2F DC 9E C0 A3 EE A9 30 31 00 3F DB 21
         :         A5 E5 73 99 8A 79 6D 7F AE DD FE 8C 35 FF 9C 88
         :         24 95 2E CB A5 50 77 00 72 96 CD A8 5C FD 0B 2A
         :         3B 79 9A C6 82 08 F8 3F 4F 48 9D 03 9D 04 D4 17
         :         55 69 C9 9F F2 10 DF AE 1B 39 7D F6 D3 EE 6B 2F
         :         9F 2C D2 E6 14 BB 4A E6 15 2C E0 D3 C0 B3 1F 20
         :         F5
    <02 81 80 22 8F 17 37 F7 07 38 30 FF 12 3E 7D 11 ED D7 3C 88 B3 D8 BC 7C>
 955  128:       INTEGER
         :         22 8F 17 37 F7 07 38 30 FF 12 3E 7D 11 ED D7 3C
         :         88 B3 D8 BC 7C 4C 2C 85 AB 9A 72 06 93 32 F9 25
         :         14 0F 43 2F FA DC C5 8C 82 F6 86 B3 8C C2 F1 55
         :         D8 81 29 A6 BF 4C 70 83 5B 20 CE 6A 79 F8 83 3D
         :         F8 61 D9 08 54 9A 51 F1 B3 18 62 BE 0A 48 77 19
         :         DD 7C 43 B2 48 97 B9 9F 61 08 82 59 6E 20 B5 FB
         :         3A 65 7B 57 4A DD F9 C9 6D B5 57 AF 32 3D 37 89
         :         4B 8B 41 71 78 39 B2 91 38 3E ED B0 1D AA 13 45
    <02 81 80 70 81 78 BA 33 78 9C B1 2C AA D9 4F 8B D7 09 F1 DB BC 26 8F A0>
1086  128:       INTEGER
         :         70 81 78 BA 33 78 9C B1 2C AA D9 4F 8B D7 09 F1
         :         DB BC 26 8F A0 C7 5D 59 11 56 46 B9 78 48 D8 49
         :         19 41 A7 E6 1B 9C B0 81 43 A3 2D 16 2D 30 B9 0B
         :         BF 36 CF CA 2A ED E5 E4 E7 5E 9A 68 71 2D BF 15
         :         15 9A A4 30 1B E6 B5 05 BA 12 23 2E 33 D9 66 CD
         :         5E 54 EC F4 7B 2E F5 0C C1 2B 5A 01 06 BB 71 3E
         :         45 C5 50 11 D4 00 F4 21 FA F1 20 2C 09 76 23 99
         :         42 FF F5 EB 82 06 11 40 26 28 7F 57 85 AC 6A 80
         :       }
         :     }
         :   }
*/

0x30, 0x82, 0x04, 0xbd, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x04, 0xa7, 0x30, 0x82, 0x04, 0xa3, 
0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xce, 0x2e, 0xba, 0x32, 0xeb, 0x19, 0x74, 0xc3, 0xd3, 0xa8, 0xea, 0x59, 0xa9, 0x9c, 0x60, 0xc6, 0x0d, 0x70, 0x2a, 0x88, 0x71, 0x9d, 
0x20, 0xd5, 0x00, 0x45, 0xfb, 0xed, 0xc2, 0x46, 0x92, 0xda, 0x2c, 0x5e, 0x0c, 0x23, 0xcc, 0xa9, 0xbe, 0xbf, 0x0f, 0x77, 0xd0, 0x87, 0x32, 0xbc, 0xa7, 0x81, 0x9b, 0x56, 0x19, 0x03, 
0x79, 0x0c, 0xd7, 0x9a, 0x37, 0x6c, 0xf5, 0x4e, 0xd9, 0x98, 0xb6, 0x6d, 0x26, 0x66, 0x16, 0xad, 0xb7, 0xa9, 0x4a, 0x40, 0xb1, 0x9d, 0x08, 0x5e, 0x83, 0x9a, 0xb9, 0x63, 0xde, 0x2d, 
0x7a, 0x64, 0x5b, 0xd4, 0xc7, 0x36, 0x03, 0xb9, 0x8c, 0xd5, 0x1e, 0xfe, 0x8f, 0x0d, 0xb5, 0x52, 0xc1, 0x1e, 0x5c, 0xc4, 0x64, 0x8c, 0xf8, 0x94, 0x2e, 0xf6, 0xac, 0xa4, 0xf4, 0x4f, 
0x78, 0x36, 0x04, 0xb6, 0x2d, 0x7b, 0x6b, 0x07, 0xd9, 0xf6, 0x8a, 0x12, 0x11, 0xe9, 0xdc, 0x71, 0xc1, 0xab, 0xac, 0x89, 0xc8, 0xb7, 0x67, 0x01, 0xe3, 0xcc, 0xb8, 0xab, 0x0b, 0x1f, 
0xcb, 0x32, 0x60, 0x63, 0x4b, 0x6f, 0x1d, 0x83, 0xde, 0x8d, 0x11, 0x08, 0x04, 0xd4, 0x0e, 0x1d, 0xdf, 0xac, 0x3a, 0xfc, 0x49, 0x98, 0xf1, 0x48, 0x6d, 0x19, 0x99, 0x56, 0xff, 0x8b, 
0x1e, 0x0b, 0x5c, 0xe7, 0x7f, 0xae, 0x9a, 0xde, 0x3d, 0x89, 0xbf, 0x57, 0x8d, 0x92, 0xf1, 0xda, 0xf8, 0x80, 0x84, 0x46, 0xe6, 0x67, 0xc7, 0x55, 0x0c, 0xf7, 0xe4, 0x81, 0x91, 0xaa, 
0x0c, 0x7b, 0xc0, 0xe2, 0xf3, 0x8e, 0xb5, 0x44, 0xa7, 0xac, 0xc4, 0x39, 0x17, 0x5a, 0xaf, 0x87, 0x41, 0xda, 0x1a, 0x9d, 0x77, 0x58, 0x0f, 0xa9, 0x9e, 0xbb, 0x83, 0xac, 0x51, 0x16, 
0x09, 0xf1, 0x18, 0x1f, 0x49, 0x56, 0x2d, 0x0b, 0xc5, 0x20, 0x80, 0xee, 0x99, 0x65, 0x7b, 0x31, 0xaf, 0x17, 0xa6, 0x68, 0x1f, 0x5f, 0x14, 0xf9, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 
0x82, 0x01, 0x00, 0x35, 0x9f, 0xd7, 0x93, 0xa8, 0xab, 0xbd, 0x3f, 0xb5, 0x4c, 0x08, 0x6f, 0x7b, 0x7a, 0x8d, 0x7c, 0xd5, 0x3f, 0xe8, 0x00, 0x06, 0xb4, 0x9c, 0x36, 0x69, 0xd4, 0xc9, 
0xda, 0x23, 0x9e, 0x21, 0x51, 0x97, 0x1a, 0x7a, 0xc3, 0xd0, 0xd6, 0x11, 0x23, 0x36, 0x0d, 0xae, 0x71, 0x8b, 0x53, 0x9f, 0xa9, 0x48, 0xd2, 0x52, 0xbd, 0x21, 0x7d, 0xa2, 0x91, 0x9c, 
0x7a, 0xbd, 0x2e, 0x5d, 0xcf, 0xa7, 0x1a, 0xaa, 0x53, 0x00, 0xf0, 0xfb, 0x84, 0x8f, 0x28, 0x56, 0x49, 0x86, 0x44, 0xb6, 0xab, 0xc6, 0x2d, 0xe0, 0x3a, 0x29, 0xcb, 0xf2, 0x4a, 0x5b, 
0xe9, 0x83, 0x7c, 0x7d, 0xd1, 0x6c, 0x37, 0x3e, 0xd3, 0x8c, 0xe6, 0x52, 0x0d, 0xe8, 0x88, 0xb7, 0xb2, 0x26, 0x70, 0xbb, 0xea, 0x32, 0x2a, 0xd0, 0xd3, 0xde, 0x6b, 0x06, 0x3c, 0xaf, 
0x85, 0x9a, 0xe7, 0xb6, 0xdb, 0xb5, 0x3b, 0x4f, 0xe7, 0x68, 0x0a, 0xc2, 0x3f, 0xa7, 0x0b, 0x8f, 0x79, 0xa1, 0xaa, 0x8c, 0xe8, 0xf9, 0x53, 0xdf, 0x74, 0xae, 0x79, 0xb2, 0xf3, 0x9b, 
0x51, 0x30, 0x25, 0x1c, 0xf9, 0x19, 0xe6, 0x9d, 0x0f, 0xb1, 0xc6, 0x3a, 0xca, 0xd4, 0xe7, 0x6a, 0x93, 0x74, 0x38, 0x0d, 0xc1, 0xfe, 0xf4, 0xe7, 0xfb, 0x65, 0xa7, 0x0f, 0x8b, 0x51, 
0xcb, 0x79, 0x8d, 0x36, 0x66, 0x37, 0x7e, 0xa8, 0x70, 0x7d, 0x3e, 0xc7, 0xe6, 0x3a, 0xac, 0xab, 0x22, 0x94, 0xf7, 0xe9, 0xa7, 0xbb, 0x62, 0x71, 0x96, 0x67, 0x9d, 0x4e, 0x31, 0x28, 
0x1e, 0xa4, 0x53, 0x48, 0xd9, 0x83, 0xe3, 0x4c, 0x18, 0xae, 0x6c, 0xcd, 0x59, 0xdb, 0x28, 0x8c, 0x01, 0xf2, 0xe9, 0x4f, 0x41, 0x06, 0x70, 0x46, 0x51, 0x9b, 0xbd, 0x89, 0x8d, 0x9f, 
0x98, 0x9c, 0xc2, 0x34, 0x52, 0xcc, 0x0d, 0x6e, 0xc8, 0x10, 0xf3, 0x25, 0x6f, 0xdf, 0x52, 0x73, 0xb7, 0x86, 0x35, 0x02, 0x81, 0x81, 0x00, 0xf7, 0xd2, 0xa8, 0xb2, 0x64, 0x79, 0x8c, 
0xd3, 0xa1, 0x8e, 0x92, 0x2b, 0x7c, 0x17, 0xc9, 0x35, 0x7b, 0xd5, 0xe6, 0x52, 0xbd, 0xe9, 0xd9, 0xbb, 0xd3, 0x59, 0xfc, 0x0b, 0x69, 0x8a, 0x3d, 0xe9, 0xe1, 0x8f, 0xa2, 0x59, 0x12, 
0xf3, 0x1c, 0x64, 0x59, 0xac, 0x9d, 0x11, 0xa1, 0x2e, 0x91, 0x11, 0xd3, 0xda, 0x05, 0x85, 0x94, 0xce, 0x58, 0x7b, 0x77, 0x42, 0xf5, 0xed, 0x3c, 0x18, 0xb8, 0xb4, 0x71, 0x52, 0x09, 
0xcb, 0x2a, 0x59, 0x90, 0x30, 0xb9, 0x0b, 0x26, 0x93, 0x7c, 0x3d, 0x04, 0x06, 0xb1, 0x8d, 0x9d, 0xa9, 0x3f, 0x0a, 0x51, 0x07, 0xf8, 0x2d, 0x51, 0xe8, 0x0c, 0xbe, 0x20, 0xca, 0xfd, 
0x6f, 0xb2, 0x0c, 0x1b, 0xa3, 0xfc, 0xee, 0x40, 0xa2, 0xec, 0x76, 0xf1, 0xb1, 0x14, 0xda, 0xd2, 0xeb, 0xc8, 0xbb, 0x71, 0xff, 0x70, 0xde, 0xa7, 0x12, 0xfb, 0x2f, 0xdf, 0xac, 0xcf, 
0x5b, 0x02, 0x81, 0x81, 0x00, 0xd4, 0xfc, 0x55, 0xdf, 0x50, 0x56, 0xa5, 0x89, 0x40, 0x29, 0x8a, 0x68, 0x4c, 0x24, 0x9e, 0xc0, 0x4c, 0xa8, 0xef, 0x96, 0xf7, 0x97, 0x0e, 0xec, 0x05, 
0x96, 0x80, 0x00, 0x20, 0x33, 0x24, 0x10, 0x4d, 0x86, 0x8d, 0xd2, 0xfb, 0xbb, 0xa3, 0xf9, 0x14, 0x3f, 0x35, 0xa3, 0x59, 0xf3, 0x88, 0x3a, 0x66, 0x25, 0x20, 0x1c, 0xb7, 0xff, 0xfe, 
0xd6, 0xeb, 0xed, 0x29, 0xd2, 0xa7, 0x87, 0x5f, 0x26, 0xa7, 0x42, 0x86, 0x93, 0x90, 0x2b, 0x4c, 0x37, 0xc7, 0x9f, 0x13, 0x44, 0xec, 0x76, 0xdc, 0x79, 0xa2, 0x73, 0xdf, 0x08, 0x3d, 
0x7c, 0x08, 0x73, 0xcf, 0x76, 0xf5, 0x1e, 0x01, 0xe1, 0x92, 0xcc, 0xd4, 0x0e, 0xf7, 0xb0, 0x6a, 0xd2, 0x52, 0xe5, 0x44, 0x19, 0x5b, 0xed, 0x2c, 0x29, 0x41, 0xc8, 0x20, 0x76, 0xf2, 
0xae, 0x3c, 0xd6, 0x9c, 0xbd, 0xf6, 0x15, 0xcf, 0x27, 0xcd, 0x66, 0xd1, 0x3b, 0x02, 0x81, 0x81, 0x00, 0xe2, 0x2a, 0xac, 0xae, 0x71, 0xa7, 0xc4, 0x6f, 0xf7, 0x87, 0x07, 0xbb, 0x0b, 
0xbb, 0x21, 0x73, 0xe0, 0x1a, 0x2b, 0xe2, 0xe3, 0x53, 0x21, 0xd4, 0x9a, 0x64, 0x0a, 0xf3, 0xd7, 0x53, 0xc4, 0x81, 0x47, 0xcb, 0x2f, 0xdc, 0x9e, 0xc0, 0xa3, 0xee, 0xa9, 0x30, 0x31, 
0x00, 0x3f, 0xdb, 0x21, 0xa5, 0xe5, 0x73, 0x99, 0x8a, 0x79, 0x6d, 0x7f, 0xae, 0xdd, 0xfe, 0x8c, 0x35, 0xff, 0x9c, 0x88, 0x24, 0x95, 0x2e, 0xcb, 0xa5, 0x50, 0x77, 0x00, 0x72, 0x96, 
0xcd, 0xa8, 0x5c, 0xfd, 0x0b, 0x2a, 0x3b, 0x79, 0x9a, 0xc6, 0x82, 0x08, 0xf8, 0x3f, 0x4f, 0x48, 0x9d, 0x03, 0x9d, 0x04, 0xd4, 0x17, 0x55, 0x69, 0xc9, 0x9f, 0xf2, 0x10, 0xdf, 0xae, 
0x1b, 0x39, 0x7d, 0xf6, 0xd3, 0xee, 0x6b, 0x2f, 0x9f, 0x2c, 0xd2, 0xe6, 0x14, 0xbb, 0x4a, 0xe6, 0x15, 0x2c, 0xe0, 0xd3, 0xc0, 0xb3, 0x1f, 0x20, 0xf5, 0x02, 0x81, 0x80, 0x22, 0x8f, 
0x17, 0x37, 0xf7, 0x07, 0x38, 0x30, 0xff, 0x12, 0x3e, 0x7d, 0x11, 0xed, 0xd7, 0x3c, 0x88, 0xb3, 0xd8, 0xbc, 0x7c, 0x4c, 0x2c, 0x85, 0xab, 0x9a, 0x72, 0x06, 0x93, 0x32, 0xf9, 0x25, 
0x14, 0x0f, 0x43, 0x2f, 0xfa, 0xdc, 0xc5, 0x8c, 0x82, 0xf6, 0x86, 0xb3, 0x8c, 0xc2, 0xf1, 0x55, 0xd8, 0x81, 0x29, 0xa6, 0xbf, 0x4c, 0x70, 0x83, 0x5b, 0x20, 0xce, 0x6a, 0x79, 0xf8, 
0x83, 0x3d, 0xf8, 0x61, 0xd9, 0x08, 0x54, 0x9a, 0x51, 0xf1, 0xb3, 0x18, 0x62, 0xbe, 0x0a, 0x48, 0x77, 0x19, 0xdd, 0x7c, 0x43, 0xb2, 0x48, 0x97, 0xb9, 0x9f, 0x61, 0x08, 0x82, 0x59, 
0x6e, 0x20, 0xb5, 0xfb, 0x3a, 0x65, 0x7b, 0x57, 0x4a, 0xdd, 0xf9, 0xc9, 0x6d, 0xb5, 0x57, 0xaf, 0x32, 0x3d, 0x37, 0x89, 0x4b, 0x8b, 0x41, 0x71, 0x78, 0x39, 0xb2, 0x91, 0x38, 0x3e, 
0xed, 0xb0, 0x1d, 0xaa, 0x13, 0x45, 0x02, 0x81, 0x80, 0x70, 0x81, 0x78, 0xba, 0x33, 0x78, 0x9c, 0xb1, 0x2c, 0xaa, 0xd9, 0x4f, 0x8b, 0xd7, 0x09, 0xf1, 0xdb, 0xbc, 0x26, 0x8f, 0xa0, 
0xc7, 0x5d, 0x59, 0x11, 0x56, 0x46, 0xb9, 0x78, 0x48, 0xd8, 0x49, 0x19, 0x41, 0xa7, 0xe6, 0x1b, 0x9c, 0xb0, 0x81, 0x43, 0xa3, 0x2d, 0x16, 0x2d, 0x30, 0xb9, 0x0b, 0xbf, 0x36, 0xcf, 
0xca, 0x2a, 0xed, 0xe5, 0xe4, 0xe7, 0x5e, 0x9a, 0x68, 0x71, 0x2d, 0xbf, 0x15, 0x15, 0x9a, 0xa4, 0x30, 0x1b, 0xe6, 0xb5, 0x05, 0xba, 0x12, 0x23, 0x2e, 0x33, 0xd9, 0x66, 0xcd, 0x5e, 
0x54, 0xec, 0xf4, 0x7b, 0x2e, 0xf5, 0x0c, 0xc1, 0x2b, 0x5a, 0x01, 0x06, 0xbb, 0x71, 0x3e, 0x45, 0xc5, 0x50, 0x11, 0xd4, 0x00, 0xf4, 0x21, 0xfa, 0xf1, 0x20, 0x2c, 0x09, 0x76, 0x23, 
0x99, 0x42, 0xff, 0xf5, 0xeb, 0x82, 0x06, 0x11, 0x40, 0x26, 0x28, 0x7f, 0x57, 0x85, 0xac, 0x6a, 0x80 

};


flea_err_t flea_test_rsa_pkcs8()
{
  flea_hash_id_t hash_id__t = flea_sha256;

  FLEA_DECL_OBJ(privkey__t, flea_private_key_t);
  FLEA_DECL_OBJ(pubkey__t, flea_public_key_t);

  FLEA_DECL_BUF(sig_buf__b_u8, flea_u8_t, FLEA_PK_MAX_SIGNATURE_LEN);
  const flea_ref_cu8_t message__rcu8 = 
  {
    .data__pcu8 = pkcs8_rsa_key_2048_crt,
    .len__dtl = sizeof(pkcs8_rsa_key_2048_crt)
  };
  flea_ref_u8_t signature__ru8;
  flea_ref_cu8_t signature__rcu8;
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(sig_buf__b_u8, FLEA_PK_MAX_SIGNATURE_LEN);
  signature__ru8.data__pcu8 = sig_buf__b_u8;
  signature__ru8.len__dtl = FLEA_PK_MAX_SIGNATURE_LEN;
  FLEA_CCALL(THR_flea_private_key_t__ctor_pkcs8(&privkey__t, pkcs8_rsa_key_2048_crt, sizeof(pkcs8_rsa_key_2048_crt))); 
  FLEA_CCALL(THR_flea_public_key_t__ctor_pkcs8(&pubkey__t, pkcs8_rsa_key_2048_crt, sizeof(pkcs8_rsa_key_2048_crt))); 
  
  FLEA_CCALL(THR_flea_pk_api__sign(&message__rcu8, &signature__ru8, &privkey__t, flea_rsa_pkcs1_v1_5_sign, hash_id__t));
  signature__rcu8.data__pcu8 = signature__ru8.data__pcu8;
  signature__rcu8.len__dtl = signature__ru8.len__dtl;
  FLEA_CCALL(THR_flea_pk_api__verify_signature(&message__rcu8, &signature__rcu8, &pubkey__t, flea_rsa_pkcs1_v1_5_sign, hash_id__t));
  FLEA_THR_FIN_SEC(
      flea_private_key_t__dtor(&privkey__t);
      flea_public_key_t__dtor(&pubkey__t);
      FLEA_FREE_BUF_FINAL(sig_buf__b_u8);
      );
}


#endif /* #if defined FLEA_HAVE_RSA && FLEA_RSA_MAX_KEY_BIT_SIZE >= 2048 */
