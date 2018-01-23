/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

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
