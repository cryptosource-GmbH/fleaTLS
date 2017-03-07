/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_tls_ciph_suite__H_
#define _flea_tls_ciph_suite__H_

#include "flea/types.h"
#include "flea/mac.h"
#include "flea/block_cipher.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
  FLEA_TLS_PRF_SHA256
} flea_tls__prf_algorithm_t;

typedef enum
{
  TLS_NULL_WITH_NULL_NULL         = 0x0000,

  TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003D,

  TLS_RSA_WITH_AES_256_CBC_SHA    = 0x0035
} flea_tls__cipher_suite_id_t;

typedef struct
{
  flea_tls__cipher_suite_id_t id;

  flea_block_cipher_id_t      cipher; // flea_des_single, flea_tdes_2key, flea_tdes_3key, flea_desx, flea_aes128, flea_aes192, flea_aes256;

  flea_u8_t                   block_size; // RFC: 8 bits => flea_block_cipher__get_block_size

  // TODO: cipher suite defines length for finished message verify_data (12 byte for all standard cipher suites)
  flea_u8_t                   iv_size;      // RFC: 8 bits
  flea_u8_t                   enc_key_size; // RFC: 8 bits => flea_block_cipher__get_key_size
  flea_u8_t                   mac_key_size; // RFC: 8 bits
  flea_u8_t                   mac_size;     // RFC: 8 bits


  flea_mac_id_t               mac_algorithm; // default: flea_hmac_sha256
  // flea_hash_id_t              hash_algorithm; // default: flea_sha256

  // flea_tls__prf_algorithm_t   prf_algorithm;
} flea_tls__cipher_suite_t;


extern const flea_tls__cipher_suite_t cipher_suites[3];


const flea_tls__cipher_suite_t* flea_tls_get_cipher_suite_by_id(flea_tls__cipher_suite_id_t id);
#ifdef __cplusplus
}
#endif
#endif /* h-guard */
