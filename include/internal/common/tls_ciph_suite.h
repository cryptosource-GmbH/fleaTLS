/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_tls_ciph_suite__H_
#define _flea_tls_ciph_suite__H_

#include "flea/types.h"
#include "flea/mac.h"
#include "flea/block_cipher.h"
#include "flea/ae.h"
#include "flea/pk_api.h"
#include "internal/common/tls_key_usage.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FLEA_TLS_CS_AUTH_MASK__RSA   0x01
#define FLEA_TLS_CS_AUTH_MASK__ECDSA 0x02

#define FLEA_TLS_CS_KEX_MASK__ECDHE  0x08
#define FLEA_TLS_CS_KEX_MASK__RSA    0x10

typedef enum
{
  FLEA_TLS_PRF_SHA256
} flea_tls__prf_algorithm_t;

typedef enum
{
  FLEA_TLS_NULL_WITH_NULL_NULL         = 0x0000,
  // FLEA_TLS_RSA_WITH_NULL_SHA           = 0x0002,
#ifdef FLEA_HAVE_TLS_RSA
  FLEA_TLS_RSA_WITH_NULL_SHA256        = 0x003B,
  // FLEA_TLS_RSA_WITH_3DES_EDE_CBC_SHA   = 0x000A,
# ifdef FLEA_HAVE_TLS_CBC_CS
  FLEA_TLS_RSA_WITH_AES_128_CBC_SHA    = 0x002F,
  FLEA_TLS_RSA_WITH_AES_256_CBC_SHA    = 0x0035,
  FLEA_TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C,
  FLEA_TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003D,
# endif
# ifdef FLEA_HAVE_TLS_GCM_CS
  FLEA_TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C,
  FLEA_TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009D,
# endif
# ifdef FLEA_HAVE_TLS_ECDHE
#  ifdef FLEA_HAVE_TLS_CBC_CS
  FLEA_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA    = 0xC013,
  FLEA_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA    = 0xC014,
  FLEA_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027,
  FLEA_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028,
#  endif
#  ifdef FLEA_HAVE_TLS_GCM_CS
  FLEA_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,
  FLEA_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,
#  endif
# endif // ifdef FLEA_HAVE_TLS_ECDHE
#endif // ifdef FLEA_HAVE_TLS_RSA
  FLEA_TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF,
} flea_tls__cipher_suite_id_t;

#define FLEA_TLS_NO_CIPHER 0
#define FLEA_TLS_AE_CIPHER(raw)       ((1 << 7) | raw)
#define FLEA_TLS_BLOCK_CIPHER(raw)    (raw)
#define FLEA_TLS_IS_AE_CIPHER(enc)    ((1 << 7) & enc)
#define FLEA_TLS_IS_BLOCK_CIPHER(enc) (!((1 << 7) & enc))
#define FLEA_TLS_CIPHER_RAW_ID(enc)   (enc & 0x7F)

typedef enum
{
  FLEA_TLS_KEX_RSA,
  FLEA_TLS_KEX_ECDHE,
} flea_tls__kex_method_t;

typedef struct
{
  flea_tls__cipher_suite_id_t id;

  flea_u8_t                   cipher;

  flea_u8_t                   block_size; // RFC: 8 bits => TODO: REMOVE FROM HERE AND USE flea_block_cipher__get_block_size

  // TODO: cipher suite defines length for finished message verify_data (12 byte for all standard cipher suites)
  flea_u8_t                   iv_size;      // RFC: 8 bits; TODO: NOT NEEDED HERE, CAN BE GOTTEN FROM BLOCK CIPHER ID
  flea_u8_t                   enc_key_size; // RFC: 8 bits => flea_block_cipher__get_key_size
  flea_u8_t                   mac_key_size; // RFC: 8 bits
  flea_u8_t                   mac_size;     // RFC: 8 bits


  flea_hash_id_t              hash_algorithm; // default: flea_sha_sha256
  // flea_hash_id_t              hash_algorithm; // default: flea_sha256

  // flea_tls__prf_algorithm_t   prf_algorithm;
  flea_u8_t mask;
} flea_tls__cipher_suite_t;


flea_err_t THR_flea_tls_get_cipher_suite_by_id(
  flea_tls__cipher_suite_id_t      id,
  const flea_tls__cipher_suite_t** result__pt
);

const flea_tls__cipher_suite_t* flea_tls_get_cipher_suite_by_id(flea_tls__cipher_suite_id_t id__t);

flea_pk_key_type_t flea_tls__get_key_type_by_cipher_suite_id(flea_tls__cipher_suite_id_t id__t);

flea_hash_id_t flea_tls_get_prf_hash_by_cipher_suite_id(flea_tls__cipher_suite_id_t id__t);

flea_tls__kex_method_t flea_tls_get_kex_method_by_cipher_suite_id(flea_tls__cipher_suite_id_t id__t);

flea_tls_kex_e flea_tls__get_kex_and_auth_method_by_cipher_suite_id(flea_tls__cipher_suite_id_t id__t);

flea_err_t THR_flea_tls_get_key_block_len_from_cipher_suite_id(
  flea_tls__cipher_suite_id_t id,
  flea_al_u16_t*              result_key_block_len__palu16
);
#ifdef __cplusplus
}
#endif
#endif /* h-guard */
