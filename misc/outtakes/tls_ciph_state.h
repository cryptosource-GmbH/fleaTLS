/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_ciph_state__H_
#define _flea_tls_ciph_state__H_

#include "flea/block_cipher.h"
#include "flea/mac.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { flea_tls_cbc_hmac } flea_tls_cipher_type_e;
typedef struct
{
  flea_cbc_mode_ctx_t cbc_ctx__t;
  // flea_cbc_mode_ctx_t decr_ctx__t;
  flea_mac_ctx_t      hmac_ctx__t;
  #ifdef FLEA_USE_HEAP_BUF
  flea_u8_t           *cipher_plain_key__bu8;
  flea_u8_t           *mac_key__bu8;
  #else
  flea_u8_t           cipher_plain_key__bu8[__FLEA_COMPUTED_MAX_MAC_HMAC_KEY_SIZE_SWITCHED];
  flea_u8_t           mac_key__bu8[__FLEA_COMPUTED_MAC];
  #endif
  flea_u8_t           cipher_plain_key_len__u8;
  flea_u8_t           mac_key_len__u8;
} flea_tls_cbc_hmac_ctx_t;

typedef struct
{
  union
  {
    flea_tls_cbc_hmac_ctx_t cbc_hmac__t;
  }                      cipher_specific__u;

  flea_bool_t            is_set__b;
  flea_tls_cipher_type_e ciph_type__e;
} flea_tls_cipher_state_t;

#define flea_tls_cipher_state_t__INIT_VALUE { 0 }
#define flea_tls_cipher_state_t__INIT(__p) memset((__p), 0, sizeof(*(__p)));

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
