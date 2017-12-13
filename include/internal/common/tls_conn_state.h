/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_conn_state__H_
#define _flea_tls_conn_state__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/error.h"
#include "internal/common/tls_ciph_suite.h"
#include "flea/rw_stream.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef FLEA_HAVE_TLS

# ifdef FLEA_HAVE_TLS_CBC_CS

typedef struct
{
  flea_block_cipher_id_t cipher_id;
  flea_u8_t              cipher_key_size__u8;
  flea_u8_t              mac_key_size__u8; // RFC: 8 bits
  flea_u8_t              mac_size__u8;     // RFC: 8 bits
  // flea_hash_id_t         hash_id;          // default: flea_sha256
  flea_mac_id_t          mac_id;
} flea_tls_cbc_hmac_suite_config_t;

typedef struct
{
#  ifdef FLEA_USE_HEAP_BUF
  flea_u8_t* cipher_key__bu8;
  flea_u8_t* mac_key__bu8;
#  else
  flea_u8_t  cipher_key__bu8[__FLEA_COMPUTED_BLOCK_CIPHER_MAX_PLAIN_KEY_LEN];
  flea_u8_t  mac_key__bu8[__FLEA_COMPUTED_MAX_MAC_HMAC_KEY_SIZE_SWITCHED];
#  endif // ifdef FLEA_USE_HEAP_BUF

  /*flea_u8_t cipher_key_len__u8;
   * flea_u8_t mac_key_len__u8;*/
} flea_tls_cbc_hmac_conn_t;
# endif // ifdef FLEA_HAVE_TLS_CBC_CS

# ifdef FLEA_HAVE_TLS_GCM_CS

typedef struct
{
  flea_ae_id_t cipher_id;
  flea_u8_t    cipher_key_size__u8;
  flea_u8_t    fixed_iv_length__u8;
  flea_u8_t    record_iv_length__u8;
} flea_tls_gcm_suite_config_t;
typedef struct
{
#  ifdef FLEA_USE_HEAP_BUF
  flea_u8_t* cipher_key__bu8;
  flea_u8_t* fixed_iv__bu8;
  flea_u8_t* record_iv__bu8;
#  else
  flea_u8_t  cipher_key__bu8[__FLEA_COMPUTED_BLOCK_CIPHER_MAX_PLAIN_KEY_LEN]; // TODO(JR): correct? copied from Falko's cbc_hmac
  flea_u8_t  fixed_iv__bu8[4];                                                // TODO(JR): use #define for numbers
  flea_u8_t  record_iv__bu8[8];                                               // ^
  // TODO(JR): do we need the entries at all if we use defines?
#  endif // ifdef FLEA_USE_HEAP_BUF
} flea_tls_gcm_conn_t;

# endif // ifdef FLEA_HAVE_TLS_GCM_CS

typedef enum { flea_null_cipher_suite, flea_gcm_cipher_suite, flea_cbc_cipher_suite } flea_cipher_suite_class_e;

typedef struct
{
  // flea_tls__cipher_suite_id_t cipher_suite_id;
  flea_cipher_suite_class_e cipher_suite_class__e;
  union
  {
# ifdef FLEA_HAVE_TLS_CBC_CS
    flea_tls_cbc_hmac_suite_config_t cbc_hmac_config__t;
# endif
# ifdef FLEA_HAVE_TLS_GCM_CS
    flea_tls_gcm_suite_config_t      gcm_config__t;
# endif
  } suite_specific__u;
} flea_tls_cipher_suite_config_t;

typedef struct
{
  flea_tls_cipher_suite_config_t cipher_suite_config__t;
  flea_u32_t                     sequence_number__au32[2];
  union
  {
# ifdef FLEA_HAVE_TLS_CBC_CS
    flea_tls_cbc_hmac_conn_t cbc_hmac_conn_state__t;
# endif
# ifdef FLEA_HAVE_TLS_GCM_CS
    flea_tls_gcm_conn_t      gcm_conn_state__t;
# endif
  }         suite_specific__u;
  flea_u8_t reserved_iv_len__u8;
} flea_tls_conn_state_t;

# define flea_tls_conn_state_t__CONSTR     flea_tls_conn_state_t__INIT_VALUE
# define flea_tls_conn_state_t__INIT_VALUE {.cipher_suite_config__t.cipher_suite_class__e = flea_null_cipher_suite}
# define flea_tls_conn_state_t__INIT(__p) {(__p)->cipher_suite_config__t.cipher_suite_class__e = flea_null_cipher_suite}

void flea_tls_conn_state_t__dtor(flea_tls_conn_state_t* conn_state__pt);

void flea_tls_conn_state_t__ctor_no_cipher(flea_tls_conn_state_t* conn_state__pt);

# ifdef FLEA_HAVE_TLS_CBC_CS
flea_err_t THR_flea_tls_conn_state_t__ctor_cbc_hmac(
  flea_tls_conn_state_t* conn_state__pt,
  flea_block_cipher_id_t block_cipher_id,
  flea_mac_id_t          mac_id,
  const flea_u8_t*       cipher_key__pcu8,
  flea_al_u8_t           cipher_key_len__alu8,
  const flea_u8_t*       mac_key__pcu8,
  flea_al_u8_t           mac_key_len__alu8,
  flea_al_u8_t           mac_size__alu8
);
# endif // ifdef FLEA_HAVE_TLS_CBC_CS

# ifdef FLEA_HAVE_TLS_GCM_CS
flea_err_t THR_flea_tls_conn_state_t__ctor_gcm(
  flea_tls_conn_state_t* conn_state__pt,
  flea_ae_id_t           ae_cipher_id,
  const flea_u8_t*       cipher_key__pcu8,
  flea_al_u8_t           cipher_key_len__alu8,
  const flea_u8_t*       fixed_iv__pcu8,
  flea_al_u8_t           fixed_iv_len__alu8
);
# endif // ifdef FLEA_HAVE_TLS_GCM_CS

#endif // ifdef FLEA_HAVE_TLS

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
