/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls__H_
#define _flea_tls__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/byte_vec.h"
#include "flea/crl.h"

#ifdef FLEA_HAVE_TLS

# ifdef __cplusplus
extern "C" {
# endif

typedef enum
{
  flea_tls_flag__reneg_mode__disallow_reneg       = 0x0,
  flea_tls_flag__reneg_mode__allow_secure_reneg   = 0x1,
  flea_tls_flag__reneg_mode__allow_insecure_reneg = 0x2,

  flea_tls_flag__sha1_cert_sigalg__allow          = 0x8,

  flea_tls_flag__rev_chk_mode__check_all          = 0x00,
  flea_tls_flag__rev_chk_mode__check_only_ee      = 0x20,
  flea_tls_flag__rev_chk_mode__check_none         = 0x40
} flea_tls_flag_e;

typedef enum
{
  flea_tls_sigalg_rsa_sha1   = (flea_sha1 << 8) | flea_rsa_pkcs1_v1_5_sign,
  flea_tls_sigalg_rsa_sha224 = (flea_sha224 << 8) | flea_rsa_pkcs1_v1_5_sign,
  flea_tls_sigalg_rsa_sha256 = (flea_sha256 << 8) | flea_rsa_pkcs1_v1_5_sign,
  flea_tls_sigalg_rsa_sha384 = (flea_sha384 << 8) | flea_rsa_pkcs1_v1_5_sign,
  flea_tls_sigalg_rsa_sha512 = (flea_sha512 << 8) | flea_rsa_pkcs1_v1_5_sign
} flea_tls_sigalg_e;

typedef enum
{
# ifdef FLEA_HAVE_TLS_RSA_WITH_AES_128_CBC_SHA
  flea_tls_rsa_with_aes_128_cbc_sha          = 0x002F,
# endif
# ifdef FLEA_HAVE_TLS_RSA_WITH_AES_256_CBC_SHA
  flea_tls_rsa_with_aes_256_cbc_sha          = 0x0035,
# endif
# ifdef FLEA_HAVE_TLS_RSA_WITH_AES_128_CBC_SHA256
  flea_tls_rsa_with_aes_128_cbc_sha256       = 0x003C,
# endif
# ifdef FLEA_HAVE_TLS_RSA_WITH_AES_256_CBC_SHA256
  flea_tls_rsa_with_aes_256_cbc_sha256       = 0x003D,
# endif
# ifdef FLEA_HAVE_TLS_RSA_WITH_AES_128_GCM_SHA256
  flea_tls_rsa_with_aes_128_gcm_sha256       = 0x009C,
# endif
# ifdef FLEA_HAVE_TLS_RSA_WITH_AES_256_GCM_SHA384
  flea_tls_rsa_with_aes_256_gcm_sha384       = 0x009D,
# endif
# ifdef FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
  flea_tls_ecdhe_rsa_with_aes_128_cbc_sha    = 0xC013,
# endif
# ifdef FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
  flea_tls_ecdhe_rsa_with_aes_256_cbc_sha    = 0xC014,
# endif
# ifdef FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
  flea_tls_ecdhe_rsa_with_aes_128_cbc_sha256 = 0xC027,
# endif
# ifdef FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
  flea_tls_ecdhe_rsa_with_aes_256_cbc_sha384 = 0xC028,
# endif
# ifdef FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  flea_tls_ecdhe_rsa_with_aes_128_gcm_sha256 = 0xC02F,
# endif
# ifdef FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  flea_tls_ecdhe_rsa_with_aes_256_gcm_sha384 = 0xC030
# endif
} flea_tls__cipher_suite_id_t;

# ifdef __cplusplus
}
# endif

#endif   // ifdef FLEA_HAVE_TLS

#endif  /* h-guard */
