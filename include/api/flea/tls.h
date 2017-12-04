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

// DONE:
# define FLEA_TLS_CFG_FLAG__RENEG_MODE__DISALLOW_RENEG       0x0
# define FLEA_TLS_CFG_FLAG__RENEG_MODE__ALLOW_SECURE_RENEG   0x1
# define FLEA_TLS_CFG_FLAG__RENEG_MODE__ALLOW_INSECURE_RENEG 0x2

// TODO: NEXT RELEASE
# define FLEA_TLS_CFG_FLAG__RENEG_CERT_CHANGE__ALLOW 0x4

// DONE:
# define FLEA_TLS_CFG_FLAG__SHA1_CERT_SIGALG__ALLOW 0x8

// DONE:
# define FLEA_TLS_CFG_FLAG__REV_CHK_MODE__CHECK_ALL     0x00
# define FLEA_TLS_CFG_FLAG__REV_CHK_MODE__CHECK_ONLY_EE 0x20
# define FLEA_TLS_CFG_FLAG__REV_CHK_MODE__CHECK_NONE    0x40

// TODO: NEXT RELEASE
# define FLEA_TLS_CFG_FLAG__MIN_KEY_STRENGTH_SYM_BITS__80  0x380
# define FLEA_TLS_CFG_FLAG__MIN_KEY_STRENGTH_SYM_BITS__100 0x180
# define FLEA_TLS_CFG_FLAG__MIN_KEY_STRENGTH_SYM_BITS__128 0x000

// # define FLEA_TLS_CFG_FLAG__MIN_KEY_STRENGTH_SYM_BITS__256   0x000

typedef enum
{
  flea_tls_sigalg_rsa_sha1   = (flea_sha1 << 8) | flea_rsa_pkcs1_v1_5_sign,
  flea_tls_sigalg_rsa_sha224 = (flea_sha224 << 8) | flea_rsa_pkcs1_v1_5_sign,
  flea_tls_sigalg_rsa_sha256 = (flea_sha256 << 8) | flea_rsa_pkcs1_v1_5_sign,
  flea_tls_sigalg_rsa_sha384 = (flea_sha384 << 8) | flea_rsa_pkcs1_v1_5_sign,
  flea_tls_sigalg_rsa_sha512 = (flea_sha512 << 8) | flea_rsa_pkcs1_v1_5_sign
} flea_tls_sigalg_e;

# ifdef __cplusplus
}
# endif

#endif // ifdef FLEA_HAVE_TLS

#endif /* h-guard */
