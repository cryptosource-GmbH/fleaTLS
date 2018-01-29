/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls__H_
#define _flea_tls__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/byte_vec.h"
#include "internal/common/crl_int.h"

#ifdef FLEA_HAVE_TLS

# ifdef __cplusplus
extern "C" {
# endif

/**
 * TLS flags for controlling TLS client and server behaviour. Different flags can be combined by using bitwise or ('|').
 * Their names are
 * are follow the pattern  flea_tls_flag__<field>__<value>. For each field,
 * only one value shall be used. For example, only one of the values flea_tls_flag__reneg_mode__... shall be combined with values of other fields.
 *
 */
typedef enum
{
  /**
   * First value of the field controlling the renegotiation. This is the default
   * choice. If this value is chosen, then the TLS client or server will deny
   * any renegotiation request.
   */
  flea_tls_flag__reneg_mode__disallow_reneg       = 0x0,

  /**
   * This choice allows renegotiation triggered by the peer as well as by the
   * flea instance itself only if the peer also supports secure renegotiation.
   */
  flea_tls_flag__reneg_mode__allow_secure_reneg   = 0x1,

  /**
   * This choice allows insecure renegotiation additionally to secure
   * renegotiation.
   */
  flea_tls_flag__reneg_mode__allow_insecure_reneg = 0x2,

  /**
   * The default value for the field controlling the acceptance of SHA-1 in
   * certificate signatures. This choice disallows the use of SHA-1.
   */
  flea_tls_flag__sha1_cert_sigalg__disallow       = 0x0,

  /**
   * This choice allows the use of SHA-1 in certificate signatures.
   */
  flea_tls_flag__sha1_cert_sigalg__allow          = 0x8,

  /**
   * The default value for the field controlling the fleaTLS client's or server's revocation checking behaviour. This choice requires CRLs for each certificate in the certificate chain provided by the peer.
   */
  flea_tls_flag__rev_chk_mode__check_all          = 0x00,

  /**
   * This choice requires a CRL only for the peer's end-entity certificate, i.e.
   * the client or server certificate.
   */
  flea_tls_flag__rev_chk_mode__check_only_ee      = 0x20,

  /**
   * This choice disables revocation checking completely.
   */
  flea_tls_flag__rev_chk_mode__check_none         = 0x40
} flea_tls_flag_e;

/**
 * Signature algorithms enums for the TLS API.
 */
typedef enum
{
# ifdef FLEA_HAVE_SHA1
  flea_tls_sigalg_rsa_sha1   = (flea_sha1 << 8) | flea_rsa_pkcs1_v1_5_sign,
# endif
  flea_tls_sigalg_rsa_sha224 = (flea_sha224 << 8) | flea_rsa_pkcs1_v1_5_sign,
  flea_tls_sigalg_rsa_sha256 = (flea_sha256 << 8) | flea_rsa_pkcs1_v1_5_sign,
# ifdef FLEA_HAVE_SHA384_512
  flea_tls_sigalg_rsa_sha384 = (flea_sha384 << 8) | flea_rsa_pkcs1_v1_5_sign,
  flea_tls_sigalg_rsa_sha512 = (flea_sha512 << 8) | flea_rsa_pkcs1_v1_5_sign
# endif
} flea_tls_sigalg_e;

/**
 * Available cipher suites for the TLS API.
 */
typedef enum
{
# ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_128_CBC_SHA
  flea_tls_rsa_with_aes_128_cbc_sha            = 0x002F,
# endif
# ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_256_CBC_SHA
  flea_tls_rsa_with_aes_256_cbc_sha            = 0x0035,
# endif
# ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_128_CBC_SHA256
  flea_tls_rsa_with_aes_128_cbc_sha256         = 0x003C,
# endif
# ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_256_CBC_SHA256
  flea_tls_rsa_with_aes_256_cbc_sha256         = 0x003D,
# endif
# ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_128_GCM_SHA256
  flea_tls_rsa_with_aes_128_gcm_sha256         = 0x009C,
# endif
# ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_256_GCM_SHA384
  flea_tls_rsa_with_aes_256_gcm_sha384         = 0x009D,
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA
  flea_tls_ecdhe_rsa_with_aes_128_cbc_sha      = 0xC013,
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA
  flea_tls_ecdhe_rsa_with_aes_256_cbc_sha      = 0xC014,
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
  flea_tls_ecdhe_rsa_with_aes_128_cbc_sha256   = 0xC027,
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
  flea_tls_ecdhe_rsa_with_aes_256_cbc_sha384   = 0xC028,
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  flea_tls_ecdhe_rsa_with_aes_128_gcm_sha256   = 0xC02F,
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  flea_tls_ecdhe_rsa_with_aes_256_gcm_sha384   = 0xC030,
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
  flea_tls_ecdhe_ecdsa_with_aes_128_cbc_sha    = 0xC009,
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
  flea_tls_ecdhe_ecdsa_with_aes_256_cbc_sha    = 0xC00A,
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
  flea_tls_ecdhe_ecdsa_with_aes_128_cbc_sha256 = 0xC023,
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
  flea_tls_ecdhe_ecdsa_with_aes_256_cbc_sha384 = 0xC024,
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  flea_tls_ecdhe_ecdsa_with_aes_128_gcm_sha256 = 0xC02B,
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  flea_tls_ecdhe_ecdsa_with_aes_256_gcm_sha384 = 0xC02C,
# endif
} flea_tls_cipher_suite_id_t;

# ifdef __cplusplus
}
# endif

#endif   // ifdef FLEA_HAVE_TLS

#endif  /* h-guard */
