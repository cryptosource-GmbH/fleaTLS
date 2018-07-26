/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls__H_
# define _flea_tls__H_

# include "internal/common/default.h"
# include "flea/types.h"
# include "flea/byte_vec.h"
# include "internal/common/crl_int.h"

# ifdef FLEA_HAVE_TLS

#  ifdef __cplusplus
extern "C" {
#  endif

/**
 * TLS flags for controlling TLS client and server behaviour. Different flags can be combined by using bitwise or ('|').
 * Their names are
 * are follow the pattern  flea_tls_flag__<field>__<value>. For each field,
 * only one value shall be used. For example, only one of the values flea_tls_flag__reneg_mode__... shall be combined with values of other fields.
 *
 *
 * The minimal required cryptographic strength (field "sec") is specified according according to
 * the NIST recommendation from 2016 ( https://www.keylength.com/en/4/ ). It is
 * applied to all public keys in the certificates in the peer's certificate
 * chain that are used for signature verification.
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
  flea_tls_flag__rev_chk_mode__check_none         = 0x40,


  /*
   * Enforce a minimum of 80 bit security for the public keys involved in the
   * certificate validation according to NIST . This value is the default if no other value is
   * specified for the "sec" field of the TLS flags.
   */
  flea_tls_flag__sec__80bit            = FLEA_PUBKEY_STRENGTH_MASK__80 << FLEA_TLS_FLAGS_SEC_LEVEL_OFFS,

  /**
   * Enforce a minimum of 112 bit security for the public keys involved in the
   * certificate validation.
   */
  flea_tls_flag__sec__112bit           = FLEA_PUBKEY_STRENGTH_MASK__112 << FLEA_TLS_FLAGS_SEC_LEVEL_OFFS,

  /**
   * Enforce a minimum of 128 bit security for the public keys involved in the
   * certificate validation.
   */
  flea_tls_flag__sec__128bit           = FLEA_PUBKEY_STRENGTH_MASK__128 << FLEA_TLS_FLAGS_SEC_LEVEL_OFFS,

  /**
   * Enforce a minimum of 192 bit security for the public keys involved in the
   * certificate validation.
   */
  flea_tls_flag__sec__192bit           = FLEA_PUBKEY_STRENGTH_MASK__192 << FLEA_TLS_FLAGS_SEC_LEVEL_OFFS,

  /**
   * Enforce a minimum of 112 bit security for the public keys involved in the
   * certificate validation.
   */
  flea_tls_flag__sec__256bit           = FLEA_PUBKEY_STRENGTH_MASK__256 << FLEA_TLS_FLAGS_SEC_LEVEL_OFFS,

  /**
   * Disable the check for the key strength. Public keys of all strengths are
   * accepted.
   */
  flea_tls_flag__sec__0bit             = FLEA_PUBKEY_STRENGTH_MASK__0 << FLEA_TLS_FLAGS_SEC_LEVEL_OFFS,

  /**
   * Accept any client or server certificate from the peer without verifying the certificate chain it
   * sends. Setting this flag renders the TLS connection insecure, since a
   * man-in-the-middle attack may be mounted. The concrete effect of this flag
   * is that only the peer's own certificate is validated and all other issuer
   * certificates sent by the peer are ignored.
   */
  flea_tls_flag__accept_untrusted_peer = 0x400,

  /*
   * For the fleaTLS client, this flag enables the use of DTLS irrespectively of
   * whether TLS was activated or not, for the fleaTLS
   * server, it enables the DTLS potentially additionally to TLS support.
   */
  flea_tls_flag__use_dtls1_2           = 0x800,

  /** When this flag is set, a DTLS server will send a HelloVerifyRequest after
   * receiving a ClientHello as a measure against denial of service attacks.
   */
  flea_tls_flag__dtls_srv_send_hvr     = 0x1000
} flea_tls_flag_e;

/**
 * Signature algorithms enums for the TLS API.
 */
typedef enum
{
#  ifdef FLEA_HAVE_SHA1
#   ifdef FLEA_HAVE_RSA
  flea_tls_sigalg_rsa_sha1   = (flea_sha1 << 8) | flea_rsa_pkcs1_v1_5_sign,
#   endif
#   ifdef FLEA_HAVE_ECDSA
  flea_tls_sigalg_ecdsa_sha1 = (flea_sha1 << 8) | flea_ecdsa_emsa1_asn1,
#   endif
#  endif // ifdef FLEA_HAVE_SHA1
#  ifdef FLEA_HAVE_RSA
  flea_tls_sigalg_rsa_sha224   = (flea_sha224 << 8) | flea_rsa_pkcs1_v1_5_sign,
  flea_tls_sigalg_rsa_sha256   = (flea_sha256 << 8) | flea_rsa_pkcs1_v1_5_sign,
#  endif
#  ifdef FLEA_HAVE_ECDSA
  flea_tls_sigalg_ecdsa_sha224 = (flea_sha224 << 8) | flea_ecdsa_emsa1_asn1,
  flea_tls_sigalg_ecdsa_sha256 = (flea_sha256 << 8) | flea_ecdsa_emsa1_asn1,
#  endif
#  ifdef FLEA_HAVE_SHA384_512
#   ifdef FLEA_HAVE_RSA
  flea_tls_sigalg_rsa_sha384   = (flea_sha384 << 8) | flea_rsa_pkcs1_v1_5_sign,
  flea_tls_sigalg_rsa_sha512   = (flea_sha512 << 8) | flea_rsa_pkcs1_v1_5_sign,
#   endif
#   ifdef FLEA_HAVE_ECDSA
  flea_tls_sigalg_ecdsa_sha384 = (flea_sha384 << 8) | flea_ecdsa_emsa1_asn1,
  flea_tls_sigalg_ecdsa_sha512 = (flea_sha512 << 8) | flea_ecdsa_emsa1_asn1,
#   endif
#  endif // ifdef FLEA_HAVE_SHA384_512
} flea_tls_sigalg_e;

/**
 * Available cipher suites for the TLS API.
 */
typedef enum
{
#  ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_128_CBC_SHA
  flea_tls_rsa_with_aes_128_cbc_sha            = 0x002F,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_256_CBC_SHA
  flea_tls_rsa_with_aes_256_cbc_sha            = 0x0035,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_128_CBC_SHA256
  flea_tls_rsa_with_aes_128_cbc_sha256         = 0x003C,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_256_CBC_SHA256
  flea_tls_rsa_with_aes_256_cbc_sha256         = 0x003D,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_128_GCM_SHA256
  flea_tls_rsa_with_aes_128_gcm_sha256         = 0x009C,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_256_GCM_SHA384
  flea_tls_rsa_with_aes_256_gcm_sha384         = 0x009D,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA
  flea_tls_ecdhe_rsa_with_aes_128_cbc_sha      = 0xC013,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA
  flea_tls_ecdhe_rsa_with_aes_256_cbc_sha      = 0xC014,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
  flea_tls_ecdhe_rsa_with_aes_128_cbc_sha256   = 0xC027,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
  flea_tls_ecdhe_rsa_with_aes_256_cbc_sha384   = 0xC028,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  flea_tls_ecdhe_rsa_with_aes_128_gcm_sha256   = 0xC02F,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  flea_tls_ecdhe_rsa_with_aes_256_gcm_sha384   = 0xC030,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
  flea_tls_ecdhe_ecdsa_with_aes_128_cbc_sha    = 0xC009,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
  flea_tls_ecdhe_ecdsa_with_aes_256_cbc_sha    = 0xC00A,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
  flea_tls_ecdhe_ecdsa_with_aes_128_cbc_sha256 = 0xC023,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
  flea_tls_ecdhe_ecdsa_with_aes_256_cbc_sha384 = 0xC024,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  flea_tls_ecdhe_ecdsa_with_aes_128_gcm_sha256 = 0xC02B,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  flea_tls_ecdhe_ecdsa_with_aes_256_gcm_sha384 = 0xC02C,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_PSK_WITH_AES_128_CBC_SHA
  flea_tls_psk_with_aes_128_cbc_sha            = 0x008C,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_PSK_WITH_AES_256_CBC_SHA
  flea_tls_psk_with_aes_256_cbc_sha            = 0x008D,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_PSK_WITH_AES_128_CBC_SHA256
  flea_tls_psk_with_aes_128_cbc_sha256         = 0x00AE,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_PSK_WITH_AES_256_CBC_SHA384
  flea_tls_psk_with_aes_256_cbc_sha384         = 0x00AF,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_PSK_WITH_AES_128_GCM_SHA256
  flea_tls_psk_with_aes_128_gcm_sha256         = 0x00A8,
#  endif
#  ifdef FLEA_HAVE_TLS_CS_PSK_WITH_AES_256_GCM_SHA384
  flea_tls_psk_with_aes_256_gcm_sha384         = 0x00A9
#  endif
} flea_tls_cipher_suite_id_t;

#  ifdef __cplusplus
}
#  endif

# endif  // ifdef FLEA_HAVE_TLS

#endif  /* h-guard */
