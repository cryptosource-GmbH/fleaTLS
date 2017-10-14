#ifndef _flea_tls_int__H_
#define _flea_tls_int__H_

#include "internal/common/algo_len_int.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FLEA_TLS_CERT_TYPE_RSA_SIGN   1
#define FLEA_TLS_CERT_TYPE_ECDSA_SIGN 64

#define FLEA_TLS_HELLO_RANDOM_SIZE    32
#define FLEA_TLS_MASTER_SECRET_SIZE   48

// maximum size that we will ever allocate to temporary store the cipher suites
#define FLEA_TLS_MAX_CIPH_SUITES_BUF_SIZE_HEAP 1024

#define FLEA_CONST_TLS_GCM_RECORD_IV_LEN       8
#define FLEA_CONST_TLS_GCM_FIXED_IV_LEN        4
#define FLEA_CONST_TLS_GCM_TAG_LEN             16


#define FLEA_TLS_MAX_MAC_SIZE     FLEA_MAC_MAX_OUTPUT_LENGTH      // (512 / 8)
#define FLEA_TLS_MAX_MAC_KEY_SIZE __FLEA_COMPUTED_MAC_MAX_KEY_LEN // 32
#define FLEA_TLS_MAX_IV_SIZE      FLEA_MAX(FLEA_CIPHER_MAX_BLOCK_LEN, FLEA_CONST_TLS_GCM_RECORD_IV_LEN)

// Falko:
// shouldn't
// the max iv
// size be 16?

typedef enum { flea_tls_read, flea_tls_write } flea_tls_stream_dir_e;

typedef enum { PRF_LABEL_TEST, PRF_LABEL_CLIENT_FINISHED, PRF_LABEL_SERVER_FINISHED, PRF_LABEL_MASTER_SECRET,
               PRF_LABEL_KEY_EXPANSION } PRFLabel;

typedef enum
{
  HANDSHAKE_TYPE_HELLO_REQUEST       = 0,
  HANDSHAKE_TYPE_CLIENT_HELLO        = 1,
  HANDSHAKE_TYPE_SERVER_HELLO        = 2,
  HANDSHAKE_TYPE_NEW_SESSION_TICKET  = 4,
  HANDSHAKE_TYPE_CERTIFICATE         = 11,
  HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12,
  HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13,
  HANDSHAKE_TYPE_SERVER_HELLO_DONE   = 14,
  HANDSHAKE_TYPE_CERTIFICATE_VERIFY  = 15,
  HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16,
  HANDSHAKE_TYPE_FINISHED            = 20
} HandshakeType;

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
