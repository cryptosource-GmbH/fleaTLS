/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_ctx_fwd__H_
#define _flea_tls_ctx_fwd__H_

#include "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif

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

typedef struct
{
  flea_u8_t major;
  flea_u8_t minor;
} flea_tls__protocol_version_t;

struct struct_flea_tls_ctx_t;

typedef struct struct_flea_tls_ctx_t flea_tls_ctx_t;

struct struct_flea_tls_handshake_ctx_t;

typedef struct struct_flea_tls_handshake_ctx_t flea_tls_handshake_ctx_t;

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
