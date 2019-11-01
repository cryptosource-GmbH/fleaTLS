/* fleaTLS cryptographic library
Copyright (C) 2015-2019 cryptosource GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

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
