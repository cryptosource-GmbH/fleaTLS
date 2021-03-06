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

#ifndef _flea_tls_fwd__H_
#define _flea_tls_fwd__H_


#ifdef __cplusplus
extern "C" {
#endif

struct struct_flea_tls_clt_ctx_t;

/**
 * \struct flea_tls_clt_ctx_t
 *
 * TLS client context type the functions of which are defined in
 * tls_client.h.
 */
typedef struct struct_flea_tls_clt_ctx_t flea_tls_clt_ctx_t;

struct struct_flea_tls_srv_ctx_t;

/**
 * \struct flea_tls_srv_ctx_t
 *
 * TLS server context type the functions of which are defined in
 * tls_server.h.
 */
typedef struct struct_flea_tls_srv_ctx_t flea_tls_srv_ctx_t;

/**
 * \struct flea_tls_session_mngr_t
 *
 * TLS server session manager for the purpose of supporting session resumption
 * the functions of which are defined in tls_session_mngr.h.
 */
typedef struct struct_flea_tls_session_mngr_t flea_tls_session_mngr_t;

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
