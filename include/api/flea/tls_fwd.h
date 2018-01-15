/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_fwd__H_
#define _flea_tls_fwd__H_


#ifdef __cplusplus
extern "C" {
#endif

struct struct_flea_tls_client_ctx_t;

/**
 * \struct flea_tls_client_ctx_t
 *
 * TLS client context type the functions of which are defined in
 * tls_client.h.
 */
typedef struct struct_flea_tls_client_ctx_t flea_tls_client_ctx_t;

struct struct_flea_tls_server_ctx_t;

/**
 * \struct flea_tls_server_ctx_t
 *
 * TLS server context type the functions of which are defined in
 * tls_server.h.
 */
typedef struct struct_flea_tls_server_ctx_t flea_tls_server_ctx_t;

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
