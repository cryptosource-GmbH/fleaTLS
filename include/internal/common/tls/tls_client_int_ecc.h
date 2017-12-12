/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_client_int_ecc__H_
#define _flea_tls_client_int_ecc__H_

#include "internal/common/tls/tls_int.h"

#ifdef __cplusplus
extern "C" {
#endif


#ifdef FLEA_HAVE_TLS


flea_err_t THR_flea_tls__send_client_key_exchange_ecdhe(
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_tls_handshake_ctx_t*     hs_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt
);


#endif // ifdef FLEA_HAVE_TLS


#ifdef __cplusplus
}
#endif
#endif /* h-guard */
