/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_client_int_ecc__H_
# define _flea_tls_client_int_ecc__H_

# include "internal/common/tls/tls_int.h"

# ifdef __cplusplus
extern "C" {
# endif


# ifdef FLEA_HAVE_TLS


flea_err_e THR_flea_tls__snd_clt_kex_ecdhe(
  flea_tls_ctx_t*           tls_ctx__pt,
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_tls_prl_hash_ctx_t*  p_hash_ctx__pt
) FLEA_ATTRIB_UNUSED_RESULT;


# endif // ifdef FLEA_HAVE_TLS


# ifdef __cplusplus
}
# endif
#endif /* h-guard */
