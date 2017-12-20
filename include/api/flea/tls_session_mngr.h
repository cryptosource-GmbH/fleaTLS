/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_session_mngr__H_
#define _flea_tls_session_mngr__H_

#include "internal/common/default.h"
#include "flea/types.h"
// #include "internal/common/tls/tls_rec_prot_fwd.h"
// #include "internal/common/tls/tls_session_mngr_int.h"
#include "internal/common/tls/tls_session_int_fwd.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Destroy a TLS session manager object. All tls_server_ctx_t objects that use this session manager instance must be
 * properly destroyed before the TLS session manager is destroyed.
 *
 * @param session_mngr__pt the session manager object to destroy
 */

void flea_tls_session_mngr_t__dtor(flea_tls_session_mngr_t* session_mngr__pt);

#ifdef FLEA_USE_HEAP_BUF
# define flea_tls_session_mngr_t__INIT(__p) memset(__p, 0, sizeof(flea_tls_session_mngr_t))
# define flea_tls_session_mngr_t__INIT_VALUE {.sessions__bt = 0, .nb_alloc_sessions__dtl = 0, .nb_used_sessions__u16 = 0}
#else
# define flea_tls_session_mngr_t__INIT(__p)
#endif

#if 0
void flea_tls_session_data_t__export_seq(
  flea_tls_session_data_t const* session__pt,
  flea_tls_stream_dir_e          dir,
  flea_u32_t                     result__pu32[2]
);
void flea_tls_session_data_t__set_seqs(
  flea_tls_session_data_t* session_data__pt,
  flea_u32_t               rd_seqs[2],
  flea_u32_t               wr_seqs[2]
);
#endif // if 0


flea_err_e THR_flea_tls_session_mngr_t__ctor(
  flea_tls_session_mngr_t* session_mngr__pt,
  flea_u32_t               session_validity_period_seconds__u32
);


#ifdef __cplusplus
}
#endif
#endif /* h-guard */
