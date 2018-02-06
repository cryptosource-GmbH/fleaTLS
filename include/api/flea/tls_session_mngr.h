/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_session_mngr__H_
#define _flea_tls_session_mngr__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "internal/common/tls/tls_session_int_fwd.h"
#include "flea/tls_fwd.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Destroy a TLS session manager object. All tls_server_ctx_t objects that use this session manager instance must be
 * properly destroyed before the TLS session manager is destroyed.
 *
 * @param session_mngr the session manager object to destroy
 */
void flea_tls_session_mngr_t__dtor(flea_tls_session_mngr_t* session_mngr);

/**
 * Init a session manager object.
 *
 * @param sm pointer to the the session manager object
 */
#ifdef FLEA_HEAP_MODE
# define flea_tls_session_mngr_t__INIT(sm) memset(sm, 0, sizeof(flea_tls_session_mngr_t))
#else
# ifdef FLEA_HAVE_MUTEX
#  define flea_tls_session_mngr_t__INIT(sm) do {(sm)->is_mutex_init__u8 = 0;} while(0)
# else
#  define flea_tls_session_mngr_t__INIT(sm)
# endif
#endif // ifdef FLEA_HEAP_MODE

/**
 * Create a TLS session manager object to be used in a fleaTLS server for
 * supporting session resumption.
 *
 * @param session_mngr the session manager object to create.
 * @param session_validity_period_seconds the number of seconds for which a
 * session remains valid (and thus resumable) after its initial creation.
 */
flea_err_e THR_flea_tls_session_mngr_t__ctor(
  flea_tls_session_mngr_t* session_mngr,
  flea_u32_t               session_validity_period_seconds
);


#ifdef __cplusplus
}
#endif
#endif /* h-guard */
