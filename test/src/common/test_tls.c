/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "self_test.h"
#include "flea/alloc.h"
#include <string.h>
#include "flea/tls.h"
#include "flea/tls_server.h"
#include "flea/tls_client.h"
#include "flea/tls_session_mngr.h"
#include "flea/tls_client_session.h"

#ifdef FLEA_HAVE_TLS_CLIENT
static void flea_test_tls_client_init_dtor()
{
  flea_tls_client_ctx_t ctx1__t;
  flea_tls_client_session_t sm__t;

  sm__t.for_resumption__u8 = 0; // avoid warning
  sm__t.session_id__au8[0] = sm__t.for_resumption__u8;
  flea_tls_client_ctx_t__INIT(&ctx1__t);
  flea_tls_client_session_t__INIT(&sm__t);
  flea_tls_client_ctx_t__dtor(&ctx1__t);
  flea_tls_client_session_t__dtor(&sm__t);
}

#endif /* ifdef FLEA_HAVE_TLS_CLIENT */
#ifdef FLEA_HAVE_TLS_SERVER
static void flea_test_tls_server_init_dtor()
{
  flea_tls_server_ctx_t ctx1__t;
  flea_tls_session_mngr_t sm__t;

  flea_tls_server_ctx_t__INIT(&ctx1__t);
  flea_tls_session_mngr_t__INIT(&sm__t);
  flea_tls_server_ctx_t__dtor(&ctx1__t);
  flea_tls_session_mngr_t__dtor(&sm__t);
}

#endif /* ifdef FLEA_HAVE_TLS_SERVER */
flea_err_e THR_flea_tls_test_basic()
{
  FLEA_THR_BEG_FUNC();
#ifdef FLEA_HAVE_TLS_SERVER
  flea_test_tls_server_init_dtor();
#endif
#ifdef FLEA_HAVE_TLS_CLIENT
  flea_test_tls_client_init_dtor();
#endif
  FLEA_THR_FIN_SEC_empty();
}
