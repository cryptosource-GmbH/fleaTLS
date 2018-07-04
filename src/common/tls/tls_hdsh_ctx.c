/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/tls/tls_hndsh_ctx.h"
#include "flea/alloc.h"

flea_err_e THR_flea_tls_handshake_ctx_t__ctor(flea_tls_handshake_ctx_t* hs_ctx__pt)
{
  // TODO: MAKE FLIGHT BUFFER SIZE CONTROLLABLE VIA API OR DYNAMICALLY
  FLEA_THR_BEG_FUNC();
#if defined FLEA_HAVE_DTLS
  hs_ctx__pt->dtls_ctx__t.msg_seq__s16 = -1;
  // TODO: MAKE PMTU-EST. AN ARGUMENT
  hs_ctx__pt->dtls_ctx__t.pmtu_estimate__alu16 = 256;
# if defined FLEA_HEAP_MODE
  FLEA_ALLOC_MEM(hs_ctx__pt->dtls_ctx__t.flight_buf__bu8, FLEA_DTLS_FLIGHT_BUF_SIZE);
# endif
#endif /* if defined FLEA_HAVE_DTLS */

  FLEA_THR_FIN_SEC_empty();
}

void flea_tls_handshake_ctx_t__dtor(flea_tls_handshake_ctx_t* hs_ctx__pt)
{
  FLEA_FREE_MEM_CHK_NULL(hs_ctx__pt->dtls_ctx__t.flight_buf__bu8);
}
