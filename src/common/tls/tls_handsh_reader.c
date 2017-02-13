/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/tls/handsh_reader.h"
#include "flea/types.h"
#include "flea/error.h"
#include "flea/error_handling.h"
#include "flea/rw_stream.h"

#if 0
static flea_err_t THR_flea_tls_handsh_reader_t__read_handsh_hdr(
  flea_tls_handsh_reader_t* rdr__pt,
  flea_rw_stream_t          underlying_read_stream__pt
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_THR_FIN_SEC_empty();
}

#endif

flea_err_t THR_flea_tls_handsh_reader_t__ctor(
  flea_tls_handsh_reader_t* handsh_rdr__pt,
  flea_rw_stream_t*         underlying_read_stream__pt
)
{
  FLEA_THR_BEG_FUNC();

  // TODO: READ HANDSH HEADER FROM STREAM, SET TYPE AND LENGTH OF HANDSH-MESS IN
  // THE CTOR CALL:
  // FLEA_CCALL(THR_flea_rw_stream_t__ctor_tls_handsh_reader(&handsh_rdr__pt->handshake_read_stream__t, &handsh_rdr__pt->hlp__t,
  FLEA_THR_FIN_SEC_empty();
}
