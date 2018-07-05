/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/tls/dtls_stream.h"

/*
 * recprot used in tls layer:
 * - THR_flea_recprot_t__get_current_record_type()
 * - THR_flea_recprot_t__read_data() for reading CCS
 * - for setting new cipher suites
 *
 */

static flea_err_e THR_dtls_rd_strm_rd_func(
  void*                   custom_obj,
  flea_u8_t*              target_buffer,
  flea_dtl_t*             nb_bytes_to_read,
  flea_stream_read_mode_e read_mode
)
{
  FLEA_THR_BEG_FUNC();

  FLEA_THR_FIN_SEC_empty();
}

// dtls assembly layer for the handshake only
flea_err_e THR_flea_rw_stream_t__ctor_dtls_rd_strm(
  flea_rw_stream_t*          stream__pt,
  flea_dtls_rd_stream_hlp_t* hlp__pt,
  flea_dtls_hdsh_ctx_t*      dtls_ctx__pt,
  flea_recprot_t*            rec_prot__pt
)
{
  FLEA_THR_BEG_FUNC();

  hlp__pt->dtls_ctx__pt = dtls_ctx__pt;
  hlp__pt->rec_prot__pt = rec_prot__pt;
  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor(
      stream__pt,
      hlp__pt,
      NULL,
      NULL,
      THR_dtls_rd_strm_rd_func,
      NULL,
      NULL,
      0
    )
  );

  FLEA_THR_FIN_SEC_empty();
}
