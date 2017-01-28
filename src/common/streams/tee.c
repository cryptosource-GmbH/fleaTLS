/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "flea/tee.h"
#include "flea/error_handling.h"
#include "flea/error.h"


static flea_err_t THR_flea_tee_write_func(void *custom_obj__pv, const flea_u8_t* source_buffer__pcu8, flea_dtl_t nb_bytes_to_write__dtl)
{
  flea_tee_w_stream_hlp_t * hlp__pt = (flea_tee_w_stream_hlp_t*) custom_obj__pv;
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_rw_stream_t__write(hlp__pt->stream_1__pt, source_buffer__pcu8, nb_bytes_to_write__dtl));
  FLEA_CCALL(THR_flea_rw_stream_t__write(hlp__pt->stream_2__pt, source_buffer__pcu8, nb_bytes_to_write__dtl));
  FLEA_THR_FIN_SEC_empty(); 
}

static flea_err_t THR_flea_tee_write_flush_func(void *custom_obj__pv)
{
  flea_tee_w_stream_hlp_t * hlp__pt = (flea_tee_w_stream_hlp_t*) custom_obj__pv;
  FLEA_THR_BEG_FUNC();
FLEA_CCALL(THR_flea_rw_stream_t__flush_write(hlp__pt->stream_1__pt));
FLEA_CCALL(THR_flea_rw_stream_t__flush_write(hlp__pt->stream_2__pt));
  FLEA_THR_FIN_SEC_empty(); 
}

flea_err_t THR_flea_rw_stream_t__ctor_tee_write_stream (flea_rw_stream_t *rw_stream__pt, flea_tee_w_stream_hlp_t* hlp__pt, flea_rw_stream_t sink_stream_1__pt, flea_rw_stream_t sink_stream_2__pt)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_rw_stream_t__ctor(rw_stream__pt, (void *)hlp__pt, NULL, NULL, NULL, THR_flea_tee_write_func, THR_flea_tee_write_flush_func));
  FLEA_THR_FIN_SEC_empty(); 
}
