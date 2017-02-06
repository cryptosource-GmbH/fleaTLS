/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "flea/mem_read_stream.h"
#include "flea/error_handling.h"
#include "flea/util.h"


static flea_err_t THR_flea_mem_read_stream__read(void *hlp__pv, flea_u8_t *target_buffer__pu8, flea_dtl_t *nb_bytes_to_read__pdtl, flea_bool_t force_read__b)
{
  flea_mem_read_stream_help_t *hlp__pt;
  flea_dtl_t to_read__dtl;

  FLEA_THR_BEG_FUNC();
  hlp__pt = (flea_mem_read_stream_help_t *) hlp__pv;

  if(*nb_bytes_to_read__pdtl > 0 && hlp__pt->len__dtl == 0)
  {
    FLEA_THROW("no more bytes to read in mem_read_stream", FLEA_ERR_FAILED_STREAM_READ);
  }
  to_read__dtl = *nb_bytes_to_read__pdtl;
  to_read__dtl = FLEA_MIN(to_read__dtl, hlp__pt->len__dtl);
  memcpy(target_buffer__pu8, &hlp__pt->data__pcu8[hlp__pt->offs__dtl], to_read__dtl);
  hlp__pt->offs__dtl     += to_read__dtl;
  hlp__pt->len__dtl      -= to_read__dtl;
  *nb_bytes_to_read__pdtl = to_read__dtl;

  force_read__b = force_read__b + 1;
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_rw_stream_t__ctor_memory(
  flea_rw_stream_t            *rw_stream__pt,
  const flea_u8_t             *source_mem__pcu8,
  flea_dtl_t                  source_mem_len__dtl,
  flea_mem_read_stream_help_t *hlp_uninit__pt
)
{
  FLEA_THR_BEG_FUNC();

  hlp_uninit__pt->data__pcu8 = source_mem__pcu8;
  hlp_uninit__pt->offs__dtl  = 0;
  hlp_uninit__pt->len__dtl   = source_mem_len__dtl;
  FLEA_CCALL(THR_flea_rw_stream_t__ctor(rw_stream__pt, (void *) hlp_uninit__pt, NULL, NULL, THR_flea_mem_read_stream__read, NULL, NULL));
  FLEA_THR_FIN_SEC_empty();
}
