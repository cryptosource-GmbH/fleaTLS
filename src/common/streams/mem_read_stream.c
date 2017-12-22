/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "flea/mem_read_stream.h"
#include "flea/error_handling.h"
#include "flea/util.h"
#include "internal/common/rw_stream_int.h"


static flea_err_e THR_flea_mem_read_stream__read(
  void*                   hlp__pv,
  flea_u8_t*              target_buffer__pu8,
  flea_dtl_t*             nb_bytes_to_read__pdtl,
  flea_stream_read_mode_e rd_mode__e
)
{
  flea_mem_read_stream_help_t* hlp__pt;
  flea_dtl_t to_read__dtl;

  FLEA_THR_BEG_FUNC();

  hlp__pt      = (flea_mem_read_stream_help_t*) hlp__pv;
  to_read__dtl = *nb_bytes_to_read__pdtl;

  memcpy(target_buffer__pu8, &hlp__pt->data__pcu8[hlp__pt->offs__dtl], to_read__dtl);
  hlp__pt->offs__dtl     += to_read__dtl;
  hlp__pt->len__dtl      -= to_read__dtl;
  *nb_bytes_to_read__pdtl = to_read__dtl;

  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_rw_stream_t__ctor_memory(
  flea_rw_stream_t*            rw_stream__pt,
  const flea_u8_t*             source_mem__pcu8,
  flea_dtl_t                   source_mem_len__dtl,
  flea_mem_read_stream_help_t* hlp_uninit__pt
)
{
  FLEA_THR_BEG_FUNC();

  hlp_uninit__pt->data__pcu8 = source_mem__pcu8;
  hlp_uninit__pt->offs__dtl  = 0;
  if(source_mem_len__dtl == 0)
  {
    /* this is necessary since a source length of 0 set as read limit actually means "no read limit" */
    FLEA_THROW("cannot construct memory read stream from empty buffer", FLEA_ERR_INV_ARG);
  }
  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor_detailed(
      rw_stream__pt,
      (void*) hlp_uninit__pt,
      NULL,
      NULL,
      THR_flea_mem_read_stream__read,
      NULL,
      NULL,
      source_mem_len__dtl,
      flea_strm_type_memory
    )
  );
  FLEA_THR_FIN_SEC_empty();
}
