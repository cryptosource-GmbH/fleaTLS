/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/data_sink.h"
#include "flea/error_handling.h"

flea_err_t THR_flea_data_sink_t__ctor(flea_data_sink_t * sink__pt, void *custom_obj__pv, flea_data_sink_open_f open_func__f, flea_data_sink_close_f close_func__f, flea_data_sink_write_f write_func__f)
{
  FLEA_THR_BEG_FUNC();
  sink__pt->custom_obj__pv = custom_obj__pv;
  sink__pt->open_func__f = open_func__f;
  sink__pt->close_func__f = close_func__f;
  sink__pt->write_func__f = write_func__f;
  FLEA_CCALL( open_func__f(custom_obj__pv));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_data_sink_t__write(flea_data_sink_t * sink__pt, const flea_u8_t* data__pcu8, flea_dtl_t data_len__dtl)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(sink__pt->write_func__f(sink__pt->custom_obj__pv, data__pcu8, data_len__dtl));
  FLEA_THR_FIN_SEC_empty();
}

void flea_data_sink_t__dtor(flea_data_sink_t *sink__pt)
{
  sink__pt->close_func__f(sink__pt->custom_obj__pv);
}
