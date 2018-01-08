/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_rw_stream_int__H_
#define _flea_rw_stream_int__H_

#include "flea/rw_stream.h"
#include "internal/common/rw_stream_types.h"

#ifdef __cplusplus
extern "C" {
#endif


flea_err_e THR_flea_rw_stream_t__ctor_detailed(
  flea_rw_stream_t*            stream,
  void*                        custom_obj,
  flea_rw_stream_open_f        open_func,
  flea_rw_stream_close_f       close_func,
  flea_rw_stream_read_f        read_func,
  flea_rw_stream_write_f       write_func,
  flea_rw_stream_flush_write_f flush_write_func,
  flea_u32_t                   read_limit,
  flea_rw_stream_type_e        strm_type
);

flea_rw_stream_type_e flea_rw_stream_t__get_strm_type(const flea_rw_stream_t* rw_stream);


#ifdef __cplusplus
}
#endif

#endif /* h-guard */
