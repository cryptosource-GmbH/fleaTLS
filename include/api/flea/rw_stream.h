/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_rw_stream__H_
#define _flea_rw_stream__H_

#include "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif

  typedef flea_err_t (*flea_rw_stream_write_f)(void *custom_obj__pv, const flea_u8_t* source_buffer__pcu8, flea_dtl_t nb_bytes_to_write__dtl);
 
  typedef flea_err_t (*flea_rw_stream_open_f)(void *custom_obj__pv);
  typedef void (*flea_rw_stream_close_f)(void *custom_obj__pv);

typedef struct
{
    void * custom_obj__pv;
    flea_rw_stream_write_f write_func__f;
    flea_rw_stream_open_f open_func__f;
    flea_rw_stream_close_f close_func__f;
} flea_rw_stream_t;



#ifdef __cplusplus
}
#endif

#endif /* h-guard */
