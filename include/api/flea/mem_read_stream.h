/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_mem_read_stream__H_
#define _flea_mem_read_stream__H_

#include "flea/rw_stream.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Helper type for memory-based flea_rw_stream_t type.
 */
typedef struct
{
  const flea_u8_t* data__pcu8;
  flea_dtl_t       len__dtl;
  flea_dtl_t       offs__dtl;
} flea_mem_read_stream_help_t;


flea_err_e THR_flea_rw_stream_t__ctor_memory(
  flea_rw_stream_t*            rw_stream__pt,
  const flea_u8_t*             source_mem__pcu8,
  flea_dtl_t                   source_mem_len__dtl,
  flea_mem_read_stream_help_t* hlp_uninit__pt
);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
