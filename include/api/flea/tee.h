/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_tee__H_
#define _flea_tee__H_

#include "flea/rw_stream.h"

#ifdef __cplusplus
extern "C" {
#endif

  typedef struct
  {
      flea_rw_stream_t * stream_1__pt;
      flea_rw_stream_t * stream_2__pt;
  } flea_tee_w_stream_hlp_t;




#ifdef __cplusplus
}
#endif

#endif /* h-guard */
