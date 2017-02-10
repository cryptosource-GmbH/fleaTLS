/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_hash_stream__H_
#define _flea_hash_stream__H_

#include "flea/error.h"
#include "flea/hash.h"
#include "flea/rw_stream.h"

#ifdef __cplusplus
extern "C" {
#endif


flea_err_t THR_flea_rw_stream_t__ctor_hash_stream(
  flea_rw_stream_t* stream__pt,
  flea_hash_ctx_t*  constructed_hash_ctx__pt
);


#ifdef __cplusplus
}
#endif

#endif /* h-guard */
