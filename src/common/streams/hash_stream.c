/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/hash_stream.h"


static flea_err_t THR_flea_hash_stream_write(void *custom_obj__pv, const flea_u8_t* data__pcu8, flea_dtl_t data_len__dtl)
{
 flea_hash_ctx_t *hash_ctx__pt = (flea_hash_ctx_t*) custom_obj__pv;
 FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_hash_ctx_t__update(hash_ctx__pt, data__pcu8, data_len__dtl));
 FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_rw_stream_t__ctor_hash_stream(flea_rw_stream_t * stream__pt, flea_hash_ctx_t *constructed_hash_ctx__pt)
{
 
 FLEA_THR_BEG_FUNC();
FLEA_CCALL(THR_flea_rw_stream_t__ctor(stream__pt, (void*) constructed_hash_ctx__pt, NULL, NULL, NULL, THR_flea_hash_stream_write, NULL));
 FLEA_THR_FIN_SEC_empty();
}
