/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/alloc_dbg_int.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"

#ifdef FLEA_USE_BUF_DBG_CANARIES
flea_u8_t flea_dbg_canaries_flag = 0;
#endif

#ifdef FLEA_USE_HEAP_BUF
flea_err_t THR_flea_alloc__realloc_mem(void** mem_in_out__ppv, flea_u32_t orig_size__u32, flea_u32_t new_size__u32)
{
  FLEA_THR_BEG_FUNC();
  void* new_mem__pv;
  void* orig__pv = *mem_in_out__ppv;

  FLEA_ALLOC_MEM(new_mem__pv, new_size__u32);
  memcpy(new_mem__pv, orig__pv, orig_size__u32);

  FLEA_FREE_MEM(orig__pv);
  *mem_in_out__ppv = new_mem__pv;

  FLEA_THR_FIN_SEC_empty();

}
#endif /* #ifdef FLEA_USE_HEAP_BUF */
