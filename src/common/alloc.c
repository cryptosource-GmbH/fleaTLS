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

flea_err_t THR_flea_alloc__ensure_buffer_capacity(void** mem_in_out__ppv, flea_dtl_t *in_out_alloc_units__pdtl, flea_dtl_t used_units__dtl, flea_dtl_t min_grow_units__dtl, flea_dtl_t max_grow_units__dtl, flea_dtl_t max_alloc_units__dtl, flea_al_u16_t unit_byte_size__alu16)
{
  FLEA_THR_BEG_FUNC();
  flea_dtl_t to_add__dtl;
  if(used_units__dtl + min_grow_units__dtl <= *in_out_alloc_units__pdtl)
  {
    FLEA_THR_RETURN();
  }
  else if((max_alloc_units__dtl == 0) || (used_units__dtl + max_grow_units__dtl <= max_alloc_units__dtl))
  {
    to_add__dtl = max_grow_units__dtl;
  }
  else if(used_units__dtl + min_grow_units__dtl <= max_alloc_units__dtl)
  {
    flea_dtl_t to_add_max_alloc__dtl = max_alloc_units__dtl - used_units__dtl;
    to_add__dtl = FLEA_MIN(to_add_max_alloc__dtl, max_grow_units__dtl);
  }
  else
  {
    FLEA_THROW("maximal buffer capacity exhausted", FLEA_ERR_BUFF_TOO_SMALL);
  }
  FLEA_CCALL(THR_flea_alloc__realloc_mem(mem_in_out__ppv, used_units__dtl*unit_byte_size__alu16, (used_units__dtl + to_add__dtl)*unit_byte_size__alu16));
  used_units__dtl += to_add__dtl;
  *in_out_alloc_units__pdtl = used_units__dtl;
  FLEA_THR_FIN_SEC_empty();
}

#endif /* #ifdef FLEA_USE_HEAP_BUF */
