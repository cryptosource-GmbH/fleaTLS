/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#define PREALLOC (20)
#include "flea/byte_vec.h"
#include "flea/util.h"
#include "flea/alloc.h"
#include "flea/error_handling.h"
#include <stdlib.h>
#include <string.h>

void flea_byte_vec_t__INIT(flea_byte_vec_t* byte_vec__pt)
{
  byte_vec__pt->dta       = 0;
  byte_vec__pt->len__dtl  = 0;
  byte_vec__pt->allo__dtl = 0;
  byte_vec__pt->is_mem_deallocable__b = FLEA_FALSE;
}

void flea_byte_vec_t__dtor(flea_byte_vec_t* byte_vec__pt)
{
  if(byte_vec__pt->is_mem_deallocable__b)
  {
    FLEA_FREE_MEM_CHK_SET_NULL(byte_vec__pt->dta);
  }
  byte_vec__pt->len__dtl  = 0;
  byte_vec__pt->allo__dtl = 0;
}

void flea_byte_vec_t__ctor_empty(flea_byte_vec_t* byte_vec__pt)
{
  byte_vec__pt = byte_vec__pt;
  /* nothing to do */
}

static flea_err_t THR_flea_byte_vec_t__grow_to(
  flea_byte_vec_t* byte_vec__pt,
  flea_u32_t       grow_allo_to
)
{
  flea_u8_t* tmp = 0;

  FLEA_THR_BEG_FUNC();
  if(grow_allo_to < byte_vec__pt->allo__dtl)
  {
    FLEA_THR_RETURN();
  }
  byte_vec__pt->is_mem_deallocable__b = FLEA_TRUE;
  grow_allo_to += PREALLOC;
  FLEA_ALLOC_MEM(tmp, grow_allo_to);
  byte_vec__pt->allo__dtl = grow_allo_to;
  if(byte_vec__pt->len__dtl != 0)
  {
    memcpy(tmp, byte_vec__pt->dta, byte_vec__pt->len__dtl);
  }
  FLEA_SWAP(flea_u8_t*, byte_vec__pt->dta, tmp);
  FLEA_THR_FIN_SEC(
    FLEA_FREE_MEM_CHK_NULL(tmp);
  );
}

flea_err_t THR_flea_byte_vec_t__resize(
  flea_byte_vec_t* byte_vec__pt,
  unsigned         new_size
)
{
  FLEA_THR_BEG_FUNC();
  if(new_size > byte_vec__pt->len__dtl)
  {
    FLEA_CCALL(THR_flea_byte_vec_t__grow_to(byte_vec__pt, new_size));
    memset(byte_vec__pt->dta + byte_vec__pt->len__dtl, 0, new_size);
  }
  byte_vec__pt->len__dtl = new_size;
  FLEA_THR_FIN_SEC_empty();
}

void flea_byte_vec_t__reset(flea_byte_vec_t* byte_vec__pt)
{
  byte_vec__pt->len__dtl = 0;
}

#if 0
has errors
flea_err_t THR_flea_byte_vec_t__shrink_capacity(flea_byte_vec_t* byte_vec__pt)
{
  flea_u8_t* copy = 0;

  FLEA_THR_BEG_FUNC();
  if(byte_vec__pt->len__dtl == byte_vec__pt->allo__dtl)
  {
    FLEA_THR_RETURN();
  }
  if(byte_vec__pt->len__dtl == 0)
  {
    FLEA_FREE_MEM_CHK_SET_NULL(byte_vec__pt->dta);
    FLEA_THR_RETURN();
  }
  FLEA_ALLOC_MEM(copy, byte_vec__pt->len__dtl);
  memcpy(copy, byte_vec__pt->dta, byte_vec__pt->len__dtl);

  FLEA_SWAP(flea_u8_t*, byte_vec__pt->dta, copy);
  byte_vec__pt->allo__dtl = byte_vec__pt->len__dtl;
  FLEA_THR_FIN_SEC_ON_ERR();
  FLEA_THR_FIN_SEC_ALWAYS(
    FLEA_FREE_MEM_CHK_NULL(copy);
  );
}

#endif /* if 0 */
flea_err_t THR_flea_byte_vec_t__reserve(
  flea_byte_vec_t* byte_vec__pt,
  flea_u32_t       reserve_len
)
{
  FLEA_THR_BEG_FUNC();
  if(reserve_len > byte_vec__pt->allo__dtl)
  {
    FLEA_CCALL(THR_flea_byte_vec_t__grow_to(byte_vec__pt, reserve_len));
  }
  FLEA_THR_FIN_SEC();
}

flea_err_t THR_flea_byte_vec_t__append_constant_bytes(
  flea_byte_vec_t* byte_vec__pt,
  flea_u8_t        value,
  flea_u32_t       repeat
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_byte_vec_t__grow_to(byte_vec__pt, byte_vec__pt->len__dtl + repeat));
  memset(byte_vec__pt->dta + byte_vec__pt->len__dtl, value, repeat);
  byte_vec__pt->len__dtl = byte_vec__pt->len__dtl + repeat;
  FLEA_THR_FIN_SEC();
}

flea_err_t THR_flea_byte_vec_t__push_back(
  flea_byte_vec_t* byte_vec__pt,
  flea_u8_t*       dta,
  flea_dtl_t       len__dtl
)
{
  FLEA_THR_BEG_FUNC();
  flea_u32_t new_len__dtl = byte_vec__pt->len__dtl + len__dtl;
  if(byte_vec__pt->allo__dtl < new_len__dtl)
  {
    FLEA_CCALL(THR_flea_byte_vec_t__grow_to(byte_vec__pt, new_len__dtl));
  }
  memcpy(byte_vec__pt->dta + byte_vec__pt->len__dtl, dta, len__dtl);
  byte_vec__pt->len__dtl = new_len__dtl;
  FLEA_THR_FIN_SEC();
}
