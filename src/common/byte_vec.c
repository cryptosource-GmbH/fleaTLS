/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#define PREALLOC (0)
#include "flea/byte_vec.h"
#include "flea/util.h"
#include "flea/alloc.h"
#include "flea/error_handling.h"
#include <stdlib.h>
#include <string.h>

void flea_byte_vec_t__INIT(flea_byte_vec_t* byte_vec__pt)
{
  byte_vec__pt->data__pu8 = 0;
  byte_vec__pt->len__dtl  = 0;
  byte_vec__pt->allo__dtl = 0;
  byte_vec__pt->is_mem_allocable__b   = FLEA_FALSE;
  byte_vec__pt->is_mem_deallocable__b = FLEA_FALSE;
}

void flea_byte_vec_t__dtor(flea_byte_vec_t* byte_vec__pt)
{
  if(byte_vec__pt->is_mem_deallocable__b)
  {
    FLEA_FREE_MEM_CHK_SET_NULL(byte_vec__pt->data__pu8);
  }
  byte_vec__pt->len__dtl  = 0;
  byte_vec__pt->allo__dtl = 0;
  byte_vec__pt->is_mem_deallocable__b = FLEA_FALSE;
  // byte_vec__pt->is_mem_allocable__b = FLEA_FALSE;
}

void flea_byte_vec_t__ctor_empty_allocatable(flea_byte_vec_t* byte_vec__pt)
{
  flea_byte_vec_t__INIT(byte_vec__pt);
  byte_vec__pt->is_mem_allocable__b = FLEA_TRUE;
  /* nothing to do */
}

void flea_byte_vec_t__set_ref(
  flea_byte_vec_t* byte_vec__pt,
  const flea_u8_t* data__pcu8,
  flea_dtl_t       data_len__dtl
)
{
  flea_byte_vec_t__dtor(byte_vec__pt);
  byte_vec__pt->data__pu8 = (flea_u8_t*) data__pcu8;
  byte_vec__pt->len__dtl  = data_len__dtl;
}

void flea_byte_vec_t__copy_content_set_ref_use_mem(
  flea_byte_vec_t*       trgt__prcu8,
  flea_u8_t*             trgt_mem,
  const flea_byte_vec_t* src__prcu8
)
{
  memcpy(trgt_mem, src__prcu8->data__pu8, src__prcu8->len__dtl);
  trgt__prcu8->data__pu8 = trgt_mem;
  trgt__prcu8->len__dtl  = src__prcu8->len__dtl;
}

static flea_err_t THR_flea_byte_vec_t__grow_to(
  flea_byte_vec_t* byte_vec__pt,
  flea_u32_t       grow_allo_to
)
{
#ifndef FLEA_USE_STACK_BUF
  flea_u8_t* tmp = NULL;
#endif

  FLEA_THR_BEG_FUNC();
  if(grow_allo_to <= byte_vec__pt->allo__dtl)
  {
    FLEA_THR_RETURN();
  }

#ifndef FLEA_USE_STACK_BUF
  if(!byte_vec__pt->is_mem_allocable__b)
#endif
  {
    FLEA_THROW("static byte buf length is too small", FLEA_ERR_BUFF_TOO_SMALL);
  }
#ifdef FLEA_USE_STACK_BUF
#else
  // TODO: CHECK OVERFLOW:
  grow_allo_to += PREALLOC;
  FLEA_ALLOC_MEM(tmp, grow_allo_to);
  byte_vec__pt->allo__dtl = grow_allo_to;
  if(byte_vec__pt->len__dtl != 0)
  {
    memcpy(tmp, byte_vec__pt->data__pu8, byte_vec__pt->len__dtl);
  }
  FLEA_SWAP(flea_u8_t*, byte_vec__pt->data__pu8, tmp);

  if(byte_vec__pt->is_mem_deallocable__b)
  {
    FLEA_FREE_MEM_CHK_NULL(tmp);
  }
  byte_vec__pt->is_mem_deallocable__b = FLEA_TRUE;
#endif /* ifdef FLEA_USE_STACK_BUF */
  FLEA_THR_FIN_SEC(
  );
} /* THR_flea_byte_vec_t__grow_to */

flea_err_t THR_flea_byte_vec_t__resize(
  flea_byte_vec_t* byte_vec__pt,
  unsigned         new_size
)
{
  FLEA_THR_BEG_FUNC();
  if(new_size > byte_vec__pt->len__dtl)
  {
    FLEA_CCALL(THR_flea_byte_vec_t__grow_to(byte_vec__pt, new_size));
    memset(byte_vec__pt->data__pu8 + byte_vec__pt->len__dtl, 0, new_size);
  }
  byte_vec__pt->len__dtl = new_size;
  FLEA_THR_FIN_SEC_empty();
}

void flea_byte_vec_t__reset(flea_byte_vec_t* byte_vec__pt)
{
  byte_vec__pt->len__dtl = 0;
}

int flea_byte_vec_t__cmp_with_cref(
  const flea_byte_vec_t* a,
  const flea_ref_cu8_t*  b
)
{
  return flea_memcmp_wsize(a->data__pu8, a->len__dtl, b->data__pcu8, b->len__dtl);
}

int flea_byte_vec_t__cmp(
  const flea_byte_vec_t* a,
  const flea_byte_vec_t* b
)
{
  return flea_memcmp_wsize(a->data__pu8, a->len__dtl, b->data__pu8, b->len__dtl);
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
    FLEA_FREE_MEM_CHK_SET_NULL(byte_vec__pt->data__pu8);
    FLEA_THR_RETURN();
  }
  FLEA_ALLOC_MEM(copy, byte_vec__pt->len__dtl);
  memcpy(copy, byte_vec__pt->data__pu8, byte_vec__pt->len__dtl);

  FLEA_SWAP(flea_u8_t*, byte_vec__pt->data__pu8, copy);
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
  memset(byte_vec__pt->data__pu8 + byte_vec__pt->len__dtl, value, repeat);
  byte_vec__pt->len__dtl = byte_vec__pt->len__dtl + repeat;
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_byte_vec_t__set_content(
  flea_byte_vec_t* byte_vec__pt,
  const flea_u8_t* data__pcu8,
  flea_dtl_t       len__dtl
)
{
  FLEA_THR_BEG_FUNC();
  flea_byte_vec_t__reset(byte_vec__pt);
  FLEA_CCALL(THR_flea_byte_vec_t__append(byte_vec__pt, data__pcu8, len__dtl));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_byte_vec_t__append(
  flea_byte_vec_t* byte_vec__pt,
  const flea_u8_t* data__pu8,
  flea_dtl_t       len__dtl
)
{
  FLEA_THR_BEG_FUNC();
  flea_u32_t new_len__dtl = byte_vec__pt->len__dtl + len__dtl;
  if(byte_vec__pt->allo__dtl < new_len__dtl)
  {
    FLEA_CCALL(THR_flea_byte_vec_t__grow_to(byte_vec__pt, new_len__dtl));
  }
  memcpy(byte_vec__pt->data__pu8 + byte_vec__pt->len__dtl, data__pu8, len__dtl);
  byte_vec__pt->len__dtl = new_len__dtl;
  FLEA_THR_FIN_SEC();
}

flea_err_t THR_flea_byte_vec_t__push_back(
  flea_byte_vec_t* byte_vec__pt,
  flea_u8_t        byte
)
{
  flea_u8_t byte__u8 = byte;

  return THR_flea_byte_vec_t__append(byte_vec__pt, &byte__u8, 1);
}
