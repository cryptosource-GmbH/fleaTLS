/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#define PREALLOC (0)
#include "flea/byte_vec.h"
#include "flea/util.h"
#include "flea/alloc.h"
#include "flea/error_handling.h"
#include "internal/common/byte_vec_int.h"
#include <stdlib.h>
#include <string.h>

void flea_byte_vec_t__ctor_not_allocatable(flea_byte_vec_t* byte_vec__pt)
{
  byte_vec__pt->data__pu8 = 0;
  byte_vec__pt->len__dtl  = 0;
  byte_vec__pt->allo__dtl = 0;
#ifdef FLEA_HEAP_MODE
  byte_vec__pt->state__u8 = FLEA_BYTEVEC_STATE_NEITHER_DE_NOR_ALLOCATABLE_MASK;
#endif
}

#ifdef FLEA_HEAP_MODE
void flea_byte_vec_t__ctor_empty_allocatable(flea_byte_vec_t* byte_vec__pt)
{
  byte_vec__pt->data__pu8 = NULL;
  byte_vec__pt->allo__dtl = 0;
  byte_vec__pt->len__dtl  = 0;
  byte_vec__pt->state__u8 = FLEA_BYTEVEC_STATE_ALLOCATABLE_MASK;
}

#endif /* ifdef FLEA_HEAP_MODE */

void flea_byte_vec_t__ctor_empty_use_ext_buf(
  flea_byte_vec_t* byte_vec__pt,
  flea_u8_t*       ext_buf__pu8,
  flea_dtl_t       ext_buf_len__dtl
)
{
  byte_vec__pt->data__pu8 = ext_buf__pu8;
  byte_vec__pt->allo__dtl = ext_buf_len__dtl;
  byte_vec__pt->len__dtl  = 0;
#ifdef FLEA_HEAP_MODE
  byte_vec__pt->state__u8 = FLEA_BYTEVEC_STATE_NEITHER_DE_NOR_ALLOCATABLE_MASK;
#endif
}

void flea_byte_vec_t__dtor(flea_byte_vec_t* byte_vec__pt)
{
#ifdef FLEA_HEAP_MODE
  FLEA_BYTEVEC_STATE_SET_AS_UNDEALLOCATABLE(byte_vec__pt->state__u8);
  if(FLEA_BYTEVEC_STATE_IS_DEALLOCATABLE(byte_vec__pt->state__u8))
  {
    FLEA_FREE_MEM_CHK_SET_NULL(byte_vec__pt->data__pu8);
  }
#endif /* ifdef FLEA_HEAP_MODE */
  byte_vec__pt->len__dtl  = 0;
  byte_vec__pt->allo__dtl = 0;
}

void flea_byte_vec_t__set_as_ref(
  flea_byte_vec_t* byte_vec__pt,
  const flea_u8_t* data__pcu8,
  flea_dtl_t       data_len__dtl
)
{
  flea_byte_vec_t__dtor(byte_vec__pt);
  byte_vec__pt->data__pu8 = (flea_u8_t*) data__pcu8;
  byte_vec__pt->len__dtl  = data_len__dtl;
#ifdef FLEA_HEAP_MODE
  FLEA_BYTEVEC_STATE_SET_AS_UNDEALLOCATABLE(byte_vec__pt->state__u8);
#endif
}

void flea_byte_vec_t__copy_content_set_ref_use_mem(
  flea_byte_vec_t*       byte_vec__pt,
  flea_u8_t*             trgt_mem,
  const flea_byte_vec_t* src__prcu8
)
{
  flea_byte_vec_t__dtor(byte_vec__pt);
  memcpy(trgt_mem, src__prcu8->data__pu8, src__prcu8->len__dtl);
  byte_vec__pt->data__pu8 = trgt_mem;
  byte_vec__pt->len__dtl  = src__prcu8->len__dtl;
#ifdef FLEA_HEAP_MODE
  FLEA_BYTEVEC_STATE_SET_AS_UNDEALLOCATABLE(byte_vec__pt->state__u8);
#endif
}

static flea_err_e THR_flea_byte_vec_t__grow_to(
  flea_byte_vec_t* byte_vec__pt,
  flea_dtl_t       grow_allo_to_arg
)
{
#ifndef FLEA_STACK_MODE
  flea_u8_t* tmp = NULL;
#endif
  flea_dtl_t grow_allo_to = grow_allo_to_arg;
  FLEA_THR_BEG_FUNC();
  if(grow_allo_to <= byte_vec__pt->allo__dtl)
  {
    FLEA_THR_RETURN();
  }

#ifndef FLEA_STACK_MODE
  if(!FLEA_BYTEVEC_STATE_IS_ALLOCATABLE(byte_vec__pt->state__u8))
#endif
  {
    FLEA_THROW("static byte buf length is too small", FLEA_ERR_BUFF_TOO_SMALL);
  }
#ifdef FLEA_STACK_MODE
#else
  FLEA_CCALL(THR_flea_add_dtl_with_overflow_check(&grow_allo_to, PREALLOC));
  FLEA_ALLOC_MEM(tmp, grow_allo_to);
  byte_vec__pt->allo__dtl = grow_allo_to;
  if(byte_vec__pt->len__dtl != 0)
  {
    memcpy(tmp, byte_vec__pt->data__pu8, byte_vec__pt->len__dtl);
  }
  FLEA_SWAP(flea_u8_t*, byte_vec__pt->data__pu8, tmp);

  if(FLEA_BYTEVEC_STATE_IS_DEALLOCATABLE(byte_vec__pt->state__u8))
  {
    FLEA_FREE_MEM_CHK_NULL(tmp);
  }
  FLEA_BYTEVEC_STATE_SET_AS_DEALLOCATABLE(byte_vec__pt->state__u8);
#endif /* ifdef FLEA_STACK_MODE */
  FLEA_THR_FIN_SEC(
  );
} /* THR_flea_byte_vec_t__grow_to */

static flea_err_e THR_flea_byte_vec_t__grow_to_add_len(
  flea_byte_vec_t* byte_vec__pt,
  flea_dtl_t       add_len__dtl
)
{
  flea_dtl_t new_len__dtl = byte_vec__pt->len__dtl;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_add_dtl_with_overflow_check(&new_len__dtl, add_len__dtl));
  FLEA_CCALL(THR_flea_byte_vec_t__grow_to(byte_vec__pt, new_len__dtl));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_byte_vec_t__resize(
  flea_byte_vec_t* byte_vec__pt,
  unsigned         new_size
)
{
  FLEA_THR_BEG_FUNC();

  if(new_size > byte_vec__pt->len__dtl)
  {
    FLEA_CCALL(THR_flea_byte_vec_t__grow_to(byte_vec__pt, new_size));
    memset(byte_vec__pt->data__pu8 + byte_vec__pt->len__dtl, 0, new_size - byte_vec__pt->len__dtl);
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

flea_err_e THR_flea_byte_vec_t__reserve(
  flea_byte_vec_t* byte_vec__pt,
  flea_dtl_t       reserve_len
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_byte_vec_t__grow_to(byte_vec__pt, reserve_len));
  FLEA_THR_FIN_SEC();
}

flea_err_e THR_flea_byte_vec_t__set_content(
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

flea_err_e THR_flea_byte_vec_t__append(
  flea_byte_vec_t* byte_vec__pt,
  const flea_u8_t* data__pu8,
  flea_dtl_t       len__dtl
)
{
  FLEA_THR_BEG_FUNC();
  flea_dtl_t new_len__dtl = byte_vec__pt->len__dtl;
  FLEA_CCALL(THR_flea_add_dtl_with_overflow_check(&new_len__dtl, len__dtl));
  FLEA_CCALL(THR_flea_byte_vec_t__grow_to_add_len(byte_vec__pt, len__dtl));
  memcpy(byte_vec__pt->data__pu8 + byte_vec__pt->len__dtl, data__pu8, len__dtl);
  byte_vec__pt->len__dtl = new_len__dtl;
  FLEA_THR_FIN_SEC();
}

flea_err_e THR_flea_byte_vec_t__push_back(
  flea_byte_vec_t* byte_vec__pt,
  flea_u8_t        byte
)
{
  flea_u8_t byte__u8 = byte;

  return THR_flea_byte_vec_t__append(byte_vec__pt, &byte__u8, 1);
}
