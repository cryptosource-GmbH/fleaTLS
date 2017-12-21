/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "flea/util.h"
#include <string.h>
#include "flea/error_handling.h"
#include "flea/error.h"

void flea_swap_mem(
  flea_u8_t* mem_a__pu8,
  flea_u8_t* mem_b__pu8,
  flea_dtl_t mem_len__dtl
)
{
  flea_dtl_t i;

  for(i = 0; i < mem_len__dtl; i++)
  {
    flea_u8_t byte;
    byte = mem_a__pu8[i];
    mem_a__pu8[i] = mem_b__pu8[i];
    mem_b__pu8[i] = byte;
  }
}

flea_bool_e flea_sec_mem_equal(
  const flea_u8_t* mem1__pcu8,
  const flea_u8_t* mem2__pcu8,
  flea_al_u16_t    mem_len__alu16
)
{
  flea_al_u16_t i;
  flea_u8_t diff__u8 = 0;
  flea_u8_t tmp__u8  = 0;
  volatile flea_u8_t* sink__pvu8 = (volatile flea_u8_t*) &tmp__u8;

  for(i = 0; i < mem_len__alu16; i++)
  {
    diff__u8 |= mem1__pcu8[i] - mem2__pcu8[i];
  }
  *sink__pvu8 = diff__u8;
  if(*sink__pvu8)
  {
    return FLEA_FALSE;
  }
  else
  {
    return FLEA_TRUE;
  }
}

void flea_memzero_secure(
  flea_u8_t* memory__pu8,
  flea_dtl_t mem_len__dtl
)
{
  volatile flea_u8_t* vm__pu8 = (volatile flea_u8_t*) memory__pu8;

  while(mem_len__dtl--)
  {
    *(vm__pu8++) = 0;
  }
}

int flea_rcu8_cmp(
  const flea_ref_cu8_t* a,
  const flea_ref_cu8_t* b
)
{
  return flea_memcmp_wsize(a->data__pcu8, a->len__dtl, b->data__pcu8, b->len__dtl);
}

void flea_copy_rcu8_use_mem(
  flea_ref_cu8_t*       trgt__prcu8,
  flea_u8_t*            trgt_mem,
  const flea_ref_cu8_t* src__prcu8
)
{
  memcpy(trgt_mem, src__prcu8->data__pcu8, src__prcu8->len__dtl);
  trgt__prcu8->data__pcu8 = trgt_mem;
  trgt__prcu8->len__dtl   = src__prcu8->len__dtl;
}

int flea_memcmp_wsize(
  const void* mem1__pv,
  flea_dtl_t  len_mem1__dtl,
  const void* mem2__pv,
  flea_dtl_t  len_mem2__dtl
)
{
  if(len_mem1__dtl > len_mem2__dtl)
  {
    return 1;
  }
  else if(len_mem2__dtl > len_mem1__dtl)
  {
    return -1;
  }
  return memcmp(mem1__pv, mem2__pv, len_mem1__dtl);
}

flea_err_e THR_flea_add_dtl_with_overflow_check(
  flea_dtl_t* in_out__pdtl,
  flea_dtl_t  b__dtl
)
{
  flea_dtl_t in__dtl     = *in_out__pdtl;
  flea_dtl_t result__dtl = *in_out__pdtl + b__dtl;

  FLEA_THR_BEG_FUNC();
  if(result__dtl < in__dtl || result__dtl < b__dtl)
  {
    FLEA_THROW("integer overflow", FLEA_ERR_INT_OVERFLOW);
  }
  *in_out__pdtl = result__dtl;
  FLEA_THR_FIN_SEC_empty();
}

flea_u32_t flea_waste_cycles(flea_u32_t iters__u32)
{
  volatile flea_al_u8_t sink__valu8 = 0;
  flea_u32_t i;

  for(i = 0; i < iters__u32; i++)
  {
    sink__valu8 += iters__u32 * i;
  }
  return sink__valu8;
}
