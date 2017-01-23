/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "flea/util.h"
#include <string.h>

flea_bool_t flea_sec_mem_equal (const flea_u8_t* mem1__pcu8, const flea_u8_t* mem2__pcu8, flea_al_u16_t mem_len__alu16)
{
  flea_al_u16_t i;
  flea_u8_t diff__u8 = 0;
  flea_u8_t tmp__u8 = 0;
  volatile flea_u8_t* sink__pvu8 = (volatile flea_u8_t*)&tmp__u8;

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
void flea_memzero_secure (flea_u8_t* memory__pu8, flea_dtl_t mem_len__dtl)
{
  volatile flea_u8_t* vm__pu8 = (volatile flea_u8_t*)memory__pu8;

  while(mem_len__dtl--)
  {
    *(vm__pu8++) = 0;
  }
}

int flea_rcu8_cmp(const flea_ref_cu8_t *a, const flea_ref_cu8_t *b)
{
 return flea_memcmp_wsize(a->data__pcu8, a->len__dtl, b->data__pcu8, b->len__dtl);
}

void flea_copy_rcu8_use_mem(flea_ref_cu8_t *trgt__prcu8, flea_u8_t* trgt_mem, const flea_ref_cu8_t *src__prcu8)
{
  memcpy(trgt_mem, src__prcu8->data__pcu8, src__prcu8->len__dtl);
  trgt__prcu8->data__pcu8 = trgt_mem;
  trgt__prcu8->len__dtl = src__prcu8->len__dtl;
}

int flea_memcmp_wsize(const void* mem1__pv, flea_dtl_t len_mem1__dtl, const void*mem2__pv, flea_dtl_t len_mem2__dtl)
{
  if(len_mem1__dtl > len_mem2__dtl)
  {
    return 1;
  }
  else if (len_mem2__dtl > len_mem1__dtl)
  {
    return -1;
  }
  return memcmp(mem1__pv, mem2__pv, len_mem1__dtl);
}
