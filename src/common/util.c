/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "flea/util.h"
#include <string.h>

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

/*flea_dtl_t flea_determine_be_bit_size(const flea_u8_t *a__pcu8, flea_dtl_t a_len__dtl)
{
  flea_al_u8_t bits;
  while(*(a__pcu8++) == 0 && a_len__dtl--);
   
}*/
