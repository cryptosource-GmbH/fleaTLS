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
