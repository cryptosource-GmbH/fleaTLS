/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/mask.h"
#include "pltf_support/mutex.h"
#include <stdint.h>

typedef uintptr_t flea_pszd_uint_t;


flea_u32_t flea_expand_u32_to_u32_mask(flea_u32_t in)
{
  volatile flea_u32_t optimization_blocker__u32 = 0;
  flea_al_u8_t i;
  flea_u32_t result = in;

  for(i = 1; i < sizeof(flea_u32_t) * 8; i *= 2)
  {
    result |= result >> i;
  }
  result &= 1;
  result  = ~(flea_u32_t) (result - 1);

  optimization_blocker__u32 = result;
  optimization_blocker__u32++;
  return result;
}

static flea_pszd_uint_t flea_expand_u32_to_ptr_szd_mask(flea_u32_t in)
{
  volatile flea_u32_t optimization_blocker__u32 = 0;
  flea_al_u8_t i;
  flea_pszd_uint_t result = in;

  for(i = 1; i < sizeof(void*) * 8; i *= 2)
  {
    result |= result >> i;
  }
  result &= 1;
  result  = ~(flea_pszd_uint_t) (result - 1);
  optimization_blocker__u32 = result;
  optimization_blocker__u32++;
  return result;
}

flea_u32_t flea_consttime__select_u32_nz_z(
  flea_u32_t select_if_nonzero,
  flea_u32_t select_if_zero,
  flea_u32_t condition
)
{
  flea_u32_t mask = flea_expand_u32_to_u32_mask(condition);

  return ((select_if_zero & ~mask) | (select_if_nonzero & mask));
}

void* flea_consttime__select_ptr_nz_z(
  void*      select_if_nonzero,
  void*      select_if_zero,
  flea_u32_t condition
)
{
  flea_pszd_uint_t mask = flea_expand_u32_to_ptr_szd_mask(condition);
  flea_pszd_uint_t if_zero__pszd    = (flea_pszd_uint_t) select_if_zero;
  flea_pszd_uint_t if_nonzero__pszd = (flea_pszd_uint_t) select_if_nonzero;

  return (void*) ((if_zero__pszd & ~mask) | (if_nonzero__pszd & mask));
}
