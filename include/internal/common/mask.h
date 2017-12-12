/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "flea/types.h"

#ifndef _flea_mask__H_
# define _flea_mask__H_


# ifdef __cplusplus
extern "C" {
# endif

/*
 * flea_u32_t flea_expand_u32_to_u32_mask(flea_u32_t in);
 *
 * flea_pszd_uint_t flea_expand_u32_to_ptr_szd_mask(flea_u32_t in);
 */

flea_u32_t flea_consttime__select_u32_nz_z(
  flea_u32_t select_if_nonzero,
  flea_u32_t select_if_zero,
  flea_u32_t condition
);

void* flea_consttime__select_ptr_nz_z(
  void*      select_if_nonzero,
  void*      select_if_zero,
  flea_u32_t condition
);

flea_u32_t flea_expand_u32_to_u32_mask(flea_u32_t in);

flea_al_u8_t flea_consttime__x_greater_y(
  flea_u32_t x,
  flea_u32_t y
);

# ifdef __cplusplus
}
# endif

#endif /* h-guard */
