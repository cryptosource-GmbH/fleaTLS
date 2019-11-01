/* fleaTLS cryptographic library
Copyright (C) 2015-2019 cryptosource GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

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
