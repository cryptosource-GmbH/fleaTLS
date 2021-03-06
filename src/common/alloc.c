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

#include "internal/common/alloc_dbg_int.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"


#ifdef FLEA_HEAP_MODE
flea_err_e THR_flea_alloc__realloc_mem(
  void**     mem_in_out__ppv,
  flea_u32_t orig_size__u32,
  flea_u32_t new_size__u32
)
{
  FLEA_THR_BEG_FUNC();
  void* new_mem__pv;
  void* orig__pv = *mem_in_out__ppv;

  FLEA_ALLOC_MEM(new_mem__pv, new_size__u32);
  memset(((flea_u8_t*) new_mem__pv) + orig_size__u32, 0, new_size__u32 - orig_size__u32);
  memcpy(new_mem__pv, orig__pv, orig_size__u32);
  FLEA_FREE_MEM(orig__pv);
  *mem_in_out__ppv = new_mem__pv;

  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_alloc__ensure_buffer_capacity(
  void**        mem_in_out__ppv,
  flea_dtl_t*   in_out_alloc_units__pdtl,
  flea_dtl_t    used_units__dtl,
  flea_dtl_t    min_grow_units__dtl,
  flea_dtl_t    max_grow_units__dtl,
  flea_dtl_t    max_alloc_units__dtl,
  flea_al_u16_t unit_byte_size__alu16
)
{
  FLEA_THR_BEG_FUNC();
  flea_dtl_t to_add__dtl;
  if(used_units__dtl + min_grow_units__dtl <= *in_out_alloc_units__pdtl)
  {
    FLEA_THR_RETURN();
  }
  else if((max_alloc_units__dtl == 0) || (used_units__dtl + max_grow_units__dtl <= max_alloc_units__dtl))
  {
    to_add__dtl = max_grow_units__dtl;
  }
  else if(used_units__dtl + min_grow_units__dtl <= max_alloc_units__dtl)
  {
    flea_dtl_t to_add_max_alloc__dtl = max_alloc_units__dtl - used_units__dtl;
    to_add__dtl = FLEA_MIN(to_add_max_alloc__dtl, min_grow_units__dtl);
  }
  else
  {
    FLEA_THROW("maximal buffer capacity exhausted", FLEA_ERR_BUFF_TOO_SMALL);
  }
  FLEA_CCALL(
    THR_flea_alloc__realloc_mem(
      mem_in_out__ppv,
      used_units__dtl * unit_byte_size__alu16,
      (used_units__dtl + to_add__dtl) * unit_byte_size__alu16
    )
  );
  *in_out_alloc_units__pdtl = used_units__dtl + to_add__dtl;
  FLEA_THR_FIN_SEC_empty();
}

#endif /* #ifdef FLEA_HEAP_MODE */
