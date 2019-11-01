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

#ifndef _flea_alloc_H_
#define _flea_alloc_H_

#include <stdlib.h> // for malloc
#include "internal/common/alloc_dbg_int.h"
#include "internal/common/alloc_int.h"

/**
 * use standard malloc and free
 */
#define FLEA_ALLOC_MEM_NOCHK(__ptr, __size) \
  do {(__ptr) = malloc(__size); \
  } while(0)

#define MY_FLEA_FREE_MEM(__ptr) \
  free(__ptr)

/***********************************/

#define FLEA_ALLOC_MEM(__ptr, __size) \
  do { \
    FLEA_ALLOC_MEM_NOCHK(__ptr, __size); \
    if(!(__ptr)) { \
      FLEA_THROW("could not aquire memory", FLEA_ERR_OUT_OF_MEM);} \
  } while(0)

#define FLEA_ALLOC_MEM_ARR(__ptr, __size) FLEA_ALLOC_MEM((__ptr), sizeof((__ptr)[0]) * (__size))

#define FLEA_ALLOC_TYPE(__ptr)            FLEA_ALLOC_MEM((__ptr), sizeof((__ptr)[0]))

#define FLEA_FREE_MEM(__ptr) \
  do { \
    MY_FLEA_FREE_MEM(__ptr); \
  } while(0)

#define FLEA_FREE_MEM_SET_NULL(__ptr) \
  do { \
    FLEA_FREE_MEM(__ptr); \
    (__ptr) = 0; \
  } while(0)

#define FLEA_FREE_MEM_CHK_NULL(__ptr) \
  do { \
    if(__ptr) { \
      FLEA_FREE_MEM(__ptr); \
    } \
  } while(0)

#define FLEA_FREE_MEM_CHK_SET_NULL(__ptr) \
  do { \
    FLEA_FREE_MEM_CHK_NULL(__ptr); \
    (__ptr) = 0; \
  } while(0)

#if defined FLEA_HEAP_MODE && defined FLEA_STACK_MODE
# error only FLEA_HEAP_MODE or FLEA_STACK_MODE may be defined, not both
#endif


#ifdef FLEA_HEAP_MODE
# define FLEA_HEAP_OR_STACK_CODE(__heap, __stack)   __heap
# define FLEA_DO_IF_USE_HEAP_BUF(__x)               do {__x} while(0)
# define __FLEA_FREE_BUF_SET_NULL(__name)           FLEA_FREE_MEM_SET_NULL(__name)
# define FLEA_DECL_DYN_LEN(__name, __type, __value) __len_type __dyn_len_name = __static_len
#else // ifdef FLEA_HEAP_MODE
# define FLEA_HEAP_OR_STACK_CODE(__heap, __stack)   __stack
# define FLEA_DO_IF_USE_HEAP_BUF(__x)
# define __FLEA_FREE_BUF_SET_NULL(__name)
#endif // ifdef FLEA_HEAP_MODE

#define FLEA_FREE_MEM_SET_NULL_IF_USE_HEAP_BUF(__x) __FLEA_FREE_BUF_SET_NULL(__x)

#ifdef FLEA_HEAP_MODE

# define FLEA_FREE_MEM_CHECK_SET_NULL_SECRET_ARR(__name, __type_len) \
  do { \
    if(__name) { \
      flea_memzero_secure((flea_u8_t*) __name, (__type_len) * sizeof(__name[0])); \
      FLEA_FREE_MEM_SET_NULL(__name); \
    } \
  } while(0)

# define FLEA_FREE_MEM_CHECK_NULL_SECRET_ARR(__name, __type_len) \
  do { \
    if(__name) { \
      flea_memzero_secure((flea_u8_t*) __name, (__type_len) * sizeof(__name[0])); \
      FLEA_FREE_MEM(__name); \
    } \
  } while(0)

# define FLEA_FREE_BUF_SECRET_ARR(__name, __type_len) \
  do { \
    if(__name) { \
      flea_memzero_secure((flea_u8_t*) __name, (__type_len) * sizeof(__name[0])); \
      FLEA_BUF_CHK_DBG_CANARIES(__name); \
      FLEA_FREE_MEM_SET_NULL(__FLEA_GET_ALLOCATED_BUF_NAME(__name)); \
      __name = NULL; /*s. th. user buffer is also NULL */ \
    } \
  } while(0)


#elif defined FLEA_STACK_MODE // #ifdef FLEA_HEAP_MODE

# define FLEA_FREE_BUF_SECRET_ARR(__name, __type_len) \
  do { \
    flea_memzero_secure((flea_u8_t*) __name, (__type_len) * sizeof(__name[0])); \
    FLEA_BUF_CHK_DBG_CANARIES(__name); \
  } while(0)
# define FLEA_FREE_MEM_CHECK_SET_NULL_SECRET_ARR(__name, __type_len) \
  do { \
    flea_memzero_secure((flea_u8_t*) __name, (__type_len) * sizeof(__name[0])); \
  } while(0)
# define FLEA_FREE_MEM_CHECK_NULL_SECRET_ARR(__name, __type_len) \
  FLEA_FREE_MEM_CHECK_SET_NULL_SECRET_ARR(__name, __type_len) \

#else // #elif defined FLEA_STACK_MODE
# error no buf type (heap or stack) defined for flea
#endif // ifdef FLEA_HEAP_MODE

flea_err_e THR_flea_alloc__realloc_mem(
  void**     mem_in_out__ppv,
  flea_u32_t orig_size__u32,
  flea_u32_t new_size__u32
);

/**
 * Ensure the size of a buffer providing minimal and maximal growth size and the
 * maximal size of the buffer for reallocation.
 *
 * @param mem_in_out__ppv [in/out] the pointer to the memory array to grow.
 * @param in_out_alloc_units__pdtl [in/out] pointer to the number of currently allocated buffer elements;
 *                                          on function return, the pointer target receives the new size,
 *                                          which is at least large enough to
 *                                          hold used_units__dtl + min_grow_units__dtl elements.
 * @param used_units__dtl the number of currently used / set  buffer elements
 * @param min_grow_units__dtl the minimal number of new units which must additionally fit into the buffer
 * @param max_grow_units__dtl the maximal number of newly allocated elements
 * @param max_alloc_units__dtl the absolute maximal value of the buffer which
 *                             may not be exceeded, in units. If 0 is provided,
 *                             no limit is applied.
 * @param unit_byte_size__alu16 the size in bytes of a single unit
 *
 * @return flea error code in the case the allocation request cannot be
 * fullfilled due to exceeding the provided limit or a failing allocation.
 */
flea_err_e THR_flea_alloc__ensure_buffer_capacity(
  void**        mem_in_out__ppv,
  flea_dtl_t*   in_out_alloc_units__pdtl,
  flea_dtl_t    used_units__dtl,
  flea_dtl_t    min_grow_units__dtl,
  flea_dtl_t    max_grow_units__dtl,
  flea_dtl_t    max_alloc_units__dtl,
  flea_al_u16_t unit_byte_size__alu16
);

#endif /* h-guard */
