/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef __flea_byte_vec_H_
#define __flea_byte_vec_H_

#include "flea/error.h"
#include "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  flea_u8_t*  data__pu8;
  flea_dtl_t  len__dtl;
  flea_dtl_t  allo__dtl;
  flea_bool_t is_mem_allocable__b;
  flea_bool_t is_mem_deallocable__b;
} flea_byte_vec_t;


#define flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE     {.data__pu8 = NULL, .len__dtl = 0, .allo__dtl = 0, .is_mem_allocable__b = FLEA_TRUE, .is_mem_deallocable__b = FLEA_FALSE}

#define flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE {.data__pu8 = NULL, .len__dtl = 0, .allo__dtl = 0, .is_mem_allocable__b = FLEA_FALSE, .is_mem_deallocable__b = FLEA_FALSE}

/**
 * Declare a byte vector using a stack buffer. The byte vector is not
 * allocatable.
 */
#define FLEA_DECL_byte_vec_t__CONSTR_STACK_BUF_EMPTY_NOT_ALLOCATABLE(name, size) \
  flea_u8_t __byte_vec_stack_buf_for_ ## name[size]; \
  flea_byte_vec_t name = {.data__pu8 = __byte_vec_stack_buf_for_ ## name, \
                          .len__dtl  =                                 0, .allo__dtl= size, .is_mem_allocable__b = FLEA_FALSE, .is_mem_deallocable__b = FLEA_FALSE}

#define flea_byte_vec_t__CONSTR_EXISTING_BUF_EMPTY_ALLOCATABLE(name, size) \
  {.data__pu8 = name, \
   .len__dtl  = 0, .allo__dtl = size, .is_mem_allocable__b = FLEA_TRUE, .is_mem_deallocable__b = FLEA_FALSE}

#define FLEA_DECL_byte_vec_t__CONSTR_EXISTING_BUF_CONTENT_NOT_ALLOCATABLE(name, buf, size) \
  flea_byte_vec_t name = flea_byte_vec_t__CONSTR_EXISTING_BUF_CONTENT_NOT_ALLOCATABLE(buf, size)

#define flea_byte_vec_t__CONSTR_EXISTING_BUF_CONTENT_NOT_ALLOCATABLE(buf, size) \
  {.data__pu8 = (flea_u8_t*) buf, \
   .len__dtl  = size, .allo__dtl = size, .is_mem_allocable__b = FLEA_FALSE, .is_mem_deallocable__b = FLEA_FALSE}

#ifdef FLEA_USE_HEAP_BUF
# define FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(name, \
    size) flea_byte_vec_t name = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE
#else
# define FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(name, \
    size) FLEA_DECL_byte_vec_t__CONSTR_STACK_BUF_EMPTY_NOT_ALLOCATABLE(name, size)
#endif


void flea_byte_vec_t__INIT(flea_byte_vec_t* byte_vec__pt);

void flea_byte_vec_t__dtor(flea_byte_vec_t* byte_vec__pt);
// #define _flea_byte_vec_t__IS_CONSTR(__p) (1)

void flea_byte_vec_t__reset(flea_byte_vec_t* byte_vec__pt);

void flea_byte_vec_t__ctor_empty(flea_byte_vec_t* byte_vec__pt);

int flea_byte_vec_t__cmp(
  const flea_byte_vec_t* a,
  const flea_byte_vec_t* b
);

void flea_byte_vec_t__set_ref(
  flea_byte_vec_t* byte_vec__pt,
  const flea_u8_t* data__pcu8,
  flea_dtl_t       data_len__dtl
);

void flea_byte_vec_t__copy_content_set_ref_use_mem(
  flea_byte_vec_t*       trgt__prcu8,
  flea_u8_t*             trgt_mem,
  const flea_byte_vec_t* src__prcu8
);

flea_err_t THR_flea_byte_vec_t__append(
  flea_byte_vec_t* byte_vec__pt,
  const flea_u8_t* data__pu8,
  flea_u32_t       len
);

flea_err_t THR_flea_byte_vec_t__push_back(
  flea_byte_vec_t* byte_vec__pt,
  flea_u8_t        byte
);

flea_err_t THR_flea_byte_vec_t__reserve(
  flea_byte_vec_t* byte_vec__pt,
  flea_u32_t       reserve_len
);

flea_err_t THR_flea_byte_vec_t__set_content(
  flea_byte_vec_t* byte_vec__pt,
  const flea_u8_t* data__pcu8,
  flea_dtl_t       len__dtl
);

flea_err_t THR_flea_byte_vec_t__append_constant_bytes(
  flea_byte_vec_t* byte_vec__pt,
  flea_u8_t        value,
  flea_u32_t       repeat
);

/**
 * set the vector to the new size. if the new size is smaller than the previous
 * size, the allocation size will not be reduced. if it is larger than the
 * previous size, the new bytes at the end are set to zero
 */
flea_err_t THR_flea_byte_vec_t__resize(
  flea_byte_vec_t* byte_vec__pt,
  unsigned         new_size
);

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
