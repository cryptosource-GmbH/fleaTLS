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
  flea_u8_t*  dta;
  flea_dtl_t  len__dtl;
  flea_dtl_t  allo__dtl;
  flea_bool_t is_mem_deallocable__b;
} flea_byte_vec_t;


#define flea_byte_vec_t__CONSTR_EMPTY {0, 0, 0, FLEA_FALSE}


void flea_byte_vec_t__INIT(flea_byte_vec_t* that);

void flea_byte_vec_t__dtor(flea_byte_vec_t* that);
// #define _flea_byte_vec_t__IS_CONSTR(__p) (1)

void flea_byte_vec_t__reset(flea_byte_vec_t* that);

void flea_byte_vec_t__ctor_empty(flea_byte_vec_t* that);

flea_err_t THR_flea_byte_vec_t__push_back(
  flea_byte_vec_t* that,
  flea_u8_t*       dta,
  flea_u32_t       len
);

flea_err_t THR_flea_byte_vec_t__reserve(
  flea_byte_vec_t* that,
  flea_u32_t       reserve_len
);

flea_err_t THR_flea_byte_vec_t__append_constant_bytes(
  flea_byte_vec_t* that,
  flea_u8_t        value,
  flea_u32_t       repeat
);

/**
 * set the vector to the new size. if the new size is smaller than the previous
 * size, the allocation size will not be reduced. if it is larger than the
 * previous size, the new bytes at the end are set to zero
 */
flea_err_t THR_flea_byte_vec_t__resize(
  flea_byte_vec_t* that,
  unsigned         new_size
);

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
