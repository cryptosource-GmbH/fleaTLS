#ifndef _flea_test_heap_stack_abstraction__H_
#define _flea_test_heap_stack_abstraction__H_

#include "internal/common/default.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef FLEA_USE_HEAP_BUF
# define FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(name, \
    size) flea_byte_vec_t name = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE
#else
# define FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(name, \
    size) FLEA_DECL_byte_vec_t__CONSTR_STACK_BUF_EMPTY_NOT_ALLOCATABLE(name, size)
#endif


#ifdef __cplusplus
}
#endif

#endif /* h-guard */
