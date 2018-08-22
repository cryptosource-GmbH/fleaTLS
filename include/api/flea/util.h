/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_util__H_
# define _flea_util__H_

# include "flea/types.h"
# include "flea/calc_util.h"
# include "internal/common/assert.h"

# ifdef __cplusplus
extern "C" {
# endif

# define FLEA_COMMA  ,

# define FLEA_MEMSET memset

# define FLEA_ZERO_STRUCT(__p) FLEA_MEMSET(__p, 0, sizeof(*(__p)))

# define FLEA_SWAP(__type, __a, __b) \
  do \
  { \
    __type __tmp; \
    __tmp = (__a); \
    (__a) = (__b); \
    (__b) = __tmp; \
  } while(0)

/**
 * Swap the contents of two objects of the same type.
 * @param ptr_a pointer to the first object
 * @param ptr_b pointer to the second object which is of the same type as
 * *ptr_a
 */
# define FLEA_SWAP_TYPE(ptr_a, ptr_b) \
  do { \
    FLEA_DEV_ASSERT(sizeof(*ptr_a) == sizeof(*ptr_b)); \
    flea_swap_mem((flea_u8_t*) (ptr_a), (flea_u8_t*) (ptr_b), sizeof(*ptr_a)); \
  } while(0)

# define FLEA_ASSGN_REF_FROM_BYTE_VEC(ref__pt, vec__pt) \
  do { \
    (ref__pt)->data__pcu8 = (vec__pt)->data__pu8; \
    (ref__pt)->len__dtl   = (vec__pt)->len__dtl; \
  } while(0)

# ifdef FLEA_DO_DBG_PRINT
#  define FLEA_DBG_PRINTF(...) printf(__VA_ARGS__)
# else
#  define FLEA_DBG_PRINTF(...)
# endif

/**
 * Type which represents a reference to strings of const u8 in memory.
 */
typedef struct
{
  const flea_u8_t* data__pcu8;
  flea_dtl_t       len__dtl;
} flea_ref_cu8_t;

/**
 * Type which represents a reference to strings of const u16 in memory.
 */
typedef struct
{
  const flea_u16_t* data__pcu16;
  flea_dtl_t        len__dtl;
} flea_ref_cu16_t;

/**
 * Overwrite potentially sensitive data. The function is implemented in such way
 * to prevent compiler optimizations to remove the call.
 *
 * @param memory pointer to the memory area to be overwritten
 * @param mem_len length of the memory area to be overwritten
 */
void flea_memzero_secure(
  flea_u8_t* memory,
  flea_dtl_t mem_len
);

void flea_swap_mem(
  flea_u8_t* mem_a__pu8,
  flea_u8_t* mem_b__pu8,
  flea_dtl_t mem_len__dtl
);

flea_bool_t flea_sec_mem_equal(
  const flea_u8_t* mem1__pcu8,
  const flea_u8_t* mem2__pcu8,
  flea_al_u16_t    mem_len__alu16
);

int flea_memcmp_wsize(
  const void* mem1__pv,
  flea_dtl_t  len_mem1__dtl,
  const void* mem2__pv,
  flea_dtl_t  len_mem2__dtl
);

int flea_rcu8_cmp(
  const flea_ref_cu8_t* a,
  const flea_ref_cu8_t* b
);

void flea_copy_rcu8_use_mem(
  flea_ref_cu8_t*       trgt__prcu8,
  flea_u8_t*            trgt_mem,
  const flea_ref_cu8_t* src__prcu8
);

flea_err_e THR_flea_add_dtl_with_overflow_check(
  flea_dtl_t* in_out__pdtl,
  flea_dtl_t  b__dtl
) FLEA_ATTRIB_UNUSED_RESULT;

flea_u32_t flea_waste_cycles(flea_u32_t iters__u32);

# ifdef __cplusplus
}
# endif

#endif /* h-guard */
