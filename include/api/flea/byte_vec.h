/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef __flea_byte_vec_H_
#define __flea_byte_vec_H_

#include "flea/error.h"
#include "flea/types.h"
#include "flea/util.h"
#include "internal/common/byte_vec_int.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  flea_u8_t* data__pu8;
  flea_dtl_t len__dtl;
  flea_dtl_t allo__dtl;
  flea_u8_t  state__u8;
} flea_byte_vec_t;


/**
 * Right hand side initialization value for a byte vector. The byte vector is
 * constructed as allocatable but with an empty capacity.
 */
#define flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE {.data__pu8 = NULL, .len__dtl = 0, .allo__dtl = 0, .state__u8 = FLEA_BYTEVEC_STATE_ALLOCATABLE_MASK}

/**
 * Right hand side initialization value for a byte vector. The byte vector is
 * constructed as non-allocatable and thus can only be used to received
 * reference values.
 */
#define flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE {.data__pu8 = NULL, .len__dtl = 0, .allo__dtl = 0, .state__u8 = FLEA_BYTEVEC_STATE_NEITHER_DE_NOR_ALLOCATABLE_MASK}


/**
 * Declare a byte vector using a stack buffer as the vector's internal buffer. The byte vector is not
 * allocatable.
 */
#define FLEA_DECL_byte_vec_t__CONSTR_STACK_BUF_EMPTY_NOT_ALLOCATABLE(name, size) \
  flea_u8_t __byte_vec_stack_buf_for_ ## name[size]; \
  flea_byte_vec_t name = {.data__pu8 = __byte_vec_stack_buf_for_ ## name, \
                          .len__dtl  =                                 0, .allo__dtl= size, .state__u8 = FLEA_BYTEVEC_STATE_NEITHER_DE_NOR_ALLOCATABLE_MASK}

/**
 * Right hand side initialization value for a byte vector using an existing buffer as the byte
 * vector's internal buffer. The byte vector is created empty. It is not
 * allocatable.
 */
#define flea_byte_vec_t__CONSTR_EXISTING_BUF_NOT_ALLOCATABLE(buf, size) \
  {.data__pu8 = (flea_u8_t*) buf, \
   .len__dtl  = 0, .allo__dtl = size, .state__u8 = FLEA_BYTEVEC_STATE_NEITHER_DE_NOR_ALLOCATABLE_MASK}

/**
 * Right hand side initialization value for a byte vector using an existing buffer as the byte
 * vector's internal buffer. The vector's intial content is set to the content of that buffer. The byte vector is not allocatable.
 */
#define flea_byte_vec_t__CONSTR_EXISTING_BUF_CONTENT_NOT_ALLOCATABLE(buf, size) \
  {.data__pu8 = (flea_u8_t*) buf, \
   .len__dtl  = size, .allo__dtl = size, .state__u8 = FLEA_BYTEVEC_STATE_NEITHER_DE_NOR_ALLOCATABLE_MASK}

/**
 * Statement for the creation of a byte vector using flea_byte_vec_t__CONSTR_EXISTING_BUF_CONTENT_NOT_ALLOCATABLE.
 */
#define FLEA_DECL_byte_vec_t__CONSTR_EXISTING_BUF_CONTENT_NOT_ALLOCATABLE(name, buf, size) \
  flea_byte_vec_t name = flea_byte_vec_t__CONSTR_EXISTING_BUF_CONTENT_NOT_ALLOCATABLE(buf, size)

/**
 * Right hand side initialization value for a byte vector. In heap mode, the byte vector is
 * constructed as allocatable with an initial capacity of zero. In stack mode,
 * the vector receives a stack array variable which servers as the vector's
 * internal buffer.
 * This initialization value is useful when writing code which is supposed to
 * run in both heap and stack mode.
 */
#ifdef FLEA_USE_HEAP_BUF
# define flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK_BUF(dummy)       flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE
#else
# define flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK_BUF(stack_array) {.data__pu8 = stack_array, .len__dtl = 0, .allo__dtl = sizeof(stack_array), .state__u8 = FLEA_BYTEVEC_STATE_NEITHER_DE_NOR_ALLOCATABLE_MASK}
#endif

/**
 * Declare a byte vector based on heap memory or a stack buffer of static size,
 * depending on the mode. In stack mode, the static buffer is also declared by
 * this macro.
 */
#ifdef FLEA_USE_HEAP_BUF
# define FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(name, \
    size) flea_byte_vec_t name = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE
#else
# define FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(name, \
    size) FLEA_DECL_byte_vec_t__CONSTR_STACK_BUF_EMPTY_NOT_ALLOCATABLE(name, size)
#endif

/**
 * Init a byte vector.
 */
void flea_byte_vec_t__INIT(flea_byte_vec_t* byte_vec);

void flea_byte_vec_t__dtor(flea_byte_vec_t* byte_vec);

/**
 * Reset the length of a byte vector to zero.
 *
 * @param byte_vec pointer to the byte_vector
 */
void flea_byte_vec_t__reset(flea_byte_vec_t* byte_vec);

/**
 * Compare two byte vectors lexicographically.
 *
 * @param a first vector to compare
 * @param b second vector to compare
 * @return If the first argument is longer than the second, 1 is returned, if
 * the second is longer, -1 is returned. If the lengths are equal, the return value is the same
 * as for standard memcmp().
 */
int flea_byte_vec_t__cmp(
  const flea_byte_vec_t* a,
  const flea_byte_vec_t* b
);

int flea_byte_vec_t__cmp_with_cref(
  const flea_byte_vec_t* a,
  const flea_ref_cu8_t*  b
);

/**
 * Set the byte vector's content as a reference to an existing buf. The byte
 * vector does not assume ownership of that buffer. A byte vector's dtor doesn't
 * free anything if it is called on a byte vector holding a reference.
 */
void flea_byte_vec_t__set_ref(
  flea_byte_vec_t* byte_vec,
  const flea_u8_t* data,
  flea_dtl_t       data_len
);

void flea_byte_vec_t__copy_content_set_ref_use_mem(
  flea_byte_vec_t*       trgt,
  flea_u8_t*             trgt_mem,
  const flea_byte_vec_t* src
);

/**
 * Append data to the byte vector. If the capacity of the internal buffer is
 * exceeded, in heap mode a reallocation is performed if necessary.
 *
 * @param byte_vec pointer to the byte_vector
 * @param data pointer to the data to append
 * @param len the length of data
 */
flea_err_t THR_flea_byte_vec_t__append(
  flea_byte_vec_t* byte_vec,
  const flea_u8_t* data,
  flea_dtl_t       len
);


/**
 * Append a single byte to the vector.
 *
 * @param byte_vec pointer to the byte_vector
 * @param byte the byte to append
 */
flea_err_t THR_flea_byte_vec_t__push_back(
  flea_byte_vec_t* byte_vec,
  flea_u8_t        byte
);

/**
 * Only supported in heap mode. Enlarge the byte vector's capacity.
 *
 * @param byte_vec pointer to the byte_vector
 * @param reserve_len new size of the vector's allocated buffer
 */
flea_err_t THR_flea_byte_vec_t__reserve(
  flea_byte_vec_t* byte_vec,
  flea_dtl_t       reserve_len
);

/**
 * Set the content of a byte vector. The previous content of the vector is
 * discarded and the new data is appended.
 *
 * @param byte_vec pointer to the byte_vector
 * @param data pointer to the data to set as the new content
 * @param len the length of data
 */
flea_err_t THR_flea_byte_vec_t__set_content(
  flea_byte_vec_t* byte_vec,
  const flea_u8_t* data,
  flea_dtl_t       len
);

/**
 * Set the vector to the new size. If the new size is smaller than the previous
 * size, the allocation size will not be reduced. If it is larger than the
 * previous size, the new bytes at the end are set to zero.
 *
 * @param byte_vec pointer to the byte_vector
 * @param new_size the new content length of the vector
 */
flea_err_t THR_flea_byte_vec_t__resize(
  flea_byte_vec_t* byte_vec,
  unsigned         new_size
);

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
