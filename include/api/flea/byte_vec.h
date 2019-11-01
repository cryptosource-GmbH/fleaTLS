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


#ifndef __flea_byte_vec_H_
# define __flea_byte_vec_H_

# include "internal/common/default.h"
# include "flea/error.h"
# include "flea/types.h"
# include "flea/util.h"
# include "internal/common/byte_vec_macro.h"

/**
 * @file byte_vec.h
 *
 *
 */
# ifdef __cplusplus
extern "C" {
# endif

/**
 * Byte vector type whose functions are defined in byte_vec.h. Works similar to C++ vectors, i.e. it has an internal
 * allocated buffer, which can used to append bytes to the vector. Internal reallocations
 * are performed only when the currently allocated size does not suffice for the appended data.
 *
 * The byte vector also supports the usage of an externally provided buffer as
 * its internal memory, in which case it does not allocate any memory at all,
 * and thus can also be used when \link FLEA_HEAP_MODE stack mode \endlink is activated. In this case the
 * byte vector behaves as a mere reference to an external buffer. In stack mode,
 * for instance the ctor \link flea_byte_vec_t__ctor_empty_use_ext_buf flea_byte_vec_t__ctor_empty_use_ext_buf() \endlink can be used
 * to create a byte vector which uses an external buffer (typically on the
 * stack) as its internal memory. Whenever during the byte vector's life-cycle a greater allocation size is required
 * that the external buffers size, the corresponding function will return with
 * an error.
 *
 * In \link FLEA_HEAP_MODE heap mode\endlink for instance the ctor \link flea_byte_vec_t__ctor_empty_allocatable flea_byte_vec_t__ctor_empty_allocatable() \endlink can be used to create an empty byte vector which will allocate more heap memory whenever necessary during its life-cycle.
 *
 * Byte vectors can also be set as mere
 * references to an existing buffer. In this case, the byte vector does not own
 * the memory it points to and the flea_byte_vect_t__dtor()
 * does not deallocate the buffer even in \link FLEA_HEAP_MODE heap mode\endlink. The fleaTLS API does not return byte vectors
 * that represent references, this feature is only internally used by fleaTLS.
 * Reference byte vectors may be passed to fleaTLS API functions whenever they
 * represent mere input arguments, i.e. where a <code>const flea_byte_vect_t*</code> is
 * passed as an argument.
 *
 */
typedef struct
{
  flea_u8_t* data__pu8;
  flea_dtl_t len__dtl;
  flea_dtl_t allo__dtl;
# ifdef FLEA_HEAP_MODE
  flea_u8_t  state__u8;
# endif
} flea_byte_vec_t;

/**
 * Get a pointer to the data of a byte vector.
 *
 * @param bv pointer to the byte vector
 *
 * @return a pointer of type flea_u8_t*
 */
# define flea_byte_vec_t__GET_DATA_PTR(bv) ((bv)->data__pu8)

/**
 * Get the length of a byte vector.
 *
 * @param bv pointer to the byte vector
 *
 * @return an integer of type flea_dtl_t
 */
# define flea_byte_vec_t__GET_DATA_LEN(bv) ((bv)->len__dtl)

/**
 * Right hand side initialization value for a byte vector. The byte vector is
 * constructed as allocatable but with an empty capacity.
 */
# ifdef FLEA_HEAP_MODE
#  define flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE \
  {.data__pu8 = NULL, .len__dtl = 0, .allo__dtl = 0, \
   .state__u8 = FLEA_BYTEVEC_STATE_ALLOCATABLE_MASK}
# else
#  define flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE {.data__pu8 = NULL, .len__dtl = 0, .allo__dtl = 0}
# endif // ifdef FLEA_HEAP_MODE

/**
 * Right hand side initialization value for a byte vector. The byte vector is
 * constructed as non-allocatable and thus can only be used to received
 * reference values.
 */
# ifdef FLEA_HEAP_MODE
#  define flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE \
  {.data__pu8 = NULL, .len__dtl = 0, .allo__dtl = 0, \
   .state__u8 = \
     FLEA_BYTEVEC_STATE_NEITHER_DE_NOR_ALLOCATABLE_MASK}
# else // ifdef FLEA_HEAP_MODE
#  define flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE {.data__pu8 = NULL, .len__dtl = 0, .allo__dtl = 0}
# endif // ifdef FLEA_HEAP_MODE

/**
 * Declare a byte vector using a stack buffer as the vector's internal buffer. The byte vector is not
 * allocatable.
 */
# ifdef FLEA_HEAP_MODE
#  define FLEA_DECL_byte_vec_t__CONSTR_STACK_BUF_EMPTY_NOT_ALLOCATABLE(name, size) \
  flea_u8_t __byte_vec_stack_buf_for_ ## name[size]; \
  flea_byte_vec_t name = {.data__pu8 = __byte_vec_stack_buf_for_ ## name, \
                          .len__dtl  =                                 0, .allo__dtl= size, \
                          .state__u8 = FLEA_BYTEVEC_STATE_NEITHER_DE_NOR_ALLOCATABLE_MASK}

# else // ifdef FLEA_HEAP_MODE
#  define FLEA_DECL_byte_vec_t__CONSTR_STACK_BUF_EMPTY_NOT_ALLOCATABLE(name, size) \
  flea_u8_t __byte_vec_stack_buf_for_ ## name[size]; \
  flea_byte_vec_t name = {.data__pu8 = __byte_vec_stack_buf_for_ ## name, \
                          .len__dtl  =                                 0, .allo__dtl= size}

# endif // ifdef FLEA_HEAP_MODE

/**
 * Right hand side initialization value for a byte vector using an existing buffer as the byte
 * vector's internal buffer. The byte vector is created empty. It is not
 * allocatable.
 */
# ifdef FLEA_HEAP_MODE
#  define flea_byte_vec_t__CONSTR_EXISTING_BUF_NOT_ALLOCATABLE(buf, size) \
  {.data__pu8 = (flea_u8_t*) buf, \
   .len__dtl  = 0, .allo__dtl = size, .state__u8 = FLEA_BYTEVEC_STATE_NEITHER_DE_NOR_ALLOCATABLE_MASK}
# else
#  define flea_byte_vec_t__CONSTR_EXISTING_BUF_NOT_ALLOCATABLE(buf, size) \
  {.data__pu8 = (flea_u8_t*) buf, \
   .len__dtl  = 0, .allo__dtl = size}
# endif // ifdef FLEA_HEAP_MODE

/**
 * Right hand side initialization value for a byte vector using an existing buffer as the byte
 * vector's internal buffer. The vector's intial content is set to the content of that buffer. The byte vector is not allocatable.
 */
# ifdef FLEA_HEAP_MODE
#  define flea_byte_vec_t__CONSTR_EXISTING_BUF_CONTENT_NOT_ALLOCATABLE(buf, size) \
  {.data__pu8 = (flea_u8_t*) buf, \
   .len__dtl  = size, .allo__dtl = size, .state__u8 = FLEA_BYTEVEC_STATE_NEITHER_DE_NOR_ALLOCATABLE_MASK}
# else
#  define flea_byte_vec_t__CONSTR_EXISTING_BUF_CONTENT_NOT_ALLOCATABLE(buf, size) \
  {.data__pu8 = (flea_u8_t*) buf, \
   .len__dtl  = size, .allo__dtl = size}
# endif // ifdef FLEA_HEAP_MODE

/**
 * Statement for the creation of a byte vector using flea_byte_vec_t__CONSTR_EXISTING_BUF_CONTENT_NOT_ALLOCATABLE.
 */
# define FLEA_DECL_byte_vec_t__CONSTR_EXISTING_BUF_CONTENT_NOT_ALLOCATABLE(name, buf, size) \
  flea_byte_vec_t name = flea_byte_vec_t__CONSTR_EXISTING_BUF_CONTENT_NOT_ALLOCATABLE(buf, size)

/**
 * Right hand side initialization value for a byte vector. In heap mode, the byte vector is
 * constructed as allocatable with an initial capacity of zero. In stack mode,
 * the vector receives a stack array variable which servers as the vector's
 * internal buffer.
 * This initialization value is useful when writing code which is supposed to
 * run in both heap and stack mode.
 */
# ifdef FLEA_HEAP_MODE
#  define flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK_BUF(dummy) \
  flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE
# else
#  define flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK_BUF(stack_array) \
  {.data__pu8 = stack_array, .len__dtl = 0, \
   .allo__dtl = sizeof(stack_array)}
# endif // ifdef FLEA_HEAP_MODE

/**
 * Declare a byte vector based on heap memory or a stack buffer of static size,
 * depending on the mode. In stack mode, the static buffer is also declared by
 * this macro.
 */
# ifdef FLEA_HEAP_MODE
#  define FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(name, \
    size) flea_byte_vec_t name = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE
# else
#  define FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(name, \
    size) FLEA_DECL_byte_vec_t__CONSTR_STACK_BUF_EMPTY_NOT_ALLOCATABLE(name, size)
# endif // ifdef FLEA_HEAP_MODE

# ifdef FLEA_HEAP_MODE
#  define flea_byte_vec_t__CTOR_ALLOCATABLE_OR_STACK_BUF(__byte_vec__pt, __stack_array__au8) \
  do { \
    (__byte_vec__pt)->data__pu8 = NULL; \
    (__byte_vec__pt)->allo__dtl = 0; \
    (__byte_vec__pt)->len__dtl  = 0; \
    (__byte_vec__pt)->state__u8 = FLEA_BYTEVEC_STATE_ALLOCATABLE_MASK; \
  } while(0)
# else // ifdef FLEA_HEAP_MODE
#  define flea_byte_vec_t__CTOR_ALLOCATABLE_OR_STACK_BUF(__byte_vec__pt, __stack_array__au8) \
  do { \
    (__byte_vec__pt)->data__pu8 = __stack_array__au8; \
    (__byte_vec__pt)->allo__dtl = sizeof(__stack_array__au8); \
    (__byte_vec__pt)->len__dtl  = 0; \
  } while(0)
# endif // ifdef FLEA_HEAP_MODE

/**
 * Create a byte vector which is not allocatable with zero capacity.
 */
void flea_byte_vec_t__ctor_not_allocatable(flea_byte_vec_t* byte_vec);


# ifdef FLEA_HEAP_MODE

/**
 * Create an empty byte vector which is allocatable.
 *
 * @param byte_vec__pt the byte vector to create
 */
void flea_byte_vec_t__ctor_empty_allocatable(flea_byte_vec_t* byte_vec__pt);
# endif

/**
 *
 * Create an empty byte vector which is not allocatable but uses an external
 * buffer for its internal memory.
 *
 * @param byte_vec__pt the byte vector to create
 * @param ext_buf__pu8 the external buffer to use
 * @param ext_buf_len__dtl size of the external buffer
 */
void flea_byte_vec_t__ctor_empty_use_ext_buf(
  flea_byte_vec_t* byte_vec__pt,
  flea_u8_t*       ext_buf__pu8,
  flea_dtl_t       ext_buf_len__dtl
);

void flea_byte_vec_t__dtor(flea_byte_vec_t* byte_vec);

/**
 * Reset the length of a byte vector to zero.
 *
 * @param byte_vec pointer to the byte_vector
 */
void flea_byte_vec_t__reset(flea_byte_vec_t* byte_vec);

/**
 * Compare two byte vectors by length and lexicographically.
 *
 * @param a first vector to compare
 * @param b second vector to compare
 *
 *  @return If the first argument is longer than the second, 1 is returned, if
 * the second is longer, -1 is returned. If the lengths are equal, the return value is the same
 * as for the standard library's memcmp().
 */
int flea_byte_vec_t__cmp(
  const flea_byte_vec_t* a,
  const flea_byte_vec_t* b
);

/**
 * Compare the contents of a byte vector with those of a flea_ref_cu8_t. The
 * result is computed in the same way as in flea_byte_vec_t__cmp().
 *
 * @param a vector to compare
 * @param b ref-object vector to compare
 *
 * @return return value as for flea_byte_vec_t__cmp()
 */
int flea_byte_vec_t__cmp_with_cref(
  const flea_byte_vec_t* a,
  const flea_ref_cu8_t*  b
);

/**
 * Set the byte vector's content as a reference to an existing buf. The byte
 * vector does not assume ownership of that buffer. A byte vector's dtor doesn't
 * free anything if it is called on a byte vector holding a reference.
 *
 * The previous content of the byte vector is deleted prior to setting the
 * reference value.
 *
 * @param byte_vec pointer to the byte_vector
 * @param dta pointer to the data to append to set
 * @param dta_len the length of data
 *
 */
void flea_byte_vec_t__set_as_ref(
  flea_byte_vec_t* byte_vec,
  const flea_u8_t* dta,
  flea_dtl_t       dta_len
);


/**
 * Append data to the byte vector. If the capacity of the internal buffer is
 * exceeded, in heap mode a reallocation is performed if necessary.
 *
 * @param byte_vec pointer to the byte_vector
 * @param dta pointer to the data to append
 * @param dta_len the length of data
 *
 * @return an error code
 */
flea_err_e THR_flea_byte_vec_t__append(
  flea_byte_vec_t* byte_vec,
  const flea_u8_t* dta,
  flea_dtl_t       dta_len
) FLEA_ATTRIB_UNUSED_RESULT;


/**
 * Append a single byte to the vector.
 *
 * @param byte_vec pointer to the byte_vector
 * @param byte the byte to append
 *
 * @return an error code
 */
flea_err_e THR_flea_byte_vec_t__push_back(
  flea_byte_vec_t* byte_vec,
  flea_u8_t        byte
) FLEA_ATTRIB_UNUSED_RESULT;

/**
 * Only supported in heap mode. Enlarge the byte vector's internal capacity.
 *
 * @param byte_vec pointer to the byte_vector
 * @param reserve_len new size of the vector's internal allocated buffer
 *
 * @return an error code
 */
flea_err_e THR_flea_byte_vec_t__reserve(
  flea_byte_vec_t* byte_vec,
  flea_dtl_t       reserve_len
) FLEA_ATTRIB_UNUSED_RESULT;

/**
 * Set the content of a byte vector. The previous content of the vector is
 * discarded and the new data is appended.
 *
 * @param byte_vec pointer to the byte_vector
 * @param data pointer to the data to set as the new content
 * @param len the length of data
 *
 * @return an error code
 */
flea_err_e THR_flea_byte_vec_t__set_content(
  flea_byte_vec_t* byte_vec,
  const flea_u8_t* data,
  flea_dtl_t       len
) FLEA_ATTRIB_UNUSED_RESULT;

/**
 * Set the vector to the new size. If the new size is smaller than the previous
 * size, the allocation size will not be reduced. If it is larger than the
 * previous size, the new bytes at the end are set to zero.
 *
 * @param byte_vec pointer to the byte_vector
 * @param new_size the new content length of the vector
 *
 * @return an error code
 */
flea_err_e THR_flea_byte_vec_t__resize(
  flea_byte_vec_t* byte_vec,
  unsigned         new_size
) FLEA_ATTRIB_UNUSED_RESULT;


# ifdef __cplusplus
}
# endif
#endif /* h-guard */
