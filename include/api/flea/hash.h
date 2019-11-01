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

#ifndef _flea_hash__H_
# define _flea_hash__H_

# include "internal/common/default.h"
# include "flea/error.h"
# include "flea/types.h"
# include "flea/byte_vec.h"
# include "internal/common/len_ctr.h"
# include "flea/block_cipher.h"
# include "internal/common/hash_int.h"

# ifdef __cplusplus
extern "C" {
# endif


/**
 * Supported hash algorithms.
 */
typedef enum
{
# ifdef FLEA_HAVE_MD5
  flea_md5                 = 1,
# endif
# ifdef FLEA_HAVE_SHA1
  flea_sha1                = 2,
# endif
# ifdef FLEA_HAVE_SHA224_256
  flea_sha224              = 3,
  flea_sha256              = 4,
# endif
# ifdef FLEA_HAVE_SHA384_512
  flea_sha384              = 5,
  flea_sha512              = 6,
# endif
# ifdef FLEA_HAVE_DAVIES_MEYER_HASH
  flea_davies_meyer_aes128 = 30,
# endif
} flea_hash_id_e;


# ifdef FLEA_HEAP_MODE
#  define flea_hash_ctx_t__INIT(__p) \
  do {(__p)->p_config = NULL; (__p)->pending_buffer = NULL; (__p)->hash_state = NULL; \
      flea_len_ctr_t__INIT(&(__p)->len_ctr__t);} while(0)
# else // ifdef FLEA_HEAP_MODE
/* needed for secret wiping */
#  define flea_hash_ctx_t__INIT(__p) do {(__p)->p_config = NULL;} while(0)
# endif // ifdef FLEA_HEAP_MODE


/**
 * Create a hash context object
 *
 * @param ctx pointer to the object to create
 * @param id id of the hash algorithm to use
 *
 * @return flea error code
 */
flea_err_e THR_flea_hash_ctx_t__ctor(
  flea_hash_ctx_t* ctx,
  flea_hash_id_e   id
);


/**
 * Copy a hash context object
 *
 * @param p_ctx_new pointer to newly created context
 * @param p_ctx pointer to context where data is copied from
 *
 */
flea_err_e THR_flea_hash_ctx_t__ctor_copy(
  flea_hash_ctx_t*       p_ctx_new,
  const flea_hash_ctx_t* p_ctx
);

/**
 * Destroy a hash context object.
 *
 * @param ctx pointer to the object to destroy
 */
void flea_hash_ctx_t__dtor(flea_hash_ctx_t* ctx);

/**
 * Reset a hash context object. The object will be in the same state as if
 * freshly created by a ctor call.
 *
 * @param ctx pointer to the object to reset
 */
void flea_hash_ctx_t__reset(flea_hash_ctx_t* ctx);

/**
 * Feed data to a hash context object
 *
 * @param ctx pointer to the context object
 * @param input pointer to the input data
 * @param input_len length of the input data
 *
 *
 */
flea_err_e THR_flea_hash_ctx_t__update(
  flea_hash_ctx_t* ctx,
  const flea_u8_t* input,
  flea_dtl_t       input_len
);

/**
 * Finalize the hash computation of a context object and generate the hash
 * value.
 *
 * @param ctx pointer to the context object
 * @param result receives the result. Must have the necessary storage capacity which is at most FLEA_MAX_HASH_OUT_LEN, the
 * concrete value can be inferred from the hash-id using flea_hash__get_output_length_by_id().
 *
 * @return flea error code (memory allocation failure)
 */
flea_err_e THR_flea_hash_ctx_t__final_byte_vec(
  flea_hash_ctx_t* ctx,
  flea_byte_vec_t* result
);

/**
 * Finalize the hash computation of a context object and generate the hash
 * value.
 *
 * @param ctx pointer to the context object
 * @param output pointer to the memory area where to store the hash value. Must
 * have length of at least the hash function's output length as returned by flea_hash_ctx_t__get_output_length()
 *
 * @return flea error code (memory allocation failure)
 */
flea_err_e THR_flea_hash_ctx_t__final(
  flea_hash_ctx_t* ctx,
  flea_u8_t*       output
);

/**
 * Finalize the hash computation of a context object and generate the hash
 * value. The hash value will be truncated according to the specified length
 * limit.
 *
 * @param ctx pointer to the context object
 * @param output pointer to the memory area where to store the hash value.
 * @param output_len the length of output, this many bytes of the hash value will be written to output
 *
 * @return flea error code (memory allocation failure)
 */
flea_err_e THR_flea_hash_ctx_t__final_with_length_limit(
  flea_hash_ctx_t* ctx,
  flea_u8_t*       output,
  flea_al_u16_t    output_len
);

/**
 * Find out the output length in bytes of a the hash algorithm used within a
 * hash context object.
 *
 * @param ctx pointer to the context object
 *
 * @return the output length of the employed hash function
 */
flea_al_u16_t flea_hash_ctx_t__get_output_length(flea_hash_ctx_t* ctx);

/**
 * Find out the output byte length of a hash algorithm by its id
 *
 * @param id the hash algorithm's id
 *
 * @return the hash algorithm's output length in bytes
 */
flea_al_u8_t flea_hash__get_output_length_by_id(flea_hash_id_e id);

/**
 * Return the hash id of a given hash_ctx object.
 *
 * @param p_ctx pointer to the context object
 *
 * @return the hash id used by the hash context object
 */
flea_hash_id_e flea_hash_ctx_t__get_hash_id(const flea_hash_ctx_t* p_ctx);


/**
 * Compute the hash value of a data string.
 *
 * @param id id of the hash algorithm to use
 * @param input pointer to the data to hash
 * @param input_len the length of input
 * @param output pointer to the memory location where the hash value shall be
 * stored - must have sufficient space for the output length associated with
 * the employed hash id
 * @param output_len the length of output. if the specified value is smaller
 * than the hash function's output length, then the output will be truncated to
 * the specified length. The output length is at most FLEA_MAX_HASH_OUT_LEN, the
 * concrete value can be inferred from the hash-id using flea_hash__get_output_length_by_id().
 *
 * @return flea error code
 */
flea_err_e THR_flea_compute_hash(
  flea_hash_id_e   id,
  const flea_u8_t* input,
  flea_dtl_t       input_len,
  flea_u8_t*       output,
  flea_al_u16_t    output_len
);

/**
 * Compute the hash value of a data string.
 *
 * @param id id of the hash algorithm to use
 * @param input pointer to the data to hash
 * @param input_len the length of input
 * @param result receives the result. Must have the necessary storage capacity which is at most FLEA_MAX_HASH_OUT_LEN, the
 * concrete value can be inferred from the hash-id using flea_hash__get_output_length_by_id().
 *
 * @return flea error code
 */
flea_err_e THR_flea_compute_hash_byte_vec(
  flea_hash_id_e   id,
  const flea_u8_t* input,
  flea_dtl_t       input_len,
  flea_byte_vec_t* result
);

# ifdef __cplusplus
}
# endif

#endif /* h-guard */
