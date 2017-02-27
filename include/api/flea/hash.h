/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_hash__H_
#define _flea_hash__H_

#include "internal/common/default.h"
#include "flea/error.h"
#include "flea/types.h"
#include "flea/byte_vec.h"
#include "internal/common/len_ctr.h"
#include "flea/block_cipher.h"
#include "internal/common/hash_int.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Supported hash algorithms.
 */
typedef enum { flea_davies_meyer_aes128, flea_md5, flea_sha1, flea_sha224, flea_sha256, flea_sha384,
               flea_sha512 } flea_hash_id_t;


/**
 * Hash context type.
 */
struct struct_flea_hash_ctx_t
{
  //  flea_u8_t counter_block_arr_len__u8;

#ifdef FLEA_USE_HEAP_BUF
  flea_u8_t*                      pending_buffer;
  flea_u32_t*                     hash_state;
#elif defined FLEA_USE_STACK_BUF
  flea_u8_t                       pending_buffer[__FLEA_COMPUTED_MAX_HASH_BLOCK_LEN];
  flea_u32_t                      hash_state[__FLEA_COMPUTED_MAX_HASH_STATE_LEN / sizeof(flea_u32_t)];
#endif
  flea_u64_t                      total_byte_length;
  const flea_hash_config_entry_t* p_config;
  flea_len_ctr_t                  len_ctr__t;
  flea_al_u8_t                    pending;
};


#ifdef FLEA_USE_HEAP_BUF
# define flea_hash_ctx_t__INIT(__p) \
  do {(__p)->p_config = NULL; (__p)->pending_buffer = NULL; (__p)->hash_state = NULL; \
      flea_len_ctr_t__INIT(&(__p)->len_ctr__t);} while(0)
# define flea_hash_ctx_t__INIT_VALUE \
  {.p_config   = NULL, .pending_buffer = NULL, .hash_state = NULL, .pending = 0, \
   .len_ctr__t = flea_len_ctr_t__INIT_VALUE}
#else
/* needed for secret wiping */
# define flea_hash_ctx_t__INIT(__p) do {(__p)->p_config = NULL;} while(0)
/* needed for secret wiping */
# define flea_hash_ctx_t__INIT_VALUE {.p_config = NULL}
#endif // ifdef FLEA_USE_HEAP_BUF


/**
 * Create a hash context object
 *
 * @param ctx pointer to the object to create
 * @param id id of the hash algorithm to use
 *
 * @return flea error code
 */
flea_err_t THR_flea_hash_ctx_t__ctor(
  flea_hash_ctx_t* ctx,
  flea_hash_id_t   id
);


/**
 * Copy a hash context object
 *
 * @param p_ctx_new pointer to newly created context
 * @param p_ctx pointer to context where data is copied from
 *
 */
flea_err_t THR_flea_hash_ctx_t__ctor_copy(
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
flea_err_t THR_flea_hash_ctx_t__update(
  flea_hash_ctx_t* ctx,
  const flea_u8_t* input,
  flea_dtl_t       input_len
);

flea_err_t THR_flea_hash_ctx_t__final_byte_vec(
  flea_hash_ctx_t* p_ctx,
  flea_byte_vec_t* result__pt
);

/**
 * Finalize the hash computation of a context object and generate the hash
 * value.
 *
 * @param ctx pointer to the context object
 * @param output pointer to the memory area where to store the hash value. Must
 * have length of at least the hash function's output length as returned by flea_hash_ctx_t__get_output_length()
 *
 * @return flea erro code (memory allocation failure)
 */
flea_err_t THR_flea_hash_ctx_t__final(
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
 * @return flea erro code (memory allocation failure)
 */
flea_err_t THR_flea_hash_ctx_t__final_with_length_limit(
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
flea_al_u16_t flea_hash__get_output_length_by_id(flea_hash_id_t id);

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
 * the specified length. The output length is at most FLEA_MAX_HASH_OUT_LEN, it
 * can be inferred from the hash-id.
 *
 * @return flea error code
 */
flea_err_t THR_flea_compute_hash(
  flea_hash_id_t   id,
  const flea_u8_t* input,
  flea_dtl_t       input_len,
  flea_u8_t*       output,
  flea_al_u16_t    output_len
);

flea_err_t THR_flea_compute_hash_byte_vec(
  flea_hash_id_t   id,
  const flea_u8_t* input_pu8,
  flea_dtl_t       input_len_al_u16,
  flea_byte_vec_t* result__pt
);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
