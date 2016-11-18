/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_util__H_
#define _flea_util__H_

#include "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Determine the maximum of two values
 */
#define FLEA_MAX(a, b) ( (a) > (b) ? (a) : (b))

/**
 * Determine the maximum of three values
 */
#define FLEA_MAX3(a, b, c) FLEA_MAX(a, FLEA_MAX(b, c))

/**
 * Determine the maximum of four values
 */
#define FLEA_MAX4(a, b, c, d) FLEA_MAX(FLEA_MAX(a, b), FLEA_MAX(c, d))

/**
 * Determine the maximum of five values
 */
#define FLEA_MAX5(a, b, c, d, e) FLEA_MAX(FLEA_MAX(a, b), FLEA_MAX3(c, d, e))

/**
 * Determine the minimum of two values
 */
#define FLEA_MIN(a, b) ( (a) > (b) ? (b) : (a))

/**
 * Determine the minimum of three values
 */
#define FLEA_MIN3(a, b, c) FLEA_MIN(a, FLEA_MIN(b, c))

/**
 * Determine the minimum of four values
 */
#define FLEA_MIN4(a, b, c, d) FLEA_MIN(FLEA_MIN(a, b), FLEA_MIN(c, d))

/**
 * Determine the word length of a string from the bit length, rounded up to full
 * words
 */
#define FLEA_CEIL_WORD_LEN_FROM_BIT_LEN(__a) (FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(__a)))

/**
 * Determine the word length of a string from the bit length, rounded up to full
 * words
 */
#define FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(__a) (((__a) + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t))

/**
 * Determine the byte length of a string from the bit length, rounded up to full
 * words
 */
#define FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(__a) (((__a) + 7) / 8)

/**
 * Determine the u32 length of a string from the bit length, rounded up to full
 * words
 */
#define FLEA_CEIL_U32_LEN_FROM_BIT_LEN(__a)  (((__a) + 8 * sizeof(flea_u32_t) - 1) / (8 * sizeof(flea_u32_t)))

/**
 * Type which reference to strings of u8 in memory.
 */
  typedef struct
  {
    const flea_u8_t *data__pcu8;
    flea_dtl_t len__dtl;
  } flea_ref_cu8_t;

  // TODO: define correctly as non-const
  typedef struct
  {
    flea_u8_t *data__pcu8;
    flea_dtl_t len__dtl;
  } flea_ref_u8_t;

/**
 * Overwrite potentially sensitive data. The function is implemented in such way
 * to prevent compiler optimizations to remove the call.
 *
 * @param memory pointer to the memory area to be overwritten
 * @param mem_len length of the memory area to be overwritten
 */
void flea_memzero_secure(flea_u8_t* memory, flea_dtl_t mem_len);

int flea_memcmp_wsize(const void* mem1__pv, flea_dtl_t len_mem1__dtl, const void*mem2__pv, flea_dtl_t len_mem2__dtl);

int flea_rcu8_cmp(const flea_ref_cu8_t *a, const flea_ref_cu8_t *b);

void flea_copy_rcu8_use_mem(flea_ref_cu8_t *trgt__prcu8, flea_u8_t* trgt_mem, flea_ref_cu8_t *src__prcu8);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
