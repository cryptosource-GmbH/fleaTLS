/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_util__H_
#define _flea_util__H_

#include "flea/types.h"
#include "flea/calc_util.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Type which references to constant strings of u8 in memory.
 */
  typedef struct
  {
    const flea_u8_t *data__pcu8;
    flea_dtl_t len__dtl;
  } flea_ref_cu8_t;

/**
 * Type which references to strings of u8 in memory.
 */
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

flea_bool_t flea_sec_mem_equal (const flea_u8_t* mem1__pcu8, const flea_u8_t* mem2__pcu8, flea_al_u16_t mem_len__alu16);

int flea_memcmp_wsize(const void* mem1__pv, flea_dtl_t len_mem1__dtl, const void*mem2__pv, flea_dtl_t len_mem2__dtl);

int flea_rcu8_cmp(const flea_ref_cu8_t *a, const flea_ref_cu8_t *b);

void flea_copy_rcu8_use_mem(flea_ref_cu8_t *trgt__prcu8, flea_u8_t* trgt_mem, const flea_ref_cu8_t *src__prcu8);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
