/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_len_ctr__H_
#define _flea_len_ctr__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
#ifdef FLEA_USE_HEAP_BUF
  flea_u32_t* counter__bu32;
#elif defined FLEA_USE_STACK_BUF
  flea_u32_t  counter__bu32[(__FLEA_COMPUTED_MAX_HASH_CNT_LEN + (sizeof(flea_u32_t) - 1)) / sizeof(flea_u32_t)];
#endif
  flea_u16_t  neg_limit_offset__u16;
  flea_u8_t   limit_exponent__u8;
  flea_u8_t   counter_block_arr_len__u8;
} flea_len_ctr_t;

#ifdef FLEA_USE_HEAP_BUF
# define flea_len_ctr_t__INIT(__p) do {(__p)->counter__bu32 = NULL;} while(0)
# define flea_len_ctr_t__INIT_VALUE {.counter__bu32 = NULL}
#else
# define flea_len_ctr_t__INIT(__p)
# define flea_len_ctr_t__INIT_VALUE {.counter__bu32[0] = 0}
#endif

flea_err_t THR_flea_len_ctr_t__ctor(
  flea_len_ctr_t* len_ctr__pt,
  flea_al_u8_t    counter_block_arr_len__u8,
  flea_al_u8_t    limit_exponent__alu8,
  flea_u16_t      neg_limit_offset__u16
);

flea_err_t THR_flea_len_ctr_t__ctor_copy(
  flea_len_ctr_t*       len_ctr__pt,
  const flea_len_ctr_t* orig__pt
);

void flea_len_ctr_t__dtor(flea_len_ctr_t* len_ctr__pt);

flea_err_t THR_flea_len_ctr_t__add_and_check_len_limit(
  flea_len_ctr_t* len_ctr__pt,
  flea_dtl_t      add_len__dtl
);

void flea_len_ctr_t__reset(flea_len_ctr_t* len_ctr__pt);

void flea_len_ctr_t__counter_byte_lengt_to_bit_length(flea_len_ctr_t* ctx__pt);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
