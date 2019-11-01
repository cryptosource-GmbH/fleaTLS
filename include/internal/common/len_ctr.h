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
#ifdef FLEA_HEAP_MODE
  flea_u32_t* counter__bu32;
#elif defined FLEA_STACK_MODE
  flea_u32_t  counter__bu32[(__FLEA_COMPUTED_MAX_HASH_CNT_LEN + (sizeof(flea_u32_t) - 1)) / sizeof(flea_u32_t)];
#endif
  flea_u16_t  neg_limit_offset__u16;
  flea_u8_t   limit_exponent__u8;
  flea_u8_t   counter_block_arr_len__u8;
} flea_len_ctr_t;

#ifdef FLEA_HEAP_MODE
# define flea_len_ctr_t__INIT(__p) do {(__p)->counter__bu32 = NULL;} while(0)
#else
# define flea_len_ctr_t__INIT(__p)
#endif // ifdef FLEA_HEAP_MODE

flea_err_e THR_flea_len_ctr_t__ctor(
  flea_len_ctr_t* len_ctr__pt,
  flea_al_u8_t    counter_block_arr_len__u8,
  flea_al_u8_t    limit_exponent__alu8,
  flea_u16_t      neg_limit_offset__u16
);

flea_err_e THR_flea_len_ctr_t__ctor_copy(
  flea_len_ctr_t*       len_ctr__pt,
  const flea_len_ctr_t* orig__pt
);

void flea_len_ctr_t__dtor(flea_len_ctr_t* len_ctr__pt);

flea_err_e THR_flea_len_ctr_t__add_and_check_len_limit(
  flea_len_ctr_t* len_ctr__pt,
  flea_dtl_t      add_len__dtl
);

void flea_len_ctr_t__reset(flea_len_ctr_t* len_ctr__pt);

void flea_len_ctr_t__counter_byte_lengt_to_bit_length(flea_len_ctr_t* ctx__pt);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
