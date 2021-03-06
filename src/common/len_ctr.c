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

#include "internal/common/default.h"
#include "internal/common/len_ctr.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/types.h"
#include "flea/alloc.h"
#include "flea/array_util.h"


flea_err_e THR_flea_len_ctr_t__ctor(
  flea_len_ctr_t* len_ctr__pt,
  flea_al_u8_t    counter_block_arr_len__u8,
  flea_al_u8_t    limit_exponent__alu8,
  flea_u16_t      neg_limit_offset__u16
)
{
  FLEA_THR_BEG_FUNC();
  len_ctr__pt->counter_block_arr_len__u8 = counter_block_arr_len__u8;
#ifdef FLEA_HEAP_MODE
  FLEA_ALLOC_MEM_ARR(len_ctr__pt->counter__bu32, len_ctr__pt->counter_block_arr_len__u8);
#endif
  FLEA_SET_ARR(len_ctr__pt->counter__bu32, 0, len_ctr__pt->counter_block_arr_len__u8);
  len_ctr__pt->neg_limit_offset__u16 = neg_limit_offset__u16;
  len_ctr__pt->limit_exponent__u8    = limit_exponent__alu8;
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_len_ctr_t__ctor_copy(
  flea_len_ctr_t*       len_ctr__pt,
  const flea_len_ctr_t* orig__pt
)
{
  FLEA_THR_BEG_FUNC();
  memcpy(len_ctr__pt, orig__pt, sizeof(*len_ctr__pt));
#ifdef FLEA_HEAP_MODE
  FLEA_ALLOC_MEM_ARR(len_ctr__pt->counter__bu32, len_ctr__pt->counter_block_arr_len__u8);
  FLEA_CP_ARR(len_ctr__pt->counter__bu32, orig__pt->counter__bu32, len_ctr__pt->counter_block_arr_len__u8);
#endif

  FLEA_THR_FIN_SEC_empty();
}

void flea_len_ctr_t__dtor(flea_len_ctr_t* len_ctr__pt)
{
#ifdef FLEA_HEAP_MODE
  FLEA_FREE_MEM_CHK_NULL(len_ctr__pt->counter__bu32);
#endif
  flea_len_ctr_t__INIT(len_ctr__pt);
}

static flea_err_e THR_flea_len_ctr_t__inner_add_and_check_len_limit(
  flea_u32_t*  ctr_block__pu32,
  flea_al_u8_t ctr_block_arr_len__alu8,
  flea_dtl_t   add_len__dtl,
  flea_al_u8_t limit_exponent__alu8
)
{
  flea_al_u8_t i;
  flea_u32_t carry__u32       = add_len__dtl;
  flea_al_u8_t comp_idx__alu8 = limit_exponent__alu8 / (sizeof(ctr_block__pu32[0]) * 8);
  flea_u32_t comp__u32        = (1 << (limit_exponent__alu8 % (sizeof(ctr_block__pu32[0]) * 8)));

  FLEA_THR_BEG_FUNC();

  for(i = 0; i < ctr_block_arr_len__alu8; i++)
  {
    flea_u32_t tmp__u32;
    flea_u32_t old__u32 = ctr_block__pu32[i];
    tmp__u32 = old__u32 + carry__u32;
    if((limit_exponent__alu8 != 0) && (((flea_al_u8_t) i) == comp_idx__alu8) && (ctr_block__pu32[i] > comp__u32))
    {
      FLEA_THROW("maximal hash input length exceeded", FLEA_ERR_INV_STATE);
    }
    ctr_block__pu32[i] = tmp__u32;
    if(tmp__u32 >= old__u32)
    {
      // no overflow
      carry__u32 = 0;
      break;
    }
    carry__u32 = 1;
  }
  if(carry__u32)
  {
    // overflow which did not lead to a length excess error => possible in MD5.
    FLEA_SET_ARR(ctr_block__pu32, 0, ctr_block_arr_len__alu8);
    ctr_block__pu32[0] = carry__u32;
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_len_ctr_t__inner_add_and_check_len_limit */

void flea_len_ctr_t__reset(flea_len_ctr_t* len_ctr__pt)
{
  FLEA_SET_ARR(len_ctr__pt->counter__bu32, 0, len_ctr__pt->counter_block_arr_len__u8);
}

flea_err_e THR_flea_len_ctr_t__add_and_check_len_limit(
  flea_len_ctr_t* len_ctr__pt,
  flea_dtl_t      add_len__dtl
)
{
#ifdef FLEA_HEAP_MODE
  flea_al_u8_t compare_len__alu8 = len_ctr__pt->counter_block_arr_len__u8 + 1;
#endif
  flea_u32_t check_len_directly__u32 = len_ctr__pt->neg_limit_offset__u16 ? 0 : len_ctr__pt->limit_exponent__u8;
  FLEA_DECL_BUF(
    compare__bu32,
    flea_u32_t,
    (sizeof(len_ctr__pt->counter__bu32) / sizeof(len_ctr__pt->counter__bu32[0]) + 1)
  );
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_len_ctr_t__inner_add_and_check_len_limit(
      len_ctr__pt->counter__bu32,
      len_ctr__pt->counter_block_arr_len__u8,
      add_len__dtl,
      check_len_directly__u32
    )
  );
  if(!check_len_directly__u32)
  {
    FLEA_ALLOC_BUF(compare__bu32, compare_len__alu8);
    FLEA_CP_ARR(compare__bu32, len_ctr__pt->counter__bu32, len_ctr__pt->counter_block_arr_len__u8);
    compare__bu32[len_ctr__pt->counter_block_arr_len__u8] = 0;
    FLEA_CCALL(
      THR_flea_len_ctr_t__inner_add_and_check_len_limit(
        compare__bu32,
        len_ctr__pt->counter_block_arr_len__u8 + 1,
        len_ctr__pt->neg_limit_offset__u16,
        len_ctr__pt->limit_exponent__u8
      )
    );
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF(compare__bu32);
  );
} /* THR_flea_len_ctr_t__add_and_check_len_limit */

void flea_len_ctr_t__counter_byte_lengt_to_bit_length(flea_len_ctr_t* ctx__pt)
{
  flea_al_u8_t i;
  flea_u32_t carry__u32 = 0;

  for(i = 0; i < ctx__pt->counter_block_arr_len__u8; i++)
  {
    flea_u32_t old__u32       = ctx__pt->counter__bu32[i];
    flea_u32_t new_carry__u32 = old__u32 >> 29;
    ctx__pt->counter__bu32[i] = (old__u32 << 3) | carry__u32;
    carry__u32 = new_carry__u32;
  }
}
