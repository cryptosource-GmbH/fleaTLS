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
#include "internal/common/math/mpi.h"
#include "flea/error_handling.h"
#include "flea/types.h"
#include "flea/bin_utils.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/bin_utils.h"
#include "flea/array_util.h"
#include "flea/util.h"
#include "flea/rng.h"
#include "internal/common/rng_int.h"
#include "internal/common/mask.h"
#include <string.h>


#define FLEA_WORD_MAX_SHIFT_RANGE (FLEA_WORD_BIT_SIZE - 1)


flea_err_e THR_flea_mpi_square(
  flea_mpi_t*       p_result,
  const flea_mpi_t* p_a
)
{
  FLEA_THR_BEG_FUNC();
  flea_mpi_ulen_t i, j;
  flea_uword_t* restrict result_ptr = p_result->m_words;
  flea_uword_t* restrict a_ptr      = p_a->m_words;
  flea_uword_t carry = 0;
  if(p_result->m_nb_alloc_words < 2 * p_a->m_nb_used_words)
  {
    FLEA_THROW("result size insufficient", FLEA_ERR_INV_ARG);
  }
  p_result->m_nb_used_words = 2 * p_a->m_nb_used_words;

  memset(result_ptr, 0, p_result->m_nb_alloc_words * sizeof(p_result->m_words[0]));

  // compute all elements "below" the diagonal
  for(i = 0; i < p_a->m_nb_used_words; i++)
  {
    flea_dbl_uword_t a_ptr_i          = ((flea_dbl_uword_t) a_ptr[i]);
    flea_mpi_ulen_t nb_lead           = p_a->m_nb_used_words - (i + 1);
    flea_mpi_ulen_t lead_limit        = nb_lead + i + 1;
    const flea_uword_t combined_iters = 4;
    carry = 0;
    // determine number of leading iters
    nb_lead %= combined_iters;
    for(j = i + 1; j < lead_limit; j++)
    {
      flea_dbl_uword_t carry__res = result_ptr[i + j] + ((flea_dbl_uword_t) a_ptr[j]) * a_ptr_i
        + ((flea_dbl_uword_t) carry);
      result_ptr[i + j] = (flea_uword_t) carry__res; // lower part
      carry = carry__res >> (sizeof(flea_uword_t) * 8);
    }
    for(; j < p_a->m_nb_used_words - 1; j += combined_iters)
    {
      flea_dbl_uword_t carry__res = result_ptr[i + j] + ((flea_dbl_uword_t) a_ptr[j]) * a_ptr_i
        + ((flea_dbl_uword_t) carry);
      result_ptr[i + j] = (flea_uword_t) carry__res; // lower part
      carry = carry__res >> (sizeof(flea_uword_t) * 8);

      carry__res = result_ptr[i + j + 1] + ((flea_dbl_uword_t) a_ptr[j + 1]) * a_ptr_i + ((flea_dbl_uword_t) carry);
      result_ptr[i + j + 1] = (flea_uword_t) carry__res; // lower part
      carry = carry__res >> (sizeof(flea_uword_t) * 8);

      carry__res = result_ptr[i + j + 2] + ((flea_dbl_uword_t) a_ptr[j + 2]) * a_ptr_i + ((flea_dbl_uword_t) carry);
      result_ptr[i + j + 2] = (flea_uword_t) carry__res; // lower part
      carry = carry__res >> (sizeof(flea_uword_t) * 8);

      carry__res = result_ptr[i + j + 3] + ((flea_dbl_uword_t) a_ptr[j + 3]) * a_ptr_i + ((flea_dbl_uword_t) carry);
      result_ptr[i + j + 3] = (flea_uword_t) carry__res; // lower part
      carry = carry__res >> (sizeof(flea_uword_t) * 8);
    }
    result_ptr[i + p_a->m_nb_used_words] = carry;
  }

  // multiply result by two
  carry = 0;
  for(i = 1; i < p_result->m_nb_used_words; i++) // lowest word is still zero
  {
    flea_dbl_uword_t carry__res = ((flea_dbl_uword_t) result_ptr[i]) * 2 + ((flea_dbl_uword_t) carry);
    result_ptr[i] = (flea_uword_t) carry__res; // lower part
    carry         = carry__res >> (sizeof(flea_uword_t) * 8);
  }
  // now take care of the diagonal elements
  carry = 0;
  for(i = 0; i < p_a->m_nb_used_words; i++)
  {
    flea_dbl_uword_t a_ptr_i = a_ptr[i];
    flea_dbl_uword_t a_ptr_i_next_odd = result_ptr[2 * i + 1];
    flea_dbl_uword_t carry__res       = ((flea_dbl_uword_t) result_ptr[2 * i]) + a_ptr_i * a_ptr_i
      + ((flea_dbl_uword_t) carry);
    result_ptr[2 * i] = (flea_uword_t) carry__res; // lower part
    carry = carry__res >> (sizeof(flea_uword_t) * 8);

    /* add the carry to the following higher word with an odd index, which
     * doesn't receive a product directly */
    carry__res = a_ptr_i_next_odd + carry;
    result_ptr[2 * i + 1] = (flea_uword_t) carry__res; /* lower part */
    carry = carry__res >> (sizeof(flea_uword_t) * 8);
  }


  flea_mpi_t__set_used_words(p_result);
  FLEA_THR_FIN_SEC();
} /* THR_flea_mpi_square */

/*
 * @param lowest_word_of_n integer to invert modulo FLEA_UWORD_MAX + 1. n must be odd
 */
flea_uword_t flea_montgomery_compute_n_prime(flea_uword_t lowest_word_of_n)
{
  // accounting for the sign in t:
  flea_dbl_sword_t q, r0, r1, r2, t0, t1, t2; // q,r0 need to be double words only before the loop!

  lowest_word_of_n |= 1; // make it odd to prevent control flow problems
  t0 = 0;
  t1 = 1;
  r0 = ((flea_dbl_sword_t) FLEA_UWORD_MAX) + 1;
  r1 = lowest_word_of_n;
  while(r1 > 0)
  {
    q  = r0 / r1;
    t2 = t1;
    t1 = t0 - q * t1;
    t0 = t2;
    r2 = r1;
    r1 = r0 - q * r1;
    r0 = r2;
  }
  if(t0 < 0)
  {
    t0 += ((flea_dbl_sword_t) FLEA_UWORD_MAX + 1);
  }
  return (((flea_dbl_sword_t) FLEA_UWORD_MAX) - t0) + 1;
}

/**
 * adds word to the word in *p_mpi at word_idx and propagates the carry.
 */
static flea_err_e THR_flea_mpi_t__montgm_mul_add_to_mpi_arr(
  flea_mpi_t*     p_mpi,
  flea_uword_t    word,
  flea_mpi_ulen_t word_idx
)
{
  FLEA_THR_BEG_FUNC();
  flea_dbl_uword_t carry__res;
  flea_uword_t carry = word;
  while(carry != 0)
  {
    if(word_idx >= p_mpi->m_nb_alloc_words)
    {
      FLEA_THROW("integer array too short", FLEA_ERR_INV_ARG);
    }
    carry__res = ((flea_dbl_uword_t) p_mpi->m_words[word_idx]) + ((flea_dbl_uword_t) carry);
    p_mpi->m_words[word_idx] = (flea_uword_t) carry__res;
    carry = carry__res >> (sizeof(flea_uword_t) * 8);
    if(carry != 0)
    {
      word_idx++;
    }
  }
  // now word_idx points to the last updated word
  if(word_idx > p_mpi->m_nb_used_words - 1)
  {
    p_mpi->m_nb_used_words = word_idx + 1;
  }
  FLEA_THR_FIN_SEC();
}

// result must have double mod size + 1 allocated
flea_err_e THR_flea_mpi_t__montgm_mul(
  flea_mpi_t*            p_result,
  const flea_mpi_t*      p_a,
  const flea_mpi_t*      p_b,
  flea_montgm_mul_ctx_t* p_ctx
)
{
  FLEA_THR_BEG_FUNC();
  flea_uword_t* restrict result_ptr = p_result->m_words;
  flea_uword_t* restrict ws_ptr     = p_ctx->p_ws->m_words;
  flea_uword_t* restrict mod_ptr    = p_ctx->p_mod->m_words;
  flea_uword_t sub_res;
  flea_uword_t borrow;
  flea_uword_t n_prime_zero = p_ctx->mod_prime;
  flea_mpi_ulen_t i, j;
  flea_mpi_t* src, * dst;
  const flea_mpi_ulen_t mod_len = p_ctx->p_mod->m_nb_used_words;
  if(p_result->m_nb_alloc_words < 2 * mod_len + 1)
  {
    FLEA_THROW("result size insufficient", FLEA_ERR_INV_ARG);
  }
  if(p_a != p_b)
  {
    FLEA_CCALL(THR_flea_mpi_t__mul(p_result, p_a, p_b)); // compute t
  }
  else
  {
    FLEA_CCALL(THR_flea_mpi_square(p_result, p_a)); // compute t
  }


  for(i = 0; i < mod_len; i++) // calculate length demands exactly here
  {
    flea_uword_t carry = 0;
    flea_uword_t m     = result_ptr[i] * n_prime_zero;
    for(j = 0; j < mod_len; j++)
    {
      flea_dbl_uword_t carry__res = ((flea_dbl_uword_t) result_ptr[i + j]) + ((flea_dbl_uword_t) m)
        * ((flea_dbl_uword_t) mod_ptr[j]) + ((flea_dbl_uword_t) carry);
      result_ptr[i + j] = (flea_uword_t) carry__res; // assign lower part
      carry = carry__res >> (sizeof(flea_uword_t) * 8);
    }
    FLEA_CCALL(THR_flea_mpi_t__montgm_mul_add_to_mpi_arr(p_result, carry, i + mod_len));
  }
  if(p_ctx->p_ws->m_nb_alloc_words < mod_len + 1)
  {
    FLEA_THROW("workspace size insufficient", FLEA_ERR_INV_ARG);
  }

  p_ctx->p_ws->m_nb_used_words = mod_len + 1;
  p_ctx->p_ws->m_sign = 1;
  memcpy(p_ctx->p_ws->m_words, &result_ptr[mod_len], (mod_len + 1) * sizeof(result_ptr[0]));
  memset(p_result->m_words, 0, p_result->m_nb_alloc_words * sizeof(flea_uword_t));
  p_result->m_nb_used_words = mod_len;
  borrow = 0;
  for(i = 0; i < mod_len; i++)
  {
    flea_uword_t new_borrow = 0;
    flea_uword_t sub_res    = (ws_ptr[i]) - (mod_ptr[i]);
    if(sub_res > ws_ptr[i])
    {
      new_borrow = 1;
    }
    result_ptr[i] = sub_res - borrow;
    if(result_ptr[i] > sub_res)
    {
      new_borrow = 1;
    }
    borrow = new_borrow;
  }

  sub_res = ws_ptr[mod_len] - borrow;
  borrow  = flea_consttime__x_greater_y(sub_res, result_ptr[mod_len]);

  p_ctx->p_ws->m_nb_used_words = p_result->m_nb_used_words;
  src = (flea_mpi_t*) flea_consttime__select_ptr_nz_z(p_ctx->p_ws, p_result, borrow);
  dst = (flea_mpi_t*) flea_consttime__select_ptr_nz_z(p_result, p_ctx->p_ws, borrow);
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(dst, src));
  flea_mpi_t__set_used_words(p_result);
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_mpi_t__montgm_mul */

flea_err_e THR_flea_mpi_t__quick_reduce_smaller_zero(
  flea_mpi_t*       p_in_out,
  const flea_mpi_t* p_mod,
  flea_mpi_t*       p_ws
)
{
  FLEA_THR_BEG_FUNC();
  while(0 > flea_mpi_t__compare_with_uword(p_in_out, 0))
  {
    FLEA_CCALL(THR_flea_mpi_t__add_in_place(p_in_out, p_mod, p_ws));
  }

  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_mpi_t__quick_reduce_greater_zero(
  flea_mpi_t*       p_in_out,
  const flea_mpi_t* p_mod,
  flea_mpi_t*       p_ws
)
{
  FLEA_THR_BEG_FUNC();
  while(0 < flea_mpi_t__compare(p_in_out, p_mod))
  {
    FLEA_CCALL(THR_flea_mpi_t__subtract(p_ws, p_in_out, p_mod));
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_in_out, p_ws));
  }

  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_mpi_t__set_pow_2(
  flea_mpi_t*   p_result,
  flea_al_u16_t exp
)
{
  FLEA_THR_BEG_FUNC();
  flea_mpi_ulen_t word_len  = (exp + FLEA_WORD_BIT_SIZE) / FLEA_WORD_BIT_SIZE;
  flea_mpi_ulen_t one_index = word_len - 1; // for exp = 0 corrected later
  if(word_len > p_result->m_nb_alloc_words)
  {
    FLEA_THROW("pow 2 setter for mpi: result does not fit in array", FLEA_ERR_INV_ARG);
  }
  if(exp != 0)
  {
    // zero low words
    memset(&p_result->m_words[0], 0, (word_len - 1) * sizeof(flea_uword_t));
  }
  else
  {
    one_index = 0;
  }

  p_result->m_words[one_index] = 1 << (exp % FLEA_WORD_BIT_SIZE);
  p_result->m_nb_used_words    = word_len;
  FLEA_THR_FIN_SEC_empty();
}

/**
 * p_quotient_ws must at least satisfy the requirements of the workspace for montg_mul
 */
#if FLEA_CRT_RSA_WINDOW_SIZE > 1
static flea_err_e THR_flea_mpi_t__precompute_window(
  flea_mpi_t*            p_this,
  flea_mpi_t*            p_previous,
  flea_mpi_t*            p_base_trf,
  flea_montgm_mul_ctx_t* p_mm_ctx,
  flea_mpi_t*            p_workspace_double_plus_one_sized
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_workspace_double_plus_one_sized, p_base_trf, p_previous, p_mm_ctx));
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_this, p_workspace_double_plus_one_sized));


  FLEA_THR_FIN_SEC();
}

#endif /* if FLEA_CRT_RSA_WINDOW_SIZE > 1 */


/**
 * quotient_ws must satisfy at least the requirements of montgm mul ws
 */
flea_err_e THR_flea_mpi_t__mod_exp_window(
  flea_mpi_t*           p_result,
  flea_mpi_t*           p_exp,
  flea_mpi_t*           p_base,
  flea_mpi_t*           p_mod,
  flea_mpi_t*           p_workspace_double_plus_one_sized,
  flea_mpi_div_ctx_t*   p_div_ctx,
  flea_mpi_t*           p_quotient_ws,
  flea_al_u8_t          window_size,
  flea_bool_t mul_always_cm__b
#ifdef                  FLEA_SCCM_USE_PUBKEY_INPUT_BASED_DELAY
  ,
  flea_ctr_mode_prng_t* delay_prng_mbn__pt
#endif
)
{
  flea_uword_t one_arr[1];
  flea_u16_t exp_bit_size;
  flea_s32_t i;
  flea_mpi_t one;

#ifdef FLEA_HEAP_MODE
  const flea_al_u16_t precomp_arr_dynamic_word_len = p_mod->m_nb_used_words;
#endif
  const flea_al_u16_t R_dynamic_word_len = p_mod->m_nb_used_words + 1; // R is one word longer than mod
  flea_mpi_ulen_t precomp_dynamic_size;

  FLEA_DECL_BUF(R_arr, flea_uword_t, ((FLEA_RSA_MAX_KEY_BIT_SIZE / 8) + 4) / sizeof(flea_uword_t) + 1); // for RSA (CRT/SF) ; + 1 because R potentially longer than mod and another +4 for p-q diff; this array must account for non CRT usage also
#if defined FLEA_HEAP_MODE
  FLEA_DECL_BUF(precomp_arrs, flea_uword_t*, (1 << FLEA_CRT_RSA_WINDOW_SIZE) - 1);
#else
  flea_uword_t precomp_arrs[(1 << FLEA_CRT_RSA_WINDOW_SIZE) - 1][FLEA_RSA_MAX_KEY_BIT_SIZE / 8 / sizeof(flea_uword_t)
  + 4 / sizeof(flea_uword_t)]; // plus 32-bit because of p-q-diff
#endif


  FLEA_DECL_BUF(precomp, flea_mpi_t, (1 << FLEA_CRT_RSA_WINDOW_SIZE) - 1);

  flea_mpi_t R;
  flea_montgm_mul_ctx_t mm_ctx;

  FLEA_THR_BEG_FUNC();

  if(window_size > FLEA_CRT_RSA_WINDOW_SIZE)
  {
    window_size = FLEA_CRT_RSA_WINDOW_SIZE;
  }
  precomp_dynamic_size = (1 << window_size) - 1;

  mm_ctx.mod_prime = flea_montgomery_compute_n_prime(p_mod->m_words[0]);
  mm_ctx.p_mod     = p_mod;
  mm_ctx.p_ws      = p_quotient_ws;

  FLEA_ALLOC_BUF(R_arr, R_dynamic_word_len);
#if defined FLEA_HEAP_MODE
  FLEA_ALLOC_BUF(precomp_arrs, precomp_dynamic_size);
  FLEA_ALLOC_BUF(precomp, precomp_dynamic_size);

  FLEA_SET_ARR(precomp_arrs, 0, precomp_dynamic_size);
  for(i = 0; i < precomp_dynamic_size; i++)
  {
    FLEA_ALLOC_MEM_ARR(precomp_arrs[i], precomp_arr_dynamic_word_len);
  }
#endif /* if defined FLEA_HEAP_MODE */
  for(i = 0; i < precomp_dynamic_size; i++)
  {
#ifdef FLEA_HEAP_MODE
    flea_mpi_t__init(&precomp[i], precomp_arrs[i], precomp_arr_dynamic_word_len);
#else
    flea_mpi_t__init(&precomp[i], precomp_arrs[i], sizeof(precomp_arrs[i]) / sizeof(flea_uword_t));
#endif
  }
#ifdef FLEA_DO_IF_USE_HEAP_BUF
  flea_mpi_t__init(&R, R_arr, R_dynamic_word_len);
#else
  flea_mpi_t__init(&R, R_arr, sizeof(R_arr) / sizeof(R_arr[0]);
#endif
  FLEA_CCALL(THR_flea_mpi_t__set_pow_2(&R, p_mod->m_nb_used_words * FLEA_WORD_BIT_SIZE));


  // window method precomputations

  flea_mpi_t__init(&one, one_arr, sizeof(one_arr) / sizeof(flea_uword_t));
  flea_mpi_t__set_to_word_value(&one, 1);

  FLEA_CCALL(THR_flea_mpi_t__mul(p_workspace_double_plus_one_sized, &R, p_base));


  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &precomp[0], p_workspace_double_plus_one_sized, p_mod, p_div_ctx));   // a_bar = a * R mod n

#if FLEA_CRT_RSA_WINDOW_SIZE > 1
  if(window_size > 1)
  {
    FLEA_CCALL(
      THR_flea_mpi_t__precompute_window(
        &precomp[1],
        &precomp[0],
        &precomp[0],
        &mm_ctx,
        p_workspace_double_plus_one_sized
      )
    );
    for(i = 2; i < (1 << window_size) - 1; i++)
    {
      FLEA_CCALL(
        THR_flea_mpi_t__precompute_window(
          &precomp[i],
          &precomp[i - 1],
          &precomp[0],
          &mm_ctx,
          p_workspace_double_plus_one_sized
        )
      );
    }
  }
#endif /* if FLEA_CRT_RSA_WINDOW_SIZE > 1 */


  // first, transform base

  // transformed base x_bar^0 in p_result:

  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, p_result, &R, p_mod, p_div_ctx));   // x_bar = 1 * R mod n

  exp_bit_size = flea_mpi_t__get_bit_size(p_exp);

  i = exp_bit_size - 1;

  while(i >= 0)
  {
    flea_al_u8_t j;
    flea_mpi_t* p_base_power;
    flea_al_u8_t exp_bit = 0;
    flea_mpi_t* result_or_fake__pt, * base_or_fake__pt;
    flea_bool_t do_mul__b;
    flea_mpi_t* result_or_fake_iter__pt = p_result;

#ifdef FLEA_SCCM_USE_PUBKEY_INPUT_BASED_DELAY
    flea_al_u8_t fix_up_i__is_fake_iter__alu8 = 0;
    flea_u8_t rnd_bytes__au8[3];
#endif
#ifdef FLEA_SCCM_USE_PUBKEY_USE_RAND_DELAY
    flea_u8_t real_rnd_bytes__au8[2];
#endif
#if defined FLEA_SCCM_USE_PUBKEY_INPUT_BASED_DELAY || defined FLEA_SCCM_USE_PUBKEY_USE_RAND_DELAY
    flea_al_u16_t delay_iters__alu16 = 0;
#endif
    while(i < window_size && window_size > 1)
    {
      window_size--;
    }

#ifdef FLEA_SCCM_USE_PUBKEY_USE_RAND_DELAY
    FLEA_CCALL(THR_flea_rng__randomize_no_flush(&real_rnd_bytes__au8[0], sizeof(real_rnd_bytes__au8)));
    if((i == exp_bit_size - 1) || (0 == (real_rnd_bytes__au8[1] & 0x0F)))
    {
      /* delay with probability 1/4 */
      delay_iters__alu16 += real_rnd_bytes__au8[0];
    }
#endif /* ifdef FLEA_SCCM_USE_PUBKEY_USE_RAND_DELAY */

#ifdef FLEA_SCCM_USE_PUBKEY_INPUT_BASED_DELAY
    if(delay_prng_mbn__pt)
    {
      flea_ctr_mode_prng_t__rndmz_no_flush(delay_prng_mbn__pt, rnd_bytes__au8, sizeof(rnd_bytes__au8));
      flea_al_u8_t cond__alu8 = rnd_bytes__au8[0] & 0x0F;
# ifdef FLEA_SCCM_USE_PUBKEY_USE_RAND_DELAY
      flea_al_u8_t cond2__alu8 = real_rnd_bytes__au8[0] & 0x0F;
      /* additional random delays */
      cond__alu8 = ~((~cond__alu8) & (~cond2__alu8));
# endif
      fix_up_i__is_fake_iter__alu8 = flea_consttime__select_u32_nz_z(0, window_size, cond__alu8);

      result_or_fake_iter__pt = (flea_mpi_t*) flea_consttime__select_ptr_nz_z(
        p_workspace_double_plus_one_sized,
        p_result,
        fix_up_i__is_fake_iter__alu8
        );
      if((i == exp_bit_size - 1) || (0 == (rnd_bytes__au8[2] & 0x0F)))
      {
        /* delay with probability 1/4 */
        delay_iters__alu16 += (rnd_bytes__au8[1]) | (rnd_bytes__au8[2] << 1);
      }
    }
#endif  /* ifdef FLEA_SCCM_USE_PUBKEY_INPUT_BASED_DELAY */

#if defined FLEA_SCCM_USE_PUBKEY_INPUT_BASED_DELAY || defined FLEA_SCCM_USE_PUBKEY_USE_RAND_DELAY
    flea_waste_cycles(delay_iters__alu16);
#endif

    exp_bit = flea_mpi_t__get_window(p_exp, i - (window_size - 1), window_size);
    // perform the squarings
    for(j = 0; j < window_size; j++)
    {
      FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_workspace_double_plus_one_sized, p_result, p_result, &mm_ctx)); // last arg needs only mod size
      // copy contents from large ws to result
      FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(result_or_fake_iter__pt, p_workspace_double_plus_one_sized));
    }

    p_base_power = &precomp[exp_bit - 1];

    result_or_fake__pt = flea_consttime__select_ptr_nz_z(
      result_or_fake_iter__pt,
      p_workspace_double_plus_one_sized,
      exp_bit
      );
    // result_or_fake__pt = flea_consttime__select_ptr_nz_z(result_or_fake_iter__pt, p_workspace_double_plus_one_sized, fix_up_i__is_fake_iter__alu8);
    base_or_fake__pt = flea_consttime__select_ptr_nz_z(p_base_power, &precomp[0], exp_bit);
    // base_or_fake__pt   = flea_consttime__select_ptr_nz_z(base_or_fake__pt, &precomp[0], fix_up_i__is_fake_iter__alu8);
    do_mul__b = flea_consttime__select_u32_nz_z(1, mul_always_cm__b, exp_bit);
    if(do_mul__b)
    {
      FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_workspace_double_plus_one_sized, p_result, base_or_fake__pt, &mm_ctx));
      FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(result_or_fake__pt, p_workspace_double_plus_one_sized));
    }

    i -= window_size;
#ifdef FLEA_SCCM_USE_PUBKEY_INPUT_BASED_DELAY
    i += fix_up_i__is_fake_iter__alu8;
#endif
  }
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_workspace_double_plus_one_sized, p_result, &one, &mm_ctx));
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_result, p_workspace_double_plus_one_sized));
  FLEA_THR_FIN_SEC(
    FLEA_DO_IF_USE_HEAP_BUF(
      if(precomp_arrs)
  {
    for(i = 0; i < precomp_dynamic_size; i++)
    {
      FLEA_FREE_MEM_CHK_NULL(precomp_arrs[i]);
    }
  }
      FLEA_FREE_BUF_FINAL(precomp_arrs);
    );
    FLEA_FREE_BUF_FINAL(precomp);
    FLEA_FREE_BUF_FINAL(R_arr);
  );
} /* THR_flea_mpi_t__mod_exp_window */

flea_al_u8_t flea_mpi_t__get_window(
  const flea_mpi_t* p_mpi,
  flea_mpi_ulen_t   low_bit_pos,
  flea_al_u8_t      window_size
)
{
  flea_mpi_ulen_t j;
  flea_al_u8_t result = 0;

  for(j = 0; j < window_size; j++)
  {
    result |= (flea_mpi_t__get_bit(p_mpi, j + low_bit_pos) << j);
  }
  return result;
}

static flea_err_e THR_flea_mpi_t__subtract_ignore_sign(
  flea_mpi_t*       p_result,
  const flea_mpi_t* p_larger,
  const flea_mpi_t* p_smaller
)
{
  flea_uword_t borrow;
  flea_mpi_ulen_t i;

  FLEA_THR_BEG_FUNC();
  memset(p_result->m_words, 0, p_result->m_nb_alloc_words * sizeof(p_result->m_words[0]));
  // length of a >= length of b
  borrow = 0;
  for(i = 0; i < p_smaller->m_nb_used_words; i++)
  {
    flea_uword_t new_borrow = 0;
    flea_uword_t new_word;
    flea_uword_t sub_res = p_larger->m_words[i] - p_smaller->m_words[i];

    if(sub_res > p_larger->m_words[i])
    {
      new_borrow = 1;
    }

    new_word = sub_res - borrow;
    if(new_word != 0)
    {
      if(p_result->m_nb_alloc_words < i + 1)
      {
        FLEA_THROW("error with size of result", FLEA_ERR_BUFF_TOO_SMALL);
      }
      p_result->m_words[i] = new_word;
    }
    if(new_word > sub_res)
    {
      new_borrow = 1;
    }
    borrow = new_borrow;
  }
  // handle remaining borrow (because a is not smaller than b, there must be
  // another word in a if there is a borrow pending after processing the highest word of b)
  for(; i < p_larger->m_nb_used_words; i++)
  {
    flea_uword_t sub_res    = p_larger->m_words[i] - borrow;
    flea_uword_t new_borrow = 0;

    if(sub_res > p_larger->m_words[i])
    {
      new_borrow = 1;
    }

    if(sub_res != 0 && p_result->m_nb_alloc_words < i + 1)
    {
      FLEA_THROW("error with size of result", FLEA_ERR_BUFF_TOO_SMALL);
    }
    p_result->m_words[i] = sub_res;
    borrow = new_borrow;
  }
  flea_mpi_t__set_used_words(p_result);
  FLEA_THR_FIN_SEC();
} /* THR_flea_mpi_t__subtract_ignore_sign */

flea_err_e THR_flea_mpi_t__subtract(
  flea_mpi_t*       p_result,
  const flea_mpi_t* p_a,
  const flea_mpi_t* p_b
)
{
  const flea_mpi_t* tmp;

  FLEA_THR_BEG_FUNC();
  p_result->m_sign = +1;
  if(p_a->m_sign == -1)
  {
    // this applies to both subtraction and addition case
    p_result->m_sign *= -1;
  }

  if(p_a->m_sign == p_b->m_sign)
  {
    if(-1 == flea_mpi_t__compare_absolute(p_a, p_b))
    {
      // a < b
      p_result->m_sign *= -1;
      tmp = p_a;
      p_a = p_b;
      p_b = tmp;
    }
    FLEA_CCALL(THR_flea_mpi_t__subtract_ignore_sign(p_result, p_a, p_b));
    FLEA_THR_RETURN();
  }
  // signs differ, thus we have an addition.
  // the sign was already treated in the beginning of the function
  FLEA_CCALL(THR_flea_mpi_t__add_ignore_sign(p_result, p_a, p_b));
  if(flea_mpi_t__is_zero(p_result))
  {
    p_result->m_sign = +1;
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_mpi_t__subtract */

flea_err_e THR_flea_mpi_t__subtract_mod(
  flea_mpi_t*       p_result,
  const flea_mpi_t* p_a,
  const flea_mpi_t* p_b,
  const flea_mpi_t* p_mod,
  flea_mpi_t*       p_workspace_mod_size
)
{
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_mpi_t__subtract(p_workspace_mod_size, p_a, p_b));
  if(p_workspace_mod_size->m_sign < 0)
  {
    // result contains absolute value of what is negative to be reduced by p
    FLEA_CCALL(THR_flea_mpi_t__subtract_ignore_sign(p_result, p_mod, p_workspace_mod_size));
  }
  else if(0 < flea_mpi_t__compare_absolute(p_workspace_mod_size, p_mod))
  {
    FLEA_CCALL(THR_flea_mpi_t__subtract(p_result, p_workspace_mod_size, p_mod));
  }
  else
  {
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_result, p_workspace_mod_size));
  }
  p_result->m_sign = +1;
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_mpi_t__add_ignore_sign(
  flea_mpi_t*       p_result,
  const flea_mpi_t* p_a,
  const flea_mpi_t* p_b
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_result, p_a));
  FLEA_CCALL(THR_flea_mpi_t__add_in_place_ignore_sign(p_result, p_b));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_mpi_t__add_in_place_ignore_sign(
  flea_mpi_t*       p_in_out,
  const flea_mpi_t* p_b
)
{
  flea_uword_t carry = 0;
  flea_mpi_ulen_t i;

  FLEA_THR_BEG_FUNC();
  if(p_in_out->m_nb_alloc_words < p_b->m_nb_used_words)
  {
    FLEA_THROW("error: addition result mpi too small to hold result value", FLEA_ERR_BUFF_TOO_SMALL);
  }
  // prepare result for expansion
  memset(
    &p_in_out->m_words[p_in_out->m_nb_used_words],
    0,
    sizeof(p_in_out->m_words[0]) * (p_in_out->m_nb_alloc_words - p_in_out->m_nb_used_words)
  );
  // from here on we can process the words of b
  for(i = 0; i < p_b->m_nb_used_words; i++)
  {
    flea_dbl_uword_t carry_res;
    carry_res = ((flea_dbl_uword_t) p_in_out->m_words[i]) + p_b->m_words[i] + carry;

    p_in_out->m_words[i] = ((flea_uword_t) carry_res);

    carry = carry_res >> (sizeof(flea_uword_t) * 8);
  }
  // handle remaining borrow (because a is not smaller than b, there must be
  // another word in a if there is a borrow pending after processing the highest word of b)
  while(carry) // maximally two iterations
  {
    flea_uword_t orig_word = 0;
    flea_dbl_uword_t carry_res;
    if(i >= p_in_out->m_nb_used_words)
    {
      if(i >= p_in_out->m_nb_alloc_words)
      {
        FLEA_THROW("addition result too large", FLEA_ERR_BUFF_TOO_SMALL);
      }
    }
    else
    {
      orig_word = p_in_out->m_words[i];
    }
    carry_res = ((flea_dbl_uword_t) orig_word) + carry;
    p_in_out->m_words[i] = ((flea_uword_t) carry_res);

    carry = carry_res >> (sizeof(flea_uword_t) * 8);
    i++;
  }
  flea_mpi_t__set_used_words(p_in_out);
  FLEA_THR_FIN_SEC();
} /* THR_flea_mpi_t__add_in_place_ignore_sign */

// ws must have the same size allocated as in_out uses
flea_err_e THR_flea_mpi_t__add_in_place(
  flea_mpi_t*       p_in_out,
  const flea_mpi_t* p_b,
  flea_mpi_t*       p_ws
)
{
  FLEA_THR_BEG_FUNC();
  if(p_in_out->m_sign == p_b->m_sign)
  {
    FLEA_CCALL(THR_flea_mpi_t__add_in_place_ignore_sign(p_in_out, p_b));
    FLEA_THR_RETURN();
  }
  if(0 < flea_mpi_t__compare_absolute(p_b, p_in_out))
  {
    // caculate -(b - a)
    flea_s8_t old_sign = p_in_out->m_sign;
    FLEA_CCALL(THR_flea_mpi_t__subtract_ignore_sign(p_ws, p_b, p_in_out));
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_in_out, p_ws));
    p_in_out->m_sign = old_sign * -1;
  }
  else
  {
    // calculate a - b
    flea_s8_t old_sign = p_in_out->m_sign;
    FLEA_CCALL(THR_flea_mpi_t__subtract_ignore_sign(p_ws, p_in_out, p_b));
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_in_out, p_ws));
    p_in_out->m_sign = old_sign;
  }
  if(flea_mpi_t__is_zero(p_in_out))
  {
    p_in_out->m_sign = +1;
  }
  FLEA_THR_FIN_SEC_empty();
}

void flea_mpi_t__shift_right(
  flea_mpi_t*   p_mpi,
  flea_al_u16_t shift
)
{
  flea_mpi_slen_t i;
  flea_uword_t carry          = 0;
  flea_al_u8_t shift_in_word  = shift % FLEA_WORD_BIT_SIZE;
  flea_mpi_ulen_t shift_words = shift / FLEA_WORD_BIT_SIZE;

  if(shift_words > p_mpi->m_nb_used_words)
  {
    flea_mpi_t__set_to_word_value(p_mpi, 0);
    return;
  }


  memmove(
    &p_mpi->m_words[0],
    &p_mpi->m_words[shift_words],
    (p_mpi->m_nb_used_words - shift_words) * sizeof(flea_uword_t)
  );
  p_mpi->m_nb_used_words -= shift_words;

  flea_al_u8_t shift_left = FLEA_WORD_BIT_SIZE - shift_in_word;
  flea_uword_t low_mask   = (((flea_uword_t) 1) << shift_in_word) - 1;
    for(i = p_mpi->m_nb_used_words - 1; i >= 0; i--)
  {
    flea_uword_t this_word = p_mpi->m_words[i];
    flea_uword_t new_carry = this_word & low_mask; // mask in the low part
    p_mpi->m_words[i] = (carry << shift_left) | (this_word >> shift_in_word);
    carry = new_carry;
  }
    // check whether the leading word became unpopulated:
    if(p_mpi->m_nb_used_words && p_mpi->m_words[p_mpi->m_nb_used_words - 1] == 0)
  {
    p_mpi->m_nb_used_words -= 1;
  }
} /* flea_mpi_t__shift_right */

flea_mpi_ulen_t flea_mpi_t__nb_trailing_zero_bits(flea_mpi_t* p_mpi)
{
  // implementation optimized for integers appearing as random
  flea_mpi_ulen_t i, result = 0;

  for(i = 0; i < p_mpi->m_nb_used_words; i++)
  {
    flea_mpi_ulen_t j;
    flea_uword_t word = p_mpi->m_words[i];
    for(j = 0; j < FLEA_WORD_BIT_SIZE; j++)
    {
      if((1 << j) & word)
      {
        return result + j;
      }
    }
    result += FLEA_WORD_BIT_SIZE;
  }
  return 0; // the integer is in fact zero
}

// shift left mpi by less than the word size (i.e. in general 0-7 is allowed as
// shift value)
flea_err_e THR_flea_mpi_t__shift_left_small(
  flea_mpi_t*   p_mpi,
  flea_al_u16_t shift
)
{
  flea_mpi_ulen_t i;
  flea_uword_t carry = 0;

  FLEA_THR_BEG_FUNC();
  if(shift > 7)
  {
    FLEA_THROW("'small' left shift by more than 7 bits", FLEA_ERR_INV_ARG);
  }


  for(i = 0; i < p_mpi->m_nb_used_words; i++)
  {
    flea_dbl_uword_t shifted = ((flea_dbl_uword_t) p_mpi->m_words[i] << shift);
    p_mpi->m_words[i] = shifted | carry;
    carry = shifted >> (sizeof(flea_uword_t) * 8);
  }
  // place the newly populated word
  if(carry != 0)
  {
    if(!(p_mpi->m_nb_alloc_words > p_mpi->m_nb_used_words))
    {
      FLEA_THROW("shift target mpi doesn't have enough allocated words", FLEA_ERR_BUFF_TOO_SMALL);
    }
    p_mpi->m_nb_used_words += 1;
    p_mpi->m_words[i] = carry;
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_mpi_t__invert_odd_mod(
  flea_mpi_t*       p_result,
  const flea_mpi_t* p_mpi,
  const flea_mpi_t* p_mod,
  flea_mpi_t        ws_mod_size[4]
)
{
  flea_mpi_t* u = &ws_mod_size[0];
  flea_mpi_t* v = &ws_mod_size[1];
  flea_mpi_t* B = &ws_mod_size[2];
  flea_mpi_t* D = p_result;
  flea_mpi_t* ws = &ws_mod_size[3];

  FLEA_THR_BEG_FUNC();
  if(flea_mpi_t__is_zero(p_mpi))
  {
    FLEA_THROW("attempt to invert 0", FLEA_ERR_INV_ARG);
  }
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(u, p_mod));
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(v, p_mpi));
  flea_mpi_t__set_to_word_value(B, 0);
  flea_mpi_t__set_to_word_value(D, 1);


  while(!flea_mpi_t__is_zero(u))
  {
    flea_al_u16_t i;


    flea_mpi_ulen_t trailing_zeroes = flea_mpi_t__nb_trailing_zero_bits(u);
    flea_mpi_t__shift_right(u, trailing_zeroes);

    for(i = 0; i < trailing_zeroes; i++)
    {
      if(flea_mpi_t__get_bit(B, 0)) // if odd
      {
        FLEA_CCALL(THR_flea_mpi_t__subtract(ws, B, p_mod));
        FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(B, ws));
      }
      flea_mpi_t__shift_right(B, 1);
    }

    trailing_zeroes = flea_mpi_t__nb_trailing_zero_bits(v);
    flea_mpi_t__shift_right(v, trailing_zeroes);

    for(i = 0; i < trailing_zeroes; i++)
    {
      if(flea_mpi_t__get_bit(D, 0)) // if odd
      {
        FLEA_CCALL(THR_flea_mpi_t__subtract(ws, D, p_mod));
        FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(D, ws));
      }
      flea_mpi_t__shift_right(D, 1);
    }

    if(0 <= flea_mpi_t__compare(u, v)) // if u >= v
    {
      FLEA_CCALL(THR_flea_mpi_t__subtract(ws, u, v));
      FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(u, ws));
      FLEA_CCALL(THR_flea_mpi_t__subtract(ws, B, D));
      FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(B, ws));
    }
    else
    {
      FLEA_CCALL(THR_flea_mpi_t__subtract(ws, v, u));
      FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(v, ws));
      FLEA_CCALL(THR_flea_mpi_t__subtract(ws, D, B));
      FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(D, ws));
    }
  }
  if(flea_mpi_t__compare_with_uword(v, 1))
  {
    flea_mpi_t__set_to_word_value(p_result, 0);
    FLEA_THR_RETURN();
  }
  while(0 > flea_mpi_t__compare_with_uword(D, 0))
  {
    FLEA_CCALL(THR_flea_mpi_t__add_in_place(D, p_mod, ws));
  }
  // absolute comparison is fine after making D positive
  while(0 <= flea_mpi_t__compare_absolute(D, p_mod))
  {
    FLEA_CCALL(THR_flea_mpi_t__subtract_ignore_sign(ws, D, p_mod));
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(D, ws));
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_mpi_t__invert_odd_mod */

flea_err_e THR_flea_mpi_t__random_integer(
  flea_mpi_t*       p_result,
  const flea_mpi_t* p_limit
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_mpi_t__random_integer_no_flush(p_result, p_limit));
  FLEA_CCALL(THR_flea_rng__flush());
  FLEA_THR_FIN_SEC(
  );
}

flea_err_e THR_flea_mpi_t__random_integer_no_flush(
  flea_mpi_t*       p_result,
  const flea_mpi_t* p_limit
)
{
  flea_u16_t byte_size, bit_size, word_size;

  FLEA_THR_BEG_FUNC();
  // create as many bytes as those in p_limit
  bit_size = flea_mpi_t__get_bit_size(p_limit);
  byte_size = FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(bit_size);
  word_size = FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(byte_size);
  if(word_size > p_result->m_nb_alloc_words)
  {
    FLEA_THROW("random integer: target memory too small", FLEA_ERR_INV_ARG);
  }
  bit_size %= FLEA_BITS_PER_WORD;
  p_result->m_nb_used_words = word_size;
  memset(
    (void*) (p_result->m_words + word_size),
    0,
    (p_result->m_nb_alloc_words - word_size) * sizeof(p_result->m_words[0])
  );
  do
  {
    flea_mpi_ulen_t i;
    for(i = 0; i < word_size; i++)
    {
      flea_u8_t enc__au8[FLEA_WORD_BIT_SIZE / 8];
      FLEA_CCALL(
        THR_flea_rng__randomize_no_flush(enc__au8, sizeof(enc__au8))
      );
#if FLEA_WORD_BIT_SIZE == 32
      p_result->m_words[i] = flea__decode_U32_BE(enc__au8);
#elif FLEA_WORD_BIT_SIZE == 16
      p_result->m_words[i] = flea__decode_U16_BE(enc__au8);
#else
      p_result->m_words[i] = enc__au8[0];
#endif /* if FLEA_WORD_BIT_SIZE == 32 */
    }
    // mask out the excess bits in the highest word
    if(bit_size)
    {
      p_result->m_words[p_result->m_nb_used_words - 1] &= FLEA_UWORD_MAX >> (FLEA_BITS_PER_WORD - bit_size);
    }
    flea_mpi_t__set_used_words(p_result);
  } while(0 <= flea_mpi_t__compare_absolute(p_result, p_limit));

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_mpi_t__random_integer_no_flush */
