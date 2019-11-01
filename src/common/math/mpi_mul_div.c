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

#include "internal/common/math/mpi_mul_div.h"
#include "flea/error_handling.h"

#define FLEA_SET_HLF_UWORD(__dest, __idx, __val) \
  do { \
    __dest[(__idx) / 2] &= ~(FLEA_HLF_UWORD_MAX << (((__idx) % 2) * 8 * sizeof(flea_hlf_uword_t))); \
    __dest[(__idx) / 2] |= (__val) << (((__idx) % 2) * 8 * sizeof(flea_hlf_uword_t)); \
  } while(0)

#define FLEA_GET_HLF_UWORD(__src, __idx) \
  ((__src[(__idx) / 2] >> (((__idx) % 2) * sizeof(flea_hlf_uword_t) * 8)) & FLEA_HLF_UWORD_MAX)

static void flea_mpi_t__inner_multiply(
  const flea_uword_t* restrict a_ptr,
  flea_mpi_ulen_t              a_len,
  const flea_uword_t* restrict b_ptr,
  flea_mpi_ulen_t              b_len,
  flea_uword_t* restrict       result_ptr
)
{
  flea_mpi_ulen_t i, j;

  for(i = 0; i < b_len; i++)
  {
    flea_uword_t carry  = 0;
    flea_uword_t i_word = ((flea_dbl_uword_t) b_ptr[i]);
    for(j = 0; j < a_len; j++)
    {
      flea_dbl_uword_t carry__res = result_ptr[i + j] + ((flea_dbl_uword_t) a_ptr[j]) * i_word
        + ((flea_dbl_uword_t) carry);
      result_ptr[i + j] = (flea_uword_t) carry__res; // lower part
      carry = carry__res >> (sizeof(flea_uword_t) * 8);
    }
    result_ptr[i + a_len] = carry;
  }
}

flea_err_e THR_flea_mpi_t__mul(
  flea_mpi_t*       p_result,
  const flea_mpi_t* p_a,
  const flea_mpi_t* p_b
)
{
  FLEA_THR_BEG_FUNC();
  if(p_result->m_nb_alloc_words < p_a->m_nb_used_words + p_b->m_nb_used_words)
  {
    FLEA_THROW("result size insufficient", FLEA_ERR_INV_ARG);
  }
  p_result->m_nb_used_words = p_a->m_nb_used_words + p_b->m_nb_used_words;

  memset(p_result->m_words, 0, p_result->m_nb_alloc_words * sizeof(p_result->m_words[0]));
  flea_mpi_t__inner_multiply(p_a->m_words, p_a->m_nb_used_words, p_b->m_words, p_b->m_nb_used_words, p_result->m_words);
  flea_mpi_t__set_used_words(p_result);
  p_result->m_sign = p_a->m_sign * p_b->m_sign;
  if(flea_mpi_t__is_zero(p_result))
  {
    p_result->m_sign = +1;
  }
  FLEA_THR_FIN_SEC();
}

// vn must have twice the size of the divisor
// un must have 2(m+1) words, where m is the word size of the dividend
flea_err_e THR_flea_mpi_t__divide(
  flea_mpi_t*         p_quotient,
  flea_mpi_t*         p_remainder,
  const flea_mpi_t*   p_dividend,
  const flea_mpi_t*   p_divisor,
  flea_mpi_div_ctx_t* p_div_ctx
)
{
  flea_mpi_ulen_t m, n;
  flea_mpi_slen_t j, i;
  const flea_uword_t* u = p_dividend->m_words;
  const flea_uword_t* v = p_divisor->m_words;
  flea_hlf_uword_t* vn  = p_div_ctx->vn;
  flea_hlf_uword_t* un  = p_div_ctx->un;

  flea_uword_t* q = NULL;

  flea_uword_t* r = p_remainder->m_words;

  const flea_uword_t b = FLEA_HLF_UWORD_MAX + 1;
  flea_sword_t t;
  flea_uword_t qhat, rhat, p;
  flea_uword_t k, s;


  FLEA_THR_BEG_FUNC();

  flea_s8_t result_sign = p_dividend->m_sign * p_divisor->m_sign;

  m = p_dividend->m_nb_used_words * 2;
  n = p_divisor->m_nb_used_words * 2;

  if(((m + 1) > p_div_ctx->un_len) || (n > p_div_ctx->vn_len))
  {
    FLEA_THROW("division context buffer too small", FLEA_ERR_BUFF_TOO_SMALL);
  }
  if(p_quotient != NULL)
  {
    flea_mpi_ulen_t quotient_min_word_len__ulen;
    flea_mpi_ubil_t dividend_bit_len__ubil, divisor_bit_len__ubil;
    dividend_bit_len__ubil      = flea_mpi_t__get_bit_size(p_dividend);
    divisor_bit_len__ubil       = flea_mpi_t__get_bit_size(p_divisor);
    quotient_min_word_len__ulen = FLEA_CEIL_WORD_LEN_FROM_BIT_LEN(dividend_bit_len__ubil - divisor_bit_len__ubil + 1);
    if(dividend_bit_len__ubil == divisor_bit_len__ubil)
    {
      quotient_min_word_len__ulen = p_dividend->m_nb_used_words;
    }
    else if(divisor_bit_len__ubil > dividend_bit_len__ubil)
    {
      quotient_min_word_len__ulen = 1;
    }
    if(p_quotient->m_nb_alloc_words < quotient_min_word_len__ulen)
    {
      FLEA_THROW("quotient nb allocated words too small in division", FLEA_ERR_BUFF_TOO_SMALL);
    }

    q = p_quotient->m_words;
  }
  if(p_remainder->m_nb_alloc_words < p_divisor->m_nb_used_words)
  {
    FLEA_THROW("remainder nb allocated words too small in division", FLEA_ERR_BUFF_TOO_SMALL);
  }
  if(0 > flea_mpi_t__compare_absolute(p_dividend, p_divisor))
  {
    if(p_quotient != NULL)
    {
      flea_mpi_t__set_to_word_value(p_quotient, 0);
    }
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_remainder, p_dividend));
    p_remainder->m_sign = result_sign;
    FLEA_THR_RETURN();
  }
  if(q != NULL)
  {
    memset(p_quotient->m_words, 0, p_quotient->m_nb_alloc_words * sizeof(flea_uword_t));
  }
  memset(p_remainder->m_words, 0, p_remainder->m_nb_alloc_words * sizeof(flea_uword_t));

  if(m == 0 || n == 0)
  {
    FLEA_THROW("invalid size for division: dividend or divisor", FLEA_ERR_INV_ARG);
  }
  // correct the "half-word" size of the arrays
  if(u[m / 2 - 1] <= FLEA_HLF_UWORD_MAX)
  {
    m--;
  }
  if(v[n / 2 - 1] <= FLEA_HLF_UWORD_MAX)
  {
    n--;
  }
  if(m < n || FLEA_GET_HLF_UWORD(v, n - 1) == 0)
  {
    FLEA_THROW("invalid size for division: divisor too large", FLEA_ERR_INV_ARG);
  }
  if(n == 1)
  {
    flea_hlf_uword_t v_0 = FLEA_GET_HLF_UWORD(v, 0);
    k = 0;
    for(j = m - 1; j >= 0; j--)
    {
      flea_hlf_uword_t u_j = FLEA_GET_HLF_UWORD(u, j);
      flea_hlf_uword_t q_j = (k * b + u_j) / v_0;
      if(q != NULL)
      {
        FLEA_SET_HLF_UWORD(q, j, q_j);
      }
      k = (k * b + u_j) - q_j * v_0;
    }
    FLEA_SET_HLF_UWORD(r, 0, k);
    p_remainder->m_nb_used_words = 1;
    if(p_quotient != NULL)
    {
      flea_mpi_t__set_used_words(p_quotient);
    }
    p_remainder->m_sign = result_sign;
    FLEA_THR_RETURN();
  }
  s = flea__nlz_uword(FLEA_GET_HLF_UWORD(v, n - 1)) - sizeof(flea_hlf_uword_t) * 8; // subtract the unused half of the full words bits
  for(i = n - 1; i > 0; i--)
  {
    vn[i] =
      (FLEA_GET_HLF_UWORD(v, i) << s)
      | (FLEA_GET_HLF_UWORD(v, i - 1) >> ((FLEA_WORD_BIT_SIZE / 2) - s));
  }
  vn[0] = FLEA_GET_HLF_UWORD(v, 0) << s;

  un[m] = FLEA_GET_HLF_UWORD(u, m - 1) >> ((FLEA_WORD_BIT_SIZE / 2) - s);

  for(i = m - 1; i > 0; i--)
  {
    un[i] = (FLEA_GET_HLF_UWORD(u, i) << s) | (FLEA_GET_HLF_UWORD(u, i - 1) >> ((FLEA_WORD_BIT_SIZE / 2) - s));
  }
  un[0] = (FLEA_GET_HLF_UWORD(u, 0) << s);
  for(j = m - n; j >= 0; j--)
  {
    qhat = (un[j + n] * b + un[j + n - 1]) / vn[n - 1];
    rhat = (un[j + n] * b + un[j + n - 1]) - qhat * vn[n - 1];
    while(qhat >= b || qhat * vn[n - 2] > b * rhat + un[j + n - 2])
    {
      qhat = qhat - 1;
      rhat = rhat + vn[n - 1];
      if(rhat < b)
      {
        continue;
      }
      break;
    }

    k = 0;
    for(i = 0; i < n; i++)
    {
      p         = qhat * vn[i];
      t         = un[i + j] - k - (p & FLEA_HLF_UWORD_MAX);
      un[i + j] = t;
      k         = (p >> (FLEA_WORD_BIT_SIZE / 2)) - (t >> (FLEA_WORD_BIT_SIZE / 2));
    }
    t         = un[j + n] - k;
    un[j + n] = t;

    if(q != NULL)
    {
      FLEA_SET_HLF_UWORD(q, j, qhat);
    }
    if(t < 0)
    {
      if(q != NULL)
      {
        flea_hlf_uword_t q_j = FLEA_GET_HLF_UWORD(q, j) - 1;
        FLEA_SET_HLF_UWORD(q, j, q_j);
      }
      k = 0;
      for(i = 0; i < n; i++)
      {
        t         = un[i + j] + vn[i] + k;
        un[i + j] = t;
        k         = t >> (FLEA_WORD_BIT_SIZE / 2);
      }
      un[j + n] = un[j + n] + k;
    }
  } // end j-loop
  if(p_remainder != NULL)
  {
    for(i = 0; i < n; i++)
    {
      flea_hlf_uword_t r_i = (un[i] >> s) | un[i + 1] << ((FLEA_WORD_BIT_SIZE / 2) - s);
      FLEA_SET_HLF_UWORD(p_remainder->m_words, i, r_i);
      flea_mpi_t__set_used_words(p_remainder);
    }
  }
  if(p_quotient != NULL)
  {
    flea_mpi_t__set_used_words(p_quotient);
  }

  p_remainder->m_sign = result_sign;
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_mpi_t__divide */

flea_err_e THR_flea_mpi_t__mod_exp_simple(
  flea_mpi_t*         p_result,
  flea_mpi_t*         p_exp,
  flea_mpi_t*         p_base,
  flea_mpi_t*         p_mod,
  flea_mpi_t*         p_workspace_double_plus_one_sized,
  flea_mpi_div_ctx_t* p_div_ctx
)
{
  flea_u16_t exp_bit_size;
  flea_s32_t i;


  FLEA_THR_BEG_FUNC();

  unsigned window_size = 1;

  flea_mpi_t__set_to_word_value(p_result, 1);
  exp_bit_size = flea_mpi_t__get_bit_size(p_exp);

  i = exp_bit_size - 1;

  while(i >= 0)
  {
    flea_al_u8_t exp_bit = 0;

    exp_bit = flea_mpi_t__get_bit(p_exp, i);

    FLEA_CCALL(THR_flea_mpi_t__mul(p_workspace_double_plus_one_sized, p_result, p_result));
    FLEA_CCALL(THR_flea_mpi_t__divide(NULL, p_result, p_workspace_double_plus_one_sized, p_mod, p_div_ctx));

    if(exp_bit)
    {
      FLEA_CCALL(THR_flea_mpi_t__mul(p_workspace_double_plus_one_sized, p_result, p_base));
      FLEA_CCALL(THR_flea_mpi_t__divide(NULL, p_result, p_workspace_double_plus_one_sized, p_mod, p_div_ctx));
    }

    i -= window_size;
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_mpi_t__mod_exp_window */
