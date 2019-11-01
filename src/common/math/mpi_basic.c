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

#include "internal/common/math/mpi_basic.h"
#include "flea/error_handling.h"
#include "flea/array_util.h"

static flea_u8_t flea_mpi_t__get_byte(
  const flea_mpi_t* p_mpi,
  flea_mpi_ulen_t   byte_pos
)
{
  flea_mpi_ulen_t word_pos = byte_pos / sizeof(p_mpi->m_words[0]);

  if(byte_pos > flea_mpi_t__get_byte_size(p_mpi))
  {
    return 0x00;
  }
  byte_pos %= sizeof(p_mpi->m_words[0]);
  return (p_mpi->m_words[word_pos] >> (byte_pos * 8)) & 0xFF;
}

flea_al_u8_t flea__nlz_uword(flea_uword_t x)
{
  flea_al_u8_t n = sizeof(flea_uword_t) * 8; // i.e. 32 for 32-bit
  flea_al_u8_t c = sizeof(flea_uword_t) * 4; // i.e. 16 for 32-bit

  do
  {
    flea_uword_t y;
    y = x >> c;
    if(y != 0)
    {
      n = n - c;
      x = y;
    }
    c = c >> 1;
  } while(c != 0);
  return n - x;
}

flea_err_e THR_flea_mpi_t__decode(
  flea_mpi_t*      p_result,
  const flea_u8_t* encoded,
  flea_mpi_ulen_t  encoded_len
)
{
  flea_mpi_slen_t i;
  unsigned int inv_i;

  FLEA_THR_BEG_FUNC();
  // strip leading zero bytes in encoded:
  while((encoded_len > 1) && (*encoded == 0))
  {
    encoded++;
    encoded_len--;
  }
  flea_mpi_ulen_t new_word_len = (encoded_len + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t);
  if(p_result->m_nb_alloc_words < new_word_len)
  {
    FLEA_THROW("result size insufficient", FLEA_ERR_BUFF_TOO_SMALL);
  }
  p_result->m_nb_used_words = new_word_len;
  memset(p_result->m_words, 0, p_result->m_nb_used_words * sizeof(p_result->m_words[0]));

  inv_i = 0;
  for(i = encoded_len - 1; i >= 0; i--)
  {
    p_result->m_words[inv_i / sizeof(flea_uword_t)] |= encoded[i] << ((inv_i % sizeof(flea_uword_t)) * 8);
    inv_i++;
  }
  p_result->m_sign = +1;
  FLEA_THR_FIN_SEC();
}

flea_err_e THR_flea_mpi_t__encode(
  flea_u8_t*        p_result,
  flea_al_u16_t     result_len,
  const flea_mpi_t* p_mpi
)
{
  FLEA_THR_BEG_FUNC();
  flea_al_u16_t nb_bytes, offset;
  flea_mpi_slen_t i;
  nb_bytes = flea_mpi_t__get_byte_size(p_mpi);
  if(nb_bytes > result_len)
  {
    FLEA_THROW("not enough bytes in result array to encode integer", FLEA_ERR_BUFF_TOO_SMALL);
  }
  offset = result_len - nb_bytes;
  memset(p_result, 0, offset);
  for(i = nb_bytes - 1; i >= 0; i--)
  {
    flea_mpi_ulen_t out_pos = offset + (nb_bytes - i - 1);
    p_result[out_pos] = flea_mpi_t__get_byte(p_mpi, i);
  }
  FLEA_THR_FIN_SEC();
}

void flea_mpi_t__init(
  flea_mpi_t*     p_result,
  flea_uword_t*   word_array,
  flea_mpi_ulen_t nb_words
)
{
  p_result->m_words          = word_array;
  p_result->m_nb_used_words  = 0;
  p_result->m_nb_alloc_words = nb_words;
  p_result->m_sign = 1;
  memset(word_array, 0, sizeof(word_array[0]) * nb_words);
}

flea_al_s8_t flea_mpi_t__compare(
  const flea_mpi_t* p_a,
  const flea_mpi_t* p_b
)
{
  if(flea_mpi_t__is_zero(p_a) && flea_mpi_t__is_zero(p_b))
  {
    return 0;
  }
  if(p_a->m_sign > p_b->m_sign)
  {
    return 1;
  }
  if(p_a->m_sign < p_b->m_sign)
  {
    return -1;
  }
  // both signs are equal
  return p_a->m_sign * flea_mpi_t__compare_absolute(p_a, p_b);
}

flea_al_s8_t flea_mpi_t__compare_absolute(
  const flea_mpi_t* p_a,
  const flea_mpi_t* p_b
)
{
  flea_mpi_slen_t i;

  if(p_a->m_nb_used_words > p_b->m_nb_used_words)
  {
    return 1;
  }
  else if(p_a->m_nb_used_words < p_b->m_nb_used_words)
  {
    return -1;
  }

  for(i = p_a->m_nb_used_words - 1; i >= 0; i--)
  {
    if(p_a->m_words[i] > p_b->m_words[i])
    {
      return 1;
    }
    else if(p_a->m_words[i] < p_b->m_words[i])
    {
      return -1;
    }
  }
  return 0;
}

flea_bool_t flea_mpi_t__equal(
  const flea_mpi_t* p_a,
  const flea_mpi_t* p_b
)
{
  if(p_a->m_sign != p_b->m_sign)
  {
    if(flea_mpi_t__is_zero(p_a) && flea_mpi_t__is_zero(p_b))
    {
      return FLEA_TRUE;
    }
    return FLEA_FALSE;
  }
  if(p_a->m_nb_used_words != p_b->m_nb_used_words)
  {
    return FLEA_FALSE;
  }
  if(memcmp(p_a->m_words, p_b->m_words, p_a->m_nb_used_words * sizeof(p_a->m_words[0])))
  {
    return FLEA_FALSE;
  }
  return FLEA_TRUE;
}

flea_al_s8_t flea_mpi_t__compare_with_uword(
  const flea_mpi_t* p_mpi,
  flea_uword_t      w
)
{
  if(p_mpi->m_sign < 0)
  {
    return -1;
  }
  if(p_mpi->m_nb_used_words > 1)
  {
    return 1;
  }
  if(p_mpi->m_words[0] > w)
  {
    return 1;
  }
  if(p_mpi->m_words[0] < w)
  {
    return -1;
  }
  return 0;
}

flea_u8_t flea_mpi_t__get_bit(
  const flea_mpi_t* p_mpi,
  flea_u16_t        bit_pos
)
{
  flea_uword_t result;

  if(bit_pos > 8 * sizeof(flea_uword_t) * p_mpi->m_nb_used_words)
  {
    return 0;
  }

  result = p_mpi->m_words[bit_pos >> FLEA_LOG2_WORD_BIT_SIZE] & (1 << (bit_pos % (sizeof(flea_uword_t) * 8)));
  if(result != 0)
  {
    result = 1;
  }
  return (flea_u8_t) result;
}

flea_u16_t flea_mpi_t__get_bit_size(const flea_mpi_t* p_mpi)
{
  // take the highest word and count the unused bits
  flea_al_u16_t i;
  flea_uword_t word;

  if(p_mpi->m_nb_used_words == 0)
  {
    return 0;
  }
  word = p_mpi->m_words[p_mpi->m_nb_used_words - 1];
  i    = flea__nlz_uword(word);
  i    = FLEA_WORD_BIT_SIZE - i;
  return i + (p_mpi->m_nb_used_words - 1) * sizeof(p_mpi->m_words[0]) * 8;
}

flea_u16_t flea_mpi_t__get_byte_size(const flea_mpi_t* p_mpi)
{
  return FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(flea_mpi_t__get_bit_size(p_mpi));
}

void flea_mpi_t__set_to_word_value(
  flea_mpi_t*  p_result,
  flea_uword_t w
)
{
  p_result->m_nb_used_words = 1;
  p_result->m_words[0]      = w;
}

flea_err_e THR_flea_mpi_t__copy_no_realloc(
  flea_mpi_t*       p_target,
  const flea_mpi_t* p_source
)
{
  FLEA_THR_BEG_FUNC();
  if(p_target == p_source)
  {
    FLEA_THR_RETURN();
  }
  if(p_target->m_nb_alloc_words < p_source->m_nb_used_words)
  {
    FLEA_THROW("mpi_t__copy_no_realloc: not enough space in destination", FLEA_ERR_INV_ARG);
  }
  FLEA_CP_ARR(p_target->m_words, p_source->m_words, p_source->m_nb_used_words);
  p_target->m_nb_used_words = p_source->m_nb_used_words;
  p_target->m_sign = p_source->m_sign;

  FLEA_THR_FIN_SEC();
}

#ifdef FLEA_DO_PRINTF_ERRS
void flea_mpi_t__print(const flea_mpi_t* p_mpi)
{
  flea_s16_t i;

  if(p_mpi->m_sign < 0)
  {
    FLEA_PRINTF_1_SWITCHED("-");
  }
  else
  {
    FLEA_PRINTF_1_SWITCHED("+");
  }
  for(i = p_mpi->m_nb_used_words - 1; i >= 0; i--)
  {
# if FLEA_WORD_BIT_SIZE == 32
    FLEA_PRINTF_2_SWITCHED("%08X", p_mpi->m_words[i]);
# elif FLEA_WORD_BIT_SIZE == 16
    FLEA_PRINTF_2_SWITCHED("%04X", p_mpi->m_words[i]);
# elif FLEA_WORD_BIT_SIZE == 8
    FLEA_PRINTF_2_SWITCHED("%02X", p_mpi->m_words[i]);
# endif /* if FLEA_WORD_BIT_SIZE == 32 */
  }
  FLEA_PRINTF_2_SWITCHED(" (%u words)", p_mpi->m_nb_used_words);
  FLEA_PRINTF_1_SWITCHED("\n");
}

#endif /* ifdef FLEA_DO_PRINTF_ERRS */

void flea_mpi_t__set_used_words(flea_mpi_t* p_mpi)
{
  flea_mpi_slen_t i = p_mpi->m_nb_alloc_words - 1;

  while(i > 0 && p_mpi->m_words[i] == 0)
  {
    i--;
  }
  // i points to the first significant word
  p_mpi->m_nb_used_words = i + 1;
}

flea_bool_t flea_mpi_t__is_zero(const flea_mpi_t* p_mpi)
{
  flea_mpi_ulen_t i = p_mpi->m_nb_used_words;

  while(i > 0)
  {
    if(p_mpi->m_words[--i] != 0)
    {
      return FLEA_FALSE;
    }
  }
  return FLEA_TRUE;
}
