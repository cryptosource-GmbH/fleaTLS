/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_mpi_basic__H_
# define _flea_mpi_basic__H_

# include "flea/types.h"

# ifdef __cplusplus
extern "C" {
# endif

typedef struct
{
  flea_uword_t*   m_words;
  flea_mpi_ulen_t m_nb_alloc_words;
  flea_mpi_ulen_t m_nb_used_words;
  flea_s8_t       m_sign;
} flea_mpi_t;

void flea_mpi_t__init(
  flea_mpi_t*     p_result,
  flea_uword_t*   word_array,
  flea_mpi_ulen_t nb_words
);

void flea_mpi_t__set_to_word_value(
  flea_mpi_t*  p_result,
  flea_uword_t w
);


flea_err_e THR_flea_mpi_t__decode(
  flea_mpi_t*      p_result,
  const flea_u8_t* encoded,
  flea_mpi_ulen_t  encoded_len
);

flea_err_e THR_flea_mpi_t__encode(
  flea_u8_t*        p_result,
  flea_al_u16_t     result_len,
  const flea_mpi_t* p_mpi
);

flea_al_s8_t flea_mpi_t__compare_absolute(
  const flea_mpi_t* p_a,
  const flea_mpi_t* p_b
);

flea_al_s8_t flea_mpi_t__compare(
  const flea_mpi_t* p_a,
  const flea_mpi_t* p_b
);

flea_al_s8_t flea_mpi_t__compare_with_uword(
  const flea_mpi_t* p_mpi,
  flea_uword_t      w
);

flea_bool_t flea_mpi_t__equal(
  const flea_mpi_t* p_a,
  const flea_mpi_t* p_b
);

flea_u16_t flea_mpi_t__get_bit_size(const flea_mpi_t* p_mpi);

flea_u16_t flea_mpi_t__get_byte_size(const flea_mpi_t* p_mpi);


flea_u8_t flea_mpi_t__get_bit(
  const flea_mpi_t* p_mpi,
  flea_u16_t        bit_pos
);

flea_err_e THR_flea_mpi_t__copy_no_realloc(
  flea_mpi_t*       p_target,
  const flea_mpi_t* p_source
);

flea_bool_t flea_mpi_t__is_zero(const flea_mpi_t* p_mpi);

flea_al_u8_t flea__nlz_uword(flea_uword_t x);

void flea_mpi_t__set_used_words(flea_mpi_t* p_mpi);

# ifdef FLEA_DO_DBG_PRINT
void flea_mpi_t__print(const flea_mpi_t* p_mpi);
# endif
# ifdef __cplusplus
}
# endif
#endif /* h-guard */
