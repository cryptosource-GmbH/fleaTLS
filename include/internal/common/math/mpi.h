/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_mpi__H_
#define _flea_mpi__H_

#include "flea/types.h"
#include "flea/ctr_mode_prng.h"
#include "internal/common/math/mpi_basic.h"
#include "internal/common/math/mpi_mul_div.h"

typedef struct
{
  const flea_mpi_t* p_mod;

  /**
   * workspace, must have one more word allocated than mod
   */
  flea_mpi_t*  p_ws;
  flea_uword_t mod_prime;
} flea_montgm_mul_ctx_t;


flea_uword_t flea_montgomery_compute_n_prime(flea_uword_t lowest_word_of_n);


flea_err_e THR_flea_mpi_t__montgm_mul(
  flea_mpi_t*            p_result,
  const flea_mpi_t*      p_a,
  const flea_mpi_t*      p_b,
  flea_montgm_mul_ctx_t* p_ctx
) FLEA_ATTRIB_UNUSED_RESULT;

/*
 * p_result must be different from p_a and p_b
 */
flea_err_e THR_flea_mpi_t__subtract(
  flea_mpi_t*       p_result,
  const flea_mpi_t* p_a,
  const flea_mpi_t* p_b
) FLEA_ATTRIB_UNUSED_RESULT;

/**
 *  both a and b must be between 0 and p-1
 * p_result is allowed to be equal to  p_a or p_b
 */
flea_err_e THR_flea_mpi_t__subtract_mod(
  flea_mpi_t*       p_result,
  const flea_mpi_t* p_a,
  const flea_mpi_t* p_b,
  const flea_mpi_t* p_mod,
  flea_mpi_t*       p_workspace_mod_size
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_mpi_t__add_in_place_ignore_sign(
  flea_mpi_t*       p_in_out,
  const flea_mpi_t* p_b
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_mpi_t__add_ignore_sign(
  flea_mpi_t*       p_result,
  const flea_mpi_t* p_a,
  const flea_mpi_t* p_b
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_mpi_t__add_in_place(
  flea_mpi_t*       p_in_out,
  const flea_mpi_t* p_b,
  flea_mpi_t*       p_ws
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_mpi_square(
  flea_mpi_t*       p_result,
  const flea_mpi_t* p_a
) FLEA_ATTRIB_UNUSED_RESULT;


flea_al_u8_t flea_mpi_t__get_window(
  const flea_mpi_t* p_mpi,
  flea_mpi_ulen_t   low_bit_pos,
  flea_al_u8_t      window_size
);


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
  flea_ctr_mode_prng_t* delay_prng__pt
#endif
) FLEA_ATTRIB_UNUSED_RESULT;


flea_mpi_ulen_t flea_mpi_t__nb_trailing_zero_bits(flea_mpi_t* p_mpi);

void flea_mpi_t__shift_right(
  flea_mpi_t*   p_mpi,
  flea_al_u16_t shift
);

flea_err_e THR_flea_mpi_t__set_pow_2(
  flea_mpi_t*   p_result,
  flea_al_u16_t exp
) FLEA_ATTRIB_UNUSED_RESULT;


flea_err_e THR_flea_mpi_t__shift_left_small(
  flea_mpi_t*   p_mpi,
  flea_al_u16_t shift
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_mpi_t__invert_odd_mod(
  flea_mpi_t*       p_result,
  const flea_mpi_t* p_mpi,
  const flea_mpi_t* p_mod,
  flea_mpi_t        ws_mod_size[4]
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_mpi_t__random_integer(
  flea_mpi_t*       p_result,
  const flea_mpi_t* p_limit
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_mpi_t__random_integer_no_flush(
  flea_mpi_t*       p_result,
  const flea_mpi_t* p_limit
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_mpi_t__quick_reduce_greater_zero(
  flea_mpi_t*       p_in_out,
  const flea_mpi_t* p_mod,
  flea_mpi_t*       p_ws
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_mpi_t__quick_reduce_smaller_zero(
  flea_mpi_t*       p_in_out,
  const flea_mpi_t* p_mod,
  flea_mpi_t*       p_ws
) FLEA_ATTRIB_UNUSED_RESULT;


#endif /* h-guard */
