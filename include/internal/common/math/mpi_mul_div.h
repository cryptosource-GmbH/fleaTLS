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

#ifndef _flea_mpi_mul_div__H_
# define _flea_mpi_mul_div__H_

# include "internal/common/math/mpi_basic.h"

# ifdef __cplusplus
extern "C" {
# endif

# define FLEA_MPI_DIV_UN_HLFW_LEN_FROM_DIVIDENT_W_LEN(__divident_word_len) \
  ((2 * (__divident_word_len) + 1))

# define FLEA_MPI_DIV_VN_HLFW_LEN_FROM_DIVISOR_W_LEN(__divisor_word_len) \
  (2 * (__divisor_word_len))

typedef struct
{
  flea_hlf_uword_t* vn;
  flea_mpi_ulen_t   vn_len;
  flea_hlf_uword_t* un;
  flea_mpi_ulen_t   un_len;
} flea_mpi_div_ctx_t;


flea_err_e THR_flea_mpi_t__divide(
  flea_mpi_t*         p_quotient,
  flea_mpi_t*         p_remainder,
  const flea_mpi_t*   p_divident,
  const flea_mpi_t*   p_divisor,
  flea_mpi_div_ctx_t* p_div_ctx
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_mpi_t__mul(
  flea_mpi_t*       p_result,
  const flea_mpi_t* p_a,
  const flea_mpi_t* p_b
) FLEA_ATTRIB_UNUSED_RESULT;


flea_err_e THR_flea_mpi_t__mod_exp_simple(
  flea_mpi_t*         p_result,
  flea_mpi_t*         p_exp,
  flea_mpi_t*         p_base,
  flea_mpi_t*         p_mod,
  flea_mpi_t*         p_workspace_double_plus_one_sized,
  flea_mpi_div_ctx_t* p_div_ctx
) FLEA_ATTRIB_UNUSED_RESULT;

# ifdef __cplusplus
}
# endif
#endif /* h-guard */
