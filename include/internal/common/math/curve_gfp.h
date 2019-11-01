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

#ifndef _flea_curve_gfp__H_
#define _flea_curve_gfp__H_

#include "internal/common/math/mpi.h"
#include "flea/ec_dom_par.h"


#ifdef FLEA_HAVE_ECC

typedef struct
{
  flea_mpi_t m_a;
  flea_mpi_t m_b;
  flea_mpi_t m_p;
} flea_curve_gfp_t;

flea_err_e THR_flea_curve_gfp_t__init(
  flea_curve_gfp_t* p_curve,
  const flea_u8_t*  a_enc,
  flea_al_u16_t     a_enc_len,
  const flea_u8_t*  b_enc,
  flea_al_u16_t     b_enc_len,
  const flea_u8_t*  p_enc,
  flea_al_u16_t     p_enc_len,
  flea_uword_t*     memory,
  flea_al_u16_t     memory_word_len
);

flea_err_e THR_flea_curve_gfp_t__init_dp_array(
  flea_curve_gfp_t*            p_curve,
  const flea_ec_dom_par_ref_t* dp__pt,
  flea_uword_t*                memory,
  flea_al_u16_t                memory_word_len
);

#endif /* #ifdef FLEA_HAVE_ECC */
#endif /* h-guard */
