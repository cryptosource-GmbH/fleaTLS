/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_curve_gfp__H_
#define _flea_curve_gfp__H_

#include "internal/common/math/mpi.h"
#include "flea/ec_gfp_dom_par.h"


#ifdef FLEA_HAVE_ECC
typedef struct
{
  flea_mpi_t m_a;
  flea_mpi_t m_b;
  flea_mpi_t m_p;

} flea_curve_gfp_t;

flea_err_t THR_flea_curve_gfp_t__init(flea_curve_gfp_t* p_curve, const flea_u8_t* a_enc, flea_al_u16_t a_enc_len, const flea_u8_t* b_enc, flea_al_u16_t b_enc_len, const flea_u8_t* p_enc, flea_al_u16_t p_enc_len, flea_uword_t* memory, flea_al_u16_t memory_word_len);

flea_err_t THR_flea_curve_gfp_t__init_dp_array (flea_curve_gfp_t* p_curve, const flea_ec_gfp_dom_par_ref_t *dp__pt, flea_uword_t* memory, flea_al_u16_t memory_word_len);

#endif /* #ifdef FLEA_HAVE_ECC */
#endif /* h-guard */
