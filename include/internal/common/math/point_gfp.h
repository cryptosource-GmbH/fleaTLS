/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_point_gfp__H_
#define _flea_point_gfp__H_

#include "internal/common/math/curve_gfp.h"

#ifdef FLEA_HAVE_ECC
typedef struct
{
  flea_mpi_t m_x;
  flea_mpi_t m_y;
  flea_mpi_t m_z;
} flea_point_jac_proj_t;

typedef struct
{
  flea_mpi_t m_x;
  flea_mpi_t m_y;

} flea_point_gfp_t;

flea_err_t THR_flea_point_gfp_t__init(flea_point_gfp_t* p_result, const flea_u8_t* x_enc, flea_al_u16_t x_enc_len, const flea_u8_t* y_enc, flea_al_u16_t y_enc_len, flea_uword_t* memory, flea_al_u16_t memory_word_len);

flea_err_t THR_flea_point_gfp_t__init_copy(flea_point_gfp_t* result__pt, const flea_point_gfp_t* other__pct, flea_uword_t* memory, flea_al_u16_t memory_word_len);

flea_err_t THR_flea_point_gfp_t__init_decode(flea_point_gfp_t* p_result, const flea_u8_t* enc_point__pc_u8, flea_al_u16_t enc_point_len__al_u8, flea_uword_t* memory, flea_al_u16_t memory_word_len);

flea_err_t THR_flea_point_gfp_t__validate_point(const flea_point_gfp_t*point__pt, const flea_curve_gfp_t* curve__pct, const flea_mpi_t* cofactor__pt, flea_mpi_div_ctx_t * div_ctx__pt);

flea_err_t THR_flea_point_jac_proj_t__init(flea_point_jac_proj_t * p_result, const flea_point_gfp_t* p_affine_point, const flea_mpi_t* p_montg_const_sq_mod_p, flea_mpi_t* p_mod_sized_ws, flea_montgm_mul_ctx_t* p_mm_ctx, flea_uword_t* memory, flea_al_u16_t memory_word_len, flea_mpi_t* p_mm_mul_result_ws );

flea_err_t THR_flea_point_jac_proj_t__init_copy(flea_point_jac_proj_t * p_result, const flea_point_jac_proj_t* p_other_point,  flea_uword_t* memory, flea_al_u16_t memory_word_len );

flea_err_t THR_flea_point_gfp_t__encode(flea_u8_t* p_u8__result, flea_al_u8_t* p_al_u8__result_len, flea_point_gfp_t* p_t_point, const flea_curve_gfp_t* p_t_curve );

flea_err_t THR_flea_point_jac_proj_t__set_to_zero(flea_point_jac_proj_t * p_result, const flea_mpi_t* p_montg_const_sq_mod_p, flea_montgm_mul_ctx_t* p_mm_ctx, flea_mpi_t* p_double_sized_ws);

flea_err_t THR_flea_point_jac_proj_t__double(flea_point_jac_proj_t * p_point, const flea_mpi_t * p_aR, const flea_mpi_t * p_bR, flea_montgm_mul_ctx_t * p_mm_ctx, flea_mpi_t p_workspace_arr[9], const flea_mpi_t * p_montg_const_sq_mod_p);

flea_err_t THR_flea_point_jac_proj_t__add(flea_point_jac_proj_t * p_point_1, const flea_point_jac_proj_t * p_point_2, const flea_mpi_t * p_aR, const flea_mpi_t * p_bR, flea_montgm_mul_ctx_t * p_mm_ctx, flea_mpi_t p_workspace_arr[9], const flea_mpi_t * p_montg_const_sq_mod_p);

/**
 * does not handle negative scalars (ignores the sign)
 */
flea_err_t THR_flea_point_gfp_t__mul(flea_point_gfp_t* p_point_in_out, const flea_mpi_t* p_scalar, const flea_curve_gfp_t* p_curve, flea_bool_t use_add_always__b);

/**
 * does not handle negative scalars (ignores the sign)
 */
flea_err_t THR_flea_point_gfp_t__mul_multi(flea_point_gfp_t* p_point_in_out, const flea_mpi_t* p_scalar, const flea_point_gfp_t* p_point_2, const flea_mpi_t* p_scalar_2, const flea_curve_gfp_t* p_curve, flea_bool_t use_add_always__b);

flea_err_t THR_flea_point_gfp_t__add(flea_point_gfp_t* p_point_1, const flea_point_gfp_t* p_point_2, const flea_curve_gfp_t* p_curve);

flea_err_t THR_flea_point_jac_proj_t__get_affine_x(flea_mpi_t * p_result, const flea_point_jac_proj_t * p_point, flea_montgm_mul_ctx_t * p_mm_ctx, flea_mpi_t inv_ws[4], flea_mpi_t * p_montg_const_sq_mod_p);

flea_err_t THR_flea_point_jac_proj_t__get_affine_y(flea_mpi_t * p_result, const flea_point_jac_proj_t * p_point, flea_montgm_mul_ctx_t * p_mm_ctx, flea_mpi_t inv_ws[4], flea_mpi_t * p_montg_const_sq_mod_p);

#endif /* #ifdef FLEA_HAVE_ECC */
#endif /* h-guard */
