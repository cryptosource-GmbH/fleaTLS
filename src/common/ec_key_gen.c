/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/ec_key_gen.h"
#include "flea/error_handling.h"
#include <stdlib.h>
#include <string.h>
#include "internal/common/math/mpi.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/util.h"
#include "internal/common/math/curve_gfp.h"
#include "flea/ec_gfp_dom_par.h"
#include "flea/ecdsa.h"
#include "internal/common/math/point_gfp.h"
#include "flea/algo_config.h"
#include "internal/common/ecc_int.h"

#ifdef FLEA_HAVE_ECC
flea_err_e THR_flea_generate_ecc_key(
  flea_u8_t*                       result_public__p_u8,
  flea_al_u8_t*                    result_public_len__p_al_u8,
  flea_u8_t*                       result_private__p_u8,
  flea_al_u8_t*                    result_private_len__p_al_u8,
  const flea_ec_gfp_dom_par_ref_t* dom_par__pt
)
{
  flea_curve_gfp_t curve;
  flea_point_gfp_t pub_point;
  flea_mpi_t sk_mpi, n;
  flea_al_u8_t private_byte_len__al_u8, order_byte_len__al_u8;

# ifdef FLEA_USE_ECC_ADD_ALWAYS
  const flea_bool_t do_use_add_always__b = FLEA_TRUE;
# else
  const flea_bool_t do_use_add_always__b = FLEA_FALSE;
# endif

  FLEA_DECL_BUF(pub_point_arr, flea_uword_t, 2 * FLEA_ECC_MAX_MOD_WORD_SIZE + 1);
  FLEA_DECL_BUF(sk_mpi_arr, flea_uword_t, FLEA_ECC_MAX_ORDER_WORD_SIZE);
  FLEA_DECL_BUF(order_word_arr, flea_uword_t, FLEA_ECC_MAX_ORDER_WORD_SIZE);
  FLEA_DECL_BUF(curve_word_arr, flea_uword_t, 3 * FLEA_ECC_MAX_MOD_WORD_SIZE);

  flea_al_u8_t prime_byte_len, prime_word_len__al_u8, curve_word_arr_word_len, pub_point_word_arr_len, order_word_len;

  FLEA_THR_BEG_FUNC();

  prime_byte_len        = dom_par__pt->p__ru8.len__dtl;
  order_byte_len__al_u8 = dom_par__pt->n__ru8.len__dtl;

  prime_word_len__al_u8   = FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(prime_byte_len);
  curve_word_arr_word_len = 3 * prime_word_len__al_u8;
  pub_point_word_arr_len  = 2 * prime_word_len__al_u8;
  order_word_len = FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(order_byte_len__al_u8);

  FLEA_ALLOC_BUF(pub_point_arr, pub_point_word_arr_len);
  FLEA_ALLOC_BUF(sk_mpi_arr, order_word_len);
  FLEA_ALLOC_BUF(curve_word_arr, curve_word_arr_word_len);
  FLEA_ALLOC_BUF(order_word_arr, order_word_len);


  flea_mpi_t__init(&sk_mpi, sk_mpi_arr, order_word_len);
  flea_mpi_t__init(&n, order_word_arr, order_word_len);

  FLEA_CCALL(THR_flea_mpi_t__decode(&n, dom_par__pt->n__ru8.data__pcu8, dom_par__pt->n__ru8.len__dtl));

  FLEA_CCALL(THR_flea_mpi_t__random_integer(&sk_mpi, &n));
  FLEA_CCALL(
    THR_flea_point_gfp_t__init(
      &pub_point,
      dom_par__pt->gx__ru8.data__pcu8,
      dom_par__pt->gx__ru8.len__dtl,
      dom_par__pt->gy__ru8.data__pcu8,
      dom_par__pt->gy__ru8.len__dtl,
      pub_point_arr,
      pub_point_word_arr_len
    )
  );

  FLEA_CCALL(THR_flea_curve_gfp_t__init_dp_array(&curve, dom_par__pt, curve_word_arr, curve_word_arr_word_len));

# ifdef FLEA_USE_PUBKEY_INPUT_BASED_DELAY
  FLEA_CCALL(THR_flea_point_gfp_t__mul(&pub_point, &sk_mpi, &curve, do_use_add_always__b, NULL));
# else
  FLEA_CCALL(THR_flea_point_gfp_t__mul(&pub_point, &sk_mpi, &curve, do_use_add_always__b));
# endif
  FLEA_CCALL(THR_flea_point_gfp_t__encode(result_public__p_u8, result_public_len__p_al_u8, &pub_point, &curve));
  private_byte_len__al_u8 = flea_mpi_t__get_byte_size(&sk_mpi);
  FLEA_CCALL(THR_flea_mpi_t__encode(result_private__p_u8, private_byte_len__al_u8, &sk_mpi));
  *result_private_len__p_al_u8 = private_byte_len__al_u8;
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF(pub_point_arr);
    FLEA_FREE_BUF(sk_mpi_arr);
    FLEA_FREE_BUF(order_word_arr);
    FLEA_FREE_BUF(curve_word_arr);
  );
} /* THR_flea_generate_ecc_key */

#endif // #ifdef FLEA_HAVE_ECC
