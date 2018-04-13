/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "internal/common/math/mpi_mul_div.h"
#include "flea/util.h"
#include "flea/error_handling.h"
#include "flea/rsa.h"
// #include "internal/common/pk_key_int.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/rsa_pub_op.h"
#include "internal/common/rsa_int.h"

#ifdef FLEA_HAVE_RSA
flea_err_e THR_flea_rsa_raw_operation(
  flea_u8_t*       result_enc,
  const flea_u8_t* exponent_enc,
  flea_al_u16_t    exponent_length,
  const flea_u8_t* base_enc,
  flea_al_u16_t    base_length,
  const flea_u8_t* modulus_enc,
  flea_al_u16_t    modulus_length
)
{
  FLEA_DECL_BUF(result_arr, flea_uword_t, FLEA_RSA_SF_MAX_MOD_WORD_LEN + 1);
  FLEA_DECL_BUF(base_arr, flea_uword_t, FLEA_RSA_SF_MAX_MOD_WORD_LEN);
  FLEA_DECL_BUF(exponent_arr, flea_uword_t, FLEA_RSA_SF_MAX_MOD_WORD_LEN);
  FLEA_DECL_BUF(mod_arr, flea_uword_t, FLEA_RSA_SF_MAX_MOD_WORD_LEN);
  FLEA_DECL_BUF(large_tmp_arr, flea_uword_t, FLEA_RSA_SF_MAX_MOD_WORD_LEN * 2 + 1);
  FLEA_DECL_BUF(ws_q_arr, flea_uword_t, FLEA_RSA_SF_MAX_MOD_WORD_LEN + 1);


  flea_mpi_ulen_t mod_word_len, result_word_len, large_tmp_word_len, ws_q_word_len;
# ifdef FLEA_HEAP_MODE
  flea_mpi_ulen_t vn_len, un_len;
# endif

  FLEA_DECL_BUF(vn, flea_hlf_uword_t, FLEA_MPI_DIV_VN_HLFW_LEN_FOR_RSA_SF_REDUCTIONS);
  FLEA_DECL_BUF(un, flea_hlf_uword_t, FLEA_MPI_DIV_UN_HLFW_LEN_FOR_RSA_SF_REDUCTIONS);
  flea_mpi_t result, exponent, base, mod, large_tmp, ws_q;
  flea_mpi_div_ctx_t div_ctx;
  FLEA_THR_BEG_FUNC();
# ifdef FLEA_STACK_MODE
  if(modulus_length > FLEA_RSA_MAX_KEY_BIT_SIZE / 8)
  {
    FLEA_THROW("modulus length too large", FLEA_ERR_INV_KEY_SIZE);
  }
# endif /* ifdef FLEA_STACK_MODE */
  mod_word_len = FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(modulus_length);

  result_word_len    = mod_word_len + 1;
  large_tmp_word_len = (mod_word_len) * 2 + 1;
  ws_q_word_len      = mod_word_len + 1;
# ifdef FLEA_HEAP_MODE
  vn_len = FLEA_MPI_DIV_VN_HLFW_LEN_FROM_DIVISOR_W_LEN(mod_word_len);
  un_len = FLEA_MPI_DIV_UN_HLFW_LEN_FROM_DIVIDENT_W_LEN(2 * mod_word_len);
# endif

  FLEA_ALLOC_BUF(result_arr, result_word_len);
  FLEA_ALLOC_BUF(base_arr, mod_word_len);
  FLEA_ALLOC_BUF(exponent_arr, mod_word_len);
  FLEA_ALLOC_BUF(mod_arr, mod_word_len);
  FLEA_ALLOC_BUF(large_tmp_arr, large_tmp_word_len);
  FLEA_ALLOC_BUF(ws_q_arr, ws_q_word_len);

  FLEA_ALLOC_BUF(vn, vn_len);
  FLEA_ALLOC_BUF(un, un_len);

  div_ctx.vn     = vn;
  div_ctx.un     = un;
  div_ctx.vn_len = FLEA_HEAP_OR_STACK_CODE(vn_len, FLEA_STACK_BUF_NB_ENTRIES(vn));
  div_ctx.un_len = FLEA_HEAP_OR_STACK_CODE(un_len, FLEA_STACK_BUF_NB_ENTRIES(un));


  flea_mpi_t__init(&result, result_arr, result_word_len);
  flea_mpi_t__init(&base, base_arr, mod_word_len);
  flea_mpi_t__init(&exponent, exponent_arr, mod_word_len);
  flea_mpi_t__init(&mod, mod_arr, mod_word_len);
  flea_mpi_t__init(&large_tmp, large_tmp_arr, large_tmp_word_len);
  flea_mpi_t__init(&ws_q, ws_q_arr, ws_q_word_len);


  FLEA_CCALL(THR_flea_mpi_t__decode(&mod, modulus_enc, modulus_length));
  FLEA_CCALL(THR_flea_mpi_t__decode(&exponent, exponent_enc, exponent_length));
  FLEA_CCALL(THR_flea_mpi_t__decode(&base, base_enc, base_length));

  FLEA_CCALL(
    THR_flea_mpi_t__mod_exp_simple(
      &result,
      &exponent,
      &base,
      &mod,
      &large_tmp,
      &div_ctx
    )
  );

  FLEA_CCALL(THR_flea_mpi_t__encode(result_enc, modulus_length, &result));

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(result_arr);
    FLEA_FREE_BUF_FINAL(base_arr);
    FLEA_FREE_BUF_FINAL(exponent_arr);
    FLEA_FREE_BUF_FINAL(mod_arr);
    FLEA_FREE_BUF_FINAL(large_tmp_arr);
    FLEA_FREE_BUF_FINAL(ws_q_arr);
    FLEA_FREE_BUF_FINAL(vn);
    FLEA_FREE_BUF_FINAL(un);
  );
} /* THR_flea_rsa_raw_operation */

#endif // #ifdef FLEA_HAVE_RSA
