/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "internal/common/math/mpi.h"
#include "flea/util.h"
#include "flea/error_handling.h"
#include "flea/rsa.h"
#include "internal/common/pk_key_int.h"
#include "flea/alloc.h"
#include "flea/privkey.h"
#include "flea/array_util.h"
#include "internal/common/privkey_int.h"
#include "internal/common/rsa_int.h"


#ifdef FLEA_HAVE_RSA

flea_err_e THR_flea_rsa_raw_operation_crt_private_key(
  const flea_private_key_t* priv_key__pt,
  flea_u8_t*                result_enc,
  const flea_u8_t*          base_enc,
  flea_al_u16_t             base_length
)
{
  FLEA_THR_BEG_FUNC();
  if(priv_key__pt->key_type__t != flea_rsa_key)
  {
    FLEA_THROW("private key is not an RSA key", FLEA_ERR_INV_KEY_TYPE);
  }
  FLEA_CCALL(
    THR_flea_rsa_raw_operation_crt(
      result_enc,
      base_enc,
      base_length,
      (priv_key__pt->key_bit_size__u16 + 7) / 8,
      priv_key__pt->privkey_with_params__u.rsa_priv_key_val__t.pqd1d2c__rcu8[RSA_PRIV_P_IDX].data__pu8,
      priv_key__pt->privkey_with_params__u.rsa_priv_key_val__t.pqd1d2c__rcu8[RSA_PRIV_P_IDX].len__dtl,
      priv_key__pt->privkey_with_params__u.rsa_priv_key_val__t.pqd1d2c__rcu8[RSA_PRIV_Q_IDX].data__pu8,
      priv_key__pt->privkey_with_params__u.rsa_priv_key_val__t.pqd1d2c__rcu8[RSA_PRIV_Q_IDX].len__dtl,
      priv_key__pt->privkey_with_params__u.rsa_priv_key_val__t.pqd1d2c__rcu8[RSA_PRIV_D1_IDX].data__pu8,
      priv_key__pt->privkey_with_params__u.rsa_priv_key_val__t.pqd1d2c__rcu8[RSA_PRIV_D1_IDX].len__dtl,
      priv_key__pt->privkey_with_params__u.rsa_priv_key_val__t.pqd1d2c__rcu8[RSA_PRIV_D2_IDX].data__pu8,
      priv_key__pt->privkey_with_params__u.rsa_priv_key_val__t.pqd1d2c__rcu8[RSA_PRIV_D2_IDX].len__dtl,
      priv_key__pt->privkey_with_params__u.rsa_priv_key_val__t.pqd1d2c__rcu8[RSA_PRIV_C_IDX].data__pu8,
      priv_key__pt->privkey_with_params__u.rsa_priv_key_val__t.pqd1d2c__rcu8[RSA_PRIV_C_IDX].len__dtl
    )
  );
  FLEA_THR_FIN_SEC_empty();
}

// result is of same length as modulus
flea_err_e THR_flea_rsa_raw_operation_crt(
  flea_u8_t*       result_enc,
  const flea_u8_t* base_enc,
  flea_al_u16_t    base_length,
  flea_al_u16_t    modulus_length,
  const flea_u8_t* p_enc,
  flea_mpi_ulen_t  p_enc_len,
  const flea_u8_t* q_enc,
  flea_mpi_ulen_t  q_enc_len,
  const flea_u8_t* d1_enc,
  flea_mpi_ulen_t  d1_enc_len,
  const flea_u8_t* d2_enc,
  flea_mpi_ulen_t  d2_enc_len,
  const flea_u8_t* c_enc,
  flea_mpi_ulen_t  c_enc_len
)
{
  FLEA_DECL_BUF(result_arr, flea_uword_t, FLEA_RSA_SF_MAX_MOD_WORD_LEN + 1);
  FLEA_DECL_BUF(base_arr, flea_uword_t, FLEA_RSA_SF_MAX_MOD_WORD_LEN + (2 * FLEA_RSA_CRT_PQ_MAX_WORDS_HALF_DIFF)); // "+2" due to p-q-diff ( must store product of two "+1" mpis)
  FLEA_DECL_BUF(base_mod_prime_arr, flea_uword_t, (FLEA_RSA_SF_MAX_MOD_WORD_LEN + 1) / 2 + 1);
  FLEA_DECL_BUF(large_tmp_arr, flea_uword_t, (FLEA_RSA_SF_MAX_MOD_WORD_LEN) * 2 + 1);
  FLEA_DECL_BUF(ws_trf_base_arr, flea_uword_t, FLEA_RSA_SF_MAX_MOD_WORD_LEN);

  FLEA_DECL_BUF(p_arr, flea_uword_t, (FLEA_RSA_SF_MAX_MOD_WORD_LEN + 1) / 2 + FLEA_RSA_CRT_PQ_MAX_WORDS_HALF_DIFF);  //  due to p-q-diff
  FLEA_DECL_BUF(q_arr, flea_uword_t, (FLEA_RSA_SF_MAX_MOD_WORD_LEN + 1) / 2 + FLEA_RSA_CRT_PQ_MAX_WORDS_HALF_DIFF);  //  due to p-q-diff
  FLEA_DECL_BUF(d1_arr, flea_uword_t, (FLEA_RSA_SF_MAX_MOD_WORD_LEN + 1) / 2 + FLEA_RSA_CRT_PQ_MAX_WORDS_HALF_DIFF); //  due to p-q-diff
  FLEA_DECL_BUF(d2_arr, flea_uword_t, (FLEA_RSA_SF_MAX_MOD_WORD_LEN + 1) / 2 + FLEA_RSA_CRT_PQ_MAX_WORDS_HALF_DIFF); //  due to p-q-diff
  FLEA_DECL_BUF(j1_arr, flea_uword_t, (FLEA_RSA_SF_MAX_MOD_WORD_LEN + 1) / 2 + FLEA_RSA_CRT_PQ_MAX_WORDS_HALF_DIFF); //  due to p-q-diff

  FLEA_DECL_BUF(vn, flea_hlf_uword_t, FLEA_MPI_DIV_VN_HLFW_LEN_FROM_DIVISOR_W_LEN(FLEA_RSA_CRT_MAX_PRIME_WORD_LEN));
  FLEA_DECL_BUF(
    un,
    flea_hlf_uword_t,
    FLEA_MPI_DIV_UN_HLFW_LEN_FROM_DIVIDENT_W_LEN(2 * FLEA_RSA_CRT_MAX_PRIME_WORD_LEN)
  );

  flea_mpi_t result, base, large_tmp, ws_trf_base, d1, d2, j1, p, q, base_mod_prime;
  flea_mpi_div_ctx_t div_ctx;

# ifdef FLEA_HEAP_MODE
  flea_mpi_ulen_t mod_byte_len, mod_word_len, base_mod_prime_len, large_tmp_len, ws_trf_base_len, half_mod_word_len,
    prime_word_len;
  flea_mpi_ulen_t result_len, base_word_len, vn_len, un_len;
# endif // #ifdef FLEA_HEAP_MODE

# ifdef FLEA_SCCM_USE_RSA_MUL_ALWAYS
  const flea_bool_t do_use_mul_always__b = FLEA_TRUE;
# else
  const flea_bool_t do_use_mul_always__b = FLEA_FALSE;
# endif

# ifdef FLEA_SCCM_USE_PUBKEY_INPUT_BASED_DELAY
  flea_ctr_mode_prng_t delay_prng__t;
# endif

  FLEA_THR_BEG_FUNC();

# ifdef FLEA_SCCM_USE_PUBKEY_INPUT_BASED_DELAY
  flea_ctr_mode_prng_t__INIT(&delay_prng__t);
# endif
# ifdef FLEA_HEAP_MODE
  mod_byte_len       = p_enc_len + q_enc_len;
  mod_word_len       = FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(mod_byte_len);
  base_mod_prime_len = (mod_word_len + 1) / 2 + FLEA_RSA_CRT_PQ_MAX_WORDS_HALF_DIFF; // +1 due to p-q-diff
  large_tmp_len      = (mod_word_len) * 2 + 1;
  ws_trf_base_len    = mod_word_len;
  half_mod_word_len  = (mod_word_len + 1) / 2;
  prime_word_len     = half_mod_word_len + FLEA_RSA_CRT_PQ_MAX_WORDS_HALF_DIFF;
  base_word_len      = mod_word_len + (2 * FLEA_RSA_CRT_PQ_MAX_WORDS_HALF_DIFF); // "+2" due to p-q-diff ( must store product of two "+1" mpis)
  result_len         = mod_word_len + 1;
  vn_len = FLEA_MPI_DIV_VN_HLFW_LEN_FROM_DIVISOR_W_LEN(prime_word_len);
  un_len = FLEA_MPI_DIV_UN_HLFW_LEN_FROM_DIVIDENT_W_LEN(2 * prime_word_len);
# endif // #ifdef FLEA_HEAP_MODE

  FLEA_ALLOC_BUF(result_arr, result_len);

  FLEA_ALLOC_BUF(base_arr, base_word_len);
  FLEA_ALLOC_BUF(base_mod_prime_arr, base_mod_prime_len);
  FLEA_ALLOC_BUF(large_tmp_arr, large_tmp_len);
  FLEA_ALLOC_BUF(ws_trf_base_arr, ws_trf_base_len);
  FLEA_ALLOC_BUF(p_arr, prime_word_len);
  FLEA_ALLOC_BUF(q_arr, prime_word_len);
  FLEA_ALLOC_BUF(d1_arr, prime_word_len);
  FLEA_ALLOC_BUF(d2_arr, prime_word_len);
  FLEA_ALLOC_BUF(j1_arr, prime_word_len);


  FLEA_ALLOC_BUF(vn, vn_len);
  FLEA_ALLOC_BUF(un, un_len);

  div_ctx.vn     = vn;
  div_ctx.un     = un;
  div_ctx.vn_len = FLEA_HEAP_OR_STACK_CODE(vn_len, FLEA_STACK_BUF_NB_ENTRIES(vn));
  div_ctx.un_len = FLEA_HEAP_OR_STACK_CODE(un_len, FLEA_STACK_BUF_NB_ENTRIES(un));

# ifdef FLEA_SCCM_USE_PUBKEY_INPUT_BASED_DELAY
  FLEA_CCALL(THR_flea_ctr_mode_prng_t__ctor(&delay_prng__t, base_enc, base_length));
  FLEA_CCALL(THR_flea_ctr_mode_prng_t__reseed(&delay_prng__t, d1_enc, d1_enc_len));
# endif

  flea_mpi_t__init(&result, result_arr, FLEA_HEAP_OR_STACK_CODE(result_len, FLEA_STACK_BUF_NB_ENTRIES(result_arr)));
  flea_mpi_t__init(&base, base_arr, FLEA_HEAP_OR_STACK_CODE(base_word_len, FLEA_STACK_BUF_NB_ENTRIES(base_arr)));
  flea_mpi_t__init(
    &base_mod_prime,
    base_mod_prime_arr,
    FLEA_HEAP_OR_STACK_CODE(base_mod_prime_len, FLEA_STACK_BUF_NB_ENTRIES(base_mod_prime_arr))
  );
  flea_mpi_t__init(
    &large_tmp,
    large_tmp_arr,
    FLEA_HEAP_OR_STACK_CODE(large_tmp_len, FLEA_STACK_BUF_NB_ENTRIES(large_tmp_arr))
  );
  flea_mpi_t__init(
    &ws_trf_base,
    ws_trf_base_arr,
    FLEA_HEAP_OR_STACK_CODE(ws_trf_base_len, FLEA_STACK_BUF_NB_ENTRIES(ws_trf_base_arr))
  );
  flea_mpi_t__init(&p, p_arr, FLEA_HEAP_OR_STACK_CODE(prime_word_len, FLEA_STACK_BUF_NB_ENTRIES(p_arr)));
  flea_mpi_t__init(&q, q_arr, FLEA_HEAP_OR_STACK_CODE(prime_word_len, FLEA_STACK_BUF_NB_ENTRIES(q_arr)));
  flea_mpi_t__init(&d1, d1_arr, FLEA_HEAP_OR_STACK_CODE(prime_word_len, FLEA_STACK_BUF_NB_ENTRIES(d1_arr)));
  flea_mpi_t__init(&d2, d2_arr, FLEA_HEAP_OR_STACK_CODE(prime_word_len, FLEA_STACK_BUF_NB_ENTRIES(d2_arr)));
  flea_mpi_t__init(&j1, j1_arr, FLEA_HEAP_OR_STACK_CODE(prime_word_len, FLEA_STACK_BUF_NB_ENTRIES(j1_arr)));

  FLEA_CCALL(THR_flea_mpi_t__decode(&base, base_enc, base_length));
  FLEA_CCALL(THR_flea_mpi_t__decode(&p, p_enc, p_enc_len));
  FLEA_CCALL(THR_flea_mpi_t__decode(&q, q_enc, q_enc_len));
  FLEA_CCALL(THR_flea_mpi_t__decode(&d1, d1_enc, d1_enc_len));
  FLEA_CCALL(THR_flea_mpi_t__decode(&d2, d2_enc, d2_enc_len));


  // reduce the base for the first prime
  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &base_mod_prime, &base, &p, &div_ctx));
  // result used as workspace here

# ifdef FLEA_SCCM_USE_PUBKEY_INPUT_BASED_DELAY
  FLEA_CCALL(
    THR_flea_mpi_t__mod_exp_window(
      &j1,
      &d1,
      &base_mod_prime,
      &p,
      &large_tmp,
      &div_ctx,
      &result,
      FLEA_CRT_RSA_WINDOW_SIZE,
      do_use_mul_always__b,
      &delay_prng__t
    )
  );
# else  /* ifdef FLEA_SCCM_USE_PUBKEY_INPUT_BASED_DELAY */
  FLEA_CCALL(
    THR_flea_mpi_t__mod_exp_window(
      &j1,
      &d1,
      &base_mod_prime,
      &p,
      &large_tmp,
      &div_ctx,
      &result,
      FLEA_CRT_RSA_WINDOW_SIZE,
      do_use_mul_always__b
    )
  );
# endif /* ifdef FLEA_SCCM_USE_PUBKEY_INPUT_BASED_DELAY */

  // d1 unused from here, used for j2
  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &base_mod_prime, &base, &q, &div_ctx));
  // result used as workspace here
# ifdef FLEA_SCCM_USE_PUBKEY_INPUT_BASED_DELAY
  FLEA_CCALL(
    THR_flea_mpi_t__mod_exp_window(
      &d1,
      &d2,
      &base_mod_prime,
      &q,
      &large_tmp,
      &div_ctx,
      &result,
      FLEA_CRT_RSA_WINDOW_SIZE,
      do_use_mul_always__b,
      &delay_prng__t
    )
  );
# else  /* ifdef FLEA_SCCM_USE_PUBKEY_INPUT_BASED_DELAY */
  FLEA_CCALL(
    THR_flea_mpi_t__mod_exp_window(
      &d1,
      &d2,
      &base_mod_prime,
      &q,
      &large_tmp,
      &div_ctx,
      &result,
      FLEA_CRT_RSA_WINDOW_SIZE,
      do_use_mul_always__b
    )
  );
# endif /* ifdef FLEA_SCCM_USE_PUBKEY_INPUT_BASED_DELAY */


  // subtract mod cannot be used because d1=j2 may be larger than p
  FLEA_CCALL(THR_flea_mpi_t__subtract(&result, &j1, &d1)); // result = j1-j2
  // check if the intermediate absolute value is larger than p
  if(-1 == flea_mpi_t__compare_absolute(&p, &result))
  {
    // result must be reduced by p (sign is ignored in division)
    FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &base, &result, &p, &div_ctx));
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&result, &base));
  }

  // trf-base unused from here, used as j1_prime
  if(result.m_sign < 0)
  {
    result.m_sign = +1;
    // result contains absolute value of what is negative to be reduced by p

    FLEA_CCALL(THR_flea_mpi_t__subtract(&base, &p, &result));
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&result, &base));
  }
  // use j1 as q_inv
  FLEA_CCALL(THR_flea_mpi_t__decode(&j1, c_enc, c_enc_len));
  FLEA_CCALL(THR_flea_mpi_t__mul(&base, &result, &j1)); // base = j1' = (j1-d1)*c

  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &ws_trf_base, &base, &p, &div_ctx));

  FLEA_CCALL(THR_flea_mpi_t__mul(&result, &ws_trf_base, &q));

  FLEA_CCALL(THR_flea_mpi_t__add_in_place_ignore_sign(&result, &d1));

  FLEA_CCALL(THR_flea_mpi_t__encode(result_enc, modulus_length, &result)); // r

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(result_arr);
    FLEA_FREE_BUF_SECRET_ARR(base_arr, FLEA_HEAP_OR_STACK_CODE(base_word_len, FLEA_STACK_BUF_NB_ENTRIES(base_arr)));
    FLEA_FREE_BUF_SECRET_ARR(
      base_mod_prime_arr,
      FLEA_HEAP_OR_STACK_CODE(base_mod_prime_len, FLEA_STACK_BUF_NB_ENTRIES(base_mod_prime_arr))
    );
    FLEA_FREE_BUF_SECRET_ARR(
      large_tmp_arr,
      FLEA_HEAP_OR_STACK_CODE(large_tmp_len, FLEA_STACK_BUF_NB_ENTRIES(large_tmp_arr))
    );
    FLEA_FREE_BUF_SECRET_ARR(
      ws_trf_base_arr,
      FLEA_HEAP_OR_STACK_CODE(ws_trf_base_len, FLEA_STACK_BUF_NB_ENTRIES(ws_trf_base_arr))
    );
    FLEA_FREE_BUF_SECRET_ARR(p_arr, FLEA_HEAP_OR_STACK_CODE(prime_word_len, FLEA_STACK_BUF_NB_ENTRIES(p_arr)));
    FLEA_FREE_BUF_SECRET_ARR(q_arr, FLEA_HEAP_OR_STACK_CODE(prime_word_len, FLEA_STACK_BUF_NB_ENTRIES(q_arr)));
    FLEA_FREE_BUF_SECRET_ARR(d1_arr, FLEA_HEAP_OR_STACK_CODE(prime_word_len, FLEA_STACK_BUF_NB_ENTRIES(d1_arr)));
    FLEA_FREE_BUF_SECRET_ARR(d2_arr, FLEA_HEAP_OR_STACK_CODE(prime_word_len, FLEA_STACK_BUF_NB_ENTRIES(d2_arr)));
    FLEA_FREE_BUF_SECRET_ARR(j1_arr, FLEA_HEAP_OR_STACK_CODE(prime_word_len, FLEA_STACK_BUF_NB_ENTRIES(j1_arr)));
    FLEA_FREE_BUF_SECRET_ARR(vn, FLEA_HEAP_OR_STACK_CODE(vn_len, FLEA_STACK_BUF_NB_ENTRIES(vn)));
    FLEA_FREE_BUF_SECRET_ARR(un, FLEA_HEAP_OR_STACK_CODE(un_len, FLEA_STACK_BUF_NB_ENTRIES(un)));
    FLEA_DO_IF_USE_PUBKEY_INPUT_BASED_DELAY(
      flea_ctr_mode_prng_t__dtor(&delay_prng__t);
    )
  );
} /* THR_flea_rsa_raw_operation_crt */

#endif // #ifdef FLEA_HAVE_RSA
