/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "self_test.h"
#include "flea/lib.h"
#include "flea/rng.h"
#include "stdio.h"
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include "internal/common/alloc_dbg_int.h"
#include "flea/error_handling.h"

static flea_bool_t is_prefix_of(
  const char* prefix,
  const char* s
)
{
  flea_u16_t prefix_len = strlen(prefix);
  flea_u16_t s_len      = strlen(s);

  if(prefix_len > s_len)
  {
    return FLEA_FALSE;
  }
  if(0 == memcmp(prefix, s, prefix_len))
  {
    return FLEA_TRUE;
  }
  return FLEA_FALSE;
}

#define __STRINGIFY(s) #s
#define STRINGIFY(s)   __STRINGIFY(s)

#ifdef FLEA_USE_BUF_DBG_CANARIES
static unsigned canary_errors = 0;
# define CHECK_DBG_CANARIES_FLAG_SWITCHED(__f) \
  do { \
    if(FLEA_IS_DBG_CANARY_ERROR_SIGNALLED()) {FLEA_PRINTF_TEST_OUTP_2_SWITCHED("canary error in test %s\n", # __f); canary_errors++;} \
    FLEA_CLEAR_DBG_CANARY_ERROR(); \
  } while(0)
#else  /* ifdef FLEA_USE_BUF_DBG_CANARIES */
# define CHECK_DBG_CANARIES_FLAG_SWITCHED(__f)
#endif /* ifdef FLEA_USE_BUF_DBG_CANARIES */

#define CALL_TEST(__f) \
  do { \
    if(!func_prefix || is_prefix_of(func_prefix, # __f)) { \
      nb_exec_tests++; \
      if((rv = __f)) {FLEA_PRINTF_TEST_OUTP_3_SWITCHED("FAILED TEST: error %x in test %s\n", rv, # __f); failed_tests++;} \
      CHECK_DBG_CANARIES_FLAG_SWITCHED(__f); \
    } \
  } while(0)

int flea_unit_tests(
  flea_u32_t  nb_reps,
  const char* cert_path_prefix,
  const char* file_path_to_be_replaced_by_std_in,
  const char* func_prefix,
  flea_bool_t full__b
)
{
  unsigned nb_exec_tests = 0;
  unsigned failed_tests  = 0;
  unsigned i;
  flea_err_e rv = 0;

  for(i = 0; i < nb_reps; i++)
  {
    if(!cert_path_prefix)
    {
#ifdef FLEA_HAVE_RSA
      flea_u32_t mass_sig_reps__u32 = full__b ? 1000 * 1000 : 100;
#endif
      CALL_TEST(THR_flea_test_dbg_canaries());
      CALL_TEST(THR_flea_test_mpi_square());
      CALL_TEST(THR_flea_test_montgm_mul_comp_n_prime());
      CALL_TEST(THR_flea_test_mpi_div());
      CALL_TEST(THR_flea_test_montgm_mul_small());
      CALL_TEST(THR_flea_test_montgm_mul_small2());
      CALL_TEST(THR_flea_test_montgm_mul());
      CALL_TEST(THR_flea_test_mpi_subtract());
      CALL_TEST(THR_flea_test_mpi_add());
      CALL_TEST(THR_flea_test_mpi_add_2());
      CALL_TEST(THR_flea_test_mpi_add_sign());
#ifdef FLEA_HAVE_RSA
      CALL_TEST(THR_flea_test_rsa_crt());
      CALL_TEST(THR_flea_test_rsa_crt_mass_sig(mass_sig_reps__u32));
#endif
      CALL_TEST(THR_flea_test_mpi_mul());
      CALL_TEST(THR_flea_test_mpi_encode());
      CALL_TEST(THR_flea_test_mpi_shift_left_small());
      CALL_TEST(THR_flea_test_mpi_shift_right());
      CALL_TEST(THR_flea_test_mpi_subtract_2());
      CALL_TEST(THR_flea_test_mpi_subtract_3());
      CALL_TEST(THR_flea_test_mpi_invert_odd_mod_1());
      CALL_TEST(THR_flea_test_mpi_invert_odd_mod_2());
      CALL_TEST(THR_flea_test_arithm());
#if defined FLEA_HAVE_ECC && FLEA_ECC_MAX_MOD_BIT_SIZE >= 160
      CALL_TEST(THR_flea_test_ecc_point_gfp_double());
      CALL_TEST(THR_flea_test_ecc_point_gfp_add());
      CALL_TEST(THR_flea_test_ecc_point_gfp_mul());
#endif
#ifdef FLEA_HAVE_ECKA
      CALL_TEST(THR_flea_test_ecka_raw_basic());
#endif
#ifdef FLEA_HAVE_ECDSA
      CALL_TEST(THR_flea_test_ecdsa_raw_basic());
      CALL_TEST(THR_flea_test_ecdsa_sig_enc());
      CALL_TEST(THR_flea_test_cvc_sig_ver());
#endif

      CALL_TEST(THR_flea_test_pk_signer_sign_verify());

#ifdef FLEA_HAVE_PK_CS
      CALL_TEST(THR_flea_test_pk_encryption());
      CALL_TEST(THR_flea_test_emsa1());
      CALL_TEST(THR_flea_test_pkcs1_v1_5_encoding());
      CALL_TEST(THR_flea_test_oaep());
#endif /* ifdef FLEA_HAVE_PK_CS */
      CALL_TEST(THR_flea_test_cipher_block_encr_decr());
      CALL_TEST(THR_flea_test_davies_meyer_aes128_hash_hash());
      CALL_TEST(THR_flea_test_sha256_update());
      CALL_TEST(THR_flea_test_hash());
#ifdef FLEA_HAVE_MAC
      CALL_TEST(THR_flea_test_mac());
#endif
#ifdef FLEA_HAVE_AE
      CALL_TEST(THR_flea_test_ae());
#endif
      CALL_TEST(THR_flea_test_ctr_mode_1());
      CALL_TEST(THR_flea_test_cbc_mode_aes());
#ifdef FLEA_HAVE_DES
      CALL_TEST(THR_flea_test_cbc_mode_3des());
#endif
      CALL_TEST(THR_flea_test_ctr_mode_parts());
      CALL_TEST(THR_flea_test_ctr_mode_prng());
      CALL_TEST(THR_flea_test_feed_entropy());

      CALL_TEST(THR_flea_test_crc16());
      CALL_TEST(THR_flea_test_enc_BE_bitlen());
      CALL_TEST(THR_flea_test_incr_enc_BE_int());
      // #endif

      CALL_TEST(THR_flea_test_mem_read_stream());

      CALL_TEST(THR_flea_test_rw_stream_init_dtor());

      CALL_TEST(THR_flea_test_ber_dec_basic());
      CALL_TEST(THR_flea_test_ber_dec_opt_and_ref_and_cpy());

      CALL_TEST(THR_flea_test_dec_ca_cert());
      CALL_TEST(THR_flea_test_dec_tls_server_cert());
      CALL_TEST(THR_flea_test_dec_tls_server_cert_broken());
      CALL_TEST(THR_flea_test_dec_tls_server_issuer_cert());
#ifdef FLEA_HAVE_TLS
      CALL_TEST(THR_flea_test_parallel_hash());
#endif

#if defined FLEA_HAVE_ASYM_SIG && defined FLEA_HAVE_SHA1
      CALL_TEST(THR_flea_test_pkcs8());
#endif
#ifdef FLEA_HAVE_RSA
      CALL_TEST(THR_flea_test_cert_verify_rsa());
      CALL_TEST(THR_flea_test_cert_chain_correct_chain_of_two());

      CALL_TEST(THR_flea_test_cert_chain_correct_chain_of_two_using_cert_store());
      CALL_TEST(THR_flea_test_tls_cert_chain());
#endif /* ifdef FLEA_HAVE_RSA */
#ifdef FLEA_HAVE_ECDSA
      CALL_TEST(THR_flea_test_cert_verify_ecdsa());
#endif
#if defined FLEA_HAVE_ECKA && defined FLEA_HAVE_ASYM_SIG
      CALL_TEST(THR_flea_test_ecc_key_plain_format_encoding());
#endif
#ifdef FLEA_HAVE_ASYM_SIG
      CALL_TEST(THR_flea_test_cert_path_valid_init());
      CALL_TEST(THR_flea_test_fuzzed_certs());
#endif
      CALL_TEST(THR_flea_test_gmt_time());

      CALL_TEST(THR_flea_test_asn1_date());
      CALL_TEST(THR_flea_test_date_addition());
#ifdef __FLEA_HAVE_LINUX_FILESYSTEM
# if defined FLEA_HAVE_ECDSA && FLEA_ECC_MAX_MOD_BIT_SIZE >= 224
      CALL_TEST(THR_test_ecdsa_self_signed_certs_file_based());
      if(full__b == FLEA_TRUE)
      {
#  if defined FLEA_HAVE_RSA && (FLEA_RSA_MAX_KEY_BIT_SIZE >= 2048)
        CALL_TEST(THR_flea_test_crt_rsa_raw_file_based());
#  endif
      }
# endif /* if defined FLEA_HAVE_ECDSA && FLEA_ECC_MAX_MOD_BIT_SIZE >= 224 */
      CALL_TEST(THR_flea_test_hash_file_based());
#endif /* __FLEA_HAVE_LINUX_FILESYSTEM */
      CALL_TEST(THR_flea_tls_test_basic());
    }
#ifdef __FLEA_HAVE_LINUX_FILESYSTEM
# if defined FLEA_HAVE_RSA && (FLEA_RSA_MAX_KEY_BIT_SIZE >= 4096) && defined FLEA_HAVE_ECDSA && (FLEA_ECC_MAX_MOD_BIT_SIZE >= 521) && defined FLEA_HAVE_SHA1 && defined FLEA_HAVE_SHA384_512
    if(!func_prefix)
    {
      flea_u32_t nb_cert_path_tests = 0;
      CALL_TEST(THR_flea_test_path_validation_file_based(cert_path_prefix, &nb_cert_path_tests, file_path_to_be_replaced_by_std_in));
      nb_exec_tests -= 1; // correct the counting of the dispatcher
      nb_exec_tests += nb_cert_path_tests;
    }
# endif /* if defined FLEA_HAVE_RSA && (FLEA_RSA_MAX_KEY_BIT_SIZE >= 4096) && defined FLEA_HAVE_ECDSA && (FLEA_ECC_MAX_MOD_BIT_SIZE >= 521) */
#endif /* __FLEA_HAVE_LINUX_FILESYSTEM */
    if(failed_tests)
    {
      break;
    }
  }
  if(!failed_tests
#ifdef FLEA_USE_BUF_DBG_CANARIES
    && !canary_errors
#endif
  )
  {
    FLEA_PRINTF_TEST_OUTP_2_SWITCHED("*** all %u tests PASSED ***\n", nb_exec_tests);
    return 0;
  }
  FLEA_PRINTF_TEST_OUTP_2_SWITCHED("%u tests executed\n", nb_exec_tests);
  FLEA_PRINTF_TEST_OUTP_2_SWITCHED("=== ERROR: there were %u FAILED tests ===\n", failed_tests);
#ifdef FLEA_USE_BUF_DBG_CANARIES
  FLEA_PRINTF_TEST_OUTP_2_SWITCHED("=== ERROR: there were %u tests with canary errors ===\n", canary_errors);
#endif

  return 1;
} /* flea_unit_tests */
