/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef __flea_self_test_H_
#define __flea_self_test_H_

#include "flea/hash.h"
#include "flea/error.h"
#include "flea/types.h"
#include "flea/hostn_ver.h"

#ifdef FLEA_DO_PRINTF_TEST_OUTPUT
# include <stdio.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif


#ifdef FLEA_DO_PRINTF_TEST_OUTPUT
# define FLEA_PRINTF_TEST_OUTP_1_SWITCHED(__format)                 printf(__format)
# define FLEA_PRINTF_TEST_OUTP_2_SWITCHED(__format, __arg1)         printf(__format, __arg1)
# define FLEA_PRINTF_TEST_OUTP_3_SWITCHED(__format, __arg1, __arg2) printf(__format, __arg1, __arg2)
# define __FLEA_EVTL_PRINT_TEST_OUTP(__func, __str)                 printf("%s: %s\n", __func, __str)
#else
# define FLEA_PRINTF_TEST_OUTP_1_SWITCHED(__format)
# define FLEA_PRINTF_TEST_OUTP_2_SWITCHED(__format, __arg1)
# define FLEA_PRINTF_TEST_OUTP_3_SWITCHED(__format, __arg1, __arg2)
# define __FLEA_EVTL_PRINT_TEST_OUTP(__func, __str) do { } while(0)
#endif

flea_err_t THR_flea_test_flea_types(void);

flea_err_t THR_flea_test_montgm_mul_comp_n_prime(void);

flea_err_t THR_flea_test_mpi_div(void);

flea_err_t THR_flea_test_montgm_mul(void);
flea_err_t THR_flea_test_montgm_mul_small(void);
flea_err_t THR_flea_test_montgm_mul_small2(void);

flea_err_t THR_flea_test_mpi_square(void);

flea_err_t THR_flea_test_mpi_mul(void);

// flea_err_t THR_flea_test_rsa(void);


flea_err_t THR_flea_test_mpi_subtract(void);
flea_err_t THR_flea_test_mpi_subtract_2(void);
flea_err_t THR_flea_test_mpi_subtract_3(void);

flea_err_t THR_flea_test_mpi_add(void);
flea_err_t THR_flea_test_mpi_add_2(void);

flea_err_t THR_flea_test_mpi_add_sign(void);

flea_err_t THR_flea_test_rsa_crt(void);

flea_err_t THR_flea_test_mpi_encode(void);

flea_err_t THR_flea_test_mpi_shift_left_small(void);

flea_err_t THR_flea_test_mpi_shift_right(void);

flea_err_t THR_flea_test_mpi_invert_odd_mod_1(void);
flea_err_t THR_flea_test_mpi_invert_odd_mod_2(void);

flea_err_t THR_flea_test_arithm(void);

flea_err_t THR_flea_test_ecc_point_gfp_add(void);
flea_err_t THR_flea_test_ecc_point_gfp_double(void);

flea_err_t THR_flea_test_ecc_point_gfp_mul(void);

flea_err_t THR_flea_test_ecdsa_raw_basic(void);
flea_err_t THR_flea_test_cvc_sig_ver(void);
flea_err_t THR_flea_test_ecka_raw_basic(void);

flea_err_t THR_flea_test_emsa1(void);

flea_err_t THR_flea_test_pkcs1_v1_5_encoding(void);

flea_err_t THR_flea_test_oaep(void);

flea_err_t THR_flea_test_pk_signer_sign_verify(void);

flea_err_t THR_flea_test_enc_BE_bitlen();

flea_err_t THR_flea_test_incr_enc_BE_int();

flea_err_t THR_flea_test_pk_encryption(void);

/**
 * PC test based on file with test vectors for CRT-RSA raw
 */
flea_err_t THR_flea_test_crt_rsa_raw_file_based(void);

/**
 * used by PC tests
 */
flea_err_t THR_flea_test_rsa_crt_inner(
  flea_mpi_ulen_t  mod_byte_len,
  const flea_u8_t* exp_sig,
  const flea_u8_t* mess_arr,
  const flea_u8_t* p_arr,
  flea_mpi_ulen_t  p_len,
  const flea_u8_t* q_arr,
  flea_mpi_ulen_t  q_len,
  const flea_u8_t* d1_arr,
  flea_mpi_ulen_t  d1_len,
  const flea_u8_t* d2_arr,
  flea_mpi_ulen_t  d2_len,
  const flea_u8_t* c_arr,
  flea_mpi_ulen_t  c_len,
  // const flea_u8_t* pub_exp_arr,
  const flea_u8_t* mod_arr
);

flea_err_t THR_flea_test_sha256_file_based();

flea_err_t THR_flea_test_hash_function_inner(
  const flea_u8_t* message,
  flea_u16_t       message_len,
  const flea_u8_t* expected_digest,
  flea_u16_t       expected_digest_len,
  flea_hash_id_t   id
);

flea_err_t THR_flea_test_cipher_block_encr_decr(void);

// flea_err_t THR_flea_test_des(void);

flea_err_t THR_flea_test_sha256_update(void);

flea_err_t THR_flea_test_hash(void);

flea_err_t THR_flea_test_davies_meyer_aes128_hash_hash(void);

flea_err_t THR_flea_test_mac(void);

flea_err_t THR_flea_test_ae(void);

flea_err_t THR_flea_test_cbc_mode(void);
flea_err_t THR_flea_test_ctr_mode_1(void);
flea_err_t THR_flea_test_ctr_mode_parts(void);
flea_err_t THR_flea_test_ctr_mode_prng(void);

flea_err_t THR_flea_test_rsa_loop(unsigned loop_cnt);

flea_err_t THR_flea_test_rsa_crt_mass_sig(flea_u32_t nb_iters);

flea_err_t THR_flea_test_dbg_canaries(void);

flea_err_t THR_flea_test_crc16(void);

flea_err_t THR_flea_test_mem_read_stream();

flea_err_t THR_flea_test_ber_dec_basic();

flea_err_t THR_flea_test_ber_dec_opt_and_ref_and_cpy();

flea_err_t THR_flea_test_dec_tls_server_cert_broken();

flea_err_t THR_flea_test_dec_tls_server_cert();

flea_err_t THR_flea_test_dec_ca_cert();

flea_err_t THR_flea_test_dec_tls_server_issuer_cert();

flea_err_t THR_flea_test_cert_verify_rsa();

flea_err_t THR_flea_test_cert_verify_ecdsa();

flea_err_t THR_test_ecdsa_self_signed_certs_file_based();

flea_err_t THR_flea_test_asn1_date();

flea_err_t THR_flea_test_pkcs8();

flea_err_t THR_flea_test_tls_cert_chain();

flea_err_t THR_flea_test_cert_chain_correct_chain_of_two();

flea_err_t THR_flea_test_cert_chain_correct_chain_of_two_using_cert_store();

flea_err_t THR_flea_test_cert_path_generic(
  const flea_u8_t*      target_cert_ptr,
  flea_u32_t            target_cert_len,
  flea_u8_t**           trust_anchor_ptrs,
  flea_u32_t*           trust_anchor_lens,
  flea_u32_t            nb_trust_anchors,
  flea_u8_t**           cert_ptrs,
  flea_u32_t*           cert_lens,
  flea_u32_t            nb_certs,
  flea_u8_t**           crl_ptrs,
  flea_u32_t*           crl_lens,
  flea_u32_t            nb_crls,
  const flea_u8_t*      validation_date_utctime,
  flea_al_u16_t         validation_date_utctime_len,
  flea_bool_t           disable_revocation_checking,
  const flea_ref_cu8_t* host_id_mbn__pcrcu8,
  flea_host_id_type_e   host_id_type
);

flea_err_t THR_flea_test_path_validation_file_based(
  const char* cert_path_prefix,
  flea_u32_t* nb_exec_tests_pu32
);

flea_err_t THR_flea_test_gmt_time();

flea_err_t THR_flea_tls_test_basic();

flea_err_t THR_flea_test_parallel_hash();

int flea_unit_tests(
  flea_u32_t  nb_reps,
  const char* cert_path_prefix,
  const char* func_prefix,
  flea_bool_t full__b
);


#ifdef __cplusplus
}
#endif
#endif /* h-guard */
