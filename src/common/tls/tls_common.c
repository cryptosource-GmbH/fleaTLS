/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


/*
 * TODO: compute hashes for all possible hmac algorithms during handshake (?)
 * TODO: read_next_handshake_message: handle the case that one record contains more than one handshake message
 * TODO: const for input values
 * TODO: proper error handling (-> distinct errors)
 * TODO: process alerts and send alerts
 * QUESTION: do we need the structs at all? Simply save the important parts in the tls_ctx (e.g. security_parameters)
 * TODO: Cipher Suites: use new struct and array of supported ciphersuites. (see "Implementing SSL/TLS" page 340f)f
 */


#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/bin_utils.h"
#include "flea/tls.h"
#include "flea/cbc_filter.h"
#include "flea/hash_stream.h"
#include "flea/tee.h"
#include "internal/common/tls/handsh_reader.h"
#include "internal/common/tls/tls_rec_prot_rdr.h"
#include "internal/common/tls/tls_common.h"

#include <string.h>

#include "flea/pubkey.h"
#include "flea/asn1_date.h"
#include "api/flea/cert_path.h"
#include "internal/common/ber_dec.h"
#include "flea/rng.h"
#include "flea/block_cipher.h"
#include "flea/bin_utils.h"

#include <stdio.h>


typedef struct
{
  flea_u8_t  type__u8;
  flea_u32_t len__u32;
} handshake_header;

// TODO: MAKE INPUT DATA
// CA cert to verify the server's certificate
flea_u8_t trust_anchor[] =
{0x30, 0x82, 0x03, 0x7f, 0x30, 0x82, 0x02, 0x67, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00, 0xfe, 0x12, 0x36,
 0x42, 0xa1, 0xb6, 0xf7, 0x11, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
 0x00, 0x30, 0x56, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30,
 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31,
 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20,
 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x31, 0x0f, 0x30, 0x0d,
 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, 0x72, 0x6f, 0x6f, 0x74, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x36,
 0x31, 0x31, 0x30, 0x31, 0x30, 0x38, 0x33, 0x39, 0x31, 0x33, 0x5a, 0x17, 0x0d, 0x31, 0x39, 0x30, 0x38, 0x32, 0x32,
 0x30, 0x38, 0x33, 0x39, 0x31, 0x33, 0x5a, 0x30, 0x56, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d,
 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74,
 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c,
 0x74, 0x64, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, 0x72, 0x6f, 0x6f, 0x74, 0x43, 0x41,
 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xcf, 0xa5, 0x70, 0x42, 0x71,
 0x64, 0xdf, 0xfa, 0x98, 0x43, 0x8a, 0x13, 0x5f, 0xe3, 0x7d, 0xed, 0x27, 0xff, 0x52, 0x3a, 0x6b, 0x7f, 0x0f, 0xd6,
 0x80, 0xaa, 0xfd, 0x2e, 0xf9, 0xb7, 0xcf, 0x6b, 0x46, 0x72, 0x91, 0x95, 0x39, 0x44, 0xc1, 0xbf, 0x69, 0x9e, 0x65,
 0xab, 0xbd, 0xa7, 0xe6, 0x3c, 0xfd, 0x12, 0x09, 0xa6, 0xda, 0x1e, 0xf4, 0x12, 0x9b, 0x0d, 0xd6, 0x5c, 0x6c, 0xdf,
 0x64, 0x77, 0xfe, 0x35, 0x2d, 0xd9, 0xad, 0x99, 0xc1, 0x47, 0x31, 0xef, 0x95, 0x23, 0x38, 0x48, 0xd7, 0xa6, 0x84,
 0x69, 0x6c, 0x4d, 0x37, 0xe8, 0x29, 0xd3, 0xb4, 0x68, 0x03, 0x19, 0xdc, 0xb1, 0xd1, 0xfd, 0xfb, 0x97, 0x61, 0x50,
 0xe7, 0x2a, 0xa0, 0xfd, 0x7c, 0x8f, 0x51, 0x88, 0x0b, 0x5d, 0x74, 0xce, 0xb6, 0xa5, 0x65, 0x53, 0xb2, 0x0d, 0xdf,
 0xb5, 0x7a, 0xe1, 0x3c, 0x98, 0x6e, 0x29, 0xa7, 0x90, 0x75, 0x13, 0xac, 0x22, 0x92, 0xdb, 0xe6, 0x8c, 0x6f, 0x32,
 0xa7, 0x42, 0xa4, 0xa4, 0x5c, 0x04, 0xdb, 0x04, 0x95, 0x34, 0x13, 0xe0, 0xa1, 0x47, 0x00, 0x21, 0xf6, 0xa1, 0xa7,
 0xaa, 0x0e, 0x97, 0xc5, 0x2b, 0x64, 0x00, 0x74, 0xdd, 0x57, 0xe3, 0x03, 0xe0, 0xb8, 0xc5, 0x4e, 0xe3, 0x3e, 0xf0,
 0x33, 0x7d, 0x5e, 0x82, 0xda, 0xaa, 0x04, 0x0d, 0xdc, 0x80, 0x14, 0xaf, 0x30, 0x10, 0x9c, 0x5b, 0xb8, 0xd2, 0xb6,
 0x76, 0x6c, 0x10, 0x27, 0xfd, 0x6e, 0xaa, 0xc2, 0x70, 0x7e, 0x0d, 0x37, 0x2c, 0x28, 0x81, 0x26, 0xc8, 0xeb, 0x7c,
 0x4b, 0x8f, 0xda, 0x7b, 0x02, 0xb0, 0x51, 0x92, 0x3d, 0x3d, 0x5e, 0x53, 0xfa, 0xcb, 0x43, 0x4f, 0xef, 0x1e, 0x61,
 0xe5, 0xb9, 0x2c, 0x08, 0x77, 0xff, 0x65, 0x77, 0x13, 0x4d, 0xd4, 0xcb, 0x2e, 0x7f, 0x9d, 0xe2, 0x1a, 0xc3, 0x19,
 0x84, 0xb1, 0x52, 0x9d, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x50, 0x30, 0x4e, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
 0x0e, 0x04, 0x16, 0x04, 0x14, 0xb7, 0x52, 0x9d, 0x67, 0xd2, 0x32, 0x3f, 0x0c, 0x4d, 0xe3, 0xa2, 0xe8, 0x95, 0xfe,
 0x23, 0x83, 0xbf, 0xaa, 0x17, 0x66, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
 0xb7, 0x52, 0x9d, 0x67, 0xd2, 0x32, 0x3f, 0x0c, 0x4d, 0xe3, 0xa2, 0xe8, 0x95, 0xfe, 0x23, 0x83, 0xbf, 0xaa, 0x17,
 0x66, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09,
 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x7b, 0x18, 0xad,
 0x25, 0x86, 0x17, 0x93, 0x93, 0xcb, 0x01, 0xe1, 0x07, 0xce, 0xfa, 0x37, 0x96, 0x5f, 0x17, 0x95, 0x1d, 0x76, 0xf3,
 0x04, 0x36, 0x81, 0x64, 0x78, 0x2a, 0xc2, 0xcc, 0xbd, 0x77, 0xf7, 0x59, 0xeb, 0x9a, 0xf7, 0xb3, 0xfc, 0x1a, 0x30,
 0xfe, 0x6f, 0x6e, 0x02, 0xc6, 0x2d, 0x4d, 0x79, 0x25, 0xaf, 0x98, 0xb4, 0xab, 0x3e, 0x25, 0xfc, 0xef, 0x98, 0x26,
 0x0f, 0x6a, 0x0a, 0x74, 0x5b, 0x4f, 0x3a, 0x6c, 0xd6, 0x42, 0x56, 0xd9, 0x25, 0x0a, 0x1e, 0x3a, 0x4c, 0x74, 0xe9,
 0x28, 0xcf, 0x7d, 0xe9, 0x48, 0xdc, 0xd6, 0xf4, 0x23, 0xf7, 0x2e, 0xc9, 0x50, 0xb7, 0xad, 0x22, 0x9b, 0xdf, 0x60,
 0xcf, 0x2f, 0x4b, 0x98, 0x79, 0x3d, 0x56, 0xf0, 0x03, 0xfd, 0xe1, 0x61, 0x12, 0xed, 0x44, 0xe8, 0x22, 0xce, 0x4d,
 0x41, 0xe7, 0xd4, 0x9c, 0xf9, 0x12, 0x57, 0x12, 0xb0, 0x20, 0xb3, 0xfa, 0xf5, 0x09, 0x8b, 0xc6, 0x38, 0xc2, 0x31,
 0x41, 0xe8, 0xf3, 0x1c, 0x9a, 0xb7, 0x87, 0x73, 0x64, 0x29, 0xc5, 0x0f, 0x8e, 0x2d, 0x80, 0xbd, 0x54, 0x16, 0x6d,
 0xc2, 0xcd, 0x5f, 0x0c, 0x12, 0xe0, 0xd2, 0x6b, 0xce, 0x99, 0x53, 0x7b, 0xa8, 0x38, 0x4e, 0x17, 0xea, 0xc1, 0x70,
 0x9b, 0x33, 0x39, 0xc2, 0x83, 0x11, 0xba, 0xbd, 0x9b, 0x79, 0x09, 0xc5, 0x01, 0xea, 0x2d, 0xc6, 0x56, 0xf2, 0x9a,
 0x14, 0x68, 0x37, 0xb2, 0x28, 0xb0, 0x60, 0xf0, 0xc6, 0xf4, 0xa6, 0x1e, 0xeb, 0x2b, 0x1d, 0x0e, 0xa0, 0x58, 0xfc,
 0xd8, 0x2c, 0x01, 0xa3, 0xcf, 0xae, 0xa8, 0x3b, 0x49, 0x9e, 0xad, 0x51, 0xe7, 0x08, 0x65, 0x8c, 0x5c, 0x33, 0x54,
 0x04, 0x14, 0x48, 0xf1, 0x79, 0xab, 0x33, 0xf5, 0xd4, 0xe0, 0xef, 0x1a, 0x62, 0x13, 0x48, 0xda, 0x52, 0x3e, 0x02,
 0x8f, 0x64, 0xba, 0x8e, 0xf1, 0x88};

// TODO: MUST BE CONST
const flea_tls__cipher_suite_t cipher_suites[2] = {
  {TLS_NULL_WITH_NULL_NULL,         (flea_block_cipher_id_t) 0,
   0, 0,
   0, 0, 0, (flea_mac_id_t) 0, (flea_hash_id_t) 0, (flea_tls__prf_algorithm_t) 0},
  {TLS_RSA_WITH_AES_256_CBC_SHA256, flea_aes256,
   16, 16, 32, 32, 32, flea_hmac_sha256, flea_sha256, FLEA_TLS_PRF_SHA256}
};


static flea_err_t P_Hash(
  const flea_u8_t* secret,
  flea_u16_t       secret_length,
  const flea_u8_t* label__pcu8,
  flea_al_u8_t     label_len__alu8,
  const flea_u8_t* seed,
  flea_u16_t       seed_length,
  flea_u8_t*       data_out,
  flea_u16_t       res_length
)
{
  const flea_u16_t hash_out_len__alu8 = 32;

  FLEA_DECL_BUF(a__bu8, flea_u8_t, 64);
  flea_u8_t* A;
  flea_u8_t* B;
  flea_u8_t* tmp__pu8;
  flea_mac_ctx_t hmac__t = flea_mac_ctx_t__INIT_VALUE;

  // expand to length bytes
  flea_al_u8_t len__alu8 = hash_out_len__alu8;
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(a__bu8, 64);
  A = a__bu8;
  B = a__bu8 + 32;
  flea_mac_ctx_t__INIT(&hmac__t);
  FLEA_CCALL(THR_flea_mac_ctx_t__ctor(&hmac__t, flea_hmac_sha256, secret, secret_length));
  FLEA_CCALL(THR_flea_mac_ctx_t__update(&hmac__t, label__pcu8, label_len__alu8));
  FLEA_CCALL(THR_flea_mac_ctx_t__update(&hmac__t, seed, seed_length));
  FLEA_CCALL(THR_flea_mac_ctx_t__final_compute(&hmac__t, A, &len__alu8));
  flea_mac_ctx_t__dtor(&hmac__t);
  // FLEA_CCALL(THR_flea_mac__compute_mac(flea_hmac_sha256, secret, secret_length, seed, seed_length, A, &len__alu8));
  while(res_length)
  {
    flea_al_u8_t to_go__alu16 = FLEA_MIN(res_length, hash_out_len__alu8);
    res_length -= to_go__alu16;
    // A(i) = HMAC_hash(secret, A(i-1))
    flea_mac_ctx_t__INIT(&hmac__t);
    FLEA_CCALL(THR_flea_mac_ctx_t__ctor(&hmac__t, flea_hmac_sha256, secret, secret_length));
    FLEA_CCALL(THR_flea_mac_ctx_t__update(&hmac__t, A, hash_out_len__alu8));
    FLEA_CCALL(THR_flea_mac_ctx_t__update(&hmac__t, label__pcu8, label_len__alu8));
    FLEA_CCALL(THR_flea_mac_ctx_t__update(&hmac__t, seed, seed_length));
    len__alu8 = to_go__alu16;
    FLEA_CCALL(THR_flea_mac_ctx_t__final_compute(&hmac__t, data_out, &len__alu8));
    data_out += to_go__alu16;
    len__alu8 = hash_out_len__alu8;
    FLEA_CCALL(
      THR_flea_mac__compute_mac(
        flea_hmac_sha256,
        secret,
        secret_length,
        A,
        hash_out_len__alu8,
        B,
        &len__alu8
      )
    );
    tmp__pu8 = A;
    A        = B;
    B        = tmp__pu8;
    flea_mac_ctx_t__dtor(&hmac__t);
  }
  FLEA_THR_FIN_SEC(
    flea_mac_ctx_t__dtor(&hmac__t);
    FLEA_FREE_BUF_FINAL_SECRET_ARR(a__bu8, 64);
  );
} /* P_Hash */

/**
 *    P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
 *                           HMAC_hash(secret, A(2) + seed) +
 *                           HMAC_hash(secret, A(3) + seed) + ...
 *
 * where + indicates concatenation.
 *
 * A() is defined as:
 *    A(0) = seed
 *    A(i) = HMAC_hash(secret, A(i-1))
 *
 *
 *    PRF(secret, label, seed) = P_<hash>(secret, label + seed)
 *
 *  P_Hash is Sha256 for all ciphers defined in RFC5246
 *
 *
 *  FinishedMessage:
 *  verify_data
 *           PRF(master_secret, finished_label, Hash(handshake_messages))
 *              [0..verify_data_length-1];
 */
// length: how long should the output be. 12 Octets = 96 Bits
flea_err_t flea_tls__prf(
  const flea_u8_t* secret,
  flea_u8_t        secret_length,
  PRFLabel         label,
  const flea_u8_t* seed,
  flea_u16_t       seed_length,
  flea_u16_t       result_length,
  flea_u8_t*       result
)
{
  FLEA_THR_BEG_FUNC();

  /**
   * TODO: no fixed sha256
   */
  const flea_u8_t client_finished[] = {99, 108, 105, 101, 110, 116, 32, 102, 105, 110, 105, 115, 104, 101, 100};
  const flea_u8_t server_finished[] = {115, 101, 114, 118, 101, 114, 32, 102, 105, 110, 105, 115, 104, 101, 100};
  const flea_u8_t master_secret[]   = {109, 97, 115, 116, 101, 114, 32, 115, 101, 99, 114, 101, 116};
  const flea_u8_t key_expansion[]   = {107, 101, 121, 32, 101, 120, 112, 97, 110, 115, 105, 111, 110};

  // TODO: REMOVE
  const flea_u8_t test_label[] = {0x74, 0x65, 0x73, 0x74, 0x20, 0x6c, 0x61, 0x62, 0x65, 0x6c};

  const flea_u8_t* label__pcu8;
  flea_al_u8_t label_len__alu8;
  switch(label)
  {
      case PRF_LABEL_CLIENT_FINISHED:
        label__pcu8     = client_finished;
        label_len__alu8 = sizeof(client_finished);
        break;
      case PRF_LABEL_MASTER_SECRET:
        label__pcu8     = master_secret;
        label_len__alu8 = sizeof(master_secret);
        break;
      case PRF_LABEL_KEY_EXPANSION:
        label__pcu8     = key_expansion,
        label_len__alu8 = sizeof(key_expansion);
        break;
      case PRF_LABEL_SERVER_FINISHED:
        label__pcu8     = server_finished;
        label_len__alu8 = sizeof(server_finished);
        break;
      // TODO: REMOVE
      case PRF_LABEL_TEST:
        label__pcu8     = test_label;
        label_len__alu8 = sizeof(test_label);
        break;
      default:
        FLEA_THROW("Invalid label!", FLEA_ERR_TLS_GENERIC);
  }
  FLEA_CCALL(P_Hash(secret, secret_length, label__pcu8, label_len__alu8, seed, seed_length, result, result_length));
  FLEA_THR_FIN_SEC_empty();
} /* flea_tls__prf */

/*
 * key_block = PRF(SecurityParameters.master_secret,
 *        "key expansion",
 *        SecurityParameters.server_random +
 *        SecurityParameters.client_random);
 */
flea_err_t THR_flea_tls__generate_key_block(
  flea_tls_ctx_t* tls_ctx,
  flea_u8_t*      key_block
)
{
  FLEA_THR_BEG_FUNC();
  flea_u8_t seed[64];
  memcpy(seed, tls_ctx->security_parameters->server_random.gmt_unix_time, 4);
  memcpy(seed + 4, tls_ctx->security_parameters->server_random.random_bytes, 28);
  memcpy(seed + 32, tls_ctx->security_parameters->client_random.gmt_unix_time, 4);
  memcpy(seed + 36, tls_ctx->security_parameters->client_random.random_bytes, 28);

  FLEA_CCALL(
    flea_tls__prf(
      tls_ctx->security_parameters->master_secret,
      48,
      PRF_LABEL_KEY_EXPANSION,
      seed,
      sizeof(seed),
      128,
      key_block
    )
  );
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls__create_finished_data(
  flea_u8_t* messages_hash,
  flea_u8_t  master_secret[48],
  PRFLabel   label,
  flea_u8_t* data,
  flea_u8_t  data_len
)
{
  FLEA_THR_BEG_FUNC();
  // TODO: hardcoded hash-len 32 always correct?
  FLEA_CCALL(flea_tls__prf(master_secret, 48, label, messages_hash, 32, data_len, data));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls__read_handshake_message(
  flea_tls_ctx_t*   tls_ctx__pt,
  HandshakeMessage* handshake_msg,
  flea_hash_ctx_t*  hash_ctx__pt
)
{
  flea_u32_t len__u32;
  flea_u8_t hdr__au8[4];
  flea_al_u16_t len__palu16 = sizeof(hdr__au8);

  FLEA_THR_BEG_FUNC();


  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__read_data(
      &tls_ctx__pt->rec_prot__t,
      CONTENT_TYPE_HANDSHAKE,
      hdr__au8,
      &len__palu16
    )
  );

  handshake_msg->type = hdr__au8[0];

  len__u32 = (((flea_u32_t) hdr__au8[1]) << 16) | (((flea_u32_t) hdr__au8[2]) << 8) | (((flea_u32_t) hdr__au8[3]));

  handshake_msg->length = len__u32;

  handshake_msg->data = calloc(handshake_msg->length, sizeof(flea_u8_t));
  len__palu16         = handshake_msg->length;
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__read_data(
      &tls_ctx__pt->rec_prot__t,
      CONTENT_TYPE_HANDSHAKE,
      handshake_msg->data,
      &len__palu16
    )
  );

  if(handshake_msg->type != HANDSHAKE_TYPE_FINISHED)
  {
    FLEA_CCALL(THR_flea_hash_ctx_t__update(hash_ctx__pt, hdr__au8, sizeof(hdr__au8)));
    FLEA_CCALL(THR_flea_hash_ctx_t__update(hash_ctx__pt, handshake_msg->data, handshake_msg->length));
  }
  if(len__palu16 != handshake_msg->length)
  {
    FLEA_THROW("did not read sufficient data for handshake message", FLEA_ERR_INT_ERR);
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__read_handshake_message */

flea_err_t THR_flea_tls__read_client_hello(
  flea_tls_ctx_t*   tls_ctx,
  HandshakeMessage* handshake_msg
)
{
  FLEA_THR_BEG_FUNC();

  flea_u32_t len = 0;

  if(handshake_msg->length < 34)
  {
    FLEA_THROW("message too short", FLEA_ERR_TLS_GENERIC);
  }

  // TODO: negotiate version properly
  if(handshake_msg->data[len++] != tls_ctx->version.major || handshake_msg->data[len++] != tls_ctx->version.minor)
  {
    FLEA_THROW("Version mismatch!", FLEA_ERR_TLS_GENERIC);
  }


  // read random
  // TODO: CHECK HOW TIME IS TO BE USED AND THEN ENCODE IT CORRECTLY
  flea_u8_t* p = (flea_u8_t*) tls_ctx->security_parameters->client_random.gmt_unix_time;
  for(flea_u8_t i = 0; i < 4; i++)
  {
    p[i] = handshake_msg->data[len++];
  }
  p = tls_ctx->security_parameters->client_random.random_bytes;
  for(flea_u8_t i = 0; i < 28; i++)
  {
    p[i] = handshake_msg->data[len++];
  }


  // session id
  flea_u8_t session_id_len = handshake_msg->data[len++];
  if(session_id_len > 0)
  {
    if(session_id_len + len > handshake_msg->length)
    {
      FLEA_THROW("parsing error", FLEA_ERR_TLS_GENERIC);
    }
    else
    {
      // TODO: handle session id !
      len += session_id_len; // TODO: !
    }
  }

  // check that we have enough bytes left to read the cipher suites length
  if(len + 2 > handshake_msg->length)
  {
    FLEA_THROW("parsing error", FLEA_ERR_TLS_GENERIC);
  }
  flea_u16_t cipher_suites_len;
  cipher_suites_len  = handshake_msg->data[len++] << 8;
  cipher_suites_len |= handshake_msg->data[len++];

  // check that we have enough bytes left to read the cipher suites
  if(len + cipher_suites_len > handshake_msg->length || cipher_suites_len % 2 != 0)
  {
    FLEA_THROW("parsing error", FLEA_ERR_TLS_GENERIC);
  }
  flea_bool_t found = FLEA_TRUE;
  // TODO: need to check if we support one of the client's cipher suite and we
  // need to choose one !! (hard coded RSA AES 256)
  if(found == FLEA_FALSE)
  {
    FLEA_THROW("Could not agree on cipher", FLEA_ERR_TLS_GENERIC);
  }
  len += cipher_suites_len;

  // check that we have enough bytes left to read the compression methods length
  if(len + 1 > handshake_msg->length)
  {
    FLEA_THROW("parsing error", FLEA_ERR_TLS_GENERIC);
  }
  flea_u8_t compression_methods_len = handshake_msg->data[len++];

  // check that we have enough bytes left to read the compression methods
  if(len + compression_methods_len > handshake_msg->length)
  {
    FLEA_THROW("parsing error", FLEA_ERR_TLS_GENERIC);
  }
  // TODO: actually read and evaluate
  len += compression_methods_len;

  // check that length was correct
  if(len != handshake_msg->length)
  {
    FLEA_THROW("parsing error", FLEA_ERR_TLS_GENERIC);
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__read_client_hello */

flea_err_t THR_flea_tls__read_finished(
  flea_tls_ctx_t*           tls_ctx,
  flea_tls_handsh_reader_t* hs_rdr__pt,
  flea_hash_ctx_t*          hash_ctx
)
{
  FLEA_DECL_BUF(messages_hash__bu8, flea_u8_t, __FLEA_COMPUTED_MAX_HASH_OUT_LEN + 2 * 12);
  // TODO: need to generalize 12byte ? (botan doesn't do it either) -  avoiding "magical number" would be better
  const flea_al_u8_t finished_len__alu8 = 12;
  flea_rw_stream_t* hs_rd_stream__pt;
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(messages_hash__bu8, __FLEA_COMPUTED_MAX_HASH_OUT_LEN + 2 * 12);
  flea_u8_t* finished__pu8     = messages_hash__bu8 + __FLEA_COMPUTED_MAX_HASH_OUT_LEN;
  flea_u8_t* rec_finished__pu8 = messages_hash__bu8 + __FLEA_COMPUTED_MAX_HASH_OUT_LEN + finished_len__alu8;
  // compute hash over handshake messages so far
  FLEA_CCALL(THR_flea_hash_ctx_t__final(hash_ctx, messages_hash__bu8));


  PRFLabel label;
  if(tls_ctx->security_parameters->connection_end == FLEA_TLS_CLIENT)
  {
    label = PRF_LABEL_SERVER_FINISHED;
  }
  else
  {
    label = PRF_LABEL_CLIENT_FINISHED;
  }

  FLEA_CCALL(
    THR_flea_tls__create_finished_data(
      messages_hash__bu8,
      tls_ctx->security_parameters->master_secret,
      label,
      finished__pu8,
      finished_len__alu8
    )
  );
  hs_rd_stream__pt = flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt);
  FLEA_CCALL(THR_flea_rw_stream_t__force_read(hs_rd_stream__pt, rec_finished__pu8, finished_len__alu8));
  if(flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt) != 0)
  {
    FLEA_THROW("trailing data in finished message", FLEA_ERR_TLS_GENERIC);
  }
  if(!flea_sec_mem_equal(rec_finished__pu8, finished__pu8, finished_len__alu8))
  {
    printf("Finished message not verifiable\n");
    printf("Got: \n");
    for(int i = 0; i < 12; i++)
    {
      printf("%02x ", rec_finished__pu8[i]);
    }
    printf("\nBut calculated: \n");
    for(int i = 0; i < 12; i++)
    {
      printf("%02x ", finished__pu8[i]);
    }
    printf("\n");

    FLEA_THROW("Finished message not verifiable", FLEA_ERR_TLS_GENERIC);
  }


  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(messages_hash__bu8);
  );
} /* THR_flea_tls__read_finished */

flea_err_t THR_verify_cert_chain(
  flea_u8_t*         tls_cert_chain__acu8,
  flea_u32_t         length,
  flea_public_key_t* pubkey__t
)
{
  FLEA_DECL_OBJ(cert_chain__t, flea_cert_path_validator_t);
  const flea_u8_t date_str[] = "170228200000Z"; // TODO: datumsfunktion aufrufen
  flea_gmt_time_t time__t;
  flea_bool_t first__b = FLEA_TRUE;
  const flea_u8_t* ptr = tls_cert_chain__acu8;
  flea_al_u16_t len    = length;

  FLEA_THR_BEG_FUNC();

  while(len > 3)
  {
    // FLEA_DECL_OBJ(ref__t, flea_x509_cert_ref_t);
    flea_u32_t new_len = ((flea_u32_t) ptr[0] << 16) | (ptr[1] << 8) | (ptr[2]);
    ptr += 3;
    len -= 3;
    if(new_len > len)
    {
      FLEA_THROW("invalid cert chain length", FLEA_ERR_INV_ARG);
    }
    // FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(&ref__t, ptr, new_len));
    if(first__b)
    {
      // FLEA_CCALL(THR_flea_cert_path_validator_t__ctor_cert_ref(&cert_chain__t, &ref__t));
      FLEA_CCALL(THR_flea_cert_path_validator_t__ctor_cert(&cert_chain__t, ptr, new_len));
      first__b = FLEA_FALSE;
    }
    else
    {
      FLEA_CCALL(THR_flea_cert_path_validator_t__add_cert_without_trust_status(&cert_chain__t, ptr, new_len));
    }
    ptr += new_len;
    len -= new_len;
  }

  FLEA_CCALL(THR_flea_asn1_parse_utc_time(date_str, sizeof(date_str) - 1, &time__t));


  // add trust anchor
  // FLEA_DECL_OBJ(trust_ref__t, flea_x509_cert_ref_t);
  // err = THR_flea_x509_cert_ref_t__ctor(&trust_ref__t, trust_anchor, sizeof(trust_anchor));
  // err = THR_flea_cert_path_validator_t__add_trust_anchor_cert_ref(&cert_chain__t, &trust_ref__t);
  FLEA_CCALL(THR_flea_cert_path_validator_t__add_trust_anchor_cert(&cert_chain__t, trust_anchor, sizeof(trust_anchor)));
  // TODO: ENABLE REVOCATION CHECKING IN TLS
  flea_cert_path_validator_t__disable_revocation_checking(&cert_chain__t);
  FLEA_CCALL(
    THR_flea_cert_path_validator__build_and_verify_cert_chain_and_create_pub_key(
      &cert_chain__t,
      &time__t,
      pubkey__t
    )
  );

  FLEA_THR_FIN_SEC(
    flea_cert_path_validator_t__dtor(&cert_chain__t);
  );
} /* THR_verify_cert_chain */

flea_err_t THR_flea_tls__read_certificate(
  flea_tls_ctx_t*           tls_ctx,
  flea_tls_handsh_reader_t* hs_rdr__pt,
  flea_public_key_t*        pubkey
)
{
  FLEA_DECL_BUF(cert_chain__bu8, flea_u8_t, 10000);
  flea_u32_t cert_chain_len__u32;
  FLEA_THR_BEG_FUNC();
  cert_chain_len__u32 = flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt);
  // TODO: cert read stream
  FLEA_ALLOC_BUF(cert_chain__bu8, cert_chain_len__u32);

  FLEA_CCALL(
    THR_flea_rw_stream_t__force_read(
      flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt),
      cert_chain__bu8,
      cert_chain_len__u32
    )
  );
  // TODO: UNSAFE ARITHM, WILL BE REPLACED...:
  FLEA_CCALL(THR_verify_cert_chain(cert_chain__bu8 + 3, cert_chain_len__u32 - 3, pubkey));

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(cert_chain__bu8);
  );
}

flea_err_t THR_flea_tls__send_handshake_message_hdr(
  flea_tls_rec_prot_t* rec_prot__pt,
  flea_hash_ctx_t*     hash_ctx_mbn__pt,
  HandshakeType        type,
  flea_u32_t           content_len__u32
)
{
  flea_u8_t enc_for_hash__au8[4];

  FLEA_THR_BEG_FUNC();

  enc_for_hash__au8[0] = type;

  enc_for_hash__au8[1] = content_len__u32 >> 16;
  enc_for_hash__au8[2] = content_len__u32 >> 8;
  enc_for_hash__au8[3] = content_len__u32;
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__write_data(
      rec_prot__pt,
      CONTENT_TYPE_HANDSHAKE,
      enc_for_hash__au8,
      sizeof(enc_for_hash__au8)
    )
  );
  if(hash_ctx_mbn__pt)
  {
    FLEA_CCALL(THR_flea_hash_ctx_t__update(hash_ctx_mbn__pt, enc_for_hash__au8, sizeof(enc_for_hash__au8)));
  }
  FLEA_THR_FIN_SEC_empty();
}

/** master_secret = PRF(pre_master_secret, "master secret",
 *    ClientHello.random + ServerHello.random)
 *    [0..47];
 */
flea_err_t THR_flea_tls__create_master_secret(
  Random     client_hello_random,
  Random     server_hello_random,
  flea_u8_t* pre_master_secret,
  flea_u8_t* master_secret_res
)
{
  FLEA_DECL_BUF(random_seed__bu8, flea_u8_t, 64);
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(random_seed__bu8, 64);
  // flea_u8_t random_seed[64];
  memcpy(random_seed__bu8, client_hello_random.gmt_unix_time, 4);
  memcpy(random_seed__bu8 + 4, client_hello_random.random_bytes, 28);
  memcpy(random_seed__bu8 + 32, server_hello_random.gmt_unix_time, 4);
  memcpy(random_seed__bu8 + 36, server_hello_random.random_bytes, 28);

  // pre_master_secret is 48 bytes, master_secret is desired to be 48 bytes
  FLEA_CCALL(
    flea_tls__prf(
      pre_master_secret,
      48,
      PRF_LABEL_MASTER_SECRET,
      random_seed__bu8,
      64,
      48,
      master_secret_res
    )
  );
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL_SECRET_ARR(random_seed__bu8, 64);
  );
}

// TODO: configurable parameters
// TODO: ctor = handshake function
flea_err_t flea_tls_ctx_t__ctor(
  flea_tls_ctx_t*   ctx,
  flea_rw_stream_t* rw_stream__pt,
  flea_u8_t*        session_id,
  flea_u8_t         session_id_len
)
{
  FLEA_THR_BEG_FUNC();
  ctx->security_parameters = calloc(1, sizeof(flea_tls__security_parameters_t));
  ctx->rw_stream__pt       = rw_stream__pt;

  /* specify connection end */
  ctx->security_parameters->connection_end = FLEA_TLS_CLIENT;

  /* set TLS version */
  ctx->version.major = 0x03;
  ctx->version.minor = 0x03;

  FLEA_CCALL(THR_flea_tls_rec_prot_t__ctor(&ctx->rec_prot__t, ctx->version.major, ctx->version.minor, rw_stream__pt));
  /* set cipher suite values */
  flea_u8_t TLS_RSA_WITH_AES_256_CBC_SHA256[] = {0x00, 0x3D};

  ctx->allowed_cipher_suites = calloc(2, sizeof(flea_u8_t));
  memcpy(ctx->allowed_cipher_suites, TLS_RSA_WITH_AES_256_CBC_SHA256, 2);
  ctx->allowed_cipher_suites_len = 2;

  // CipherSuite TLS_NULL_WITH_NULL_NULL = { 0x00,0x00 };
  ctx->selected_cipher_suite[0] = 0x00;
  ctx->selected_cipher_suite[1] = 0x00;

  /* set SessionID */
  if(session_id_len > 32)
  {
    printf("max session id length: 32");
    FLEA_THROW("session id too large", FLEA_ERR_TLS_GENERIC);
  }
  memcpy(&ctx->session_id, session_id, session_id_len);
  ctx->session_id_len = session_id_len;

  /* set client_random */
  // TODO: do we need these parameters in the ctx? everything only needed during
  // handshake should be local to that function
  flea_rng__randomize(ctx->security_parameters->client_random.gmt_unix_time, 4); // TODO: check RFC for correct implementation - actual time?
  flea_rng__randomize(ctx->security_parameters->client_random.random_bytes, 28);

  /* set server random */
  flea_rng__randomize(ctx->security_parameters->server_random.gmt_unix_time, 4);
  flea_rng__randomize(ctx->security_parameters->server_random.random_bytes, 28);


  ctx->resumption = FLEA_FALSE;

  ctx->premaster_secret = calloc(256, sizeof(flea_u8_t));


  FLEA_THR_FIN_SEC_empty();
} /* flea_tls_ctx_t__ctor */

flea_err_t THR_flea_tls__send_record(
  flea_tls_ctx_t* tls_ctx,
  flea_u8_t*      bytes,
  flea_u16_t      bytes_len,
  ContentType     content_type
)
{
  FLEA_THR_BEG_FUNC();

  printf("send record called with %u bytes\n", bytes_len);
  FLEA_CCALL(THR_flea_tls_rec_prot_t__write_data(&tls_ctx->rec_prot__t, content_type, bytes, bytes_len));
#ifdef FLEA_TLS_SEND_RECORD_EAGER
  FLEA_CCALL(THR_flea_tls_rec_prot_t__write_flush(&tls_ctx->rec_prot__t));
#endif

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_record */

flea_err_t THR_flea_tls__send_alert(
  flea_tls_ctx_t*               tls_ctx,
  flea_tls__alert_description_t description,
  flea_tls__alert_level_t       level
)
{
  FLEA_THR_BEG_FUNC();

  flea_u8_t alert_bytes[2];
  alert_bytes[0] = level;
  alert_bytes[1] = description;

  FLEA_CCALL(THR_flea_tls__send_record(tls_ctx, alert_bytes, sizeof(alert_bytes), CONTENT_TYPE_ALERT));


  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls__send_handshake_message_content(
  flea_tls_rec_prot_t* rec_prot__pt,
  flea_hash_ctx_t*     hash_ctx_mbn__pt,
  flea_u8_t*           msg_bytes,
  flea_u32_t           msg_bytes_len
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__write_data(
      rec_prot__pt,
      CONTENT_TYPE_HANDSHAKE,
      msg_bytes,
      msg_bytes_len
    )
  );
  if(hash_ctx_mbn__pt)
  {
    FLEA_CCALL(THR_flea_hash_ctx_t__update(hash_ctx_mbn__pt, msg_bytes, msg_bytes_len));
  }
  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_flea_tls__send_handshake_message(
  flea_tls_rec_prot_t* rec_prot__pt,
  flea_hash_ctx_t*     hash_ctx_mbn__pt,
  HandshakeType        type,
  flea_u8_t*           msg_bytes,
  flea_u32_t           msg_bytes_len
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_tls__send_handshake_message_hdr(rec_prot__pt, hash_ctx_mbn__pt, type, msg_bytes_len));

  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(rec_prot__pt, hash_ctx_mbn__pt, msg_bytes, msg_bytes_len));
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_handshake_message */

flea_err_t THR_flea_tls__send_change_cipher_spec(
  flea_tls_ctx_t*  tls_ctx,
  flea_hash_ctx_t* hash_ctx
)
{
  FLEA_THR_BEG_FUNC();

  flea_u8_t css_bytes[1] = {1};

  FLEA_CCALL(THR_flea_tls__send_record(tls_ctx, css_bytes, sizeof(css_bytes), CONTENT_TYPE_CHANGE_CIPHER_SPEC));

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls__send_finished(
  flea_tls_ctx_t*  tls_ctx,
  flea_hash_ctx_t* hash_ctx
)
{
  FLEA_DECL_BUF(verify_data__bu8, flea_u8_t, 12 + 32);
  const flea_al_u8_t verify_data_len__alu8 = 12;
  flea_u8_t* messages_hash__pu8;
  PRFLabel label;

  FLEA_DECL_OBJ(hash_ctx_copy, flea_hash_ctx_t);
  FLEA_THR_BEG_FUNC();

  // compute hash over handshake messages so far and create struct
  FLEA_ALLOC_BUF(verify_data__bu8, verify_data_len__alu8 + 32);
  messages_hash__pu8 = verify_data__bu8 + verify_data_len__alu8;

  /*
   * use a copy of hash_ctx for send_finished instead of finalizing the original
   */
  FLEA_CCALL(THR_flea_hash_ctx_t__ctor_copy(&hash_ctx_copy, hash_ctx));
  FLEA_CCALL(THR_flea_hash_ctx_t__final(&hash_ctx_copy, messages_hash__pu8));

  // TODO: REMOVE LABEL ENUM, USE REF TO LABELS DIRECTLY
  if(tls_ctx->security_parameters->connection_end == FLEA_TLS_CLIENT)
  {
    label = PRF_LABEL_CLIENT_FINISHED;
  }
  else
  {
    label = PRF_LABEL_SERVER_FINISHED;
  }

  FLEA_CCALL(
    THR_flea_tls__create_finished_data(
      messages_hash__pu8,
      tls_ctx->security_parameters->master_secret,
      label,
      verify_data__bu8,
      verify_data_len__alu8
    )
  );

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message(
      &tls_ctx->rec_prot__t,
      hash_ctx,
      HANDSHAKE_TYPE_FINISHED,
      verify_data__bu8,
      12
    )
  );


  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL_SECRET_ARR(verify_data__bu8, 12);
    flea_hash_ctx_t__dtor(&hash_ctx_copy);
  );
} /* THR_flea_tls__send_finished */

static flea_err_t THR_flea_tls__send_server_hello(
  flea_tls_ctx_t*  tls_ctx,
  flea_hash_ctx_t* hash_ctx
)
{
  FLEA_THR_BEG_FUNC();

  // calculate length for the header
  // TODO: include cipher suites length instead of hard coded 2 (5+6th place)
  // TODO: include extensions length (last place)
  // TODO: change 4th element (32) to the real SessionID length

  flea_u32_t len = 2 + 32 + 1 + 32 + 2 + 1;
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_hdr(
      &tls_ctx->rec_prot__t,
      hash_ctx,
      HANDSHAKE_TYPE_SERVER_HELLO,
      len
    )
  );

  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, hash_ctx, &tls_ctx->version.major, 1));
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, hash_ctx, &tls_ctx->version.minor, 1));

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      hash_ctx,
      tls_ctx->security_parameters->client_random.gmt_unix_time,
      sizeof(tls_ctx->security_parameters->client_random.gmt_unix_time)
    )
  );
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      hash_ctx,
      tls_ctx->security_parameters->client_random.random_bytes,
      sizeof(tls_ctx->security_parameters->client_random.random_bytes)
    )
  );

  // TODO: actual implementation, e.g. support renegotiation
  flea_u8_t dummy_session_id_len = 32;
  flea_u8_t dummy_session_id[32];
  flea_rng__randomize(dummy_session_id, dummy_session_id_len);


  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, hash_ctx, &dummy_session_id_len, 1));
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      hash_ctx,
      dummy_session_id,
      dummy_session_id_len
    )
  );

  // TODO: hard coded
  flea_u8_t suite[] = {0x00, 0x3d};
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, hash_ctx, suite, 2));

  // We don't support compression
  flea_u8_t null_byte = 0;
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx->rec_prot__t, hash_ctx, &null_byte, 1));


  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_client_hello */

/**
 * Implementation note: Public-key-encrypted data is represented as an
 * opaque vector <0..2^16-1> (see Section 4.7).  Thus, the RSA-encrypted
 * PreMasterSecret in a ClientKeyExchange is preceded by two length
 * bytes.
 *
 * These bytes are redundant in the case of RSA because the
 * EncryptedPreMasterSecret is the only data in the ClientKeyExchange
 * and its length can therefore be unambiguously determined
 *
 * => send 2 length bytes
 */


void flea_tls__handshake_state_ctor(flea_tls__handshake_state_t* state)
{
  state->expected_messages = 0;
  state->finished         = FLEA_FALSE;
  state->initialized      = FLEA_FALSE;
  state->send_client_cert = FLEA_FALSE;
  state->sent_first_round = FLEA_FALSE;
}

flea_err_t THR_flea_tls__server_handshake(
  flea_tls_ctx_t*   tls_ctx,
  flea_rw_stream_t* rw_stream__pt,
  flea_ref_cu8_t*   cert_chain,
  flea_u32_t        cert_chain_len
)
{
  FLEA_THR_BEG_FUNC();

  // define and init state
  flea_tls__handshake_state_t handshake_state;
  flea_tls__handshake_state_ctor(&handshake_state);
  flea_hash_ctx_t hash_ctx;
  THR_flea_hash_ctx_t__ctor(&hash_ctx, flea_sha256); // TODO: initialize properly

  // flea_public_key_t pubkey; // TODO: -> tls_ctx

  // received records and handshakes for processing the current state
  HandshakeMessage recv_handshake;

  // set to true and wait for hello_client
  handshake_state.initialized       = FLEA_TRUE;
  handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CLIENT_HELLO;
  handshake_state.send_client_cert  = FLEA_FALSE; // TODO: implement client cert checking / certificate request

  while(handshake_state.finished != FLEA_TRUE)
  {
    /*
     * read next record
     */
    if(handshake_state.expected_messages != FLEA_TLS_HANDSHAKE_EXPECT_NONE)
    {
      ContentType cont_type__e;
      FLEA_CCALL(THR_flea_tls_rec_prot_t__get_current_record_type(&tls_ctx->rec_prot__t, &cont_type__e));

      // TODO: record type argument has to be removed because it's determined by the current connection state in tls_ctx
      if(cont_type__e == CONTENT_TYPE_HANDSHAKE)
      {
        FLEA_CCALL(THR_flea_tls__read_handshake_message(tls_ctx, &recv_handshake, &hash_ctx));
      }
      else if(cont_type__e == CONTENT_TYPE_CHANGE_CIPHER_SPEC)
      {
        if(handshake_state.expected_messages != FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC)
        {
          FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
        }
        else
        {
          /*
           * Enable encryption for incoming messages
           */
          // setup key material
          FLEA_CCALL(
            THR_flea_tls__create_master_secret(
              tls_ctx->security_parameters->client_random,
              tls_ctx->security_parameters->server_random,
              tls_ctx->premaster_secret,
              tls_ctx->security_parameters->master_secret
            )
          );
          FLEA_CCALL(THR_flea_tls__generate_key_block(tls_ctx, tls_ctx->key_block));

          // enable encryption for read direction
          FLEA_CCALL(
            THR_flea_tls_rec_prot_t__set_cbc_hmac_ciphersuite(
              &tls_ctx->rec_prot__t,
              flea_tls_read,
              flea_aes256,
              flea_sha256,
              flea_hmac_sha256,
              tls_ctx->key_block + 2 * 32 + 32,               /* cipher_key__pcu8, "2*32" = 2*mac key size, "+ 32" = cipher_key_size */
              32,                                             /* cipher_key_len */
              tls_ctx->key_block + 32 /* 32 = mac_key_size*/, /* mac_key__pcu8 */
              32 /*mac_key_len */,
              32 /* mac_len */
            )
          );


          handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_FINISHED;

          continue;
        }
      }
      else if(cont_type__e == CONTENT_TYPE_ALERT)
      {
        // TODO: handle alert message properly
        FLEA_THROW("Received unhandled alert", FLEA_ERR_TLS_GENERIC);
      }
      else
      {
        FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
      }
    }
    // We don't expect another message so it's our turn to continue
    else
    {
      if(handshake_state.sent_first_round == FLEA_FALSE)
      {
        FLEA_CCALL(THR_flea_tls__send_server_hello(tls_ctx, &hash_ctx));

        // send Certificate

        FLEA_CCALL(
          THR_flea_tls__send_handshake_message(
            &tls_ctx->rec_prot__t,
            &hash_ctx,
            HANDSHAKE_TYPE_SERVER_HELLO_DONE,
            (flea_u8_t*) NULL,
            0
          )
        );

        handshake_state.sent_first_round = FLEA_TRUE;
      }
      else
      {
        // send change_cipher_spec
        printf("SM: switching on encryption on write...\n");
        FLEA_CCALL(
          THR_flea_tls_rec_prot_t__set_cbc_hmac_ciphersuite(
            &tls_ctx->rec_prot__t,
            flea_tls_write,
            flea_aes256,
            flea_sha256,
            flea_hmac_sha256,
            tls_ctx->key_block + 2 * 32, /* cipher_key__pcu8, 32 = mac key size*/
            32,                          /* cipher_key_len */
            tls_ctx->key_block,          /* mac_key__pcu8 */
            32 /*mac_key_len */,
            32 /* mac_len */
          )
        );


        // send finished
        printf("sent finished\n");

        handshake_state.finished = FLEA_TRUE;


        /*
         * Enable encryption for outgoing messages
         */
      }

      continue;
    }

    if(handshake_state.expected_messages == FLEA_TLS_HANDSHAKE_EXPECT_CLIENT_HELLO)
    {
      if(recv_handshake.type == HANDSHAKE_TYPE_CLIENT_HELLO)
      {
        FLEA_CCALL(THR_flea_tls__read_client_hello(tls_ctx, &recv_handshake));
        handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_NONE;
      }
    }

    if(handshake_state.expected_messages == FLEA_TLS_HANDSHAKE_EXPECT_CLIENT_HELLO)
    {
      if(recv_handshake.type == HANDSHAKE_TYPE_CLIENT_HELLO)
      {
        FLEA_CCALL(THR_flea_tls__read_client_hello(tls_ctx, &recv_handshake));
      }
      else
      {
        FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
      }
    }

    if(handshake_state.expected_messages == FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE)
    {
      if(handshake_state.send_client_cert == FLEA_FALSE)
      {
        FLEA_THROW("Invalid state transition", FLEA_ERR_TLS_INVALID_STATE);
      }
      if(recv_handshake.type == (flea_u8_t) FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE)
      {
        FLEA_CCALL(THR_flea_tls__read_client_hello(tls_ctx, &recv_handshake));
      }
      else
      {
        FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
      }
    }
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__server_handshake */

flea_err_t THR_flea_tls__send_app_data(
  flea_tls_ctx_t* tls_ctx,
  flea_u8_t*      data,
  flea_u8_t       data_len
)
{
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_tls__send_record(tls_ctx, data, data_len, CONTENT_TYPE_APPLICATION_DATA));


  FLEA_THR_FIN_SEC_empty();
}
