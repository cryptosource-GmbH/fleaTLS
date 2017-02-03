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

#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h> // inet_addr
#include <unistd.h>    // for close

#include "flea/pubkey.h"
#include "flea/asn1_date.h"
#include "api/flea/cert_path.h"
#include "internal/common/ber_dec.h"
#include "flea/rng.h"
#include "flea/block_cipher.h"
#include "flea/bin_utils.h"

#include <stdio.h>


// CA cert to verify the server's certificate
flea_u8_t trust_anchor[] =
{ 0x30, 0x82, 0x03, 0x7f, 0x30, 0x82, 0x02, 0x67, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00, 0xfe, 0x12, 0x36,
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
  0x8f, 0x64, 0xba, 0x8e, 0xf1, 0x88 };

// TODO: MUST BE CONST
flea_tls__cipher_suite_t cipher_suites[2] = {
  { TLS_NULL_WITH_NULL_NULL,         (flea_block_cipher_id_t) 0,
    0, 0,
    0, 0, 0, (flea_mac_id_t) 0, (flea_hash_id_t) 0, (flea_tls__prf_algorithm_t) 0               },
  { TLS_RSA_WITH_AES_256_CBC_SHA256, flea_aes256,
    16, 16, 32, 32, 32, flea_hmac_sha256, flea_sha256, FLEA_TLS_PRF_SHA256          }
};


static flea_err_t P_Hash(
  const flea_u8_t *secret,
  flea_u16_t      secret_length,
  const flea_u8_t *label__pcu8,
  flea_al_u8_t    label_len__alu8,
  const flea_u8_t *seed,
  flea_u16_t      seed_length,
  flea_u8_t       *data_out,
  flea_u16_t      res_length
)
{
  const flea_u16_t hash_out_len__alu8 = 32;

  FLEA_DECL_BUF(a__bu8, flea_u8_t, 64);
  flea_u8_t *A;
  flea_u8_t *B;
  flea_u8_t *tmp__pu8;
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
        flea_hmac_sha256, secret, secret_length, A, hash_out_len__alu8, B,
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
  const flea_u8_t *secret,
  flea_u8_t       secret_length,
  PRFLabel        label,
  const flea_u8_t *seed,
  flea_u16_t      seed_length,
  flea_u16_t      result_length,
  flea_u8_t       *result
)
{
  FLEA_THR_BEG_FUNC();

  /**
   * TODO: no fixed sha256
   */
  const flea_u8_t client_finished[] = { 99, 108, 105, 101, 110, 116, 32, 102, 105, 110, 105, 115, 104, 101, 100 };
  const flea_u8_t server_finished[] = { 115, 101, 114, 118, 101, 114, 32, 102, 105, 110, 105, 115, 104, 101, 100 };
  const flea_u8_t master_secret[]   = { 109, 97, 115, 116, 101, 114, 32, 115, 101, 99, 114, 101, 116 };
  const flea_u8_t key_expansion[]   = { 107, 101, 121, 32, 101, 120, 112, 97, 110, 115, 105, 111, 110 };

  // TODO: REMOVE
  const flea_u8_t test_label[] = { 0x74, 0x65, 0x73, 0x74, 0x20, 0x6c, 0x61, 0x62, 0x65, 0x6c };

  const flea_u8_t *label__pcu8;
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
flea_err_t THR_flea_tls__generate_key_block(flea_tls_ctx_t *tls_ctx, flea_u8_t *key_block)
{
  FLEA_THR_BEG_FUNC();
  flea_u8_t seed[64];
  memcpy(seed, tls_ctx->security_parameters->server_random.gmt_unix_time, 4);
  memcpy(seed + 4, tls_ctx->security_parameters->server_random.random_bytes, 28);
  memcpy(seed + 32, tls_ctx->security_parameters->client_random.gmt_unix_time, 4);
  memcpy(seed + 36, tls_ctx->security_parameters->client_random.random_bytes, 28);

  FLEA_CCALL(
    flea_tls__prf(
      tls_ctx->security_parameters->master_secret, 48, PRF_LABEL_KEY_EXPANSION, seed, sizeof(seed),
      128, key_block
    )
  );
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls__compute_mac(
  flea_u8_t                    *data,
  flea_u32_t                   data_len,
  flea_tls__protocol_version_t *version,
  flea_mac_id_t                mac_algorithm,
  flea_u8_t                    *mac_key,
  flea_u8_t                    mac_key_len,
  const flea_u8_t              sequence_number__au8[8],
  ContentType                  content_type,
  flea_u8_t                    *mac_out,
  flea_u8_t                    *mac_len_out
)
{
  flea_mac_ctx_t mac__t = flea_mac_ctx_t__INIT_VALUE;

  FLEA_THR_BEG_FUNC();

  /*
   * MAC(MAC_write_key, seq_num +
   *                      TLSCompressed.type +
   *                      TLSCompressed.version +
   *                      TLSCompressed.length +
   *                      TLSCompressed.fragment);
   */
  // 8 + 1 + (1+1) + 2 + length


  flea_u32_t mac_data_len = 13 + data_len;
  flea_u8_t mac_data[FLEA_TLS_MAX_RECORD_DATA_SIZE];

  // FLEA_CCALL(THR_flea_mac_ctx_t__ctor(&mac__t, mac_algorithm, secret, secret_length));

  // memcpy(mac_data, &sequence_number, 8);
  memcpy(mac_data, sequence_number__au8, 8);
  mac_data[8]  = content_type;
  mac_data[9]  = version->major;
  mac_data[10] = version->minor;

  /*mac_data[11] = ((flea_u8_t*)&data_len)[1];	// TODO: do properly
   * mac_data[12] = ((flea_u8_t*)&data_len)[0];*/
  mac_data[11] = data_len >> 8;
  mac_data[12] = data_len;
  memcpy(mac_data + 13, data, data_len);
  flea_al_u8_t mac_len_out_al = *mac_len_out;

  FLEA_CCALL(
    THR_flea_mac__compute_mac(
      mac_algorithm, mac_key, mac_key_len, mac_data, mac_data_len, mac_out,
      &mac_len_out_al
    )
  );

  FLEA_THR_FIN_SEC(
    flea_mac_ctx_t__dtor(&mac__t);
  );
} /* THR_flea_tls__compute_mac */

static void inc_seq_nbr(flea_u32_t *seq__au32)
{
  seq__au32[0]++;
  if(seq__au32[0] == 0)
  {
    seq__au32[1]++;
  }
}

flea_err_t THR_flea_tls__decrypt_record(flea_tls_ctx_t *tls_ctx, Record *record)
{
  flea_u32_t seq_lo__u32, seq_hi__u32;
  flea_u8_t enc_seq_nbr__au8[8];

  FLEA_THR_BEG_FUNC();
  // TODO: this is for client connection end. need other keys for server connection end
  flea_u8_t *mac_key    = tls_ctx->active_read_connection_state->mac_key;
  flea_u8_t *enc_key    = tls_ctx->active_read_connection_state->enc_key;
  flea_u8_t iv_len      = tls_ctx->active_read_connection_state->cipher_suite->iv_size;
  flea_u8_t mac_len     = tls_ctx->active_read_connection_state->cipher_suite->mac_size;
  flea_u8_t mac_key_len = tls_ctx->active_read_connection_state->cipher_suite->mac_key_size;
  flea_u8_t enc_key_len = tls_ctx->active_read_connection_state->cipher_suite->enc_key_size;
  flea_u8_t mac[FLEA_TLS_MAX_MAC_SIZE];
  flea_u8_t iv[FLEA_TLS_MAX_IV_SIZE];
  seq_lo__u32 = tls_ctx->active_read_connection_state->sequence_number__au32[0];
  seq_hi__u32 = tls_ctx->active_read_connection_state->sequence_number__au32[1];
  inc_seq_nbr(tls_ctx->active_read_connection_state->sequence_number__au32);
  // TODO: was ist mit SEQ overflow?
  flea__encode_U32_BE(seq_lo__u32, enc_seq_nbr__au8 + 4);
  flea__encode_U32_BE(seq_hi__u32, enc_seq_nbr__au8);

  /*
   * First decrypt
   */

  // TODO: can read and write from/in the same buffer?
  FLEA_CCALL(
    THR_flea_cbc_mode__decrypt_data(
      tls_ctx->active_read_connection_state->cipher_suite->cipher, enc_key,
      enc_key_len, iv, iv_len, record->data, record->data, record->length
    )
  );


  /*
   * Remove padding and read IV
   */
  flea_u8_t padding_len = record->data[record->length - 1];
  memcpy(iv, record->data, iv_len);

  /*
   * Check MAC
   */
  flea_u8_t in_out_mac_len = mac_len;
  flea_u16_t data_len      = record->length - (padding_len + 1) - iv_len - mac_len;
  FLEA_CCALL(
    THR_flea_tls__compute_mac(
      record->data + iv_len, data_len, &tls_ctx->version,
      tls_ctx->active_read_connection_state->cipher_suite->mac_algorithm, mac_key, mac_key_len, enc_seq_nbr__au8,
      record->content_type, mac, &in_out_mac_len
    )
  );

  if(!flea_sec_mem_equal(mac, record->data + iv_len + data_len, mac_len))
  {
    printf("MAC does not match!\n");
    FLEA_THROW("MAC failure", FLEA_ERR_TLS_GENERIC);
  }

  /*
   * adjust record
   */
  memmove(record->data, record->data + iv_len, data_len);
  record->length = data_len;

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__decrypt_record */

/**
 * TODO: fragmentation
 * Reads in the record - "Header Data" is copied to the struct fields and the data is copied to a new location
 */
flea_err_t THR_flea_tls__read_record(
  flea_tls_ctx_t *tls_ctx,
  flea_u8_t      *buff,
  flea_u32_t     buff_len,
  Record         *record,
  flea_u32_t     *bytes_left
)
{
  FLEA_THR_BEG_FUNC();
  flea_u32_t i = 0;

  // TODO: if we support ciphers without encryption: need to adjust
  if(tls_ctx->active_read_connection_state->cipher_suite->id == TLS_NULL_WITH_NULL_NULL)
  {
    record->record_type = RECORD_TYPE_PLAINTEXT;
  } else
  {
    record->record_type = RECORD_TYPE_CIPHERTEXT;
  }

  /*
   * read data into record struct
   */

  if(buff_len < 5)
  {
    // printf("Record too short!\n");
    FLEA_THROW("record length too short", FLEA_ERR_TLS_GENERIC);
  }

  record->content_type = buff[i++];

  record->version.major = buff[i++];
  record->version.minor = buff[i++];

  // TODO: have to allow several TLS versions, maybe use <, <=, >, >= instead of ==, !=
  if(record->version.minor != tls_ctx->version.minor && record->version.major != tls_ctx->version.major)
  {
    FLEA_THROW("version mismatch", FLEA_ERR_TLS_GENERIC);
  }

  record->length  = buff[i++] << 8;
  record->length |= buff[i++];


  // need more data?
  if(record->length > buff_len - i)
  {
    // TODO: READ MORE DATA
    printf("Record Fragmenting not yet supported!\n");
    FLEA_THROW("Not Yet Implemented", FLEA_ERR_TLS_GENERIC);
  }
  // TODO: IF record-length > max_rec_len, then error
  // everything else is the record content
  record->data = calloc(record->length, sizeof(flea_u8_t));
  memcpy(record->data, buff + i, record->length);
  i += record->length;

  // *bytes_left = buff_len - i;
  *bytes_left = *bytes_left - i;

  /*
   * decrypt data if encrypted
   */
  if(record->record_type == RECORD_TYPE_CIPHERTEXT)
  {
    FLEA_CCALL(THR_flea_tls__decrypt_record(tls_ctx, record));
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__read_record */

flea_err_t THR_flea_tls__create_finished_data(
  flea_u8_t *messages_hash,
  flea_u8_t master_secret[48],
  PRFLabel  label,
  flea_u8_t *data,
  flea_u8_t data_len
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(flea_tls__prf(master_secret, 48, label, messages_hash, 32, data_len, data));
  FLEA_THR_FIN_SEC_empty();
}

/*
 * typedef struct {
 * flea_u8_t* verify_data;
 * flea_u16_t verify_data_length;	// 12 for all cipher suites defined in TLS 1.2 - RFC 5246
 * } Finished;
 *
 * PRF(master_secret, finished_label, Hash(handshake_messages))
 *  [0..verify_data_length-1];
 */

#if 0
flea_err_t THR_flea_tls__create_finished_message_with_12_bytes_verify_data(
  flea_u8_t *messages_hash,
  flea_u8_t master_secret[48],
  PRFLabel  label,
  flea_u8_t *result_12_bytes_len__pu8
  // flea_tls__finished_t *finished_message
)
{
  FLEA_THR_BEG_FUNC();

  /*finished_message->verify_data_length = 12; // 12 octets for all cipher suites defined in RFC 5246
   * finished_message->verify_data        = calloc(finished_message->verify_data_length, sizeof(flea_u8_t));
   */

  FLEA_CCALL(
    THR_flea_tls__create_finished_data(
      messages_hash, master_secret, label, result_12_bytes_len__pu8, 12
    )
  );
  FLEA_THR_FIN_SEC_empty();
}

#endif /* if 0 */
flea_err_t THR_flea_tls__read_handshake_message(Record *record, HandshakeMessage *handshake_msg)
{
  FLEA_THR_BEG_FUNC();
  if(record->length < 4)
  {
    FLEA_THROW("length too small", FLEA_ERR_TLS_GENERIC);
  }

  handshake_msg->type = record->data[0];

  flea_u8_t *p = (flea_u8_t *) &handshake_msg->length;
  p[3] = 0;
  p[2] = record->data[1];
  p[1] = record->data[2];
  p[0] = record->data[3];

  if(handshake_msg->length < record->length - 4)
  {
    FLEA_THROW("length incorrect", FLEA_ERR_TLS_GENERIC);
  }

  if(handshake_msg->length > record->length - 4)
  {
    // TODO: indicate somehow that this record is missing X byte and the handshake message is continuing in the next record
    // TODO: Check if necessary or done before this is called
  }
  handshake_msg->data = calloc(record->length - 4, sizeof(flea_u8_t));
  memcpy(handshake_msg->data, record->data + 4, sizeof(flea_u8_t) * (record->length - 4));
  FLEA_THR_FIN_SEC_empty();
}


flea_err_t THR_flea_tls__read_client_hello(flea_tls_ctx_t *tls_ctx, HandshakeMessage *handshake_msg)
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
  flea_u8_t *p = (flea_u8_t *) tls_ctx->security_parameters->client_random.gmt_unix_time;
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
    } else
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
  flea_u8_t i = 0;
  flea_u8_t j;
  flea_bool_t found = FLEA_FALSE;
  while(i < cipher_suites_len / 2)
  {
    j = 0;
    while(j < sizeof(cipher_suites))
    {
      if(memcmp(&cipher_suites[j], &handshake_msg->data[2 * i], 2) == 0)
      {
        memcpy(tls_ctx->selected_cipher_suite, &handshake_msg->data[2 * i], 2);
        break;
      }
      j++;
    }
    i++;
  }
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
  if(len + cipher_suites_len > handshake_msg->length || cipher_suites_len % 2 != 0)
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


/*
 * typedef struct {
 * ProtocolVersion server_version;
 * Random random;
 * SessionID session_id;
 * flea_u8_t* cipher_suites;
 * flea_u16_t cipher_suites_length;
 * CompressionMethod compression_method;
 * flea_u8_t* extensions;	// 2^16 bytes
 * } ServerHello;
 */
flea_err_t THR_flea_tls__read_server_hello(
  flea_tls_ctx_t   *tls_ctx,
  HandshakeMessage *handshake_msg,
  ServerHello      *server_hello
)
{
  FLEA_THR_BEG_FUNC();
  if(handshake_msg->length < 41) // min ServerHello length
  {
    FLEA_THROW("length too small", FLEA_ERR_TLS_GENERIC);
  }

  // keep track of length
  int length = 0;

  // read version
  server_hello->server_version.major = handshake_msg->data[length++];
  server_hello->server_version.minor = handshake_msg->data[length++];

  // TODO: in this part the client has to decide if he accepts the server's TLS version - implement negotiation
  if(server_hello->server_version.major != tls_ctx->version.major ||
    server_hello->server_version.minor != tls_ctx->version.minor)
  {
    FLEA_THROW("version mismatch", FLEA_ERR_TLS_GENERIC);
  }

  // read random
  flea_u8_t *p = (flea_u8_t *) server_hello->random.gmt_unix_time;
  for(flea_u8_t i = 0; i < 4; i++)
  {
    p[i] = handshake_msg->data[length++];
  }
  p = server_hello->random.random_bytes;
  for(flea_u8_t i = 0; i < 28; i++)
  {
    p[i] = handshake_msg->data[length++];
  }

  // read session id length
  server_hello->session_id_length = handshake_msg->data[length++];
  if(server_hello->session_id_length > 0)
  {
    server_hello->session_id = calloc(server_hello->session_id_length, sizeof(flea_u8_t));
    p = (flea_u8_t *) server_hello->session_id;
    for(flea_u8_t i = 0; i < server_hello->session_id_length; i++)
    {
      p[i] = handshake_msg->data[length++];
    }
  }

  if(length + 3 > handshake_msg->length)
  {
    FLEA_THROW("length incorrect", FLEA_ERR_TLS_GENERIC);
  }

  // read cipher suites
  p    = (flea_u8_t *) &server_hello->cipher_suite;
  p[0] = handshake_msg->data[length++];
  p[1] = handshake_msg->data[length++];

  // read compression method
  server_hello->compression_method = handshake_msg->data[length++];

  // TODO: parse extension
  // for now simply ignore them

  // update security parameters
  memcpy(
    tls_ctx->security_parameters->server_random.gmt_unix_time, server_hello->random.gmt_unix_time,
    sizeof(tls_ctx->security_parameters->server_random.gmt_unix_time)
  ); // QUESTION: sizeof durch variablen (#define) ersetzen?
  memcpy(
    tls_ctx->security_parameters->server_random.random_bytes, server_hello->random.random_bytes,
    sizeof(tls_ctx->security_parameters->server_random.random_bytes)
  );

  // client wants to resume connection and has provided a session id
  if(tls_ctx->session_id_len != 0)
  {
    if(tls_ctx->session_id_len == server_hello->session_id_length)
    {
      if(memcmp(tls_ctx->session_id, server_hello->session_id, tls_ctx->session_id_len) == 0)
      {
        tls_ctx->resumption = FLEA_TRUE;
      }
    }
  }
  memcpy(tls_ctx->session_id, server_hello->session_id, server_hello->session_id_length);

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__read_server_hello */

flea_err_t THR_flea_tls__read_finished(
  flea_tls_ctx_t   *tls_ctx,
  flea_hash_ctx_t  *hash_ctx,
  HandshakeMessage *handshake_msg
)
{
  FLEA_THR_BEG_FUNC();

  // compute hash over handshake messages so far
  flea_u8_t messages_hash[32];
  FLEA_CCALL(THR_flea_hash_ctx_t__final(hash_ctx, messages_hash));


  PRFLabel label;
  if(tls_ctx->security_parameters->connection_end == FLEA_TLS_CLIENT)
  {
    label = PRF_LABEL_SERVER_FINISHED;
  } else
  {
    label = PRF_LABEL_CLIENT_FINISHED;
  }
  // TODO: need to generalize 12byte ? (botan doesn't do it either) -  avoiding "magical number" would be better
  flea_u8_t finished_len = 12;
  flea_u8_t *finished    = calloc(finished_len, sizeof(flea_u8_t));

  FLEA_CCALL(
    THR_flea_tls__create_finished_data(
      messages_hash, tls_ctx->security_parameters->master_secret, label,
      finished, finished_len
    )
  );

  if(finished_len == handshake_msg->length)
  {
    if(memcmp(handshake_msg->data, finished, finished_len) != 0)
    {
      printf("Finished message not verifiable\n");
      printf("Got: \n");
      for(int i = 0; i < 12; i++)
      {
        printf("%02x ", handshake_msg->data[i]);
      }
      printf("\nBut calculated: \n");
      for(int i = 0; i < 12; i++)
      {
        printf("%02x ", finished[i]);
      }
      printf("\n");

      FLEA_THROW("Finished message not verifiable", FLEA_ERR_TLS_GENERIC);
    }
  } else
  {
    FLEA_THROW("Finished message not verifiable", FLEA_ERR_TLS_GENERIC);
  }


  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__read_finished */

flea_err_t THR_verify_cert_chain(flea_u8_t *tls_cert_chain__acu8, flea_u32_t length, flea_public_key_t *pubkey__t)
{
  FLEA_DECL_OBJ(cert_chain__t, flea_cert_path_validator_t);
  const flea_u8_t date_str[] = "170228200000Z"; // TODO: datumsfunktion aufrufen
  flea_gmt_time_t time__t;
  flea_bool_t first__b = FLEA_TRUE;
  flea_err_t err;
  const flea_u8_t *ptr = tls_cert_chain__acu8;
  flea_al_u16_t len    = length;

  FLEA_THR_BEG_FUNC();

  while(len > 3)
  {
    FLEA_DECL_OBJ(ref__t, flea_x509_cert_ref_t);
    flea_u32_t new_len = ((flea_u32_t) ptr[0] << 16) | (ptr[1] << 8) | (ptr[2]);
    ptr += 3;
    len -= 3;
    if(new_len > len)
    {
      FLEA_THROW("invalid cert chain length", FLEA_ERR_INV_ARG);
    }
    FLEA_CCALL(THR_flea_x509_cert_ref_t__ctor(&ref__t, ptr, new_len));
    ptr += new_len;
    len -= new_len;
    if(first__b)
    {
      FLEA_CCALL(THR_flea_cert_path_validator_t__ctor_cert_ref(&cert_chain__t, &ref__t));
      first__b = FLEA_FALSE;
    } else
    {
      FLEA_CCALL(THR_flea_cert_path_validator_t__add_cert_ref_without_trust_status(&cert_chain__t, &ref__t));
    }
  }

  FLEA_CCALL(THR_flea_asn1_parse_utc_time(date_str, sizeof(date_str) - 1, &time__t));


  // add trust anchor
  FLEA_DECL_OBJ(trust_ref__t, flea_x509_cert_ref_t);
  err = THR_flea_x509_cert_ref_t__ctor(&trust_ref__t, trust_anchor, sizeof(trust_anchor));
  err = THR_flea_cert_path_validator_t__add_trust_anchor_cert_ref(&cert_chain__t, &trust_ref__t);

  flea_cert_path_validator_t__disable_revocation_checking(&cert_chain__t);
  err =
    THR_flea_cert_path_validator__build_and_verify_cert_chain_and_create_pub_key(&cert_chain__t, &time__t, pubkey__t);

  /* TODO: make test cases to check that this works as intended */
  if(err)
  {
    FLEA_THROW("failed to verify chain!", FLEA_ERR_CERT_PATH_NOT_FOUND);
  }

  FLEA_THR_FIN_SEC(
    flea_cert_path_validator_t__dtor(&cert_chain__t);
  );
} /* THR_verify_cert_chain */

flea_err_t THR_flea_tls__read_certificate(
  flea_tls_ctx_t    *tls_ctx,
  HandshakeMessage  *handshake_msg,
  Certificate       *cert_message,
  flea_public_key_t *pubkey
)
{
  FLEA_THR_BEG_FUNC();

  // TODO: do properly and read the 3 length bytes in instead of skipping them
  cert_message->certificate_list_length = handshake_msg->length - 3;

  cert_message->certificate_list = calloc(cert_message->certificate_list_length, sizeof(flea_u8_t));

  memcpy(cert_message->certificate_list, handshake_msg->data + 3, cert_message->certificate_list_length);

  FLEA_CCALL(THR_verify_cert_chain(cert_message->certificate_list, cert_message->certificate_list_length, pubkey));

  FLEA_THR_FIN_SEC_empty();
}

/**
 * Variable-length vectors are defined by specifying a subrange of legal
 * lengths, inclusively, using the notation <floor..ceiling>.  When
 * these are encoded, the actual length precedes the vector's contents
 * in the byte stream.
 */
void flea_tls__client_hello_to_bytes(flea_tls__client_hello_t *hello, flea_u8_t *bytes, flea_u32_t *length)
{
  flea_u16_t i = 0;

  memcpy(bytes, &hello->client_version.major, sizeof(flea_u8_t));
  i += sizeof(flea_u8_t);
  memcpy(bytes + i, &hello->client_version.minor, sizeof(flea_u8_t));
  i += sizeof(flea_u8_t);

  memcpy(bytes + i, hello->random.gmt_unix_time, sizeof(flea_u32_t));
  i += sizeof(flea_u32_t);
  memcpy(bytes + i, hello->random.random_bytes, 28);
  i += 28;

  flea_bool_t session_id_greater_0 = FLEA_FALSE;
  for(flea_u8_t j = 0; i < 32; j++)
  {
    if(hello->session_id[j] != 0)
    {
      session_id_greater_0 = FLEA_TRUE;
    }
  }
  if(session_id_greater_0 == FLEA_TRUE)
  {
    bytes[i++] = hello->session_id_length;
    memcpy(bytes + i, hello->session_id, hello->session_id_length);
    i += hello->session_id_length;
  } else
  {
    bytes[i++] = 0;
  }

  // cipher suites length
  flea_u8_t *p = (flea_u8_t *) &hello->cipher_suites_length;
  bytes[i++] = p[1];
  bytes[i++] = p[0];

  for(flea_u8_t j = 0; j < hello->cipher_suites_length / 2; j++)
  {
    bytes[i++] = hello->cipher_suites[2 * j];
    bytes[i++] = hello->cipher_suites[2 * j + 1];
  }

  flea_u8_t len = hello->compression_methods_length / sizeof(hello->compression_methods[0]);
  bytes[i++] = len;
  for(flea_u8_t j = 0; j < len; j++)
  {
    bytes[i++] = (flea_u8_t) hello->compression_methods[j]; // convert enum (usually 4byte int but only holding values <=255) to byte
  }

  *length = i;
} /* flea_tls__client_hello_to_bytes */

flea_err_t THR_flea_tls__send_handshake_message_hdr(
  HandshakeType    type,
  flea_u32_t       content_len__u32,
  flea_rw_stream_t *rw_stream__pt,
  flea_hash_ctx_t  *hash_ctx__pt,
  flea_mac_ctx_t   *mac_ctx__pt
)
{
  flea_u8_t enc_for_hash__au8[4];

  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_rw_stream_t__write_byte(rw_stream__pt, type));
  enc_for_hash__au8[0] = type;

  FLEA_CCALL(THR_flea_rw_stream_t__write_u32_be(rw_stream__pt, content_len__u32, 3));
  enc_for_hash__au8[1] = content_len__u32 >> 16;
  enc_for_hash__au8[2] = content_len__u32 >> 8;
  enc_for_hash__au8[3] = content_len__u32;

  // TODO: MAKE HASH STREAM AND FUNCTION WHICH WRITE THE SAME DATA TO TWO STREAMS
  // (CONSIDER A TEE-OBJECTS, BUT THIS IS OVERDOING HERE MOST PROBABLY)
  FLEA_CCALL(THR_flea_hash_ctx_t__update(hash_ctx__pt, enc_for_hash__au8, sizeof(enc_for_hash__au8)));
  if(mac_ctx__pt)
  {
    FLEA_CCALL(THR_flea_mac_ctx_t__update(mac_ctx__pt, enc_for_hash__au8, sizeof(enc_for_hash__au8)));
  }
  FLEA_THR_FIN_SEC_empty();

  /*  out[i++] = type;
   *
   * // set handshake length
   * out[i++] = length_in >> 16;
   * out[i++] = length_in >> 8;
   * out[i++] = length_in;*/

  // copy all data
}

void flea_tls__create_handshake_message(
  HandshakeType type,
  flea_u8_t     *in,
  flea_u32_t    length_in,
  flea_u8_t     *out,
  flea_u32_t    *length_out
)
{
  flea_u32_t i = 0;

  // TODO: keine Längenprüfung nötig?
  // set handshake type
  out[i++] = type;

  // set handshake length
  out[i++] = length_in >> 16;
  out[i++] = length_in >> 8;
  out[i++] = length_in;

  // copy all data
  memcpy(out + i, in, length_in);
  i += length_in;

  *length_out = i;
}

void flea_tls__record_to_bytes(Record *record, flea_u8_t *bytes, flea_u16_t *length)
{
  flea_u16_t i = 0;

  bytes[i++] = record->content_type;
  bytes[i++] = record->version.major;
  bytes[i++] = record->version.minor;

  bytes[i++] = record->length >> 8;
  bytes[i++] = record->length;

  memcpy(bytes + i, record->data, record->length);
  i += record->length;

  *length = i;
}

void flea_tls__print_client_hello(flea_tls__client_hello_t hello)
{
  printf("\nPrinting ClientHello Struct\n");
  printf("Protocol Version major, minor: %i, %i\n", hello.client_version.major, hello.client_version.minor);

  printf("Random: \n");
  printf("\n\tUnix time ");
  for(int i = 0; i < 4; i++)
  {
    printf("%02x ", hello.random.gmt_unix_time[i]);
  }
  printf("\n\trandom bytes ");
  for(int i = 0; i < 28; i++)
  {
    printf("%02x ", hello.random.random_bytes[i]);
  }
  printf("\nSessionID: \n");
  for(flea_u8_t i = 0; i < hello.session_id_length; i++)
  {
    printf("%02x ", hello.session_id[i]);
  }

  printf("\nCipher Suites: ");
  for(flea_u8_t i = 0; i < hello.cipher_suites_length / 2; i += 2)
  {
    printf("(%02x, %02x) ", hello.cipher_suites[i], hello.cipher_suites[i + 1]);
  }

  printf("\nCompression Methods: ");
  for(flea_u8_t i = 0; i < hello.compression_methods_length; i++)
  {
    printf("%02x ", hello.compression_methods[i]);
  }
} /* flea_tls__print_client_hello */

void print_server_hello(ServerHello hello)
{
  printf("\nPrinting ServerHello Struct\n");
  printf("Protocol Version major, minor: %i, %i\n", hello.server_version.major, hello.server_version.minor);

  printf("Random: \n");
  printf("\n\tUnix time ");
  for(int i = 0; i < 4; i++)
  {
    printf("%02x ", hello.random.gmt_unix_time[i]);
  }
  printf("\n\trandom bytes ");
  for(int i = 0; i < 28; i++)
  {
    printf("%02x ", hello.random.random_bytes[i]);
  }
  printf("\nSessionID: \n");
  for(flea_u8_t i = 0; i < hello.session_id_length; i++)
  {
    printf("%02x ", hello.session_id[i]);
  }
  printf("\nCipher Suite: ");
  flea_u8_t *p = (flea_u8_t *) &hello.cipher_suite;
  printf("(%02x, %02x) ", p[0], p[1]);

  printf("\nCompression Method: ");
  printf("%02x ", hello.compression_method);
}

/**
 * Implementation note: Public-key-encrypted data is represented as an
 * opaque vector <0..2^16-1> (see Section 4.7).  Thus, the RSA-encrypted
 * PreMasterSecret in a ClientKeyExchange is preceded by two length
 * bytes.
 *
 * These bytes are redundant in the case of RSA because the
 * EncryptedPreMasterSecret is the only data in the ClientKeyExchange
 * and its length can therefore be unambiguously determined
 */
flea_err_t THR_flea_tls__create_client_key_exchange(
  flea_tls_ctx_t            *tls_ctx,
  flea_public_key_t         *pubkey,
  flea_tls__client_key_ex_t *key_ex
)
{
  flea_u8_t premaster_secret[48];

  FLEA_THR_BEG_FUNC();

  premaster_secret[0] = 3;
  premaster_secret[1] = 3;
  key_ex->algorithm   = KEY_EXCHANGE_ALGORITHM_RSA;

  // random 46 bit
  flea_rng__randomize(premaster_secret + 2, 46);

  tls_ctx->premaster_secret[0] = tls_ctx->version.major;
  tls_ctx->premaster_secret[1] = tls_ctx->version.minor;
  // flea_rng__randomize(tls_ctx->premaster_secret+2, 46);
  memcpy(tls_ctx->premaster_secret + 2, premaster_secret + 2, 46);

  memcpy(key_ex->premaster_secret, premaster_secret, 48);

  /**
   *   RSA encryption is done using the RSAES-PKCS1-v1_5 encryption scheme
   *   https://tools.ietf.org/html/rfc3447#section-7.2
   */

  // pubkey->key_bit_size__u16
  flea_al_u16_t result_len = 256;
  flea_u8_t buf[256];
  // THR_flea_public_key_t__encrypt_message(*key__pt, pk_scheme_id__t, hash_id__t, message__pcu8, message_len__alu16, result__pu8, result_len__palu16);
  FLEA_CCALL(
    THR_flea_public_key_t__encrypt_message(
      pubkey, flea_rsa_pkcs1_v1_5_encr, 0, premaster_secret,
      sizeof(premaster_secret), buf, &result_len
    )
  );

  key_ex->encrypted_premaster_secret = calloc(result_len, sizeof(flea_u8_t));
  memcpy(key_ex->encrypted_premaster_secret, buf, result_len);
  key_ex->encrypted_premaster_secret_length = result_len;

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__create_client_key_exchange */

void flea_tls__client_key_exchange_to_bytes(flea_tls__client_key_ex_t *key_ex, flea_u8_t *bytes, flea_u32_t *length)
{
  flea_u16_t i = 0;
  flea_u8_t *p = (flea_u8_t *) &key_ex->encrypted_premaster_secret_length;

  bytes[i++] = p[1];
  bytes[i++] = p[0];

  for(flea_u16_t j = 0; j < key_ex->encrypted_premaster_secret_length; j++)
  {
    bytes[i++] = key_ex->encrypted_premaster_secret[j];
  }

  *length = i;
}

/*void flea_tls__finished_to_bytes(flea_tls__finished_t *finished, flea_u8_t *bytes, flea_u32_t *length)
 * {
 * flea_u32_t i = 0;
 *
 * for(flea_u32_t j = 0; j < finished->verify_data_length; j++)
 * {
 *  bytes[i++] = finished->verify_data[j];
 * }
 *
 * length = i;
 * }*/

void flea_tls__create_hello_message(flea_tls_ctx_t *tls_ctx, flea_tls__client_hello_t *hello)
{
  hello->client_version.major = tls_ctx->version.major;
  hello->client_version.minor = tls_ctx->version.minor;

  // session ID empty => no resumption (new handshake negotiation)
  hello->session_id = calloc(tls_ctx->session_id_len, sizeof(flea_u8_t));
  memcpy(hello->session_id, tls_ctx->session_id, tls_ctx->session_id_len);

  memcpy(
    hello->random.gmt_unix_time, tls_ctx->security_parameters->client_random.gmt_unix_time,
    sizeof(tls_ctx->security_parameters->client_random.gmt_unix_time)
  ); // QUESTION: sizeof durch variablen (#define) ersetzen?
  memcpy(
    hello->random.random_bytes, tls_ctx->security_parameters->client_random.random_bytes,
    sizeof(tls_ctx->security_parameters->client_random.random_bytes)
  );

  hello->cipher_suites        = tls_ctx->allowed_cipher_suites;
  hello->cipher_suites_length = tls_ctx->allowed_cipher_suites_len;

  hello->compression_methods        = tls_ctx->security_parameters->compression_methods;
  hello->compression_methods_length = tls_ctx->security_parameters->compression_methods_len;
}

flea_err_t THR_flea_tls__encrypt_record(flea_tls_ctx_t *tls_ctx, Record *record, flea_u8_t *data, flea_u32_t data_len)
{
  flea_u32_t seq_lo__u32, seq_hi__u32;
  flea_u8_t enc_seq_nbr__au8[8];

  FLEA_THR_BEG_FUNC();

  // TODO: this is for client connection end. need other keys for server connection end
  flea_u8_t *mac_key    = tls_ctx->active_write_connection_state->mac_key;
  flea_u8_t *enc_key    = tls_ctx->active_write_connection_state->enc_key;
  flea_u8_t iv_len      = tls_ctx->active_write_connection_state->cipher_suite->iv_size;
  flea_u8_t mac_len     = tls_ctx->active_write_connection_state->cipher_suite->mac_size;
  flea_u8_t mac_key_len = tls_ctx->active_write_connection_state->cipher_suite->mac_key_size;
  flea_u8_t enc_key_len = tls_ctx->active_write_connection_state->cipher_suite->enc_key_size;
  flea_u8_t mac[FLEA_TLS_MAX_MAC_SIZE];
  flea_u8_t iv[FLEA_TLS_MAX_IV_SIZE];
  flea_u8_t block_len = tls_ctx->active_write_connection_state->cipher_suite->block_size;

  seq_lo__u32 = tls_ctx->active_write_connection_state->sequence_number__au32[0];
  seq_hi__u32 = tls_ctx->active_write_connection_state->sequence_number__au32[1];
  // TODO: put back in
  // inc_seq_nbr(tls_ctx->active_write_connection_state->sequence_number__au32);

  // TODO: was ist mit SEQ overflow? => reneg. implement
  flea__encode_U32_BE(seq_lo__u32, enc_seq_nbr__au8 + 4);
  flea__encode_U32_BE(seq_hi__u32, enc_seq_nbr__au8);
  // compute mac
  FLEA_CCALL(
    THR_flea_tls__compute_mac(
      data, data_len, &tls_ctx->version,
      tls_ctx->active_write_connection_state->cipher_suite->mac_algorithm, mac_key, mac_key_len, enc_seq_nbr__au8,
      record->content_type, mac, &mac_len
    )
  );

  // compute IV ... TODO: xor with last plaintext block? -> RFC

  /*
   * Initialization Vector (IV)
   *  When a block cipher is used in CBC mode, the initialization vector
   *  is exclusive-ORed with the first plaintext block prior to
   *  encryption.
   */
  flea_rng__randomize(iv, iv_len);

  // compute padding
  // TODO: 2x % block_len => was war beabsichtigt?
  // flea_u8_t padding_len = (block_len - (data_len + mac_len + 1) % block_len) % block_len + 1;	// +1 for padding_length entry
  flea_u8_t padding_len = (block_len - (data_len + mac_len + 1) % block_len) + 1; // +1 for padding_length entry
  flea_u8_t padding[FLEA_TLS_MAX_PADDING_SIZE];
  flea_dtl_t input_output_len = data_len + padding_len + mac_len;
  flea_u8_t padded_data[FLEA_TLS_MAX_RECORD_DATA_SIZE];
  printf("padding len orig version = %u\n", padding_len);
  for(flea_u8_t k = 0; k < padding_len; k++)
  {
    padding[k] = padding_len - 1; // account for padding_length entry again
  }
  memcpy(padded_data, data, data_len);
  memcpy(padded_data + data_len, mac, mac_len);
  memcpy(padded_data + data_len + mac_len, padding, padding_len);

  // compute encryption
  flea_u8_t encrypted[FLEA_TLS_MAX_RECORD_DATA_SIZE];
  FLEA_CCALL(
    THR_flea_cbc_mode__encrypt_data(
      tls_ctx->active_write_connection_state->cipher_suite->cipher, enc_key,
      enc_key_len, iv, iv_len, encrypted, padded_data, input_output_len
    )
  );

  {
    unsigned i;
    printf("encrypt_record: encrypt %u bytes of data:\n", input_output_len);
    for(i = 0; i < input_output_len; i++)
    {
      printf("%02x ", padded_data[i]);
    }
    printf("\n");
  }

  record->length = input_output_len + iv_len;
  record->data   = calloc(input_output_len + iv_len, sizeof(flea_u8_t));
  memcpy(record->data, iv, iv_len);
  memcpy(record->data + iv_len, encrypted, input_output_len);

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__encrypt_record */

/*
 * Initialization Vector (IV)
 *    When a block cipher is used in CBC mode, the initialization vector
 *    is exclusive-ORed with the first plaintext block prior to
 *    encryption.
 *
 *  IV
 *       The Initialization Vector (IV) SHOULD be chosen at random, and
 *       MUST be unpredictable.  Note that in versions of TLS prior to 1.1,
 *       there was no IV field, and the last ciphertext block of the
 *       previous record (the "CBC residue") was used as the IV.  This was
 *       changed to prevent the attacks described in [CBCATT].  For block
 *       ciphers, the IV length is of length
 *       SecurityParameters.record_iv_length, which is equal to the
 *       SecurityParameters.block_size.
 *
 */
flea_err_t THR_flea_tls__create_record(
  flea_tls_ctx_t *tls_ctx,
  Record         *record,
  flea_u8_t      *data,
  flea_u32_t     length,
  ContentType    content_type
)
{
  FLEA_THR_BEG_FUNC();

  // TODO: if we support ciphers without encryption: need to adjust
  if(tls_ctx->active_write_connection_state->cipher_suite->id == TLS_NULL_WITH_NULL_NULL)
  {
    record->record_type = RECORD_TYPE_PLAINTEXT;
  } else
  {
    record->record_type = RECORD_TYPE_CIPHERTEXT;
  }

  if(length > 16384) // 2^14 is max length for record, +1024 / +2048 for compressed / ciphertext
  {
    printf("Data too large for record: Need to implement fragmentation.\n");
    FLEA_THROW("record too large", FLEA_ERR_TLS_GENERIC);
  }

  record->content_type  = content_type;
  record->version.major = tls_ctx->version.major;
  record->version.minor = tls_ctx->version.minor;

  // TODO: have to implement compression ?
  // TODO: length max 2^14
  if(record->record_type == RECORD_TYPE_PLAINTEXT)
  {
    record->length = length;
    record->data   = calloc(length, sizeof(flea_u8_t));
    memcpy(record->data, data, length);
  }
  // TODO: length max 2^14 + 2048
  else
  if(record->record_type == RECORD_TYPE_CIPHERTEXT)
  {
    printf("calling THR_flea_tls__encrypt_record, content_type = %u\n", content_type);
    FLEA_CCALL(THR_flea_tls__encrypt_record(tls_ctx, record, data, length));
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__create_record */

flea_err_t THR_flea_tls__create_connection_params(
  flea_tls_ctx_t               *tls_ctx,
  flea_tls__connection_state_t *connection_state,
  flea_tls__cipher_suite_t     *cipher_suite,
  flea_bool_t                  writing_state
)
{
  FLEA_THR_BEG_FUNC();

  connection_state->cipher_suite       = cipher_suite;
  connection_state->compression_method = NO_COMPRESSION;
  // connection_state->sequence_number = 0;
  connection_state->sequence_number__au32[0] = 0;
  connection_state->sequence_number__au32[1] = 0;

  connection_state->mac_key = calloc(connection_state->cipher_suite->mac_key_size, sizeof(flea_u8_t));
  connection_state->enc_key = calloc(connection_state->cipher_suite->enc_key_size, sizeof(flea_u8_t));


  if(writing_state == FLEA_TRUE)
  {
    if(tls_ctx->security_parameters->connection_end == FLEA_TLS_CLIENT)
    {
      memcpy(connection_state->mac_key, tls_ctx->key_block, connection_state->cipher_suite->mac_key_size);
      memcpy(
        connection_state->enc_key, tls_ctx->key_block + 2 * connection_state->cipher_suite->mac_key_size,
        connection_state->cipher_suite->enc_key_size
      );
    }
  } else
  if(writing_state == FLEA_FALSE)
  {
    if(tls_ctx->security_parameters->connection_end == FLEA_TLS_CLIENT)
    {
      memcpy(
        connection_state->mac_key, tls_ctx->key_block + connection_state->cipher_suite->mac_key_size,
        connection_state->cipher_suite->mac_key_size
      );
      memcpy(
        connection_state->enc_key,
        tls_ctx->key_block + 2 * connection_state->cipher_suite->mac_key_size + connection_state->cipher_suite->enc_key_size,
        connection_state->cipher_suite->enc_key_size
      );
    }
  }
  // TODO: !! implement other cases !! (server)

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__create_connection_params */

/** master_secret = PRF(pre_master_secret, "master secret",
 *    ClientHello.random + ServerHello.random)
 *    [0..47];
 */
flea_err_t THR_flea_tls__create_master_secret(
  Random    client_hello_random,
  Random    server_hello_random,
  flea_u8_t *pre_master_secret,
  flea_u8_t *master_secret_res
)
{
  FLEA_THR_BEG_FUNC();
  flea_u8_t random_seed[64];
  memcpy(random_seed, client_hello_random.gmt_unix_time, 4);
  memcpy(random_seed + 4, client_hello_random.random_bytes, 28);
  memcpy(random_seed + 32, server_hello_random.gmt_unix_time, 4);
  memcpy(random_seed + 36, server_hello_random.random_bytes, 28);

  // pre_master_secret is 48 bytes, master_secret is desired to be 48 bytes
  FLEA_CCALL(flea_tls__prf(pre_master_secret, 48, PRF_LABEL_MASTER_SECRET, random_seed, 64, 48, master_secret_res));
  FLEA_THR_FIN_SEC_empty();
}

// TODO: configurable parameters
flea_err_t flea_tls_ctx_t__ctor(flea_tls_ctx_t *ctx, flea_u8_t *session_id, flea_u8_t session_id_len)
{
  FLEA_THR_BEG_FUNC();
  ctx->security_parameters = calloc(1, sizeof(flea_tls__security_parameters_t));

  /* specify connection end */
  ctx->security_parameters->connection_end = FLEA_TLS_CLIENT;

  /* set TLS version */
  ctx->version.minor = 0x03;
  ctx->version.major = 0x03;

  /* set cipher suite values */
  flea_u8_t TLS_RSA_WITH_AES_256_CBC_SHA256[] = { 0x00, 0x3D };

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
  flea_rng__randomize(ctx->security_parameters->client_random.gmt_unix_time, 4); // TODO: check RFC for correct implementation - actual time?
  flea_rng__randomize(ctx->security_parameters->client_random.random_bytes, 28);

  /* set compression methods  */
  ctx->security_parameters->compression_methods =
    calloc(1, sizeof(ctx->security_parameters->compression_methods[0]));
  ctx->security_parameters->compression_methods[0]  = NO_COMPRESSION;
  ctx->security_parameters->compression_methods_len = sizeof(ctx->security_parameters->compression_methods[0]);

  ctx->resumption = FLEA_FALSE;

  ctx->premaster_secret = calloc(256, sizeof(flea_u8_t));

  ctx->pending_read_connection_state  = calloc(1, sizeof(flea_tls__connection_state_t));
  ctx->pending_write_connection_state = calloc(1, sizeof(flea_tls__connection_state_t));
  ctx->active_read_connection_state   = calloc(1, sizeof(flea_tls__connection_state_t));
  ctx->active_write_connection_state  = calloc(1, sizeof(flea_tls__connection_state_t));
  ctx->active_read_connection_state->cipher_suite  = &cipher_suites[0]; // set TLS_NULL_WITH_NULL_NULL
  ctx->active_write_connection_state->cipher_suite = &cipher_suites[0];

  FLEA_THR_FIN_SEC_empty();
} /* flea_tls_ctx_t__ctor */

// TODO: instead of socket_fd use something else
flea_err_t THR_flea_tls__receive(int socket_fd, flea_u8_t *buff, flea_u32_t buff_size, flea_u32_t *res_len)
{
  FLEA_THR_BEG_FUNC();
  flea_s32_t res_tmp; // need temporarily signed variable for recv() result
  res_tmp = recv(socket_fd, buff, buff_size, 0);
  if(res_tmp < 0)
  {
    FLEA_THROW("recv err", FLEA_ERR_TLS_GENERIC);
  }
  *res_len = res_tmp;
  FLEA_THR_FIN_SEC_empty();
}


static flea_err_t THR_flea_tls__send_record(
  flea_tls_ctx_t *tls_ctx,
  flea_u8_t      *bytes,
  flea_u16_t     bytes_len,
  ContentType    content_type
)
{
  FLEA_THR_BEG_FUNC();
  // TODO: INIT OBJECT
  flea_tls_rec_prot_t rec_prot__t;
  flea_u8_t record_buf__au8[1000];
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__ctor(
      &rec_prot__t, record_buf__au8, sizeof(record_buf__au8),
      tls_ctx->active_write_connection_state->cipher_suite, tls_ctx->version.major, tls_ctx->version.minor,
      tls_ctx->rw_stream__pt
    )
  );

  FLEA_CCALL(THR_flea_tls_rec_prot_t__start_record(&rec_prot__t, content_type));
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__write_data(
      &rec_prot__t, bytes, bytes_len,
      tls_ctx->active_write_connection_state
    )
  );
  FLEA_CCALL(THR_flea_tls_rec_prot_t__write_flush(&rec_prot__t, tls_ctx->active_write_connection_state));
  FLEA_THR_FIN_SEC_empty();
}

#if 0
flea_err_t THR_flea_tls__send_record(
  flea_tls_ctx_t *tls_ctx,
  flea_u8_t      *bytes,
  flea_u16_t     bytes_len,
  ContentType    content_type,
  int            socket_fd
)
{
  // TODO: INIT OBJECT
  flea_tls_rec_prot_t rec_prot__t;
  flea_u8_t record_buf__au8[1000];

  FLEA_THR_BEG_FUNC();

  // create record
  // Record record;
  // flea_u8_t record_bytes[16384];
  // flea_u16_t record_bytes_len;
  // FLEA_CCALL(THR_flea_tls__create_record(tls_ctx, &record, bytes, bytes_len, content_type));
  // flea_tls__record_to_bytes(&record, record_bytes, &record_bytes_len);

  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__ctor(
      &rec_prot__t, record_buf__au8, sizeof(record_buf__au8),
      tls_ctx->active_write_connection_state->cipher_suite, tls_ctx->version.major, tls_ctx->version.minor,
      tls_ctx->rw_stream__pt
    )
  );

  FLEA_CCALL(THR_flea_tls_rec_prot_t__start_record(&rec_prot__t, content_type));
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__write_data(
      &rec_prot__t, bytes, bytes_len,
      tls_ctx->active_write_connection_state
    )
  );
  FLEA_CCALL(THR_flea_tls_rec_prot_t__write_flush(&rec_prot__t, tls_ctx->active_write_connection_state));

  // send record

  /*if(socket_fd != -1)
   * {
   * if(send(socket_fd, record_bytes, record_bytes_len, 0) < 0)
   * {
   *  printf("send failed\n");
   *  FLEA_THROW("Send failed!", FLEA_ERR_TLS_GENERIC);
   * }
   * }*/
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_record */

#endif /* if 0 */

flea_err_t THR_flea_tls__send_alert(
  flea_tls_ctx_t                *tls_ctx,
  flea_tls__alert_description_t description,
  flea_tls__alert_level_t       level,
  int                           socket_fd
)
{
  FLEA_THR_BEG_FUNC();

  flea_u8_t alert_bytes[2];
  alert_bytes[0] = level;
  alert_bytes[1] = description;

  FLEA_CCALL(THR_flea_tls__send_record(tls_ctx, alert_bytes, sizeof(alert_bytes), CONTENT_TYPE_ALERT));


  FLEA_THR_FIN_SEC_empty();
}

#if 0
flea_err_t THR_flea_tls__send_handshake_message_new(
  flea_tls_ctx_t   *tls_ctx,
  flea_hash_ctx_t  *hash_ctx,
  HandshakeType    type,
  flea_u8_t        *msg_bytes,
  flea_u32_t       msg_bytes_len,
  int              socket_fd,
  flea_rw_stream_t *rw_stream__pt
)
{
  FLEA_THR_BEG_FUNC();

  // create handshake message
  flea_u8_t handshake_bytes[16384]; // TODO: max length for handshake is 2^24 = 16777216
  flea_u32_t handshake_bytes_len;
  flea_tls__create_handshake_message(type, msg_bytes, msg_bytes_len, handshake_bytes, &handshake_bytes_len);

  // send record
  FLEA_CCALL(
    THR_flea_tls__send_record_new(
      tls_ctx, handshake_bytes, handshake_bytes_len, CONTENT_TYPE_HANDSHAKE
    )
  );


  // add handshake message to Hash
  FLEA_CCALL(THR_flea_hash_ctx_t__update(hash_ctx, handshake_bytes, handshake_bytes_len));

  FLEA_THR_FIN_SEC_empty();
}

#endif /* if 0 */

flea_err_t THR_flea_tls__send_handshake_message(
  flea_tls_ctx_t  *tls_ctx,
  flea_hash_ctx_t *hash_ctx,
  HandshakeType   type,
  flea_u8_t       *msg_bytes,
  flea_u32_t      msg_bytes_len
)
{
  flea_al_s8_t i;

  // TODO: INIT OBJECT
  flea_tls_rec_prot_t rec_prot__t;

  FLEA_THR_BEG_FUNC();


  flea_u8_t record_buf__au8[1000];
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__ctor(
      &rec_prot__t, record_buf__au8, sizeof(record_buf__au8),
      tls_ctx->active_write_connection_state->cipher_suite, tls_ctx->version.major, tls_ctx->version.minor,
      tls_ctx->rw_stream__pt
    )
  );

  FLEA_CCALL(THR_flea_tls_rec_prot_t__start_record(&rec_prot__t, CONTENT_TYPE_HANDSHAKE));

  flea_u8_t type_byte = type;
  FLEA_CCALL(THR_flea_tls_rec_prot_t__write_data(&rec_prot__t, &type_byte, 1, tls_ctx->active_write_connection_state));
  FLEA_CCALL(THR_flea_hash_ctx_t__update(hash_ctx, &type_byte, 1));
  for(i = 2; i >= 0; i--)
  {
    flea_u8_t byte = msg_bytes_len >> (i * 8);
    FLEA_CCALL(THR_flea_tls_rec_prot_t__write_data(&rec_prot__t, &byte, 1, tls_ctx->active_write_connection_state));
    FLEA_CCALL(THR_flea_hash_ctx_t__update(hash_ctx, &byte, 1));
  }
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__write_data(
      &rec_prot__t, msg_bytes, msg_bytes_len,
      tls_ctx->active_write_connection_state
    )
  );
  FLEA_CCALL(THR_flea_hash_ctx_t__update(hash_ctx, msg_bytes, msg_bytes_len));
  FLEA_CCALL(THR_flea_tls_rec_prot_t__write_flush(&rec_prot__t, tls_ctx->active_write_connection_state));


  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_handshake_message */

static flea_bool_t flea_tls_does_chosen_ciphersuite_support_encryption(const flea_tls_ctx_t *tls_ctx__pt)
{
  return tls_ctx__pt->active_write_connection_state->cipher_suite->id != TLS_NULL_WITH_NULL_NULL;
}

#if 0
flea_err_t THR_flea_tls__send_change_cipher_spec(flea_tls_ctx_t *tls_ctx, flea_hash_ctx_t *hash_ctx, int socket_fd)
{
  FLEA_THR_BEG_FUNC();

  Record css_record;
  flea_u8_t css_bytes[1] = { 1 };
  THR_flea_tls__create_record(tls_ctx, &css_record, css_bytes, 1, CONTENT_TYPE_CHANGE_CIPHER_SPEC);

  flea_u8_t css_record_bytes[16384];
  flea_u16_t css_record_bytes_len = 0;
  flea_tls__record_to_bytes(&css_record, css_record_bytes, &css_record_bytes_len);

  if(send(socket_fd, css_record_bytes, css_record_bytes_len, 0) < 0)
  {
    printf("send failed\n");
    FLEA_THROW("Send failed!", FLEA_ERR_TLS_GENERIC);
  }

  FLEA_THR_FIN_SEC_empty();
}

#endif /* if 0 */

flea_err_t THR_flea_tls__send_change_cipher_spec(flea_tls_ctx_t *tls_ctx, flea_hash_ctx_t *hash_ctx)
{
  FLEA_THR_BEG_FUNC();

  flea_u8_t css_bytes[1] = { 1 };

  FLEA_CCALL(THR_flea_tls__send_record(tls_ctx, css_bytes, sizeof(css_bytes), CONTENT_TYPE_CHANGE_CIPHER_SPEC));

  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_flea_tls__send_finished(
  flea_tls_ctx_t  *tls_ctx,
  flea_hash_ctx_t *hash_ctx
)
{
  flea_u8_t messages_hash[32];

  FLEA_DECL_BUF(verify_data__bu8, flea_u8_t, 12);
  const flea_al_u8_t verify_data_len__alu8 = 12;
  FLEA_THR_BEG_FUNC();

  // compute hash over handshake messages so far and create struct
  // flea_tls__finished_t finished;
  FLEA_ALLOC_BUF(verify_data__bu8, verify_data_len__alu8);

  /*
   * use a copy of hash_ctx for send_finished instead of finalizing the original
   */
  flea_hash_ctx_t hash_ctx_copy;
  THR_flea_hash_ctx_t__ctor_copy(&hash_ctx_copy, hash_ctx);
  FLEA_CCALL(THR_flea_hash_ctx_t__final(&hash_ctx_copy, messages_hash));

  PRFLabel label;
  if(tls_ctx->security_parameters->connection_end == FLEA_TLS_CLIENT)
  {
    label = PRF_LABEL_CLIENT_FINISHED;
  } else
  {
    label = PRF_LABEL_SERVER_FINISHED;
  }

  /*FLEA_CCALL(
   * THR_flea_tls__create_finished_message_with_12_bytes_verify_data(
   *  messages_hash, tls_ctx->security_parameters->master_secret, label, verify_data__bu8
   * )
   * );*/

  FLEA_CCALL(
    THR_flea_tls__create_finished_data(
      messages_hash, tls_ctx->security_parameters->master_secret, label, verify_data__bu8, verify_data_len__alu8
    )
  );

  // transform struct to bytes

  /*flea_u8_t finished_bytes[16384];
   * flea_u32_t finished_bytes_len;
   * flea_tls__finished_to_bytes(&finished, finished_bytes, &finished_bytes_len);*/

  // FLEA_CCALL(THR_flea_tls__send_handshake_message(tls_ctx, hash_ctx, HANDSHAKE_TYPE_FINISHED, finished_bytes, finished_bytes_len, socket_fd));

  // FLEA_CCALL(THR_flea_tls__send_handshake_message(tls_ctx, hash_ctx, HANDSHAKE_TYPE_FINISHED, finished_bytes, finished_bytes_len, -1));

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message(
      tls_ctx, hash_ctx, HANDSHAKE_TYPE_FINISHED, verify_data__bu8,
      12
    )
  );

  /*FLEA_CCALL(
   * THR_flea_tls__send_handshake_message_stream(
   *  tls_ctx, hash_ctx, HANDSHAKE_TYPE_FINISHED, finished_bytes,
   *  finished_bytes_len, rw_stream__pt
   * )
   * );*/

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL_SECRET_ARR(verify_data__bu8, 12);
  );
} /* THR_flea_tls__send_finished */

flea_err_t THR_flea_tls__send_client_hello(
  flea_tls_ctx_t  *tls_ctx,
  flea_hash_ctx_t *hash_ctx,
  int             socket_fd
)
{
  FLEA_THR_BEG_FUNC();

  flea_tls__client_hello_t client_hello;
  flea_tls__create_hello_message(tls_ctx, &client_hello);

  // transform struct to bytes
  flea_u8_t client_hello_bytes[16384];
  flea_u32_t client_hello_bytes_len; // 24 bit
  flea_tls__client_hello_to_bytes(&client_hello, client_hello_bytes, &client_hello_bytes_len);

  // FLEA_CCALL(THR_flea_tls__send_handshake_message(tls_ctx, hash_ctx, HANDSHAKE_TYPE_CLIENT_HELLO, client_hello_bytes, client_hello_bytes_len, socket_fd));
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message(
      tls_ctx, hash_ctx, HANDSHAKE_TYPE_CLIENT_HELLO,
      client_hello_bytes, client_hello_bytes_len
    )
  );

  /*FLEA_CCALL(
   * THR_flea_tls__send_handshake_message_stream(
   *  tls_ctx, hash_ctx, HANDSHAKE_TYPE_CLIENT_HELLO,
   *  client_hello_bytes, client_hello_bytes_len, rw_stream__pt
   * )
   * );*/

  // TODO: dorther stammen die beiden Werte ja schon. Was ist beabsichtigt?
  // add random to tls_ctx
  memcpy(
    tls_ctx->security_parameters->client_random.gmt_unix_time, client_hello.random.gmt_unix_time,
    sizeof(tls_ctx->security_parameters->client_random.gmt_unix_time)
  );
  memcpy(
    tls_ctx->security_parameters->client_random.random_bytes, client_hello.random.random_bytes,
    sizeof(tls_ctx->security_parameters->client_random.random_bytes)
  );

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_client_hello */

// send_client_key_exchange
flea_err_t THR_flea_tls__send_client_key_exchange(
  flea_tls_ctx_t    *tls_ctx,
  flea_hash_ctx_t   *hash_ctx,
  flea_public_key_t *pubkey
)
{
  FLEA_THR_BEG_FUNC();

  flea_tls__client_key_ex_t client_key_ex;
  FLEA_CCALL(THR_flea_tls__create_client_key_exchange(tls_ctx, pubkey, &client_key_ex));


  // transform struct to bytes
  flea_u8_t client_key_ex_bytes[16384];
  flea_u32_t client_key_ex_bytes_len;
  flea_tls__client_key_exchange_to_bytes(&client_key_ex, client_key_ex_bytes, &client_key_ex_bytes_len);

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message(
      tls_ctx, hash_ctx, HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
      client_key_ex_bytes, client_key_ex_bytes_len
    )
  );

  // add secrets to tls_ctx
  memcpy(tls_ctx->premaster_secret, client_key_ex.premaster_secret, 256); // TODO: variable size depending on key ex method


  FLEA_THR_FIN_SEC_empty();
}

typedef struct
{
  flea_u8_t   *read_buff;
  flea_u32_t  read_buff_len;
  flea_u32_t  bytes_left;
  flea_u32_t  bytes_read;
  flea_bool_t connection_closed;
} flea_tls__read_state_t;

void flea_tls__read_state_ctor(flea_tls__read_state_t *state)
{
  state->read_buff         = calloc(16384, sizeof(flea_u8_t));
  state->read_buff_len     = 0;
  state->bytes_left        = 0;
  state->bytes_read        = 0;
  state->connection_closed = FLEA_FALSE;
}

flea_err_t THR_flea_tls__read_next_record(
  flea_tls_ctx_t         *tls_ctx,
  Record                 *record,
  RecordType             record_type,
  int                    socket_fd,
  flea_tls__read_state_t *state
)
{
  FLEA_THR_BEG_FUNC();

  // When no bytes are left we have to read new data from the network
  if(state->bytes_left == 0)
  {
    // TODO: REPLACE FIXED LENGTH
    FLEA_CCALL(THR_flea_tls__receive(socket_fd, state->read_buff, 16384, &state->read_buff_len));
    state->bytes_left = state->read_buff_len;
    state->bytes_read = 0;
    if(state->read_buff_len == 0)
    {
      state->connection_closed = FLEA_TRUE;
      return FLEA_ERR_FINE;
    }
  }

  // else we read the next record
  FLEA_CCALL(
    THR_flea_tls__read_record(
      tls_ctx, state->read_buff + state->bytes_read, state->read_buff_len, record,
      &state->bytes_left
    )
  );
  state->bytes_read = state->read_buff_len - state->bytes_left;

  FLEA_THR_FIN_SEC_empty();
}

typedef enum
{
  FLEA_TLS_HANDSHAKE_EXPECT_NONE                = 0x0, // zero <=> client needs to send his "second round"
  FLEA_TLS_HANDSHAKE_EXPECT_HELLO_REQUEST       = 0x1,
  FLEA_TLS_HANDSHAKE_EXPECT_CLIENT_HELLO        = 0x2,
  FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO        = 0x4,
  FLEA_TLS_HANDSHAKE_EXPECT_NEW_SESSION_TICKET  = 0x8,
  FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE         = 0x10,
  FLEA_TLS_HANDSHAKE_EXPECT_SERVER_KEY_EXCHANGE = 0x20,
  FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_REQUEST = 0x40,
  FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO_DONE   = 0x80,
  FLEA_TLS_HANDSHAKE_EXPECT_f                   = 0x100,
  FLEA_TLS_HANDSHAKE_EXPECT_CLIENT_KEY_EXCHANGE = 0x200,
  FLEA_TLS_HANDSHAKE_EXPECT_FINISHED            = 0x400,
  FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC  = 0x800
} flea_tls__expect_handshake_type_t;

typedef struct
{
  flea_u16_t  expected_messages;
  flea_bool_t finished;
  flea_bool_t initialized;
  flea_bool_t send_client_cert;
  flea_bool_t sent_first_round; 	// only relevant for server
} flea_tls__handshake_state_t;

void flea_tls__handshake_state_ctor(flea_tls__handshake_state_t *state)
{
  state->expected_messages = 0;
  state->finished         = FLEA_FALSE;
  state->initialized      = FLEA_FALSE;
  state->send_client_cert = FLEA_FALSE;
  state->sent_first_round = FLEA_FALSE;
}

flea_err_t THR_flea_tls__server_handshake(int socket_fd, flea_tls_ctx_t *tls_ctx, flea_rw_stream_t *rw_stream__pt)
{
  FLEA_THR_BEG_FUNC();

  // define and init state
  flea_tls__handshake_state_t handshake_state;
  flea_tls__handshake_state_ctor(&handshake_state);
  flea_tls__read_state_t read_state;
  flea_tls__read_state_ctor(&read_state);
  flea_hash_ctx_t hash_ctx;
  THR_flea_hash_ctx_t__ctor(&hash_ctx, flea_sha256); // TODO: initialize properly

  flea_public_key_t pubkey; // TODO: -> tls_ctx

  // received records and handshakes for processing the current state
  Record recv_record;
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
      // TODO: record type argument has to be removed because it's determined by the current connection state in tls_ctx
      FLEA_CCALL(THR_flea_tls__read_next_record(tls_ctx, &recv_record, RECORD_TYPE_PLAINTEXT, socket_fd, &read_state));
      if(read_state.connection_closed == FLEA_TRUE)
      {
        printf("peer closed connection\n");
        break;
      }

      if(recv_record.content_type == CONTENT_TYPE_HANDSHAKE)
      {
        FLEA_CCALL(THR_flea_tls__read_handshake_message(&recv_record, &recv_handshake));

        // update hash for all incoming handshake messages
        FLEA_CCALL(THR_flea_hash_ctx_t__update(&hash_ctx, recv_record.data, recv_record.length));
      } else
      if(recv_record.content_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC)
      {
        if(handshake_state.expected_messages != FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC)
        {
          FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
        } else
        {
          /*
           * Enable encryption for incoming messages
           */
          // setup key material
          FLEA_CCALL(
            THR_flea_tls__create_master_secret(
              tls_ctx->security_parameters->client_random,
              tls_ctx->security_parameters->server_random, tls_ctx->premaster_secret,
              tls_ctx->security_parameters->master_secret
            )
          );
          FLEA_CCALL(THR_flea_tls__generate_key_block(tls_ctx, tls_ctx->key_block));

          // TODO: verify that message is correct?
          FLEA_CCALL(
            THR_flea_tls__create_connection_params(
              tls_ctx, tls_ctx->pending_read_connection_state,
              &cipher_suites[1], FLEA_FALSE
            )
          );

          // make pending state active
          // TODO: call destructor on active read state / TODO: create constructor/destructor
          tls_ctx->active_read_connection_state = tls_ctx->pending_read_connection_state;
          // TODO: call constructor on pending read state

          handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_FINISHED;

          continue;
        }
      } else
      if(recv_record.content_type == CONTENT_TYPE_ALERT)
      {
        // TODO: handle alert message properly
        FLEA_THROW("Received unhandled alert", FLEA_ERR_TLS_GENERIC);
      } else
      {
        FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
      }
    }
    // We don't expect another message so it's our turn to continue
    else
    {
      if(handshake_state.sent_first_round == FLEA_FALSE)
      {
        // send server_hello
        // send Certificate
        // send server_hello_done

        handshake_state.sent_first_round = FLEA_TRUE;
      } else
      {
        // send change_cipher_spec

        // make pending state active
        // TODO: call destructor active write state
        tls_ctx->active_write_connection_state = tls_ctx->pending_write_connection_state;
        // TODO: call constructor on pending write state

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
      } else
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
      if(recv_handshake.type == FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE)
      {
        FLEA_CCALL(THR_flea_tls__read_client_hello(tls_ctx, &recv_handshake));
      } else
      {
        FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
      }
    }
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__server_handshake */

flea_err_t THR_flea_tls__client_handshake(int socket_fd, flea_tls_ctx_t *tls_ctx, flea_rw_stream_t *rw_stream__pt)
{
  FLEA_THR_BEG_FUNC();

  /*
   * TODO: make this a real test case
   * flea_u8_t secret[] =   {0x9b, 0xbe, 0x43, 0x6b ,0xa9, 0x40, 0xf0, 0x17, 0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35} ;
   * flea_u8_t seed[] =     {0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18, 0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5, 0x19, 0x8c};
   * flea_u8_t result[100];
   * //   flea_u8_t test_label[] =  {0x74, 0x65, 0x73, 0x74, 0x20, 0x6c, 0x61, 0x62, 0x65, 0x6c};
   * PRF(secret, 16, PRF_LABEL_TEST, seed, 16, 100, result);
   *
   * printf("PRF TEST\n");
   * for (int i=0; i<100; i++)
   * {
   * printf("%02x ", result[i]);
   * }
   * printf("\n");
   */


  // define and init state
  flea_tls__handshake_state_t handshake_state;
  flea_tls__handshake_state_ctor(&handshake_state);
  flea_tls__read_state_t read_state;
  flea_tls__read_state_ctor(&read_state);
  flea_hash_ctx_t hash_ctx;
  THR_flea_hash_ctx_t__ctor(&hash_ctx, flea_sha256); // TODO: initialize properly

  flea_public_key_t pubkey; // TODO: -> tls_ctx

  // received records and handshakes for processing the current state
  Record recv_record;
  HandshakeMessage recv_handshake;

  tls_ctx->rw_stream__pt = rw_stream__pt;
  while(1)
  {
    // initialize handshake by sending CLIENT_HELLO
    if(handshake_state.initialized == FLEA_FALSE)
    {
      // send client hello
      FLEA_CCALL(THR_flea_tls__send_client_hello(tls_ctx, &hash_ctx, socket_fd));

      handshake_state.initialized       = FLEA_TRUE;
      handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO;
    }

    /*
     *  1) read next Record
     *  2) if it's Alert: handle it
     *     if it's Handshake Message or Change Cipher Spec Message: process it if it's among the expected_messages
     */


    /*
     * read next record
     */
    if(handshake_state.expected_messages != FLEA_TLS_HANDSHAKE_EXPECT_NONE)
    {
      // TODO: record type argument has to be removed because it's determined by the current connection state in tls_ctx
      FLEA_CCALL(THR_flea_tls__read_next_record(tls_ctx, &recv_record, RECORD_TYPE_PLAINTEXT, socket_fd, &read_state));
      if(read_state.connection_closed == FLEA_TRUE)
      {
        printf("peer closed connection\n");
        break;
      }

      if(recv_record.content_type == CONTENT_TYPE_HANDSHAKE)
      {
        FLEA_CCALL(THR_flea_tls__read_handshake_message(&recv_record, &recv_handshake));

        // update hash for all incoming handshake messages
        // TODO: only include messages sent AFTER ClientHello. At the moment it could include HelloRequest received before sending HelloRequest

        // exclude finished message because we must not have it in our hash computation
        if(recv_handshake.type != HANDSHAKE_TYPE_FINISHED)
        {
          FLEA_CCALL(THR_flea_hash_ctx_t__update(&hash_ctx, recv_record.data, recv_record.length));
        }
      } else
      if(recv_record.content_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC)
      {
        if(handshake_state.expected_messages != FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC)
        {
          FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
        } else
        {
          // TODO: verify that message is correct?

          /*
           * Enable encryption for incoming messages
           */

          FLEA_CCALL(
            THR_flea_tls__create_connection_params(
              tls_ctx, tls_ctx->pending_read_connection_state,
              &cipher_suites[1], FLEA_FALSE
            )
          );

          // make pending state active
          // TODO: call destructor on active read state / TODO: create constructor/destructor
          tls_ctx->active_read_connection_state = tls_ctx->pending_read_connection_state;
          // TODO: call constructor on pending read state

          handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_FINISHED;

          continue;
        }
      } else
      if(recv_record.content_type == CONTENT_TYPE_ALERT)
      {
        // TODO: handle alert message properly
        FLEA_THROW("Received unhandled alert", FLEA_ERR_TLS_GENERIC);
      } else
      {
        FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
      }
    }
    // We don't expect another message so it's our turn to continue
    else
    {
      if(handshake_state.send_client_cert == FLEA_TRUE)
      {
        // TODO: send certificate message
      }

      FLEA_CCALL(THR_flea_tls__send_client_key_exchange(tls_ctx, &hash_ctx, &pubkey));

      FLEA_CCALL(THR_flea_tls__send_change_cipher_spec(tls_ctx, &hash_ctx));

      /*
       * Enable encryption for outgoing messages
       */

      FLEA_CCALL(
        THR_flea_tls__create_master_secret(
          tls_ctx->security_parameters->client_random,
          tls_ctx->security_parameters->server_random, tls_ctx->premaster_secret,
          tls_ctx->security_parameters->master_secret
        )
      );
      FLEA_CCALL(THR_flea_tls__generate_key_block(tls_ctx, tls_ctx->key_block));

      FLEA_CCALL(
        THR_flea_tls__create_connection_params(
          tls_ctx, tls_ctx->pending_write_connection_state,
          &cipher_suites[1], FLEA_TRUE
        )
      );

      // make pending state active
      // TODO: call destructor active write state
      tls_ctx->active_write_connection_state = tls_ctx->pending_write_connection_state;
      // TODO: call constructor on pending write state
      FLEA_CCALL(THR_flea_tls__send_finished(tls_ctx, &hash_ctx));


      handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CHANGE_CIPHER_SPEC;
      continue;
    }


    if(handshake_state.expected_messages == FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO)
    {
      if(recv_handshake.type == HANDSHAKE_TYPE_SERVER_HELLO)
      {
        ServerHello server_hello; // TODO: don't need this
        FLEA_CCALL(THR_flea_tls__read_server_hello(tls_ctx, &recv_handshake, &server_hello));

        handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE
          | FLEA_TLS_HANDSHAKE_EXPECT_SERVER_KEY_EXCHANGE
          | FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_REQUEST
          | FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO_DONE;
        continue;
      } else
      {
        FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
      }
    }


    if(handshake_state.expected_messages & FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE)
    {
      if(recv_handshake.type == HANDSHAKE_TYPE_CERTIFICATE)
      {
        Certificate certificate_message; // TODO: don't need this
        FLEA_CCALL(THR_flea_tls__read_certificate(tls_ctx, &recv_handshake, &certificate_message, &pubkey));
        tls_ctx->server_pubkey = pubkey;
        continue;
      }
      handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_SERVER_KEY_EXCHANGE
        | FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_REQUEST
        | FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO_DONE;
    }

    // TODO: include here: FLEA_TLS_HANDSHAKE_EXPECT_SERVER_KEY_EXCHANGE and FLEA_TLS_HANDSHAKE_EXPECT_CERTIFICATE_REQUEST

    if(handshake_state.expected_messages & FLEA_TLS_HANDSHAKE_EXPECT_SERVER_HELLO_DONE)
    {
      if(recv_handshake.type == HANDSHAKE_TYPE_SERVER_HELLO_DONE)
      {
        handshake_state.expected_messages = FLEA_TLS_HANDSHAKE_EXPECT_NONE;
        // TODO: verify server hello done (?)
        continue;
      }
    }

    if(handshake_state.expected_messages == FLEA_TLS_HANDSHAKE_EXPECT_FINISHED)
    {
      if(recv_handshake.type == HANDSHAKE_TYPE_FINISHED)
      {
        FLEA_CCALL(THR_flea_tls__read_finished(tls_ctx, &hash_ctx, &recv_handshake));
        printf("Handshake completed!\n");
        // FLEA_CCALL(THR_flea_tls__send_alert(tls_ctx, FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY, FLEA_TLS_ALERT_LEVEL_WARNING, socket_fd));

        break;
      } else
      {
        FLEA_THROW("Received unexpected message", FLEA_ERR_TLS_GENERIC);
      }
    }
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__client_handshake */



flea_err_t THR_flea_tls__send_app_data(int socket_fd, flea_tls_ctx_t *tls_ctx, flea_u8_t *data, flea_u8_t data_len)
{
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_tls__send_record(tls_ctx, data, data_len, CONTENT_TYPE_APPLICATION_DATA, socket_fd));


  FLEA_THR_FIN_SEC_empty();
}
