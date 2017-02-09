/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_rec_prot__H_
#define _flea_tls_rec_prot__H_

#include "flea/types.h"
#include "flea/error.h"
#include "internal/common/tls_ciph_suite.h"
#include "internal/common/tls_conn_state.h"
#include "flea/rw_stream.h"


#ifdef __cplusplus
extern "C" {
#endif

/*
 * typedef enum
 * {
 * NO_COMPRESSION = 0,
 * COMPRESSION    = 255
 * } CompressionMethod;
 */
#if 0
flea_tls__cipher_suite_id_t id;

flea_block_cipher_id_t cipher; // flea_des_single, flea_tdes_2key, flea_tdes_3key, flea_desx, flea_aes128, flea_aes192, flea_aes256;

flea_u8_t block_size; // RFC: 8 bits => flea_block_cipher__get_block_size

// TODO: cipher suite defines length for finished message verify_data (12 byte for all standard cipher suites)
flea_u8_t iv_size;      // RFC: 8 bits
flea_u8_t enc_key_size; // RFC: 8 bits => flea_block_cipher__get_key_size
flea_u8_t mac_key_size; // RFC: 8 bits
flea_u8_t mac_size;     // RFC: 8 bits


flea_mac_id_t mac_algorithm;   // default: flea_hmac_sha256
flea_hash_id_t hash_algorithm; // default: flea_sha256

flea_tls__prf_algorithm_t prf_algorithm;
#endif // if 0

typedef enum { flea_tls_write, flea_tls_read } flea_tls_stream_dir_e;

#if 0

typedef struct
{
  /*
   * RFC 5246 6.1.  Connection States
   */
  // TODO:
  flea_tls__cipher_suite_t *cipher_suite;


  /* keys */
  flea_u8_t *mac_key; // length inside cipher_suite
  flea_u8_t *enc_key;
  //  flea_u8_t         *iv;

  /* compression state */
  // CompressionMethod compression_method;

  /* sequence number */
  // flea_u64_t sequence_number;
  flea_u32_t sequence_number__au32[2];
  // flea_u32_t sequence_number_hi;

  // TODO: maybe need to add more fields for stream ciphers
} flea_tls__connection_state_t;
#endif // if 0

typedef struct
{
  flea_u8_t major;
  flea_u8_t minor;
} flea_tls__protocol_version_t;

typedef enum
{
  CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20,
  CONTENT_TYPE_ALERT              = 21,
  CONTENT_TYPE_HANDSHAKE          = 22,
  CONTENT_TYPE_APPLICATION_DATA   = 23,
  CONTENT_TYPE_HEARTBEAT          = 24
} ContentType;

typedef enum
{
  RECORD_TYPE_PLAINTEXT,
  RECORD_TYPE_CIPHERTEXT,
  RECORD_TYPE_COMPRESSED,
} RecordType;

typedef struct
{
  flea_tls_conn_state_t read_state__t;
  flea_tls_conn_state_t write_state__t;
  // TODO: BUFFER OF LEN
  // FLEA_TLS_MAX_RECORD_DATA_SIZE + RECORD_HDR_LEN
#ifdef FLEA_USE_HEAP_BUF
  flea_u8_t                    *send_rec_buf_raw__bu8;
#else
  flea_u8_t                    send_rec_buf_raw__bu8[FLEA_TLS_REC_BUF_SIZE];
#endif
  flea_u16_t                   send_rec_buf_raw_len__u16;
  flea_u8_t                    *payload_buf__pu8;
  flea_u16_t                   payload_max_len__u16;
  flea_u16_t                   payload_used_len__u16;
  flea_u16_t                   payload_offset__u16;
  flea_u8_t                    reserved_iv_len__u8;
  flea_tls__protocol_version_t prot_version__t;
  flea_rw_stream_t             *rw_stream__pt;
  // flea_tls__cipher_suite_id_t    ciph_suite_id;
  flea_u8_t                    write_ongoing__u8;
} flea_tls_rec_prot_t;

#define flea_tls_rec_prot_t__INIT_VALUE { .send_rec_buf_raw__bu8 = 0 }
#define flea_tls_rec_prot_t__INIT(__p) memset ((__p), 0, sizeof(*(__p))

void flea_tls_rec_prot_t__dtor(flea_tls_rec_prot_t *rec_prot__pt);

flea_err_t THR_flea_tls_rec_prot_t__ctor(
  flea_tls_rec_prot_t *rec_prot__pt,
  // flea_u8_t                *send_rec_buf_raw__pu8,
  // flea_al_u16_t            send_rec_buf_raw_len__alu16,
  // flea_tls__cipher_suite_t *suite__pt,
  flea_al_u8_t        prot_vers_major,
  flea_al_u8_t        prot_vers_minor,
  flea_rw_stream_t    *rw_stream__pt
);

void flea_tls_rec_prot_t__set_null_ciphersuite(
  flea_tls_rec_prot_t   *rec_prot__pt,
  flea_tls_stream_dir_e direction
);


flea_err_t THR_flea_tls_rec_prot_t__write_data(
  flea_tls_rec_prot_t *rec_prot__pt,
  ContentType         content_type__e,
  const flea_u8_t     *data__pcu8,
  flea_dtl_t          data_len__dtl
);

flea_err_t THR_flea_tls_rec_prot_t__write_flush(
  flea_tls_rec_prot_t *rec_prot__pt
);

flea_err_t THR_flea_tls_rec_prot_t__read_data(
  flea_tls_rec_prot_t          *rec_prot__pt,
  flea_u8_t                    *data__pu8,
  flea_al_u16_t                *data_len__palu16,
  // flea_tls__connection_state_t *conn_state__pt,
  flea_tls__protocol_version_t *prot_version__pt,
  flea_bool_t                  do_verify_prot_version__b,
  ContentType                  cont_type__e,
  flea_bool_t                  do_verify_content_type__b
);

flea_err_t THR_flea_tls_rec_prot_t__get_current_record_type(
  flea_tls_rec_prot_t *rec_prot__pt,
  ContentType         *cont_type__pe
);

flea_err_t THR_flea_tls_rec_prot_t__set_cbc_hmac_ciphersuite(
  flea_tls_rec_prot_t    *rec_prot__pt,
  flea_tls_stream_dir_e  direction,
  flea_block_cipher_id_t block_cipher_id,
  flea_hash_id_t         hash_id,
  flea_mac_id_t          mac_id,
  const flea_u8_t        *cipher_key__pcu8,
  flea_al_u8_t           cipher_key_len__alu8,
  const flea_u8_t        *mac_key__pcu8,
  flea_al_u8_t           mac_key_len__alu8,
  flea_al_u8_t           mac_size__alu8
);

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
