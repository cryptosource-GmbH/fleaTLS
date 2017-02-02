/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_rec_prot__H_
#define _flea_tls_rec_prot__H_

#include "flea/types.h"
#include "flea/error.h"
#include "internal/common/tls_ciph_suite.h"
#include "flea/rw_stream.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
  NO_COMPRESSION = 0,
  COMPRESSION    = 255
} CompressionMethod;
typedef struct
{
  /*
   * RFC 5246 6.1.  Connection States
   */
  // TODO:
  flea_tls__cipher_suite_t *cipher_suite;


  /* keys */
  flea_u8_t         *mac_key; // length inside cipher_suite
  flea_u8_t         *enc_key;
  flea_u8_t         *iv;

  /* compression state */
  CompressionMethod compression_method;

  /* sequence number */
  // flea_u64_t sequence_number;
  flea_u32_t sequence_number__au32[2];
  // flea_u32_t sequence_number_hi;

  // TODO: maybe need to add more fields for stream ciphers
} flea_tls__connection_state_t;

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
  flea_u8_t                    *send_rec_buf_raw__pu8;
  flea_u16_t                   send_rec_buf_raw_len__u16;
  flea_u8_t                    *payload_buf__pu8;
  flea_u16_t                   payload_max_len__u16;
  flea_u16_t                   payload_used_len__u16;
  flea_u8_t                    reserved_iv_len__u8;
  flea_tls__protocol_version_t prot_version__t;
  flea_rw_stream_t             *rw_stream__pt;
  flea_tls__cipher_suite_id_t  ciph_suite_id;
} flea_tls_rec_prot_t;

flea_err_t
THR_flea_tls_rec_prot_t__ctor(
  flea_tls_rec_prot_t      *rec_prot__pt,
  flea_u8_t                *send_rec_buf_raw__pu8,
  flea_al_u16_t            send_rec_buf_raw_len__alu16,
  // flea_al_u8_t             reserved_iv_len__alu8,
  flea_tls__cipher_suite_t *suite__pt,
  flea_al_u8_t             prot_vers_major,
  flea_al_u8_t             prot_vers_minor,
  flea_rw_stream_t         *rw_stream__pt
);

flea_err_t
THR_flea_tls_rec_prot_t__start_record(flea_tls_rec_prot_t *rec_prot__pt, ContentType content_type__e);


flea_err_t
THR_flea_tls_rec_prot_t__write_data(
  flea_tls_rec_prot_t          *rec_prot__pt,
  const flea_u8_t              *data__pcu8,
  flea_dtl_t                   data_len__dtl,
  flea_tls__connection_state_t *conn_state__pt
);

flea_err_t
THR_flea_tls_rec_prot_t__write_flush(flea_tls_rec_prot_t *rec_prot__pt, flea_tls__connection_state_t *conn_state__pt);

// TODO: DTOR
#ifdef __cplusplus
}
#endif
#endif /* h-guard */
