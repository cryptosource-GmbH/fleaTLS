/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/tls_rec_prot.h"
#include "internal/common/tls_ciph_suite.h"
#include "flea/error_handling.h"
#include "flea/bin_utils.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "flea/rng.h"
#include "flea/util.h"
#include <stdio.h>

// TODO: REMOVE ALL OF THESE DEFINES EXCEPT MAX_PADDING_SIZE ?
#define FLEA_TLS_MAX_MAC_SIZE     32
#define FLEA_TLS_MAX_MAC_KEY_SIZE 32
#define FLEA_TLS_MAX_IV_SIZE      32
// #define FLEA_TLS_MAX_RECORD_DATA_SIZE 16384 // 2^14 max record sizeof
#define FLEA_TLS_MAX_PADDING_SIZE 255 // each byte must hold the padding value => 255 is max

#define RECORD_HDR_LEN            5

static void inc_seq_nbr(flea_u32_t* seq__au32)
{
  seq__au32[0]++;
  if(seq__au32[0] == 0)
  {
    seq__au32[1]++;
  }
}

static flea_err_t THR_flea_tls_rec_prot_t__compute_mac_cbc_hmac(
  flea_tls_rec_prot_t*   rec_prot__pt,
  flea_tls_conn_state_t* conn_state__pt,
  flea_u8_t*             data,
  flea_u32_t             data_len,
  flea_u8_t*             mac_out
)
{
  flea_mac_ctx_t mac__t = flea_mac_ctx_t__INIT_VALUE;
  flea_al_u8_t mac_len_out_alu8;
  flea_u8_t enc_len__au8[2];
  flea_u8_t enc_seq_nbr__au8[8];
  flea_u32_t seq_lo__u32, seq_hi__u32;

  flea_u8_t* mac_key    = conn_state__pt->suite_specific__u.cbc_hmac_conn_state__t.mac_key__bu8;
  flea_u8_t mac_len     = conn_state__pt->cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.mac_size__u8;
  flea_u8_t mac_key_len = conn_state__pt->cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.mac_key_size__u8;

  FLEA_THR_BEG_FUNC();

  /*
   * MAC(MAC_write_key, seq_num +
   *                      TLSCompressed.type +
   *                      TLSCompressed.version +
   *                      TLSCompressed.length +
   *                      TLSCompressed.fragment);
   */
  // 8 + 1 + (1+1) + 2 + length

  seq_lo__u32 = conn_state__pt->sequence_number__au32[0];
  seq_hi__u32 = conn_state__pt->sequence_number__au32[1];
  flea__encode_U32_BE(seq_hi__u32, enc_seq_nbr__au8);
  flea__encode_U32_BE(seq_lo__u32, enc_seq_nbr__au8 + 4);
  FLEA_CCALL(
    THR_flea_mac_ctx_t__ctor(
      &mac__t,
      conn_state__pt->cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.mac_id,
      mac_key,
      mac_key_len
    )
  );
  FLEA_CCALL(THR_flea_mac_ctx_t__update(&mac__t, enc_seq_nbr__au8, sizeof(enc_seq_nbr__au8)));
  FLEA_CCALL(THR_flea_mac_ctx_t__update(&mac__t, rec_prot__pt->send_rec_buf_raw__bu8, 3));

  enc_len__au8[0] = data_len >> 8;
  enc_len__au8[1] = data_len;
  FLEA_CCALL(THR_flea_mac_ctx_t__update(&mac__t, enc_len__au8, sizeof(enc_len__au8)));
  FLEA_CCALL(THR_flea_mac_ctx_t__update(&mac__t, data, data_len));

  mac_len_out_alu8 = mac_len;

  FLEA_CCALL(THR_flea_mac_ctx_t__final_compute(&mac__t, mac_out, &mac_len_out_alu8));

  FLEA_THR_FIN_SEC(
    flea_mac_ctx_t__dtor(&mac__t);
  );
} /* THR_flea_tls_rec_prot_t__compute_mac_cbc_hmac */

static void flea_tls_rec_prot_t__discard_pending_write(flea_tls_rec_prot_t* rec_prot__pt)
{
  rec_prot__pt->write_ongoing__u8     = 0;
  rec_prot__pt->payload_offset__u16   = 0;
  rec_prot__pt->payload_used_len__u16 = 0;
}

static flea_err_t THR_flea_tls_rec_prot_t__close_with_fatal_alert_and_throw(
  flea_tls_rec_prot_t*          rec_prot__pt,
  flea_tls__alert_description_t alert_desc__e,
  flea_err_t                    error__e
)
{
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__send_alert(
      rec_prot__pt,
      alert_desc__e,
      FLEA_TLS_ALERT_LEVEL_FATAL
    )
  );
  rec_prot__pt->is_session_closed__u8 = FLEA_TRUE;
  FLEA_THROW("closing session with fatal alert", error__e);
  FLEA_THR_FIN_SEC_empty();
}

/* potentially sends alerts and throws if the received alert indicates this */
static flea_err_t THR_flea_tls_rec_prot_t__handle_alert(flea_tls_rec_prot_t* rec_prot__pt)
{
  FLEA_THR_BEG_FUNC();
  if(rec_prot__pt->payload_used_len__u16 != 2)
  {
    FLEA_CCALL(
      THR_flea_tls_rec_prot_t__close_with_fatal_alert_and_throw(
        rec_prot__pt,
        FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY,
        FLEA_ERR_TLS_INV_REC
      )
    );
  }

  rec_prot__pt->payload_offset__u16   = 0;
  rec_prot__pt->payload_used_len__u16 = 0;
  if(rec_prot__pt->payload_buf__pu8[0] == FLEA_TLS_ALERT_LEVEL_FATAL)
  {
    rec_prot__pt->is_session_closed__u8 = FLEA_TRUE;
    FLEA_THROW("received fatal alert", FLEA_ERR_TLS_REC_FATAL_ALERT);
  }
  else if(rec_prot__pt->payload_buf__pu8[1] == FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY)
  {
    FLEA_THROW("received fatal alert", FLEA_ERR_TLS_SESSION_CLOSED);
  }

  rec_prot__pt->payload_offset__u16   = 0;
  rec_prot__pt->payload_used_len__u16 = 0;
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls_rec_prot_t__ctor(
  flea_tls_rec_prot_t* rec_prot__pt,
  flea_al_u8_t         prot_vers_major,
  flea_al_u8_t         prot_vers_minor,
  flea_rw_stream_t*    rw_stream__pt
)
{
  // TODO: need to implement limit for maximal send buffer size explicitly, since
  // the actual buffer will be larger for the reserved space
  FLEA_THR_BEG_FUNC();
  /* TODO: do all inits except for stream in start_record */
  // rec_prot__pt->send_rec_buf_raw__bu8     = send_rec_buf_raw__bu8;

#ifdef FLEA_USE_HEAP_BUF
  FLEA_ALLOC_MEM_ARR(rec_prot__pt->send_rec_buf_raw__bu8, FLEA_TLS_TRNSF_BUF_SIZE);
#endif
  rec_prot__pt->send_rec_buf_raw_len__u16 = FLEA_TLS_TRNSF_BUF_SIZE;
  // rec_prot__pt->payload_used_len = 0;
  rec_prot__pt->prot_version__t.major = prot_vers_major;
  rec_prot__pt->prot_version__t.minor = prot_vers_minor;
  rec_prot__pt->rw_stream__pt         = rw_stream__pt;
  // rec_prot__pt->ciph_suite_id         = suite__pt->id;
  rec_prot__pt->payload_offset__u16 = 0;
  rec_prot__pt->read_bytes_from_current_record__u16 = 0;

  rec_prot__pt->current_record_content_len__u16 = 0;
  rec_prot__pt->is_session_closed__u8       = FLEA_FALSE;
  rec_prot__pt->is_current_record_alert__u8 = FLEA_FALSE;

  /*flea_tls_conn_state_t__ctor_no_cipher(&rec_prot__pt->write_state__t);
   * flea_tls_conn_state_t__ctor_no_cipher(&rec_prot__pt->read_state__t);*/

  flea_tls_rec_prot_t__set_null_ciphersuite(rec_prot__pt, flea_tls_write);
  flea_tls_rec_prot_t__set_null_ciphersuite(rec_prot__pt, flea_tls_read);
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__ctor */

void flea_tls_rec_prot_t__set_null_ciphersuite(
  flea_tls_rec_prot_t*  rec_prot__pt,
  flea_tls_stream_dir_e direction
)
{
  rec_prot__pt->reserved_iv_len__u8  = 0;
  rec_prot__pt->payload_buf__pu8     = rec_prot__pt->send_rec_buf_raw__bu8 + RECORD_HDR_LEN;
  rec_prot__pt->payload_max_len__u16 = rec_prot__pt->send_rec_buf_raw_len__u16 - RECORD_HDR_LEN;

  if(direction == flea_tls_write)
  {
    flea_tls_conn_state_t__dtor(&rec_prot__pt->write_state__t);
    flea_tls_conn_state_t__ctor_no_cipher(&rec_prot__pt->write_state__t);
  }
  else
  {
    flea_tls_conn_state_t__dtor(&rec_prot__pt->read_state__t);
    flea_tls_conn_state_t__ctor_no_cipher(&rec_prot__pt->read_state__t);
  }
  // flea_tls_rec_prot_t__update_max_buf_len(rec_prot__pt);
}

flea_err_t THR_flea_tls_rec_prot_t__set_cbc_hmac_ciphersuite(
  flea_tls_rec_prot_t*   rec_prot__pt,
  flea_tls_stream_dir_e  direction,
  flea_block_cipher_id_t block_cipher_id,
  // flea_hash_id_t         hash_id,
  flea_mac_id_t          mac_id,
  const flea_u8_t*       cipher_key__pcu8,
  flea_al_u8_t           cipher_key_len__alu8,
  const flea_u8_t*       mac_key__pcu8,
  flea_al_u8_t           mac_key_len__alu8,
  flea_al_u8_t           mac_size__alu8
)
{
  flea_tls_conn_state_t* conn_state__pt;
  flea_al_u16_t reserved_payl_len__alu16;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_tls_rec_prot_t__write_flush(rec_prot__pt));
  rec_prot__pt->reserved_iv_len__u8 = flea_block_cipher__get_block_size(block_cipher_id);
  rec_prot__pt->payload_buf__pu8    = rec_prot__pt->send_rec_buf_raw__bu8 + rec_prot__pt->reserved_iv_len__u8
    + RECORD_HDR_LEN;

  reserved_payl_len__alu16 = mac_size__alu8 + 2 * rec_prot__pt->reserved_iv_len__u8; /* 2* block size: one for IV, one for padding */

  if((reserved_payl_len__alu16 + RECORD_HDR_LEN) > rec_prot__pt->send_rec_buf_raw_len__u16)
  {
    FLEA_THROW("send/receive buffer is too small", FLEA_ERR_BUFF_TOO_SMALL);
  }

  rec_prot__pt->payload_max_len__u16 = rec_prot__pt->send_rec_buf_raw_len__u16 - RECORD_HDR_LEN
    - reserved_payl_len__alu16;
  // flea_tls_rec_prot_t__update_max_buf_len(rec_prot__pt);
  if(direction == flea_tls_write)
  {
    conn_state__pt = &rec_prot__pt->write_state__t;
  }
  else
  {
    conn_state__pt = &rec_prot__pt->read_state__t;
  }
  flea_tls_conn_state_t__dtor(conn_state__pt);
  FLEA_CCALL(
    THR_flea_tls_conn_state_t__ctor_cbc_hmac(
      conn_state__pt,
      block_cipher_id,
      // hash_id,
      mac_id,
      cipher_key__pcu8,
      cipher_key_len__alu8,
      mac_key__pcu8,
      mac_key_len__alu8,
      mac_size__alu8
    )
  );
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__set_cbc_hmac_ciphersuite */

void flea_tls_rec_prot_t__write_record_header(
  flea_tls_rec_prot_t* rec_prot__pt,
  ContentType          content_type__e
)
{
  rec_prot__pt->send_rec_buf_raw__bu8[0] = content_type__e;
  rec_prot__pt->send_rec_buf_raw__bu8[1] = rec_prot__pt->prot_version__t.major;
  rec_prot__pt->send_rec_buf_raw__bu8[2] = rec_prot__pt->prot_version__t.minor;
  rec_prot__pt->payload_used_len__u16    = 0;
  rec_prot__pt->payload_offset__u16      = 0;
}

flea_err_t THR_flea_tls_rec_prot_t__write_data(
  flea_tls_rec_prot_t* rec_prot__pt,
  ContentType          content_type__e,
  const flea_u8_t*     data__pcu8,
  flea_dtl_t           data_len__dtl
)
{
  flea_al_u16_t buf_free_len__alu16;

  FLEA_THR_BEG_FUNC();
  if(rec_prot__pt->is_session_closed__u8)
  {
    FLEA_THROW("tls session closed", FLEA_ERR_TLS_SESSION_CLOSED);
  }
  if(rec_prot__pt->write_ongoing__u8)
  {
    if(rec_prot__pt->send_rec_buf_raw__bu8[0] != content_type__e)
    {
      FLEA_CCALL(THR_flea_tls_rec_prot_t__write_flush(rec_prot__pt));
      flea_tls_rec_prot_t__write_record_header(rec_prot__pt, content_type__e);
    }
  }
  else
  {
    flea_tls_rec_prot_t__write_record_header(rec_prot__pt, content_type__e);
  }

  buf_free_len__alu16 = rec_prot__pt->payload_max_len__u16 - rec_prot__pt->payload_used_len__u16;
  while(data_len__dtl)
  {
    rec_prot__pt->write_ongoing__u8 = 1;
    flea_al_u16_t to_go__alu16 = FLEA_MIN(data_len__dtl, buf_free_len__alu16);
    memcpy(rec_prot__pt->payload_buf__pu8 + rec_prot__pt->payload_used_len__u16, data__pcu8, to_go__alu16);
    data_len__dtl -= to_go__alu16;
    data__pcu8    += to_go__alu16;
    rec_prot__pt->payload_used_len__u16 += to_go__alu16;
    buf_free_len__alu16 -= to_go__alu16;

    if(buf_free_len__alu16 == 0)
    {
      FLEA_CCALL(THR_flea_tls_rec_prot_t__write_flush(rec_prot__pt));
    }
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__write_data */

static flea_err_t THR_flea_tls_rec_prot_t__decrypt_record_cbc_hmac(
  flea_tls_rec_prot_t* rec_prot__pt,
  flea_al_u16_t*       decrypted_len__palu16,
  ContentType          content_type__e
)
{
  flea_u32_t seq_lo__u32, seq_hi__u32;
  flea_u8_t enc_seq_nbr__au8[8];

  FLEA_THR_BEG_FUNC();
  flea_u8_t mac_len =
    rec_prot__pt->read_state__t.cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.mac_size__u8;
  flea_u8_t* enc_key = rec_prot__pt->read_state__t.suite_specific__u.cbc_hmac_conn_state__t.cipher_key__bu8;
  flea_u8_t iv_len   = flea_block_cipher__get_block_size(
    rec_prot__pt->read_state__t.cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.cipher_id
    );
  flea_u8_t enc_key_len =
    rec_prot__pt->read_state__t.cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.cipher_key_size__u8;
  flea_u8_t mac[FLEA_TLS_MAX_MAC_SIZE];
  flea_u8_t padding_len;
  flea_u8_t* data        = rec_prot__pt->payload_buf__pu8;
  flea_u8_t* iv          = data;
  flea_al_u16_t data_len = rec_prot__pt->payload_used_len__u16;
  flea_al_u16_t data_len_previous__alu16;

  seq_lo__u32 = rec_prot__pt->read_state__t.sequence_number__au32[0];
  seq_hi__u32 = rec_prot__pt->read_state__t.sequence_number__au32[1];

  flea__encode_U32_BE(seq_hi__u32, enc_seq_nbr__au8);
  flea__encode_U32_BE(seq_lo__u32, enc_seq_nbr__au8 + 4);
  if(data_len < 2 * iv_len)
  {
    FLEA_THROW("invalid payload length of encrypted TLS_RSA_WITH_AES_256_CBC_SHA256 message", FLEA_ERR_TLS_INV_REC);
  }

  /*
   * First decrypt
   */

  // TODO: can read and write from/in the same buffer?
  FLEA_CCALL(
    THR_flea_cbc_mode__decrypt_data(
      rec_prot__pt->read_state__t.cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.cipher_id,
      enc_key,
      enc_key_len,
      iv,
      iv_len,
      data + iv_len,
      data + iv_len,
      data_len - iv_len
      /*record->data, record->data, record->length*/
    )
  );


  /*
   * Remove padding and read IV
   */
  padding_len = data[data_len - 1];

  /*
   * Check MAC
   */
  // TODO: CAPTURE UNDERFLOW
  data_len_previous__alu16 = data_len;
  data_len = data_len - (padding_len + 1) - iv_len - mac_len;
  if(data_len > data_len_previous__alu16)
  {
    FLEA_THROW("insufficient size of hmac-cbc record payload", FLEA_ERR_TLS_INV_REC);
  }
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__compute_mac_cbc_hmac(
      rec_prot__pt,
      &rec_prot__pt->read_state__t,
      data + iv_len,
      data_len,
      // enc_seq_nbr__au8,
      mac
    )
  );
  if(!flea_sec_mem_equal(mac, data + iv_len + data_len, mac_len))
  {
    FLEA_THROW("MAC failure", FLEA_ERR_TLS_GENERIC);
  }

  /*
   * adjust record
   */
  memmove(data, data + iv_len, data_len);
  *decrypted_len__palu16 = data_len;
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__decrypt_record_cbc_hmac */

static flea_err_t THR_flea_tls_rec_prot_t__encrypt_record_cbc_hmac(
  flea_tls_rec_prot_t* rec_prot__pt,
  flea_al_u16_t*       encrypted_len__palu16
)
{
  flea_al_u16_t length_tot;

  FLEA_THR_BEG_FUNC();
  flea_u8_t* enc_key = rec_prot__pt->write_state__t.suite_specific__u.cbc_hmac_conn_state__t.cipher_key__bu8;
  flea_u8_t iv_len   = flea_block_cipher__get_block_size(
    rec_prot__pt->write_state__t.cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.cipher_id
    );
  flea_u8_t mac_len =
    rec_prot__pt->write_state__t.cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.mac_size__u8;
  flea_u8_t enc_key_len =
    rec_prot__pt->write_state__t.cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.cipher_key_size__u8;
  flea_u8_t* iv       = rec_prot__pt->send_rec_buf_raw__bu8 + RECORD_HDR_LEN;
  flea_u8_t block_len = iv_len;

  flea_u8_t* data        = rec_prot__pt->payload_buf__pu8;
  flea_al_u16_t data_len = rec_prot__pt->payload_used_len__u16;
  flea_u8_t padding_len  = (block_len - (data_len + mac_len + 1) % block_len) + 1; // +1 for padding_length entry

  flea_u8_t* mac     = data + data_len;
  flea_u8_t* padding = mac + mac_len;
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__compute_mac_cbc_hmac(
      rec_prot__pt,
      &rec_prot__pt->write_state__t,
      data,
      data_len,
      mac
    )
  );

  flea_rng__randomize(iv, iv_len);

  flea_dtl_t input_output_len = data_len + padding_len + mac_len;

  for(flea_u8_t k = 0; k < padding_len; k++)
  {
    padding[k] = padding_len - 1;
  }

  // flea_u8_t encrypted[FLEA_TLS_MAX_RECORD_DATA_SIZE];
  FLEA_CCALL(
    THR_flea_cbc_mode__encrypt_data(
      rec_prot__pt->write_state__t.cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.cipher_id,
      enc_key,
      enc_key_len,
      iv,
      iv_len,
      data,
      data,
      input_output_len
    )
  );

  /*{
   * unsigned i;
   * printf("encrypt_record: encrypt %u bytes of data:\n", input_output_len);
   * for(i = 0; i < input_output_len; i++)
   * {
   *  printf("%02x ", padded_data[i]);
   * }
   * printf("\n");
   * }*/

  length_tot = input_output_len + iv_len;
  rec_prot__pt->send_rec_buf_raw__bu8[3] = length_tot >> 8;
  rec_prot__pt->send_rec_buf_raw__bu8[4] = length_tot;
  // memcpy(rec_prot__pt->payload_buf__pu8, encrypted, input_output_len);
  *encrypted_len__palu16 = input_output_len;
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__encrypt_record_cbc_hmac */

flea_err_t THR_flea_tls_rec_prot_t__write_flush(
  flea_tls_rec_prot_t* rec_prot__pt
)
{
  FLEA_THR_BEG_FUNC();
  if((rec_prot__pt->payload_used_len__u16 == 0) || !rec_prot__pt->write_ongoing__u8)
  {
    FLEA_THR_RETURN();
  }
  if(rec_prot__pt->write_state__t.cipher_suite_config__t.cipher_suite_id == TLS_RSA_WITH_AES_256_CBC_SHA256)
  {
    flea_al_u16_t encrypted_len__alu16;
    FLEA_CCALL(THR_flea_tls_rec_prot_t__encrypt_record_cbc_hmac(rec_prot__pt, &encrypted_len__alu16));
    FLEA_CCALL(
      THR_flea_rw_stream_t__write(
        rec_prot__pt->rw_stream__pt,
        rec_prot__pt->send_rec_buf_raw__bu8,
        encrypted_len__alu16 + RECORD_HDR_LEN + rec_prot__pt->reserved_iv_len__u8
      )
    );

    /*{
     * unsigned i;
     * printf("encrypt_record_new: encrypt %u bytes of data:\n", input_output_len);
     * for(i = 0; i < input_output_len; i++)
     * {
     *  printf("%02x ", padded_data[i]);
     * }
     * printf("\n");
     * }*/
    inc_seq_nbr(rec_prot__pt->write_state__t.sequence_number__au32);
  }
  else if(rec_prot__pt->write_state__t.cipher_suite_config__t.cipher_suite_id == TLS_NULL_WITH_NULL_NULL)
  {
    rec_prot__pt->send_rec_buf_raw__bu8[3] = rec_prot__pt->payload_used_len__u16 >> 8;
    rec_prot__pt->send_rec_buf_raw__bu8[4] = rec_prot__pt->payload_used_len__u16;
    // printf("rec_prot write_flush: writing %u PLAIN bytes to underlying stream\n", rec_prot__pt->payload_used_len__u16 + RECORD_HDR_LEN);
    FLEA_CCALL(
      THR_flea_rw_stream_t__write(
        rec_prot__pt->rw_stream__pt,
        rec_prot__pt->send_rec_buf_raw__bu8,
        rec_prot__pt->payload_used_len__u16 + RECORD_HDR_LEN
      )
    );
  }
  FLEA_CCALL(THR_flea_rw_stream_t__flush_write(rec_prot__pt->rw_stream__pt));

  flea_tls_rec_prot_t__discard_pending_write(rec_prot__pt);

  /*rec_prot__pt->write_ongoing__u8     = 0;
   *  rec_prot__pt->payload_offset__u16   = 0;
   *  rec_prot__pt->payload_used_len__u16 = 0;*/
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__write_flush */

flea_err_t THR_flea_tls_rec_prot_t__send_record(
  flea_tls_rec_prot_t* rec_prot__pt,
  const flea_u8_t*     bytes,
  flea_u16_t           bytes_len,
  ContentType          content_type
)
{
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_tls_rec_prot_t__write_data(rec_prot__pt, content_type, bytes, bytes_len));
#ifdef FLEA_TLS_SEND_RECORD_EAGER
  FLEA_CCALL(THR_flea_tls_rec_prot_t__write_flush(rec_prot__pt));
#endif

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_record */

flea_err_t THR_flea_tls_rec_prot_t__send_alert(
  flea_tls_rec_prot_t*          rec_prot__pt,
  flea_tls__alert_description_t description,
  flea_tls__alert_level_t       level
)
{
  FLEA_THR_BEG_FUNC();

  flea_u8_t alert_bytes[2];
  alert_bytes[0] = level;
  alert_bytes[1] = description;

  FLEA_CCALL(THR_flea_tls_rec_prot_t__send_record(rec_prot__pt, alert_bytes, sizeof(alert_bytes), CONTENT_TYPE_ALERT));

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls_rec_prot_t__close_and_send_close_notify(flea_tls_rec_prot_t* rec_prot__pt)
{
  FLEA_THR_BEG_FUNC();

  if(!rec_prot__pt->is_session_closed__u8)
  {
    flea_tls_rec_prot_t__discard_pending_write(rec_prot__pt);
    FLEA_CCALL(
      THR_flea_tls_rec_prot_t__send_alert(
        rec_prot__pt,
        FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY,
        FLEA_TLS_ALERT_LEVEL_WARNING
      )
    );
    rec_prot__pt->is_session_closed__u8 = FLEA_TRUE;
  }
  FLEA_THR_FIN_SEC_empty();
}

// TODO: ADD ALERT HANDLING TO THIS FUNCTION
static flea_err_t THR_flea_tls_rec_prot_t__read_data_inner(
  flea_tls_rec_prot_t*          rec_prot__pt,
  flea_u8_t*                    data__pu8,
  flea_al_u16_t*                data_len__palu16,
  flea_tls__protocol_version_t* prot_version_mbn__pt,
  flea_bool_t                   do_verify_prot_version__b,
  ContentType                   cont_type__e,
  flea_bool_t                   current_or_next_record_for_content_type__b,
  flea_stream_read_mode_e       rd_mode__e
)
{
  flea_al_u16_t to_cp__alu16, read_bytes_count__alu16 = 0;
  flea_dtl_t data_len__dtl = *data_len__palu16;

  FLEA_THR_BEG_FUNC();
  if(rec_prot__pt->is_session_closed__u8)
  {
    FLEA_THROW("tls session closed", FLEA_ERR_TLS_SESSION_CLOSED);
  }
  if(rec_prot__pt->write_ongoing__u8)
  {
    FLEA_CCALL(THR_flea_tls_rec_prot_t__write_flush(rec_prot__pt));
    // TODO: SHOULD BE UNNECCESSARY:
    rec_prot__pt->read_bytes_from_current_record__u16 = 0;
    rec_prot__pt->current_record_content_len__u16     = 0;
  }
  // TODO: MERGE THIS COPYING WITH THE FINAL COPYING
  to_cp__alu16 = FLEA_MIN(data_len__dtl, rec_prot__pt->payload_used_len__u16 - rec_prot__pt->payload_offset__u16);
  memcpy(data__pu8, rec_prot__pt->payload_buf__pu8 + rec_prot__pt->payload_offset__u16, to_cp__alu16);
  rec_prot__pt->payload_offset__u16 += to_cp__alu16;
  data_len__dtl -= to_cp__alu16;
  data__pu8     += to_cp__alu16;
  read_bytes_count__alu16 += to_cp__alu16;
  // enter only if
  // - called with current_or_next_record_for_content_type__b
  //   OR
  // - called with non-zero length and data copied above did not suffice
  // no more data left. this is important for 0-length reads to
  // get the current record type

  // TODO: FOR GETTING ONLY THE CONTENT, THE HEADER WOULD SUFFICE. THUS THE
  // CONDITIONS FOR ENTERING THE LOOP CAN BE LOOSENED (WOULDN'T HELP IN MUCH IN
  // PRACTICE THOUGH)
  if((current_or_next_record_for_content_type__b &&
    (rec_prot__pt->payload_used_len__u16 - rec_prot__pt->payload_offset__u16 == 0)) || data_len__dtl)
  {
    /* start reading a new record */
    flea_stream_read_mode_e local_rd_mode__e = rd_mode__e;
    flea_dtl_t raw_read_len__dtl;
    flea_al_u16_t raw_rec_content_len__alu16; // = raw_read_len__dtl;
    if(local_rd_mode__e == flea_read_blocking)
    {
      local_rd_mode__e = flea_read_full;

      /* otherwise not a single content byte could be returned (in case of
       * encryption) */
    }
    do
    {
      if(rec_prot__pt->read_bytes_from_current_record__u16 < RECORD_HDR_LEN)
      {
        while(rec_prot__pt->read_bytes_from_current_record__u16 < RECORD_HDR_LEN)
        {
          raw_read_len__dtl = RECORD_HDR_LEN - rec_prot__pt->read_bytes_from_current_record__u16;
          FLEA_CCALL(
            THR_flea_rw_stream_t__read(
              rec_prot__pt->rw_stream__pt,
              &rec_prot__pt->send_rec_buf_raw__bu8[rec_prot__pt->read_bytes_from_current_record__u16],
              &raw_read_len__dtl,
              local_rd_mode__e
            )
          );
          rec_prot__pt->read_bytes_from_current_record__u16 += raw_read_len__dtl;
          if(raw_read_len__dtl == 0)
          {
            if(local_rd_mode__e == flea_read_nonblocking)
            {
              *data_len__palu16 = 0;
              FLEA_THR_RETURN();
            }
            else
            {
              FLEA_THROW("0 bytes returned from blocking read", FLEA_ERR_FAILED_STREAM_READ);
            }
          }
        }
        /* header is read completely */
        if(rec_prot__pt->send_rec_buf_raw__bu8[0] == CONTENT_TYPE_ALERT)
        {
          rec_prot__pt->is_current_record_alert__u8 = FLEA_TRUE;
        }
        else if(!current_or_next_record_for_content_type__b && (cont_type__e != rec_prot__pt->send_rec_buf_raw__bu8[0]))
        {
          FLEA_THROW("content type does not match", FLEA_ERR_TLS_INV_REC_HDR);
        }
        if(!rec_prot__pt->is_current_record_alert__u8)
        {
          if(do_verify_prot_version__b)
          {
            if((prot_version_mbn__pt->major != rec_prot__pt->send_rec_buf_raw__bu8[1]) ||
              (prot_version_mbn__pt->minor != rec_prot__pt->send_rec_buf_raw__bu8[2]))
            {
              FLEA_THROW("invalid protocol version in record", FLEA_ERR_TLS_INV_REC_HDR);
            }
          }
          else if(prot_version_mbn__pt)
          {
            prot_version_mbn__pt->major = rec_prot__pt->send_rec_buf_raw__bu8[1];
            prot_version_mbn__pt->minor = rec_prot__pt->send_rec_buf_raw__bu8[2];
          }
        }
        rec_prot__pt->current_record_content_len__u16  = rec_prot__pt->send_rec_buf_raw__bu8[3] << 8;
        rec_prot__pt->current_record_content_len__u16 |= rec_prot__pt->send_rec_buf_raw__bu8[4];
        // rec_prot__pt->current_record_content_len__u16 = raw_rec_content_len__alu16;
        // TODO: CORRECT ALL SIZE ALLOCATIONS / REQUIREMENTS:
        if(rec_prot__pt->current_record_content_len__u16 > FLEA_TLS_TRNSF_BUF_SIZE - RECORD_HDR_LEN)
        {
          FLEA_THROW("received record does not fit into receive buffer", FLEA_ERR_TLS_EXCSS_REC_LEN);
        }
      }

      while(rec_prot__pt->read_bytes_from_current_record__u16 <
        rec_prot__pt->current_record_content_len__u16 + RECORD_HDR_LEN)
      {
        flea_stream_read_mode_e content_read_mode__e = local_rd_mode__e;
        if(rec_prot__pt->is_current_record_alert__u8)
        {
          content_read_mode__e = flea_read_full;
        }
        raw_read_len__dtl = rec_prot__pt->current_record_content_len__u16
          - (rec_prot__pt->read_bytes_from_current_record__u16 - RECORD_HDR_LEN);
        FLEA_CCALL(
          THR_flea_rw_stream_t__read(
            rec_prot__pt->rw_stream__pt,
            rec_prot__pt->payload_buf__pu8,
            &raw_read_len__dtl,
            content_read_mode__e
          )
        );
        rec_prot__pt->read_bytes_from_current_record__u16 += raw_read_len__dtl;

        if(raw_read_len__dtl == 0)
        {
          if(local_rd_mode__e == flea_read_nonblocking)
          {
            *data_len__palu16 = 0;
            FLEA_THR_RETURN();
          }
          else
          {
            FLEA_THROW("0 bytes returned from blocking read", FLEA_ERR_FAILED_STREAM_READ);
          }
        }
      }
      /* read full content */

      rec_prot__pt->payload_used_len__u16 = rec_prot__pt->read_bytes_from_current_record__u16 - RECORD_HDR_LEN;
      rec_prot__pt->payload_offset__u16   = 0;

      raw_rec_content_len__alu16 = rec_prot__pt->current_record_content_len__u16;

      /* not needed any more, reset: */
      rec_prot__pt->read_bytes_from_current_record__u16 = 0;
      rec_prot__pt->current_record_content_len__u16     = 0;
      if(rec_prot__pt->read_state__t.cipher_suite_config__t.cipher_suite_id == TLS_RSA_WITH_AES_256_CBC_SHA256)
      {
        FLEA_CCALL(
          THR_flea_tls_rec_prot_t__decrypt_record_cbc_hmac(
            rec_prot__pt,
            &raw_rec_content_len__alu16,
            (ContentType) rec_prot__pt->send_rec_buf_raw__bu8[0]
          )
        );
        rec_prot__pt->payload_used_len__u16 = raw_rec_content_len__alu16;
        inc_seq_nbr(rec_prot__pt->read_state__t.sequence_number__au32);
      }

      /*else
       * {
       * raw_rec_content_len__alu16 = raw_read_len__dtl;
       * }*/
      if(rec_prot__pt->is_current_record_alert__u8)
      {
        FLEA_CCALL(THR_flea_tls_rec_prot_t__handle_alert(rec_prot__pt));
      }
      else
      {
        to_cp__alu16 = FLEA_MIN(raw_rec_content_len__alu16, data_len__dtl);
        memcpy(data__pu8, rec_prot__pt->payload_buf__pu8, to_cp__alu16);
        rec_prot__pt->payload_offset__u16 = to_cp__alu16;
        read_bytes_count__alu16 += to_cp__alu16;
        data_len__dtl -= to_cp__alu16;
        data__pu8     += to_cp__alu16;
      }
    } while(
      ((rd_mode__e == flea_read_full) && data_len__dtl) ||
      ((rd_mode__e == flea_read_blocking) && !read_bytes_count__alu16)
    );
  }
  *data_len__palu16 = read_bytes_count__alu16;
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__read_data_inner */

flea_err_t THR_flea_tls_rec_prot_t__get_current_record_type(
  flea_tls_rec_prot_t* rec_prot__pt,
  ContentType*         cont_type__pe
)
{
  FLEA_THR_BEG_FUNC();
  flea_tls__protocol_version_t dummy_version__t;
  flea_al_u16_t read_len_zero__alu16 = 0;
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__read_data_inner(
      rec_prot__pt,
      NULL,
      &read_len_zero__alu16,
      &dummy_version__t,
      FLEA_FALSE,
      0 /*dummy_content_type */,
      FLEA_TRUE,
      flea_read_full
    )
  );
  *cont_type__pe = rec_prot__pt->send_rec_buf_raw__bu8[0];
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls_rec_prot_t__read_data(
  flea_tls_rec_prot_t*    rec_prot__pt,
  ContentType             cont_type__e,
  flea_u8_t*              data__pu8,
  flea_al_u16_t*          data_len__palu16,
  flea_stream_read_mode_e rd_mode__e
)
{
  return THR_flea_tls_rec_prot_t__read_data_inner(
    rec_prot__pt,
    data__pu8,
    data_len__palu16,
    NULL,
    FLEA_FALSE,
    cont_type__e,
    FLEA_FALSE,
    rd_mode__e
  );
}

void flea_tls_rec_prot_t__dtor(flea_tls_rec_prot_t* rec_prot__pt)
{
  /* no way to handle error here: */
  if(rec_prot__pt->payload_buf__pu8)
  {
    THR_flea_tls_rec_prot_t__close_and_send_close_notify(rec_prot__pt);
  }
  flea_tls_conn_state_t__dtor(&rec_prot__pt->write_state__t);
  flea_tls_conn_state_t__dtor(&rec_prot__pt->read_state__t);
  FLEA_FREE_MEM_CHECK_SET_NULL_SECRET_ARR(rec_prot__pt->send_rec_buf_raw__bu8, FLEA_TLS_TRNSF_BUF_SIZE);
}
