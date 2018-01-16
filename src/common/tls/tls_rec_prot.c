/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/tls/tls_rec_prot.h"
#include "internal/common/tls/tls_ciph_suite.h"
#include "flea/error_handling.h"
#include "flea/bin_utils.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "flea/rng.h"
#include "flea/util.h"
#include "flea/tls.h"
#include "internal/common/tls/tls_common.h"
#include "internal/common/mask.h"
#include "internal/common/tls/tls_int.h"


#ifdef FLEA_HAVE_TLS
static void inc_seq_nbr(flea_u32_t* seq__au32)
{
  seq__au32[0]++;
  if(seq__au32[0] == 0)
  {
    seq__au32[1]++;
  }
}

# ifdef FLEA_HAVE_TLS_CS_CBC
static flea_err_e THR_flea_tls_rec_prot_t__compute_mac_cbc_hmac(
  const flea_u8_t*       rec_hdr__pcu8,
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
  FLEA_CCALL(THR_flea_mac_ctx_t__update(&mac__t, /*rec_prot__pt->send_rec_buf_raw__bu8*/ rec_hdr__pcu8, 3));

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

# endif /* ifdef FLEA_HAVE_HMAC */

static void flea_tls_rec_prot_t__discard_pending_write(flea_tls_rec_prot_t* rec_prot__pt)
{
  rec_prot__pt->write_ongoing__u8          = 0;
  rec_prot__pt->send_payload_offset__u16   = 0;
  rec_prot__pt->send_payload_used_len__u16 = 0;
}

static flea_err_e THR_flea_tls_rec_prot_t__close_with_fatal_alert_and_throw(
  flea_tls_rec_prot_t*          rec_prot__pt,
  flea_tls__alert_description_t alert_desc__e,
  flea_err_e                    error__e
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
static flea_err_e THR_flea_tls_rec_prot_t__handle_alert(
  flea_tls_rec_prot_t* rec_prot__pt,
  flea_dtl_t           read_bytes_count__dtl
)
{
  FLEA_THR_BEG_FUNC();
  if(rec_prot__pt->payload_used_len__u16 != 2)
  {
    FLEA_CCALL(
      THR_flea_tls_rec_prot_t__close_with_fatal_alert_and_throw(
        rec_prot__pt,
        FLEA_TLS_ALERT_DESC_DECODE_ERROR,
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

  else if(rec_prot__pt->payload_buf__pu8[1] == FLEA_TLS_ALERT_DESC_NO_RENEGOTIATION)
  {
    FLEA_THROW("received no renegotiation alert", FLEA_ERR_TLS_REC_NORENEG_AL_DURING_RENEG);
  }
  rec_prot__pt->payload_offset__u16   = 0;
  rec_prot__pt->payload_used_len__u16 = 0;
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__handle_alert */

flea_err_e THR_flea_tls_rec_prot_t__ctor(
  flea_tls_rec_prot_t* rec_prot__pt,
  flea_al_u8_t         prot_vers_major,
  flea_al_u8_t         prot_vers_minor,
  flea_rw_stream_t*    rw_stream__pt
)
{
  FLEA_THR_BEG_FUNC();

# ifdef FLEA_HEAP_MODE
  FLEA_ALLOC_MEM_ARR(rec_prot__pt->send_rec_buf_raw__bu8, FLEA_TLS_TRNSF_BUF_SIZE);
  FLEA_ALLOC_MEM_ARR(rec_prot__pt->alt_send_buf__raw__bu8, FLEA_TLS_ALT_SEND_BUF_SIZE);
# endif
  rec_prot__pt->send_rec_buf_raw_len__u16 = FLEA_TLS_TRNSF_BUF_SIZE;
  rec_prot__pt->prot_version__t.major     = prot_vers_major;
  rec_prot__pt->prot_version__t.minor     = prot_vers_minor;
  rec_prot__pt->rw_stream__pt       = rw_stream__pt;
  rec_prot__pt->payload_offset__u16 = 0;
  rec_prot__pt->read_bytes_from_current_record__u16 = 0;

  rec_prot__pt->current_record_content_len__u16 = 0;
  rec_prot__pt->is_session_closed__u8       = FLEA_FALSE;
  rec_prot__pt->is_current_record_alert__u8 = FLEA_FALSE;
  rec_prot__pt->pending_close_notify__u8    = FLEA_FALSE;

  flea_tls_rec_prot_t__set_null_ciphersuite(rec_prot__pt, flea_tls_write);
  flea_tls_rec_prot_t__set_null_ciphersuite(rec_prot__pt, flea_tls_read);
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__ctor */

void flea_tls_rec_prot_t__set_null_ciphersuite(
  flea_tls_rec_prot_t*  rec_prot__pt,
  flea_tls_stream_dir_e direction
)
{
  rec_prot__pt->payload_max_len__u16     = rec_prot__pt->send_rec_buf_raw_len__u16 - FLEA_TLS_RECORD_HDR_LEN;
  rec_prot__pt->alt_payload_max_len__u16 = FLEA_TLS_ALT_SEND_BUF_SIZE - FLEA_TLS_RECORD_HDR_LEN;

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
}

# ifdef FLEA_HAVE_TLS_CS_CBC
static flea_err_e THR_flea_tls_rec_prot_t__set_cbc_hmac_ciphersuite_inner(
  flea_tls_rec_prot_t*   rec_prot__pt,
  flea_tls_stream_dir_e  direction,
  flea_block_cipher_id_e block_cipher_id,
  flea_mac_id_e          mac_id,
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
      mac_id,
      cipher_key__pcu8,
      cipher_key_len__alu8,
      mac_key__pcu8,
      mac_key_len__alu8,
      mac_size__alu8
    )
  );

  reserved_payl_len__alu16 = mac_size__alu8 + 2 * rec_prot__pt->read_state__t.reserved_iv_len__u8; /* 2* block size: one for IV, one for padding */

  if(((reserved_payl_len__alu16 + FLEA_TLS_RECORD_HDR_LEN) > rec_prot__pt->send_rec_buf_raw_len__u16) ||
    ((reserved_payl_len__alu16 + FLEA_TLS_RECORD_HDR_LEN) > FLEA_TLS_ALT_SEND_BUF_SIZE))
  {
    FLEA_THROW("send/receive buffer is too small", FLEA_ERR_BUFF_TOO_SMALL);
  }

  rec_prot__pt->payload_max_len__u16 = rec_prot__pt->send_rec_buf_raw_len__u16 - FLEA_TLS_RECORD_HDR_LEN
    - reserved_payl_len__alu16;
  rec_prot__pt->alt_payload_max_len__u16 = FLEA_TLS_ALT_SEND_BUF_SIZE - FLEA_TLS_RECORD_HDR_LEN
    - reserved_payl_len__alu16;
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__set_cbc_hmac_ciphersuite_inner */

static flea_err_e THR_flea_tls_rec_prot_t__set_cbc_hmac_ciphersuite(
  flea_tls_rec_prot_t*            rec_prot__pt,
  flea_tls_stream_dir_e           direction,
  flea_tls__connection_end_t      conn_end__e,
  const flea_tls__cipher_suite_t* suite__pt,
  const flea_u8_t*                key_block__pcu8
)
{
  FLEA_THR_BEG_FUNC();
  flea_al_u8_t mac_key_len__alu8, mac_len__alu8, cipher_key_len__alu8;
  flea_al_u8_t mac_key_offs__alu8 = 0, ciph_key_offs__alu8 = 0;

  /*FLEA_CCALL(THR_flea_tls_get_cipher_suite_by_id(suite_id, &suite__pt));
   * if(suite__pt == NULL)
   * {
   * FLEA_THROW("invalid ciphersuite selected", FLEA_ERR_INT_ERR);
   * }*/
  mac_key_len__alu8    = suite__pt->mac_key_size;
  mac_len__alu8        = suite__pt->mac_size;
  cipher_key_len__alu8 = suite__pt->enc_key_size;
  if((direction == flea_tls_write && conn_end__e == FLEA_TLS_SERVER) ||
    (direction == flea_tls_read && conn_end__e == FLEA_TLS_CLIENT)
  )
  {
    mac_key_offs__alu8  = mac_key_len__alu8;
    ciph_key_offs__alu8 = cipher_key_len__alu8;
  }

  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__set_cbc_hmac_ciphersuite_inner(
      rec_prot__pt,
      direction,
      FLEA_TLS_CIPHER_RAW_ID(suite__pt->cipher),
      flea_tls__map_hmac_to_hash(suite__pt->hash_algorithm),
      key_block__pcu8 + 2 * mac_key_len__alu8 + ciph_key_offs__alu8,
      cipher_key_len__alu8,
      key_block__pcu8 + mac_key_offs__alu8,
      mac_key_len__alu8,
      mac_len__alu8
    )
  );
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__set_cbc_hmac_ciphersuite */

# endif /* ifdef FLEA_HAVE_TLS_CS_CBC */

# ifdef FLEA_HAVE_TLS_CS_GCM
static flea_err_e THR_flea_tls_rec_prot_t__set_gcm_ciphersuite_inner(
  flea_tls_rec_prot_t*  rec_prot__pt,
  flea_tls_stream_dir_e direction,
  flea_ae_id_e          ae_cipher_id,
  const flea_u8_t*      cipher_key__pcu8,
  flea_al_u8_t          cipher_key_len__alu8,
  const flea_u8_t*      fixed_iv__pcu8,
  flea_al_u8_t          fixed_iv_len__alu8
)
{
  flea_tls_conn_state_t* conn_state__pt;
  flea_al_u16_t reserved_payl_len__alu16;

  FLEA_THR_BEG_FUNC();

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
    THR_flea_tls_conn_state_t__ctor_gcm(
      conn_state__pt,
      ae_cipher_id,
      cipher_key__pcu8,
      cipher_key_len__alu8,
      fixed_iv__pcu8,
      fixed_iv_len__alu8
    )
  );

  /* 16 is the GCM tag length */
  reserved_payl_len__alu16 = 16 + rec_prot__pt->read_state__t.reserved_iv_len__u8;

  if(((reserved_payl_len__alu16 + FLEA_TLS_RECORD_HDR_LEN) > rec_prot__pt->send_rec_buf_raw_len__u16) ||
    ((reserved_payl_len__alu16 + FLEA_TLS_RECORD_HDR_LEN) > FLEA_TLS_ALT_SEND_BUF_SIZE))
  {
    FLEA_THROW("send/receive buffer is too small", FLEA_ERR_BUFF_TOO_SMALL);
  }

  rec_prot__pt->payload_max_len__u16 = rec_prot__pt->send_rec_buf_raw_len__u16 - FLEA_TLS_RECORD_HDR_LEN
    - reserved_payl_len__alu16;
  rec_prot__pt->alt_payload_max_len__u16 = FLEA_TLS_ALT_SEND_BUF_SIZE - FLEA_TLS_RECORD_HDR_LEN
    - reserved_payl_len__alu16;
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__set_gcm_ciphersuite_inner */

static flea_err_e THR_flea_tls_rec_prot_t__set_gcm_ciphersuite(
  flea_tls_rec_prot_t*            rec_prot__pt,
  flea_tls_stream_dir_e           direction,
  flea_tls__connection_end_t      conn_end__e,
  const flea_tls__cipher_suite_t* suite__pt,
  const flea_u8_t*                key_block__pcu8
)
{
  FLEA_THR_BEG_FUNC();
  flea_al_u8_t fixed_iv_len__alu8, cipher_key_len__alu8;
  flea_al_u8_t fixed_iv_offs__alu8 = 0, ciph_key_offs__alu8 = 0;
  if(suite__pt == NULL)
  {
    FLEA_THROW("invalid ciphersuite selected", FLEA_ERR_INT_ERR);
  }
  fixed_iv_len__alu8   = FLEA_CONST_TLS_GCM_FIXED_IV_LEN;
  cipher_key_len__alu8 = suite__pt->enc_key_size;
  if((direction == flea_tls_write && conn_end__e == FLEA_TLS_SERVER) ||
    (direction == flea_tls_read && conn_end__e == FLEA_TLS_CLIENT)
  )
  {
    fixed_iv_offs__alu8 = fixed_iv_len__alu8;
    ciph_key_offs__alu8 = cipher_key_len__alu8;
  }

  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__set_gcm_ciphersuite_inner(
      rec_prot__pt,
      direction,
      FLEA_TLS_CIPHER_RAW_ID(suite__pt->cipher),
      key_block__pcu8 + ciph_key_offs__alu8,
      cipher_key_len__alu8,
      key_block__pcu8 + 2 * cipher_key_len__alu8 + fixed_iv_offs__alu8,
      fixed_iv_len__alu8 // 4
    )
  );
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__set_gcm_ciphersuite */

# endif /* ifdef FLEA_HAVE_TLS_CS_GCM */

flea_err_e THR_flea_tls_rec_prot_t__set_ciphersuite(
  flea_tls_rec_prot_t*       rec_prot__pt,
  flea_tls_stream_dir_e      direction,
  flea_tls__connection_end_t conn_end__e,
  flea_tls_cipher_suite_id_t suite_id,
  const flea_u8_t*           key_block__pcu8
)
{
  const flea_tls__cipher_suite_t* suite__pt;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_tls_rec_prot_t__write_flush(rec_prot__pt));
  FLEA_CCALL(THR_flea_tls_get_cipher_suite_by_id(suite_id, &suite__pt));

# ifdef FLEA_HAVE_TLS_CS_GCM
  if(FLEA_TLS_IS_AE_CIPHER(suite__pt->cipher))
  {
    FLEA_CCALL(
      THR_flea_tls_rec_prot_t__set_gcm_ciphersuite(
        rec_prot__pt,
        direction,
        conn_end__e,
        suite__pt,
        key_block__pcu8
      )
    );
  }
  else
# endif /* ifdef FLEA_HAVE_TLS_CS_GCM */
# ifdef FLEA_HAVE_TLS_CS_CBC
  {
    FLEA_CCALL(
      THR_flea_tls_rec_prot_t__set_cbc_hmac_ciphersuite(
        rec_prot__pt,
        direction,
        conn_end__e,
        suite__pt,
        key_block__pcu8
      )
    );
  }
# endif /* ifdef FLEA_HAVE_TLS_CS_CBC */
  { }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__set_ciphersuite */

static void flea_tls_rec_prot_t__set_record_header(
  flea_tls_rec_prot_t*     rec_prot__pt,
  flea_tls_rec_cont_type_e content_type__e
)
{
  rec_prot__pt->send_buf_raw__pu8[0]       = content_type__e;
  rec_prot__pt->send_buf_raw__pu8[1]       = rec_prot__pt->prot_version__t.major;
  rec_prot__pt->send_buf_raw__pu8[2]       = rec_prot__pt->prot_version__t.minor;
  rec_prot__pt->send_payload_used_len__u16 = 0;
  rec_prot__pt->send_payload_offset__u16   = 0;
}

static flea_bool_t flea_tls_rec_prot_t__have_pending_read_data(const flea_tls_rec_prot_t* rec_prot__pt)
{
  return (rec_prot__pt->payload_used_len__u16 - rec_prot__pt->payload_offset__u16 > 0);
}

flea_err_e THR_flea_tls_rec_prot_t__write_data(
  flea_tls_rec_prot_t*     rec_prot__pt,
  flea_tls_rec_cont_type_e content_type__e,
  const flea_u8_t*         data__pcu8,
  flea_dtl_t               data_len__dtl
)
{
  flea_al_u16_t buf_free_len__alu16;

  FLEA_THR_BEG_FUNC();

  if(rec_prot__pt->pending_close_notify__u8)
  {
    FLEA_THROW("connection closed by peer", FLEA_ERR_TLS_REC_CLOSE_NOTIFY);
  }
  if(rec_prot__pt->is_session_closed__u8)
  {
    FLEA_THROW("tls session closed", FLEA_ERR_TLS_SESSION_CLOSED);
  }
  if(rec_prot__pt->write_ongoing__u8)
  {
    if(rec_prot__pt->send_buf_raw__pu8[0] != content_type__e)
    {
      FLEA_CCALL(THR_flea_tls_rec_prot_t__write_flush(rec_prot__pt));
      flea_tls_rec_prot_t__set_record_header(rec_prot__pt, content_type__e);
    }
    rec_prot__pt->send_buf_raw__pu8         = rec_prot__pt->alt_send_buf__raw__bu8;
    rec_prot__pt->send_buf_raw_len__u16     = FLEA_TLS_ALT_SEND_BUF_SIZE;
    rec_prot__pt->send_payload_max_len__u16 = rec_prot__pt->alt_payload_max_len__u16;
  }
  else
  {
    rec_prot__pt->send_buf_raw__pu8         = rec_prot__pt->alt_send_buf__raw__bu8;
    rec_prot__pt->send_buf_raw_len__u16     = FLEA_TLS_ALT_SEND_BUF_SIZE;
    rec_prot__pt->send_payload_max_len__u16 = rec_prot__pt->alt_payload_max_len__u16;

    flea_tls_rec_prot_t__set_record_header(rec_prot__pt, content_type__e);
  }
  rec_prot__pt->send_payload_buf__pu8 = rec_prot__pt->send_buf_raw__pu8 + FLEA_TLS_RECORD_HDR_LEN
    + rec_prot__pt->write_state__t.reserved_iv_len__u8;

  buf_free_len__alu16 = rec_prot__pt->send_payload_max_len__u16 - rec_prot__pt->send_payload_used_len__u16;
  while(data_len__dtl)
  {
    rec_prot__pt->write_ongoing__u8 = 1;
    flea_al_u16_t to_go__alu16 = FLEA_MIN(data_len__dtl, buf_free_len__alu16);
    memcpy(rec_prot__pt->send_payload_buf__pu8 + rec_prot__pt->send_payload_used_len__u16, data__pcu8, to_go__alu16);
    data_len__dtl -= to_go__alu16;
    data__pcu8    += to_go__alu16;
    rec_prot__pt->send_payload_used_len__u16 += to_go__alu16;
    buf_free_len__alu16 -= to_go__alu16;

    if(buf_free_len__alu16 == 0)
    {
      FLEA_CCALL(THR_flea_tls_rec_prot_t__write_flush(rec_prot__pt));
      buf_free_len__alu16 = rec_prot__pt->send_payload_max_len__u16 - rec_prot__pt->send_payload_used_len__u16;
      /* no need to write new header in this case: content stays, length comes later */
    }
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__write_data */

# ifdef FLEA_HAVE_TLS_CS_CBC
static flea_err_e THR_flea_tls_rec_prot_t__decrypt_record_cbc_hmac(
  flea_tls_rec_prot_t*     rec_prot__pt,
  flea_al_u16_t*           decrypted_len__palu16,
  flea_tls_rec_cont_type_e content_type__e
)
{
  flea_u32_t seq_lo__u32, seq_hi__u32;
  flea_u8_t enc_seq_nbr__au8[8];
  flea_al_s16_t max_padd_len__als16;
  flea_al_u16_t plaintext_len__alu16;
  flea_al_u16_t i__alu16;
  flea_al_u8_t left_range_mask__alu8;
  flea_al_u8_t padd_err__alu8;

  flea_u8_t mac_len =
    rec_prot__pt->read_state__t.cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.mac_size__u8;
  flea_u8_t* enc_key = rec_prot__pt->read_state__t.suite_specific__u.cbc_hmac_conn_state__t.cipher_key__bu8;
  flea_u8_t iv_len   = flea_block_cipher__get_block_size(
    rec_prot__pt->read_state__t.cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.cipher_id
    );
  flea_u8_t enc_key_len =
    rec_prot__pt->read_state__t.cipher_suite_config__t.suite_specific__u.cbc_hmac_config__t.cipher_key_size__u8;

  FLEA_DECL_BUF(mac__bu8, flea_u8_t, FLEA_TLS_MAX_MAC_SIZE);
  flea_al_u16_t padding_len__alu16;
  flea_al_u8_t last_padd_byte__alu8;
  flea_u8_t* data        = rec_prot__pt->payload_buf__pu8;
  flea_u8_t* iv          = data;
  flea_al_u16_t data_len = rec_prot__pt->payload_used_len__u16;

  FLEA_THR_BEG_FUNC();
  seq_lo__u32 = rec_prot__pt->read_state__t.sequence_number__au32[0];
  seq_hi__u32 = rec_prot__pt->read_state__t.sequence_number__au32[1];

  flea__encode_U32_BE(seq_hi__u32, enc_seq_nbr__au8);
  flea__encode_U32_BE(seq_lo__u32, enc_seq_nbr__au8 + 4);
  if(data_len < 2 * iv_len)
  {
    /* sending a different alert than BAD_RECORD_MAC here causes TLS_Attacker to
     * signal false positives */
    FLEA_THROW(
      "invalid payload length of encrypted TLS_**_WITH_**_CBC_SHA** message",
      FLEA_ERR_TLS_ENCOUNTERED_BAD_RECORD_MAC /*FLEA_ERR_TLS_PROT_DECODE_ERR*/
    );
  }

  /*
   * First decrypt
   */

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
    )
  );

  plaintext_len__alu16 = data_len - iv_len;

  max_padd_len__als16 = plaintext_len__alu16 - mac_len - 1;
  if(max_padd_len__als16 < 1)
  {
    /* sending a different alert than BAD_RECORD_MAC here causes TLS_Attacker to
     * signal false positives */
    FLEA_THROW(
      "invalid plaintext size in CBC-based ciphersuite",
      FLEA_ERR_TLS_ENCOUNTERED_BAD_RECORD_MAC /*FLEA_ERR_TLS_PROT_DECODE_ERR*/
    );
  }
  if(max_padd_len__als16 > 256)
  {
    max_padd_len__als16 = 256;
  }

  /*
   * Remove padding
   */
  last_padd_byte__alu8  = data[data_len - 1];
  padding_len__alu16    = last_padd_byte__alu8 + 1;
  left_range_mask__alu8 = 0;
  padd_err__alu8        = 0;
  for(i__alu16 = 0; i__alu16 <= (flea_al_u16_t) max_padd_len__als16; i__alu16++)
  {
    flea_al_u8_t last_iter_mask__alu8;
    flea_al_u8_t diff__alu8         = last_padd_byte__alu8;
    flea_al_u8_t padding_byte__alu8 = data[data_len - 1 - i__alu16];
    diff__alu8            ^= padding_byte__alu8;
    padd_err__alu8        |= (diff__alu8 & ~left_range_mask__alu8);
    last_iter_mask__alu8   = ~flea_expand_u32_to_u32_mask((i__alu16 + 1) ^ padding_len__alu16);
    left_range_mask__alu8 |= last_iter_mask__alu8;
  }

  /*
   * Check MAC
   */
  data_len = plaintext_len__alu16 - (padding_len__alu16) - mac_len;
  /* capture underflow */
  if(data_len > plaintext_len__alu16)
  {
    FLEA_THROW("insufficient size of hmac-cbc record payload", FLEA_ERR_TLS_ENCOUNTERED_BAD_RECORD_MAC);
  }
  FLEA_ALLOC_BUF(mac__bu8, mac_len);
#  ifdef FLEA_SCCM_USE_CACHEWARMING_IN_TA_CM
  /* cache warming */
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__compute_mac_cbc_hmac(
      rec_prot__pt->send_rec_buf_raw__bu8,
      &rec_prot__pt->read_state__t,
      data + iv_len,
      plaintext_len__alu16,
      mac__bu8
    )
  );
#  endif /* ifdef FLEA_SCCM_USE_CACHEWARMING_IN_TA_CM */
  /* compute the actual MAC */
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__compute_mac_cbc_hmac(
      rec_prot__pt->send_rec_buf_raw__bu8,
      &rec_prot__pt->read_state__t,
      data + iv_len,
      data_len,
      mac__bu8
    )
  );


  padd_err__alu8 |= !flea_sec_mem_equal(mac__bu8, data + iv_len + data_len, mac_len);
  if(padd_err__alu8)
  {
    flea_bool_t found__b = FLEA_FALSE;
    for(i__alu16 = 0; i__alu16 <= (flea_al_u16_t) max_padd_len__als16; i__alu16++)
    {
      flea_al_u16_t maced_data_len__alu16 = plaintext_len__alu16 - i__alu16 - mac_len;

      if(maced_data_len__alu16 == data_len)
      {
        found__b = FLEA_TRUE;
        continue;
      }
      FLEA_CCALL(
        THR_flea_tls_rec_prot_t__compute_mac_cbc_hmac(
          rec_prot__pt->send_rec_buf_raw__bu8,
          &rec_prot__pt->read_state__t,
          data + iv_len,
          maced_data_len__alu16,
          mac__bu8
        )
      );
    }
    if(!found__b)
    {
      /* this cannot happen */
      FLEA_THROW("internal error", FLEA_ERR_INT_ERR);
    }
    FLEA_THROW("MAC failure", FLEA_ERR_TLS_ENCOUNTERED_BAD_RECORD_MAC);
  }
  memmove(data, data + iv_len, data_len);
  *decrypted_len__palu16 = data_len;
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(mac__bu8);
  );
} /* THR_flea_tls_rec_prot_t__decrypt_record_cbc_hmac */

static flea_err_e THR_flea_tls_rec_prot_t__encrypt_record_cbc_hmac(
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
  flea_u8_t* iv       = rec_prot__pt->send_buf_raw__pu8 + FLEA_TLS_RECORD_HDR_LEN;
  flea_u8_t block_len = iv_len;

  flea_u8_t* data        = rec_prot__pt->send_payload_buf__pu8;
  flea_al_u16_t data_len = rec_prot__pt->send_payload_used_len__u16;
  flea_u8_t padding_len  = (block_len - (data_len + mac_len + 1) % block_len) + 1; // +1 for padding_length entry

  flea_u8_t* mac     = data + data_len;
  flea_u8_t* padding = mac + mac_len;
  flea_dtl_t input_output_len;
  flea_u8_t k;
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__compute_mac_cbc_hmac(
      rec_prot__pt->send_buf_raw__pu8,
      &rec_prot__pt->write_state__t,
      data,
      data_len,
      mac
    )
  );

  FLEA_CCALL(THR_flea_rng__randomize(iv, iv_len));

  input_output_len = data_len + padding_len + mac_len;

  for(k = 0; k < padding_len; k++)
  {
    padding[k] = padding_len - 1;
  }

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

  length_tot = input_output_len + iv_len;
  rec_prot__pt->send_buf_raw__pu8[3] = length_tot >> 8;
  rec_prot__pt->send_buf_raw__pu8[4] = length_tot;
  *encrypted_len__palu16 = input_output_len;
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__encrypt_record_cbc_hmac */

# endif /* ifdef FLEA_HAVE_HMAC */

# ifdef FLEA_HAVE_TLS_CS_GCM
static flea_err_e THR_flea_tls_rec_prot_t__decrypt_record_gcm(
  flea_tls_rec_prot_t*     rec_prot__pt,
  flea_al_u16_t*           decrypted_len__palu16,
  flea_tls_rec_cont_type_e content_type__e
)
{
  flea_u32_t seq_lo__u32, seq_hi__u32;
  flea_u8_t enc_seq_nbr__au8[8];
  flea_u8_t gcm_header__au8[13];
  flea_u8_t enc_data_len__au8[2];
  flea_u8_t* gcm_tag__pu8;
  flea_u8_t gcm_tag_len__u8         = FLEA_CONST_TLS_GCM_TAG_LEN;
  const flea_u8_t record_iv_len__u8 =
    rec_prot__pt->read_state__t.cipher_suite_config__t.suite_specific__u.gcm_config__t.record_iv_length__u8;
  const flea_u8_t fixed_iv_len__u8 =
    rec_prot__pt->read_state__t.cipher_suite_config__t.suite_specific__u.gcm_config__t.fixed_iv_length__u8;


  FLEA_THR_BEG_FUNC();
  flea_u8_t* enc_key    = rec_prot__pt->read_state__t.suite_specific__u.gcm_conn_state__t.cipher_key__bu8;
  flea_u8_t enc_key_len =
    rec_prot__pt->read_state__t.cipher_suite_config__t.suite_specific__u.gcm_config__t.cipher_key_size__u8;

  // iv = fixed_iv + record_iv (record_iv is directly adjacent in memory)
  flea_u8_t* iv    = rec_prot__pt->read_state__t.suite_specific__u.gcm_conn_state__t.fixed_iv__bu8;
  flea_u8_t iv_len = fixed_iv_len__u8 + record_iv_len__u8;

  flea_u8_t* data        = rec_prot__pt->payload_buf__pu8;
  flea_al_u16_t data_len = rec_prot__pt->payload_used_len__u16;

  if(data_len <= record_iv_len__u8 + gcm_tag_len__u8)
  {
    FLEA_THROW("invalid payload length of encrypted TLS_**_WITH_**_GCM_SHA** message", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }

  // copy received explicit nonce into record iv
  memcpy(iv + fixed_iv_len__u8, data, record_iv_len__u8);

  seq_lo__u32 = rec_prot__pt->read_state__t.sequence_number__au32[0];
  seq_hi__u32 = rec_prot__pt->read_state__t.sequence_number__au32[1];

  flea__encode_U32_BE(seq_hi__u32, enc_seq_nbr__au8);
  flea__encode_U32_BE(seq_lo__u32, enc_seq_nbr__au8 + 4);

  *decrypted_len__palu16 = data_len - record_iv_len__u8 - gcm_tag_len__u8;

  // copy seq nr, type, version, length into gcm header
  enc_data_len__au8[0] = *decrypted_len__palu16 >> 8;
  enc_data_len__au8[1] = *decrypted_len__palu16;
  memcpy(gcm_header__au8, enc_seq_nbr__au8, 8);
  gcm_header__au8[8]  = rec_prot__pt->send_rec_buf_raw__bu8[0];
  gcm_header__au8[9]  = rec_prot__pt->prot_version__t.major;
  gcm_header__au8[10] = rec_prot__pt->prot_version__t.minor;
  memcpy(gcm_header__au8 + 11, enc_data_len__au8, 2);

  gcm_tag__pu8 = data + (data_len - gcm_tag_len__u8);
  FLEA_CCALL(
    THR_flea_ae__decrypt(
      rec_prot__pt->read_state__t.cipher_suite_config__t.suite_specific__u.gcm_config__t.cipher_id,
      enc_key,
      enc_key_len,
      iv,
      iv_len,
      gcm_header__au8,
      sizeof(gcm_header__au8),
      data + record_iv_len__u8,
      data + record_iv_len__u8,
      *decrypted_len__palu16,
      gcm_tag__pu8,
      gcm_tag_len__u8
    )
  );

  memmove(data, data + record_iv_len__u8, *decrypted_len__palu16);
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__decrypt_record_gcm */

static flea_err_e THR_flea_tls_rec_prot_t__encrypt_record_gcm(
  flea_tls_rec_prot_t* rec_prot__pt,
  flea_al_u16_t*       encrypted_len__palu16
)
{
  flea_al_u16_t length_tot;
  flea_u8_t enc_seq_nbr__au8[8];
  flea_u32_t seq_lo__u32, seq_hi__u32;
  flea_u8_t* gcm_tag__pu8;
  flea_u8_t gcm_tag_len__u8 = FLEA_CONST_TLS_GCM_TAG_LEN;
  flea_u8_t gcm_header__au8[13]; // 8+1+2+2
  flea_u8_t enc_data_len__au8[2];

  FLEA_THR_BEG_FUNC();
  flea_u8_t* enc_key    = rec_prot__pt->write_state__t.suite_specific__u.gcm_conn_state__t.cipher_key__bu8;
  flea_u8_t enc_key_len =
    rec_prot__pt->write_state__t.cipher_suite_config__t.suite_specific__u.gcm_config__t.cipher_key_size__u8;


  // iv = fixed_iv + record_iv (record_iv is directly adjacent in memory)
  flea_u8_t* iv    = rec_prot__pt->write_state__t.suite_specific__u.gcm_conn_state__t.fixed_iv__bu8;
  flea_u8_t iv_len =
    rec_prot__pt->write_state__t.cipher_suite_config__t.suite_specific__u.gcm_config__t.fixed_iv_length__u8
    + rec_prot__pt->write_state__t.cipher_suite_config__t.suite_specific__u.gcm_config__t.record_iv_length__u8;

  // copy sequence number to explicit nonce part as suggested in RFC 5288
  seq_lo__u32 = rec_prot__pt->write_state__t.sequence_number__au32[0];
  seq_hi__u32 = rec_prot__pt->write_state__t.sequence_number__au32[1];
  flea__encode_U32_BE(seq_hi__u32, enc_seq_nbr__au8);
  flea__encode_U32_BE(seq_lo__u32, enc_seq_nbr__au8 + 4);
  memcpy(
    rec_prot__pt->write_state__t.suite_specific__u.gcm_conn_state__t.record_iv__bu8,
    enc_seq_nbr__au8,
    rec_prot__pt->write_state__t.cipher_suite_config__t.suite_specific__u.gcm_config__t.record_iv_length__u8
  );

  // write explicit part of nonce/iv before the encrypted data
  flea_u8_t* expl_nonce = rec_prot__pt->send_buf_raw__pu8 + FLEA_TLS_RECORD_HDR_LEN;
  memcpy(
    expl_nonce,
    enc_seq_nbr__au8,
    rec_prot__pt->write_state__t.cipher_suite_config__t.suite_specific__u.gcm_config__t.record_iv_length__u8
  );

  flea_u8_t* data        = rec_prot__pt->send_payload_buf__pu8;
  flea_al_u16_t data_len = rec_prot__pt->send_payload_used_len__u16;

  // copy seq nr, type, version, length into gcm header
  enc_data_len__au8[0] = data_len >> 8;
  enc_data_len__au8[1] = data_len;
  memcpy(gcm_header__au8, enc_seq_nbr__au8, 8);
  gcm_header__au8[8]  = rec_prot__pt->send_buf_raw__pu8[0];
  gcm_header__au8[9]  = rec_prot__pt->prot_version__t.major;
  gcm_header__au8[10] = rec_prot__pt->prot_version__t.minor;
  memcpy(gcm_header__au8 + 11, enc_data_len__au8, 2);

  // set gcm tag to point "behind the data"
  gcm_tag__pu8 = data + data_len;

  FLEA_CCALL(
    THR_flea_ae__encrypt(
      rec_prot__pt->write_state__t.cipher_suite_config__t.suite_specific__u.gcm_config__t.cipher_id,
      enc_key,
      enc_key_len,
      iv, // fixed iv || record iv
      iv_len,
      gcm_header__au8,
      sizeof(gcm_header__au8),
      data,
      data,
      data_len,
      gcm_tag__pu8,
      gcm_tag_len__u8
    )
  );

  // copy authentication tag

  length_tot = data_len
    + rec_prot__pt->write_state__t.cipher_suite_config__t.suite_specific__u.gcm_config__t.record_iv_length__u8
    + gcm_tag_len__u8;
  rec_prot__pt->send_buf_raw__pu8[3] = length_tot >> 8;
  rec_prot__pt->send_buf_raw__pu8[4] = length_tot;
  *encrypted_len__palu16 = data_len + gcm_tag_len__u8;

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__encrypt_record_gcm */

# endif /* ifdef FLEA_HAVE_TLS_CS_GCM */
flea_err_e THR_flea_tls_rec_prot_t__write_flush(
  flea_tls_rec_prot_t* rec_prot__pt
)
{
  FLEA_THR_BEG_FUNC();
  if((rec_prot__pt->send_payload_used_len__u16 == 0) || !rec_prot__pt->write_ongoing__u8)
  {
    FLEA_THR_RETURN();
  }
# ifdef FLEA_HAVE_TLS_CS_CBC
  if(rec_prot__pt->write_state__t.cipher_suite_config__t.cipher_suite_class__e == flea_cbc_cipher_suite)
  {
    flea_al_u16_t encrypted_len__alu16;
    FLEA_CCALL(THR_flea_tls_rec_prot_t__encrypt_record_cbc_hmac(rec_prot__pt, &encrypted_len__alu16));
    FLEA_CCALL(
      THR_flea_rw_stream_t__write(
        rec_prot__pt->rw_stream__pt,
        rec_prot__pt->send_buf_raw__pu8,
        encrypted_len__alu16 + FLEA_TLS_RECORD_HDR_LEN + rec_prot__pt->write_state__t.reserved_iv_len__u8
      )
    );

    inc_seq_nbr(rec_prot__pt->write_state__t.sequence_number__au32);
  }
  else
# endif /* ifdef FLEA_HAVE_TLS_CS_CBC */
# ifdef FLEA_HAVE_TLS_CS_GCM
  if(rec_prot__pt->write_state__t.cipher_suite_config__t.cipher_suite_class__e == flea_gcm_cipher_suite)
  {
    flea_al_u16_t encrypted_len__alu16;
    FLEA_CCALL(THR_flea_tls_rec_prot_t__encrypt_record_gcm(rec_prot__pt, &encrypted_len__alu16));
    FLEA_CCALL(
      THR_flea_rw_stream_t__write(
        rec_prot__pt->rw_stream__pt,
        rec_prot__pt->send_buf_raw__pu8,
        encrypted_len__alu16 + FLEA_TLS_RECORD_HDR_LEN + rec_prot__pt->write_state__t.reserved_iv_len__u8
      )
    );

    inc_seq_nbr(rec_prot__pt->write_state__t.sequence_number__au32);
  }
  else
# endif /* ifdef FLEA_HAVE_TLS_CS_GCM */
  if(rec_prot__pt->write_state__t.cipher_suite_config__t.cipher_suite_class__e == flea_null_cipher_suite)
  {
    rec_prot__pt->send_buf_raw__pu8[3] = rec_prot__pt->send_payload_used_len__u16 >> 8;
    rec_prot__pt->send_buf_raw__pu8[4] = rec_prot__pt->send_payload_used_len__u16;
    FLEA_CCALL(
      THR_flea_rw_stream_t__write(
        rec_prot__pt->rw_stream__pt,
        rec_prot__pt->send_buf_raw__pu8,
        rec_prot__pt->send_payload_used_len__u16 + FLEA_TLS_RECORD_HDR_LEN
      )
    );
  }
  else
  {
    FLEA_THROW("unsupported ciphersuite", FLEA_ERR_INT_ERR);
  }
  FLEA_CCALL(THR_flea_rw_stream_t__flush_write(rec_prot__pt->rw_stream__pt));

  flea_tls_rec_prot_t__discard_pending_write(rec_prot__pt);

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__write_flush */

flea_err_e THR_flea_tls_rec_prot_t__send_record(
  flea_tls_rec_prot_t*     rec_prot__pt,
  const flea_u8_t*         bytes__pcu8,
  flea_dtl_t               bytes_len__dtl,
  flea_tls_rec_cont_type_e content_type
)
{
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_tls_rec_prot_t__write_data(rec_prot__pt, content_type, bytes__pcu8, bytes_len__dtl));

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_record */

flea_err_e THR_flea_tls_rec_prot_t__send_alert_and_throw(
  flea_tls_rec_prot_t*          rec_prot__pt,
  flea_tls__alert_description_t description,
  flea_err_e                    err__t
)
{
  flea_tls__alert_level_t lev = FLEA_TLS_ALERT_LEVEL_FATAL;

  FLEA_THR_BEG_FUNC();
  if(rec_prot__pt->is_session_closed__u8)
  {
    FLEA_THROW(
      "unable to send fatal alert due to session being already closed",
      FLEA_ERR_TLS_SESSION_CLOSED_WHEN_TRYING_TO_SEND_ALERT
    );
  }
  if(description == FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY)
  {
    lev = FLEA_TLS_ALERT_LEVEL_WARNING;
  }
  if(description != FLEA_TLS_ALERT_NO_ALERT)
  {
    flea_tls_rec_prot_t__discard_pending_write(rec_prot__pt);
    FLEA_CCALL(THR_flea_tls_rec_prot_t__send_alert(rec_prot__pt, description, lev));
    rec_prot__pt->is_session_closed__u8 = 1;
  }
  FLEA_THROW("throwing error after (potentially) sending fatal TLS alert", err__t);

  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_tls_rec_prot_t__send_alert(
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
  FLEA_CCALL(THR_flea_tls_rec_prot_t__write_flush(rec_prot__pt));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_tls_rec_prot_t__close_and_send_close_notify(flea_tls_rec_prot_t* rec_prot__pt)
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

void flea_tls_rec_prot_t__discard_current_read_record(flea_tls_rec_prot_t* rec_prot__pt)
{
  rec_prot__pt->payload_offset__u16   = 0;
  rec_prot__pt->payload_used_len__u16 = 0;
  rec_prot__pt->read_bytes_from_current_record__u16 = 0;
}

static flea_err_e THR_flea_tls_rec_prot_t__read_data_inner(
  flea_tls_rec_prot_t*          rec_prot__pt,
  flea_u8_t*                    data__pu8,
  flea_dtl_t*                   data_len__pdtl,
  flea_tls__protocol_version_t* prot_version_mbn__pt,
  flea_bool_t                   do_verify_prot_version__b,
  flea_tls_rec_cont_type_e      cont_type__e,
  flea_bool_t                   current_or_next_record_for_content_type__b,
  flea_stream_read_mode_e       rd_mode__e
)
{
  flea_al_u16_t to_cp__alu16, read_bytes_count__dtl = 0;
  flea_dtl_t data_len__dtl = *data_len__pdtl;

  flea_bool_t is_handsh_msg_during_app_data__b = FLEA_FALSE;

  FLEA_THR_BEG_FUNC();
  *data_len__pdtl = 0;

  if(rec_prot__pt->pending_close_notify__u8)
  {
    FLEA_THROW("connection closed by peer", FLEA_ERR_TLS_REC_CLOSE_NOTIFY);
  }
  if(rec_prot__pt->is_session_closed__u8)
  {
    FLEA_THROW("tls session closed", FLEA_ERR_TLS_SESSION_CLOSED);
  }
  if(rec_prot__pt->write_ongoing__u8)
  {
    FLEA_CCALL(THR_flea_tls_rec_prot_t__write_flush(rec_prot__pt));
    rec_prot__pt->read_bytes_from_current_record__u16 = 0;
    rec_prot__pt->current_record_content_len__u16     = 0;
  }

  rec_prot__pt->payload_buf__pu8 = rec_prot__pt->send_rec_buf_raw__bu8 + FLEA_TLS_RECORD_HDR_LEN;

  to_cp__alu16 = FLEA_MIN(data_len__dtl, rec_prot__pt->payload_used_len__u16 - rec_prot__pt->payload_offset__u16);
  memcpy(data__pu8, rec_prot__pt->payload_buf__pu8 + rec_prot__pt->payload_offset__u16, to_cp__alu16);
  rec_prot__pt->payload_offset__u16 += to_cp__alu16;
  data_len__dtl         -= to_cp__alu16;
  data__pu8             += to_cp__alu16;
  read_bytes_count__dtl += to_cp__alu16;
  // enter only if
  // - called with current_or_next_record_for_content_type__b
  //   OR
  // - called with non-zero length and data copied above did not suffice
  // no more data left. this is important for 0-length reads to
  // get the current record type

  /* get new record hdr and content */
  if((current_or_next_record_for_content_type__b &&
    !flea_tls_rec_prot_t__have_pending_read_data(rec_prot__pt)) || data_len__dtl)
  {
    /* start reading a new record */
    flea_stream_read_mode_e local_rd_mode__e = rd_mode__e;
    flea_dtl_t raw_read_len__dtl;
    flea_al_u16_t raw_rec_content_len__alu16;
    if(local_rd_mode__e == flea_read_blocking)
    {
      local_rd_mode__e = flea_read_full;
    }
    do
    {
      /* read the hdr */
      if(rec_prot__pt->read_bytes_from_current_record__u16 < FLEA_TLS_RECORD_HDR_LEN)
      {
        while(rec_prot__pt->read_bytes_from_current_record__u16 < FLEA_TLS_RECORD_HDR_LEN)
        {
          raw_read_len__dtl = FLEA_TLS_RECORD_HDR_LEN - rec_prot__pt->read_bytes_from_current_record__u16;
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
              *data_len__pdtl = 0;
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
        else
        {
          rec_prot__pt->is_current_record_alert__u8 = 0;
        }
        if(!rec_prot__pt->is_current_record_alert__u8)
        {
          if(
            (cont_type__e == CONTENT_TYPE_APPLICATION_DATA) &&
            (rec_prot__pt->send_rec_buf_raw__bu8[0] == CONTENT_TYPE_HANDSHAKE))
          {
            is_handsh_msg_during_app_data__b = FLEA_TRUE;
          }
          else if(!current_or_next_record_for_content_type__b &&
            (cont_type__e != rec_prot__pt->send_rec_buf_raw__bu8[0]))
          {
            FLEA_THROW("content type does not match", FLEA_ERR_TLS_INV_REC_HDR);
          }

          /* }
             if(!rec_prot__pt->is_current_record_alert__u8)
             {*/
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
        if(rec_prot__pt->current_record_content_len__u16 > FLEA_TLS_TRNSF_BUF_SIZE - FLEA_TLS_RECORD_HDR_LEN)
        {
          FLEA_THROW("received record does not fit into receive buffer", FLEA_ERR_TLS_EXCSS_REC_LEN);
        }
      } /* end of 'read the hdr' */

      if(rec_prot__pt->read_bytes_from_current_record__u16 <
        rec_prot__pt->current_record_content_len__u16 + FLEA_TLS_RECORD_HDR_LEN)
      {
        flea_stream_read_mode_e content_read_mode__e = local_rd_mode__e;
        flea_al_u16_t needed_read_len__alu16;
        if(rec_prot__pt->is_current_record_alert__u8)
        {
          content_read_mode__e = flea_read_full;
        }
        needed_read_len__alu16 = raw_read_len__dtl = rec_prot__pt->current_record_content_len__u16
            - (rec_prot__pt->read_bytes_from_current_record__u16 - FLEA_TLS_RECORD_HDR_LEN);
        FLEA_CCALL(
          THR_flea_rw_stream_t__read(
            rec_prot__pt->rw_stream__pt,
            rec_prot__pt->payload_buf__pu8 + rec_prot__pt->read_bytes_from_current_record__u16
            - FLEA_TLS_RECORD_HDR_LEN,
            &raw_read_len__dtl,
            content_read_mode__e
          )
        );
        rec_prot__pt->read_bytes_from_current_record__u16 += raw_read_len__dtl;

        if(raw_read_len__dtl < needed_read_len__alu16)
        {
          if(local_rd_mode__e == flea_read_nonblocking)
          {
            *data_len__pdtl = 0;
            FLEA_THR_RETURN();
          }
          else
          {
            FLEA_THROW("0 bytes returned from blocking read", FLEA_ERR_FAILED_STREAM_READ);
          }
        }
      } /* did read full content */
      rec_prot__pt->payload_used_len__u16 = rec_prot__pt->read_bytes_from_current_record__u16 - FLEA_TLS_RECORD_HDR_LEN;
      rec_prot__pt->payload_offset__u16   = 0;

      raw_rec_content_len__alu16 = rec_prot__pt->current_record_content_len__u16;

      /* not needed any more, reset: */
      rec_prot__pt->read_bytes_from_current_record__u16 = 0;
      rec_prot__pt->current_record_content_len__u16     = 0;
# ifdef FLEA_HAVE_TLS_CS_CBC
      if(rec_prot__pt->read_state__t.cipher_suite_config__t.cipher_suite_class__e == flea_cbc_cipher_suite)
      {
        FLEA_CCALL(
          THR_flea_tls_rec_prot_t__decrypt_record_cbc_hmac(
            rec_prot__pt,
            &raw_rec_content_len__alu16,
            (flea_tls_rec_cont_type_e) rec_prot__pt->send_rec_buf_raw__bu8[0]
          )
        );
        rec_prot__pt->payload_used_len__u16 = raw_rec_content_len__alu16;
        inc_seq_nbr(rec_prot__pt->read_state__t.sequence_number__au32);
      }
# endif /* ifdef FLEA_HAVE_TLS_CS_CBC */
# ifdef FLEA_HAVE_TLS_CS_GCM
      if(rec_prot__pt->read_state__t.cipher_suite_config__t.cipher_suite_class__e == flea_gcm_cipher_suite)
      {
        FLEA_CCALL(
          THR_flea_tls_rec_prot_t__decrypt_record_gcm(
            rec_prot__pt,
            &raw_rec_content_len__alu16,
            (flea_tls_rec_cont_type_e) rec_prot__pt->send_rec_buf_raw__bu8[0]
          )
        );
        rec_prot__pt->payload_used_len__u16 = raw_rec_content_len__alu16;
        inc_seq_nbr(rec_prot__pt->read_state__t.sequence_number__au32);
      }
# endif /* ifdef FLEA_HAVE_TLS_CS_GCM */


      if(is_handsh_msg_during_app_data__b)
      {
        FLEA_THROW("received tls handshake message when app data was expected", FLEA_EXC_TLS_HS_MSG_DURING_APP_DATA);
      }
      else if(rec_prot__pt->is_current_record_alert__u8)
      {
        if(rec_prot__pt->payload_buf__pu8[1] == FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY)
        {
          if(((rd_mode__e == flea_read_full) && data_len__dtl) || !read_bytes_count__dtl)
          {
            FLEA_THROW("received close notify", FLEA_ERR_TLS_REC_CLOSE_NOTIFY);
          }
          else
          {
            rec_prot__pt->pending_close_notify__u8 = 1;
          }
        }

        FLEA_CCALL(THR_flea_tls_rec_prot_t__handle_alert(rec_prot__pt, read_bytes_count__dtl));
      }
      else
      {
        to_cp__alu16 = FLEA_MIN(raw_rec_content_len__alu16, data_len__dtl);
        memcpy(data__pu8, rec_prot__pt->payload_buf__pu8, to_cp__alu16);
        rec_prot__pt->payload_offset__u16 += to_cp__alu16;
        read_bytes_count__dtl += to_cp__alu16;
        data_len__dtl         -= to_cp__alu16;
        data__pu8      += to_cp__alu16;
        *data_len__pdtl = read_bytes_count__dtl;
      }
    } while(
      rec_prot__pt->is_current_record_alert__u8 || ((rd_mode__e == flea_read_full) && data_len__dtl) ||
      ((rd_mode__e == flea_read_blocking) && !read_bytes_count__dtl)
    );
  } /* end of ' get new record hdr and content' */


  if(!flea_tls_rec_prot_t__have_pending_read_data(rec_prot__pt))
  {
    flea_tls_rec_prot_t__discard_current_read_record(rec_prot__pt);
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__read_data_inner */

/* get the content type of the currently (and not yet completely read) or newly received buffer */
flea_err_e THR_flea_tls_rec_prot_t__get_current_record_type(
  flea_tls_rec_prot_t*      rec_prot__pt,
  flea_tls_rec_cont_type_e* cont_type__pe,
  flea_stream_read_mode_e   rd_mode__e
)
{
  FLEA_THR_BEG_FUNC();
  flea_tls__protocol_version_t dummy_version__t;
  flea_dtl_t read_len_zero__dtl = 0;
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__read_data_inner(
      rec_prot__pt,
      NULL,
      &read_len_zero__dtl,
      &dummy_version__t,
      FLEA_FALSE,
      0 /*dummy_content_type */,
      FLEA_TRUE,
      rd_mode__e
    )
  );
  *cont_type__pe = rec_prot__pt->send_rec_buf_raw__bu8[0];
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_tls_rec_prot_t__read_data(
  flea_tls_rec_prot_t*     rec_prot__pt,
  flea_tls_rec_cont_type_e cont_type__e,
  flea_u8_t*               data__pu8,
  flea_dtl_t*              data_len__pdtl,
  flea_stream_read_mode_e  rd_mode__e
)
{
  return THR_flea_tls_rec_prot_t__read_data_inner(
    rec_prot__pt,
    data__pu8,
    data_len__pdtl,
    NULL,
    FLEA_FALSE,
    cont_type__e,
    FLEA_FALSE,
    rd_mode__e
  );
}

flea_bool_t flea_tls_rec_prot_t__have_done_initial_handshake(const flea_tls_rec_prot_t* rec_prot__pt)
{
  if(rec_prot__pt->write_state__t.cipher_suite_config__t.cipher_suite_class__e != flea_null_cipher_suite)
  {
    return FLEA_TRUE;
  }
  return FLEA_FALSE;
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
  FLEA_FREE_MEM_CHECK_SET_NULL_SECRET_ARR(rec_prot__pt->alt_send_buf__raw__bu8, FLEA_TLS_ALT_SEND_BUF_SIZE);
}

#endif /* ifdef FLEA_HAVE_TLS */
