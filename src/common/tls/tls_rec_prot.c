/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/tls_rec_prot.h"
#include "internal/common/tls_ciph_suite.h"
#include "flea/error_handling.h"
#include "flea/bin_utils.h"
#include "flea/error.h"
#include "flea/rng.h"

#define FLEA_TLS_MAX_MAC_SIZE         32
#define FLEA_TLS_MAX_MAC_KEY_SIZE     32
#define FLEA_TLS_MAX_IV_SIZE          32
#define FLEA_TLS_MAX_RECORD_DATA_SIZE 16384 // 2^14 max record sizeof
#define FLEA_TLS_MAX_PADDING_SIZE     255   // each byte must hold the padding value => 255 is max

#define RECORD_HDR_LEN                5

static flea_err_t THR_flea_tls__compute_mac(
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

flea_err_t THR_flea_tls_rec_prot_t__ctor(
  flea_tls_rec_prot_t            *rec_prot__pt,
  flea_u8_t                      *send_rec_buf_raw__pu8,
  flea_al_u16_t                  send_rec_buf_raw_len__alu16,
  // flea_al_u8_t             reserved_iv_len__alu8,
  const flea_tls__cipher_suite_t *suite__pt,
  flea_al_u8_t                   prot_vers_major,
  flea_al_u8_t                   prot_vers_minor,
  flea_rw_stream_t               *rw_stream__pt
)
{
  flea_al_u16_t reserved_payl_len__alu16;

  FLEA_THR_BEG_FUNC();
  /* TODO: do all inits except for stream in start_record */
  rec_prot__pt->send_rec_buf_raw__pu8     = send_rec_buf_raw__pu8;
  rec_prot__pt->payload_buf__pu8          = send_rec_buf_raw__pu8 + suite__pt->iv_size + RECORD_HDR_LEN;
  rec_prot__pt->send_rec_buf_raw_len__u16 = send_rec_buf_raw_len__alu16;
  // rec_prot__pt->payload_used_len = 0;
  rec_prot__pt->prot_version__t.major = prot_vers_major;
  rec_prot__pt->prot_version__t.minor = prot_vers_minor;
  rec_prot__pt->rw_stream__pt         = rw_stream__pt;
  rec_prot__pt->ciph_suite_id         = suite__pt->id;
  rec_prot__pt->reserved_iv_len__u8   = suite__pt->iv_size;
  rec_prot__pt->payload_offset__u16   = 0;
  if(suite__pt->id == TLS_NULL_WITH_NULL_NULL)
  {
    reserved_payl_len__alu16 = 0;
  }
  else
  if(suite__pt->id == TLS_RSA_WITH_AES_256_CBC_SHA256)
  {
    reserved_payl_len__alu16 = suite__pt->mac_size + suite__pt->block_size + suite__pt->iv_size;
  }
  else
  {
    FLEA_THROW("unknown ciphersuite", FLEA_ERR_INV_ARG);
  }
  if((reserved_payl_len__alu16 + RECORD_HDR_LEN) > send_rec_buf_raw_len__alu16)
  {
    FLEA_THROW("send/receive buffer is too small", FLEA_ERR_BUFF_TOO_SMALL);
  }
  rec_prot__pt->payload_max_len__u16 = send_rec_buf_raw_len__alu16 - RECORD_HDR_LEN - reserved_payl_len__alu16;
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__ctor */

flea_err_t THR_flea_tls_rec_prot_t__start_record_writing(flea_tls_rec_prot_t *rec_prot__pt, ContentType content_type__e)
{
  FLEA_THR_BEG_FUNC();
  rec_prot__pt->send_rec_buf_raw__pu8[0] = content_type__e;
  rec_prot__pt->send_rec_buf_raw__pu8[1] = rec_prot__pt->prot_version__t.major;
  rec_prot__pt->send_rec_buf_raw__pu8[2] = rec_prot__pt->prot_version__t.minor;
  rec_prot__pt->payload_used_len__u16    = 0;
  rec_prot__pt->payload_offset__u16      = 0;

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls_rec_prot_t__write_data(
  flea_tls_rec_prot_t          *rec_prot__pt,
  const flea_u8_t              *data__pcu8,
  flea_dtl_t                   data_len__dtl,
  flea_tls__connection_state_t *conn_state__pt
)
{
  flea_al_u16_t buf_free_len__alu16 = rec_prot__pt->payload_max_len__u16 - rec_prot__pt->payload_used_len__u16;

  FLEA_THR_BEG_FUNC();
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
      FLEA_CCALL(THR_flea_tls_rec_prot_t__write_flush(rec_prot__pt, conn_state__pt));
    }
  }
  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_flea_tls_rec_prot_t__encrypt_record_cbc_hmac(
  flea_tls_rec_prot_t                *rec_prot__pt,
  const flea_tls__connection_state_t *conn_state__pt,
  flea_al_u16_t                      *encrypted_len__palu16
)
{
  flea_u32_t seq_lo__u32, seq_hi__u32;
  flea_u8_t enc_seq_nbr__au8[8];
  flea_al_u16_t length_tot;

  FLEA_THR_BEG_FUNC();
  // TODO: this is for client connection end. need other keys for server connection end
  flea_u8_t *mac_key    = conn_state__pt->mac_key;
  flea_u8_t *enc_key    = conn_state__pt->enc_key;
  flea_u8_t iv_len      = conn_state__pt->cipher_suite->iv_size;
  flea_u8_t mac_len     = conn_state__pt->cipher_suite->mac_size;
  flea_u8_t mac_key_len = conn_state__pt->cipher_suite->mac_key_size;
  flea_u8_t enc_key_len = conn_state__pt->cipher_suite->enc_key_size;
  flea_u8_t mac[FLEA_TLS_MAX_MAC_SIZE];
  // flea_u8_t iv[FLEA_TLS_MAX_IV_SIZE];
  flea_u8_t *iv       = rec_prot__pt->send_rec_buf_raw__pu8 + RECORD_HDR_LEN;
  flea_u8_t block_len = conn_state__pt->cipher_suite->block_size;

  flea_u8_t *data        = rec_prot__pt->payload_buf__pu8;
  flea_al_u16_t data_len = rec_prot__pt->payload_used_len__u16;
  seq_lo__u32 = conn_state__pt->sequence_number__au32[0];
  seq_hi__u32 = conn_state__pt->sequence_number__au32[1];
  // TODO: put back in
  // inc_seq_nbr(tls_ctx->active_write_connection_state->sequence_number__au32);

  // TODO: was ist mit SEQ overflow? => reneg. implement
  flea__encode_U32_LE(seq_lo__u32, enc_seq_nbr__au8);
  flea__encode_U32_LE(seq_hi__u32, enc_seq_nbr__au8 + 4);
  // compute mac
  FLEA_CCALL(
    THR_flea_tls__compute_mac(
      data, data_len, &rec_prot__pt->prot_version__t, // &tls_ctx->version,
      conn_state__pt->cipher_suite->mac_algorithm, mac_key, mac_key_len, enc_seq_nbr__au8,
      rec_prot__pt->send_rec_buf_raw__pu8[0] /* content_type */, mac, &mac_len
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

  // printf("padding len orig version = %u\n", padding_len);
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
      conn_state__pt->cipher_suite->cipher, enc_key,
      enc_key_len, iv, iv_len, encrypted, padded_data, input_output_len
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
  rec_prot__pt->send_rec_buf_raw__pu8[3] = length_tot >> 8;
  rec_prot__pt->send_rec_buf_raw__pu8[4] = length_tot;
  // record->data   = calloc(input_output_len + iv_len, sizeof(flea_u8_t));
  // memcpy(rec_prot__pt->send_rec_buf_raw__pu8 + RECORD_HDR_LEN, iv, iv_len);
  memcpy(rec_prot__pt->payload_buf__pu8, encrypted, input_output_len);
  *encrypted_len__palu16 = input_output_len;
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__encrypt_record_cbc_hmac */

flea_err_t THR_flea_tls_rec_prot_t__write_flush(
  flea_tls_rec_prot_t          *rec_prot__pt,
  flea_tls__connection_state_t *conn_state__pt
)
{
  FLEA_THR_BEG_FUNC();

  if(rec_prot__pt->ciph_suite_id == TLS_RSA_WITH_AES_256_CBC_SHA256)
  {
    flea_al_u16_t encrypted_len__alu16;
    FLEA_CCALL(THR_flea_tls_rec_prot_t__encrypt_record_cbc_hmac(rec_prot__pt, conn_state__pt, &encrypted_len__alu16));
    FLEA_CCALL(
      THR_flea_rw_stream_t__write(
        rec_prot__pt->rw_stream__pt, rec_prot__pt->send_rec_buf_raw__pu8,
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
  }
  else
  if(rec_prot__pt->ciph_suite_id == TLS_NULL_WITH_NULL_NULL)
  {
    rec_prot__pt->send_rec_buf_raw__pu8[3] = rec_prot__pt->payload_used_len__u16 >> 8;
    rec_prot__pt->send_rec_buf_raw__pu8[4] = rec_prot__pt->payload_used_len__u16;

    FLEA_CCALL(
      THR_flea_rw_stream_t__write(
        rec_prot__pt->rw_stream__pt, rec_prot__pt->send_rec_buf_raw__pu8,
        rec_prot__pt->payload_used_len__u16 + RECORD_HDR_LEN
      )
    );
  }
  FLEA_CCALL(THR_flea_rw_stream_t__flush_write(rec_prot__pt->rw_stream__pt));
  rec_prot__pt->write_ongoing__u8 = 0;
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__write_flush */

flea_err_t THR_flea_tls_rec_prot_t__read_data(
  flea_tls_rec_prot_t          *rec_prot__pt,
  flea_u8_t                    *data__pu8,
  flea_dtl_t                   *data_len__pdtl,
  flea_tls__connection_state_t *conn_state__pt,
  flea_tls__protocol_version_t *prot_version__pt,
  flea_bool_t                  do_verify_prot_version__b,
  ContentType                  *cont_type__pe
)
{
  flea_al_u16_t to_cp__alu16, read_bytes_count__alu16 = 0;
  flea_dtl_t data_len__dtl = *data_len__pdtl;

  FLEA_THR_BEG_FUNC();
  if(rec_prot__pt->write_ongoing__u8)
  {
    FLEA_CCALL(THR_flea_rw_stream_t__flush_write(rec_prot__pt->rw_stream__pt));
  }
  to_cp__alu16 = FLEA_MIN(data_len__dtl, rec_prot__pt->payload_used_len__u16 - rec_prot__pt->payload_offset__u16);
  memcpy(data__pu8, rec_prot__pt->payload_buf__pu8 + rec_prot__pt->payload_offset__u16, to_cp__alu16);
  rec_prot__pt->payload_offset__u16 += to_cp__alu16;
  data_len__dtl -= to_cp__alu16;
  data__pu8     += to_cp__alu16;
  read_bytes_count__alu16 += to_cp__alu16;
  while(data_len__dtl)
  {
    flea_dtl_t raw_read_len__dtl = RECORD_HDR_LEN;
    flea_al_u16_t raw_rec_content_len__alu16;
    FLEA_CCALL(THR_flea_rw_stream_t__read(rec_prot__pt->rw_stream__pt, rec_prot__pt->send_rec_buf_raw__pu8, &raw_read_len__dtl));
    *cont_type__pe = rec_prot__pt->payload_buf__pu8[0];
    if(do_verify_prot_version__b)
    {
      if((prot_version__pt->major != rec_prot__pt->payload_buf__pu8[1]) ||
        (prot_version__pt->minor != rec_prot__pt->payload_buf__pu8[2]))
      {
        FLEA_THROW("invalid protocol version in record", FLEA_ERR_TLS_INV_REC_HDR);
      }
    }
    else
    {
      prot_version__pt->major = rec_prot__pt->payload_buf__pu8[1];
      prot_version__pt->minor = rec_prot__pt->payload_buf__pu8[2];
    }
    raw_rec_content_len__alu16  = rec_prot__pt->payload_buf__pu8[3] << 8;
    raw_rec_content_len__alu16 |= rec_prot__pt->payload_buf__pu8[3];
    if(raw_rec_content_len__alu16 > FLEA_TLS_MAX_RECORD_DATA_SIZE)
    {
      FLEA_THROW("received record does not fit into receive buffer", FLEA_ERR_TLS_EXCSS_REC_LEN);
    }
    raw_read_len__dtl = raw_rec_content_len__alu16;
    FLEA_CCALL(THR_flea_rw_stream_t__read(rec_prot__pt->rw_stream__pt, rec_prot__pt->payload_buf__pu8, &raw_read_len__dtl));
    rec_prot__pt->payload_offset__u16   = 0;
    rec_prot__pt->payload_used_len__u16 = raw_rec_content_len__alu16;
    to_cp__alu16 = FLEA_MIN(raw_rec_content_len__alu16, data_len__dtl);
    memcpy(data__pu8, rec_prot__pt->payload_buf__pu8, to_cp__alu16);
    rec_prot__pt->payload_offset__u16 = to_cp__alu16;
    read_bytes_count__alu16 += to_cp__alu16;
    data_len__dtl -= to_cp__alu16;
    data__pu8     += to_cp__alu16;
  }
  *data_len__pdtl = read_bytes_count__alu16;
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_rec_prot_t__read_data */
