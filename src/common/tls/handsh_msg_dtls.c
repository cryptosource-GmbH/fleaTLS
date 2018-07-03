/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "internal/common/tls/tls_rec_prot.h"
#include "internal/common/tls/handsh_read_stream.h"
#include "internal/common/tls/tls_int.h"
#include "internal/common/tls/tls_hndsh_layer.h"
#include "flea/bin_utils.h"
#include "internal/common/tls/tls_hndsh_ctx.h"

#ifdef FLEA_HAVE_DTLS

# define FLIGHT_BUF_AT_CURRENT_READ_POS(hs_ctx__pt) \
  (&(hs_ctx__pt)->dtls_ctx__t.flight_buf__bu8[(hs_ctx__pt)-> \
  dtls_ctx__t.flight_buf_read_pos__u32])

static flea_u32_t flea_dtls_hndsh__get_flight_buf_rem_free_size(
  flea_tls_handshake_ctx_t* hs_ctx__pt
)
{
  return FLEA_DTLS_FLIGHT_BUF_SIZE - hs_ctx__pt->dtls_ctx__t.flight_buf_write_pos__u32;
}

static flea_u32_t flea_dtls_hndsh__flight_buf_avail_send_len(
  flea_tls_handshake_ctx_t* hs_ctx__pt
)
{
  return hs_ctx__pt->dtls_ctx__t.flight_buf_write_pos__u32 - hs_ctx__pt->dtls_ctx__t.flight_buf_read_pos__u32;
}

static flea_err_e THR_flea_dtls_hndsh__try_send_out_from_flight_buf(
  flea_tls_handshake_ctx_t* hs_ctx__pt
)
{
  flea_u8_t* flight_ptr__pu8 = hs_ctx__pt->dtls_ctx__t.flight_buf__bu8;

  FLEA_THR_BEG_FUNC();
  // read in the header
  if(flight_ptr__pu8[hs_ctx__pt->dtls_ctx__t.flight_buf_read_pos__u32++] == 0xFF)
  {
    // TODO: SET A FLAG THAT CURRENT FLIGHT HAS CCS: BEFORE RETRANSMIT, THE RP'S
    // SEND EPOCH MUST BE DECREASED AGAIN
    FLEA_CCALL(THR_flea_tls__send_change_cipher_spec(hs_ctx__pt->tls_ctx__pt));
  }
  else if(flea_dtls_hndsh__flight_buf_avail_send_len(hs_ctx__pt) > FLEA_DTLS_HANDSH_HDR_LEN)
  {
    // TODO: CHECK THAT THIS MSG IS ALREADY COMPLETELY WRITTEN
    // (introduce further pos: ready_for_read_until_here)
    flea_al_u16_t max_record_pt__alu16;
    flea_al_u16_t max_pt_expansion__alu16;
    flea_al_u16_t limit__alu16;
    // message type not needed.
    // determine this msg's length, then check whether it must be fragmented.
    flea_u32_t msg_len__u32 = flea__decode_U24_BE(&FLIGHT_BUF_AT_CURRENT_READ_POS(hs_ctx__pt)[1]);
    // need information from record protocol about the maximal add data
    max_record_pt__alu16    = flea_recprot_t__get_current_max_record_pt_size(&hs_ctx__pt->tls_ctx__pt->rec_prot__t);
    max_pt_expansion__alu16 = flea_recprot_t__get_current_max_pt_expansion(&hs_ctx__pt->tls_ctx__pt->rec_prot__t);

    // TODO: DEFINE MIN PMTU-ESTIMATE to be used when decreasing it
    limit__alu16 = FLEA_MIN(
      max_record_pt__alu16 - FLEA_DTLS_HANDSH_HDR_LEN,
      hs_ctx__pt->dtls_ctx__t.pmtu_estimate__alu16
      - (max_pt_expansion__alu16 + FLEA_DTLS_HANDSH_HDR_LEN + FLEA_DTLS_RECORD_HDR_LEN)
    );
    if(msg_len__u32 > limit__alu16)
    {
      // create handshake header with fragment information
      // send the hdr | content-fragment
    }
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_dtls_hndsh__try_send_out_from_flight_buf */

static flea_err_e THR_flea_dtls_hndsh__append_to_flight_buffer(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  const flea_u8_t*          data__pcu8,
  flea_u32_t                data_len__u32
)
{
  FLEA_THR_BEG_FUNC();

  while(data_len__u32)
  {
    flea_u32_t to_go__u32;
    flea_u32_t flight_buf_rem_free_len__u32;
    flight_buf_rem_free_len__u32 = flea_dtls_hndsh__get_flight_buf_rem_free_size(hs_ctx__pt);
    to_go__u32 = FLEA_MIN(flight_buf_rem_free_len__u32, data_len__u32);
    memcpy(
      &hs_ctx__pt->dtls_ctx__t.flight_buf__bu8[ hs_ctx__pt->dtls_ctx__t.flight_buf_write_pos__u32],
      data__pcu8,
      to_go__u32
    );
    data_len__u32 -= to_go__u32;
    data__pcu8    += to_go__u32;
    hs_ctx__pt->dtls_ctx__t.flight_buf_write_pos__u32 += to_go__u32;
    FLEA_CCALL(THR_flea_dtls_hndsh__try_send_out_from_flight_buf(hs_ctx__pt));
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_dtls_hdsh__snd_hands_msg_hdr(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_tls_prl_hash_ctx_t*  p_hash_ctx_mbn__pt,
  HandshakeType             type,
  flea_u32_t                content_len__u32
)
{
  flea_u8_t hdr__au8[FLEA_DTLS_HANDSH_HDR_LEN];
  flea_recprot_t* rec_prot__pt = &hs_ctx__pt->tls_ctx__pt->rec_prot__t;
  flea_al_u16_t wrt_rcrd_free_len__alu16;

  FLEA_THR_BEG_FUNC();

  /* dtls:
     handshaketype msg_type;
     uint24 length;
     uint16 message_seq;                               // new field
     uint24 fragment_offset;                           // new field
     uint24 fragment_length;                           // new field
     */
  /* for dtls, set the 'unfragmented' header here, then hash it */
  /* message fragmentation will be performed when the message is sent */
  hdr__au8[0] = type;

  hdr__au8[1] = content_len__u32 >> 16;
  hdr__au8[2] = content_len__u32 >> 8;
  hdr__au8[3] = content_len__u32;

  hs_ctx__pt->dtls_ctx__t.msg_seq__s16 += 1; // is 0 when called for the first time

  flea__encode_U16_BE(hs_ctx__pt->dtls_ctx__t.msg_seq__s16, &hdr__au8[4]);
  flea__encode_U24_BE(0, &hdr__au8[6]);
  flea__encode_U24_BE(content_len__u32, &hdr__au8[9]);
  FLEA_CCALL(
    THR_flea_dtls_hndsh__append_to_flight_buffer(
      hs_ctx__pt,
      hdr__au8,
      sizeof(hdr__au8)
    )
  );

  /*FLEA_CCALL(
      THR_flea_recprot_t__wrt_data(
        rec_prot__pt,
        CONTENT_TYPE_HANDSHAKE,
        hdr__au8,
        sizeof(hdr__au8)
        )
      );*/
  if(p_hash_ctx_mbn__pt)
  {
    FLEA_CCALL(
      THR_flea_tls_prl_hash_ctx_t__update(
        p_hash_ctx_mbn__pt,
        hdr__au8,
        sizeof(hdr__au8)
      )
    );
  }
  // hs_ctx__pt->dtls_ctx__t.msg_seq__s16++; // this is done in the
  // flight_buffer_writing
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__snd_hands_msg_hdr */

#endif /* ifdef FLEA_HAVE_DTLS */