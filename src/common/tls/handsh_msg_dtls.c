/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "internal/common/tls/tls_rec_prot.h"
#include "internal/common/tls/handsh_read_stream.h"
#include "internal/common/tls/tls_int.h"
// #include "internal/common/tls/tls_hndsh_layer.h"
#include "flea/bin_utils.h"
#include "internal/common/tls/tls_hndsh_ctx.h"
#include "internal/common/tls/hndsh_msg_dtls.h"
#include "internal/common/tls/tls_int.h"

#ifdef FLEA_HAVE_DTLS

// TODO: DELETE
# define FLEA_DTLS_FLIGHT_BUF_CCS_CODE 0xFF

# define FLIGHT_BUF_AT_CURRENT_READ_POS(hs_ctx__pt) \
  (&(hs_ctx__pt)->dtls_ctx__t.flight_buf__bu8[(hs_ctx__pt)-> \
  dtls_ctx__t.flight_buf_read_pos__u32])


/*static flea_u32_t flea_dtls_hndsh__get_flight_buf_rem_free_size(
  flea_tls_handshake_ctx_t* hs_ctx__pt
)
{
  return FLEA_DTLS_FLIGHT_BUF_SIZE - tls_ctx__pt->dtls_retransm_state__t.flight_buf_write_pos__u32;
}*/


// TODO: MOVE TO RETRANSM_STATE


flea_err_e THR_flea_dtls_hdsh__snd_hands_msg_hdr(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_tls_prl_hash_ctx_t*  p_hash_ctx_mbn__pt,
  HandshakeType             type,
  flea_u32_t                content_len__u32
)
{
  flea_tls_ctx_t* tls_ctx__pt = hs_ctx__pt->tls_ctx__pt;
  flea_u8_t hdr__au8[FLEA_DTLS_HANDSH_HDR_LEN];

  /*flea_recprot_t* rec_prot__pt = &hs_ctx__pt->tls_ctx__pt->rec_prot__t;
  flea_al_u16_t wrt_rcrd_free_len__alu16;*/

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

  hs_ctx__pt->dtls_ctx__t.send_msg_seq__s16 += 1; // is 0 when called for the first time

  flea__encode_U16_BE(hs_ctx__pt->dtls_ctx__t.send_msg_seq__s16, &hdr__au8[4]);
  flea__encode_U24_BE(0, &hdr__au8[6]);
  flea__encode_U24_BE(content_len__u32, &hdr__au8[9]);

  FLEA_CCALL(
    THR_flea_dtls_rtrsm_st_t__append_to_flight_buffer_and_try_to_send_record(
      &tls_ctx__pt->dtls_retransm_state__t,
      tls_ctx__pt->connection_end,
      &tls_ctx__pt->rec_prot__t,
      &hs_ctx__pt->dtls_ctx__t.is_in_sending_state__u8,
      hdr__au8,
      sizeof(hdr__au8)
    )
  );
// TODO: DRAW OUT TO CALLER (TLS/DTLS DISPATCHER)
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
  // tls_ctx__pt->dtls_retransm_state__t.send_msg_seq__s16++; // this is done in the
  // flight_buffer_writing
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__snd_hands_msg_hdr */

#endif /* ifdef FLEA_HAVE_DTLS */
