/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "internal/common/tls/tls_rec_prot.h"
#include "internal/common/tls/handsh_read_stream.h"
#include "internal/common/tls/tls_int.h"
// #include "internal/common/tls/tls_hndsh_layer.h"
#include "flea/bin_utils.h"
#include "internal/common/tls/tls_hndsh_ctx.h"
#include "internal/common/tls/hndsh_msg_dtls.h"

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
  flea_u8_t* flight_ptr__pu8         = hs_ctx__pt->dtls_ctx__t.flight_buf__bu8;
  flea_recprot_t* rec_prot__pt       = &hs_ctx__pt->tls_ctx__pt->rec_prot__t;
  flea_dtls_hdsh_ctx_t* dtls_ctx__pt = &hs_ctx__pt->dtls_ctx__t;

  FLEA_THR_BEG_FUNC();
  // TODO: THIS FUNCTION NEEDS TO LOOP UNTIL NO MORE RECORDS CAN BE SEND
  printf("starting THR_flea_dtls_hndsh__try_send_out_from_flight_buf()\n");
  // read in the header
  if(flea_dtls_hndsh__flight_buf_avail_send_len(hs_ctx__pt) &&
    flight_ptr__pu8[hs_ctx__pt->dtls_ctx__t.flight_buf_read_pos__u32] == 0xFF)
  {
    printf(" sending out CCS\n");
    // TODO: SET A FLAG THAT CURRENT FLIGHT HAS CCS: BEFORE RETRANSMIT, THE RP'S
    // SEND EPOCH MUST BE DECREASED AGAIN
    FLEA_CCALL(THR_flea_recprot_t__write_flush(rec_prot__pt));
    // TODO: THR_flea_tls__send_change_cipher_spec() is the
    // handshake-logic-level function. It must be reimplemented as a
    // dispatcher. Here we must call the raw send-function
    FLEA_CCALL(THR_flea_tls__send_change_cipher_spec_directly(hs_ctx__pt->tls_ctx__pt));
    FLEA_CCALL(THR_flea_recprot_t__write_flush(rec_prot__pt));
    hs_ctx__pt->dtls_ctx__t.flight_buf_read_pos__u32++;
  }
  else if(flea_dtls_hndsh__flight_buf_avail_send_len(hs_ctx__pt) > FLEA_DTLS_HANDSH_HDR_LEN)
  {
    printf(" have at least HS-HDR len in flight buffer\n");
    // (introduce further pos: ready_for_read_until_here)
    flea_al_u16_t max_record_pt__alu16;
    flea_al_u16_t max_pt_expansion__alu16;
    flea_al_u16_t limit__alu16;
    flea_u32_t rem_msg_len__u32;
    // message type not needed.
    // determine this msg's length, then check whether it must be fragmented.
    flea_u32_t msg_len__u32 = flea__decode_U24_BE(&FLIGHT_BUF_AT_CURRENT_READ_POS(hs_ctx__pt)[1]);
    rem_msg_len__u32 = msg_len__u32;
    // need information from record protocol about the maximal add data
    max_record_pt__alu16    = flea_recprot_t__get_current_max_record_pt_size(&hs_ctx__pt->tls_ctx__pt->rec_prot__t);
    max_pt_expansion__alu16 = flea_recprot_t__get_current_max_pt_expansion(&hs_ctx__pt->tls_ctx__pt->rec_prot__t);

    /* must have at least one byte of content: */
    if(msg_len__u32 + FLEA_DTLS_HANDSH_HDR_LEN + dtls_ctx__pt->flight_buf_read_pos__u32 + 1 >
      dtls_ctx__pt->flight_buf_write_pos__u32)
    {
      /* hndsh msg is not yet completed */
      FLEA_THR_RETURN();
    }
    // TODO: DEFINE MIN PMTU-ESTIMATE to be used as lower limit when decreasing it so that the 2nd arg cannot become negative
    limit__alu16 = FLEA_MIN(
      max_record_pt__alu16 - FLEA_DTLS_HANDSH_HDR_LEN,
      hs_ctx__pt->dtls_ctx__t.pmtu_estimate__alu16
      - (max_pt_expansion__alu16 + FLEA_DTLS_HANDSH_HDR_LEN + FLEA_DTLS_RECORD_HDR_LEN)
    );
    printf(
      " current PMTU est. = %u, record content limit = %u\n",
      hs_ctx__pt->dtls_ctx__t.pmtu_estimate__alu16,
      limit__alu16
    );
    FLEA_CCALL(THR_flea_recprot_t__write_flush(rec_prot__pt));

    flea_u8_t* data_ptr__pu8 = dtls_ctx__pt->flight_buf__bu8 + dtls_ctx__pt->flight_buf_read_pos__u32
      + FLEA_DTLS_HANDSH_HDR_LEN;
    flea_u32_t fragm_off__u32 = 0;
    flea_u8_t frag_offs_and_len__alu8[6];
    printf("dtls_ctx__pt->flight_buf_read_pos__u32 = %u\n", dtls_ctx__pt->flight_buf_read_pos__u32);
    printf("hs_msg in flight buffer to be sent: header = ");
    for(unsigned i = 0; i < FLEA_DTLS_HANDSH_HDR_LEN; i++)
    {
      printf("%02x ", dtls_ctx__pt->flight_buf__bu8[i + dtls_ctx__pt->flight_buf_read_pos__u32]);
    }
    printf("\n");
    printf("hs_msg in flight buffer to be sent: content = ");
    for(unsigned i = 0; i < msg_len__u32; i++)
    {
      printf("%02x ", data_ptr__pu8[i]);
    }
    printf("\n");
    while(rem_msg_len__u32)
    {
      // create handshake header with fragment information.
      // then send the hdr | content-fragment.
      flea_u32_t to_go__u32;
      /* write hs_type, hs_length, and hs_seq */
      FLEA_CCALL(
        THR_flea_recprot_t__wrt_data(
          rec_prot__pt,
          CONTENT_TYPE_HANDSHAKE,
          &dtls_ctx__pt->flight_buf__bu8[dtls_ctx__pt->flight_buf_read_pos__u32],
          6
        )
      );

      to_go__u32 = FLEA_MIN(rem_msg_len__u32, limit__alu16);
      printf(" sending hs-msg fragment of length %u\n", to_go__u32);
      printf("hs_msg content fragment: header = ");
      for(unsigned i = 0; i < 6; i++)
      {
        printf("%02x ", dtls_ctx__pt->flight_buf__bu8[dtls_ctx__pt->flight_buf_read_pos__u32 + i]);
      }

      flea__encode_U24_BE(fragm_off__u32, frag_offs_and_len__alu8);
      flea__encode_U24_BE(to_go__u32, frag_offs_and_len__alu8 + 3);
      // TODO: ENSURE THAT RECORD CANNOT BE BE FLUSHED PREMATURELY
      /* write the fragment offset and length */
      FLEA_CCALL(THR_flea_recprot_t__wrt_data(rec_prot__pt, CONTENT_TYPE_HANDSHAKE, frag_offs_and_len__alu8, 6));
      for(unsigned i = 0; i < 6; i++)
      {
        printf("%02x ", frag_offs_and_len__alu8[i]);
      }
      printf("\n");
      /* write the data */
      FLEA_CCALL(THR_flea_recprot_t__wrt_data(rec_prot__pt, CONTENT_TYPE_HANDSHAKE, data_ptr__pu8, to_go__u32));

      printf("hs_msg content fragment of length %u: content = ", to_go__u32);
      for(unsigned i = 0; i < to_go__u32; i++)
      {
        printf("%02x ", data_ptr__pu8[i]);
      }

      printf("\n");
      FLEA_CCALL(THR_flea_recprot_t__write_flush(rec_prot__pt));
      data_ptr__pu8    += to_go__u32;
      rem_msg_len__u32 -= to_go__u32;
      fragm_off__u32   += to_go__u32;
    }
    dtls_ctx__pt->flight_buf_read_pos__u32 += FLEA_DTLS_HANDSH_HDR_LEN + msg_len__u32;
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_dtls_hndsh__try_send_out_from_flight_buf */

flea_err_e THR_flea_dtls_hndsh__append_to_flight_buffer_and_try_to_send_record(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  const flea_u8_t*          data__pcu8,
  flea_u32_t                data_len__u32
)
{
  FLEA_THR_BEG_FUNC();
  printf("data to be appended to flight buf = ");

  for(unsigned i = 0; i < data_len__u32; i++)
  {
    printf("%02x ", data__pcu8[i]);
  }
  printf("\nat write pos = %u\n", hs_ctx__pt->dtls_ctx__t.flight_buf_write_pos__u32);
  while(data_len__u32)
  {
    flea_u32_t to_go__u32;
    flea_u32_t flight_buf_rem_free_len__u32;
    flight_buf_rem_free_len__u32 = flea_dtls_hndsh__get_flight_buf_rem_free_size(hs_ctx__pt);
    to_go__u32 = FLEA_MIN(flight_buf_rem_free_len__u32, data_len__u32);
    // TODO: HANDLE THE CASE WHERE DESPITE AN EMPTY FLIGHT BUFFER THE MESSAGE
    // IS TOO LARGE
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

  hs_ctx__pt->dtls_ctx__t.msg_seq__s16 += 1; // is 0 when called for the first time

  flea__encode_U16_BE(hs_ctx__pt->dtls_ctx__t.msg_seq__s16, &hdr__au8[4]);
  flea__encode_U24_BE(0, &hdr__au8[6]);
  flea__encode_U24_BE(content_len__u32, &hdr__au8[9]);

  FLEA_CCALL(
    THR_flea_dtls_hndsh__append_to_flight_buffer_and_try_to_send_record(
      hs_ctx__pt,
      hdr__au8,
      sizeof(hdr__au8)
    )
  );
// TOOD: DRAW OUT TO CALLER (TLS/DTLS DISPATCHER)
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
