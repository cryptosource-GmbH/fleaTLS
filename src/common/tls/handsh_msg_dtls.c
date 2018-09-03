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

# define FLEA_DTLS_FLIGHT_BUF_CCS_CODE 0xFF

# define FLIGHT_BUF_AT_CURRENT_READ_POS(hs_ctx__pt) \
  (&(hs_ctx__pt)->dtls_ctx__t.flight_buf__bu8[(hs_ctx__pt)-> \
  dtls_ctx__t.flight_buf_read_pos__u32])


/*
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 */

/*static flea_u32_t flea_dtls_hndsh__get_flight_buf_rem_free_size(
  flea_tls_handshake_ctx_t* hs_ctx__pt
)
{
  return FLEA_DTLS_FLIGHT_BUF_SIZE - hs_ctx__pt->dtls_ctx__t.flight_buf_write_pos__u32;
}*/

/*
 * returns the available send length based on the current read position. Does not at all take into account whether there
 * is a completed handshake message within the data characterized by that length.
 */
static flea_u32_t flea_dtls_hndsh__flight_buf_avail_send_len(
  flea_tls_handshake_ctx_t* hs_ctx__pt
)
{
  return /*hs_ctx__pt->dtls_ctx__t.flight_buf_write_pos__u32*/ qheap_qh_get_queue_len(
    hs_ctx__pt->dtls_ctx__t.qheap__pt,
    hs_ctx__pt->dtls_ctx__t.current_flight_buf__qhh
  ) - hs_ctx__pt->dtls_ctx__t.flight_buf_read_pos__u32;
}

static flea_err_e THR_flea_dtls_hndsh__try_send_out_from_flight_buf(
  flea_tls_handshake_ctx_t*    hs_ctx__pt,
  flea_dtls_conn_state_data_t* conn_state_to_activate_after_ccs_mbn__pt
)
{
  // flea_u8_t* flight_ptr__pu8         = hs_ctx__pt->dtls_ctx__t.flight_buf__bu8;
  flea_recprot_t* rec_prot__pt       = &hs_ctx__pt->tls_ctx__pt->rec_prot__t;
  flea_dtls_hdsh_ctx_t* dtls_ctx__pt = &hs_ctx__pt->dtls_ctx__t;

  FLEA_DECL_BUF(send_portion__bu8, flea_u8_t, 64); /* must at least be FLEA_DTLS_HANDSH_HDR_LEN */
  // flea_bool_t in_sending__b = FLEA_TRUE;

  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(send_portion__bu8, 64);

  // TODO: THIS FUNCTION NEEDS TO LOOP UNTIL NO MORE RECORDS CAN BE SEND
  FLEA_DBG_PRINTF("starting THR_flea_dtls_hndsh__try_send_out_from_flight_buf()\n");
  while(1)
  {
    // read in the header
    flea_u32_t avail_len__u32 = flea_dtls_hndsh__flight_buf_avail_send_len(hs_ctx__pt);
    flea_u8_t first_byte;
    if(!qheap_qh_peek(
        dtls_ctx__pt->qheap__pt,
        dtls_ctx__pt->current_flight_buf__qhh,
        hs_ctx__pt->dtls_ctx__t.flight_buf_read_pos__u32,
        &first_byte,
        1
    ))
    {
      /* no avail_len */
      FLEA_THR_RETURN();
    }
    if(avail_len__u32 &&
      first_byte == FLEA_DTLS_FLIGHT_BUF_CCS_CODE)
    {
      FLEA_DBG_PRINTF(" sending out CCS\n");
      // TODO: SET A FLAG THAT CURRENT FLIGHT HAS CCS: BEFORE RETRANSMIT, THE RP'S
      // SEND EPOCH MUST BE DECREASED AGAIN
      FLEA_CCALL(THR_flea_recprot_t__write_flush(rec_prot__pt));

      FLEA_CCALL(THR_flea_tls__send_change_cipher_spec_directly(hs_ctx__pt->tls_ctx__pt));
      /* if this is a retransmission, we must now restore the actual current write connection state */


      FLEA_CCALL(THR_flea_recprot_t__write_flush(rec_prot__pt));
      hs_ctx__pt->dtls_ctx__t.flight_buf_read_pos__u32++;

      if(conn_state_to_activate_after_ccs_mbn__pt)
      {
        flea_tls_ctx_t* tls_ctx__pt = hs_ctx__pt->tls_ctx__pt;
        /* activate the logically current connection again, the one that was active until now was due to retransmission of handshake messages in a flight containing a CCS. */
        FLEA_CCALL(
          THR_flea_recprot_t__set_dtls_conn_state_and_epoch_and_sqn_in_write_conn(
            &hs_ctx__pt->tls_ctx__pt->
            rec_prot__t,
            conn_state_to_activate_after_ccs_mbn__pt,
            tls_ctx__pt->connection_end
          )
        );
      }
    }
    else if(avail_len__u32 >= FLEA_DTLS_HANDSH_HDR_LEN)
    {
      // TODO: ONLY TYPE BYTE, MESSAGE LENGTH AND SEQ IS NEEDED
      flea_u8_t dtls_hs_hdr__au8[FLEA_DTLS_HANDSH_HDR_LEN];
      FLEA_DBG_PRINTF(" have at least HS-HDR len in flight buffer\n");
      // (introduce further pos: ready_for_read_until_here)
      flea_al_u16_t max_record_pt__alu16;
      flea_al_u16_t max_pt_expansion__alu16;
      flea_al_u16_t limit__alu16;
      flea_u32_t rem_msg_len__u32;
      /* check of avail_len ensures that this peek can be satisfied */
      qheap_qh_peek(
        dtls_ctx__pt->qheap__pt,
        dtls_ctx__pt->current_flight_buf__qhh,
        hs_ctx__pt->dtls_ctx__t.flight_buf_read_pos__u32,
        dtls_hs_hdr__au8,
        sizeof(dtls_hs_hdr__au8)
      );
      // message type not needed.
      // determine this msg's length, then check whether it must be fragmented.
      // flea_u32_t msg_len__u32 = flea__decode_U24_BE(&FLIGHT_BUF_AT_CURRENT_READ_POS(hs_ctx__pt)[1]);
      flea_u32_t msg_len__u32 = flea__decode_U24_BE(&dtls_hs_hdr__au8[1]);
      rem_msg_len__u32 = msg_len__u32;
      // need information from record protocol about the maximal add data
      max_record_pt__alu16    = flea_recprot_t__get_current_max_record_pt_size(&hs_ctx__pt->tls_ctx__pt->rec_prot__t);
      max_pt_expansion__alu16 = flea_recprot_t__get_current_max_pt_expansion(&hs_ctx__pt->tls_ctx__pt->rec_prot__t);

      /* must have at least one byte of content: */
      if(msg_len__u32 + FLEA_DTLS_HANDSH_HDR_LEN /*+ dtls_ctx__pt->flight_buf_read_pos__u32*/ >
        avail_len__u32
        // dtls_ctx__pt->flight_buf_write_pos__u32
      )
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
      FLEA_DBG_PRINTF(
        " current PMTU est. = %u, record content limit = %u\n",
        hs_ctx__pt->dtls_ctx__t.pmtu_estimate__alu16,
        limit__alu16
      );
      FLEA_CCALL(THR_flea_recprot_t__write_flush(rec_prot__pt));

      flea_u32_t data_pos__u32 = dtls_ctx__pt->flight_buf_read_pos__u32 + FLEA_DTLS_HANDSH_HDR_LEN;

      /*flea_u8_t* data_ptr__pu8 = dtls_ctx__pt->flight_buf__bu8 + dtls_ctx__pt->flight_buf_read_pos__u32
        + FLEA_DTLS_HANDSH_HDR_LEN;*/
      flea_u32_t fragm_off__u32 = 0;
      flea_u8_t frag_offs_and_len__alu8[6];

      /*FLEA_DBG_PRINTF("dtls_ctx__pt->flight_buf_read_pos__u32 = %u\n", dtls_ctx__pt->flight_buf_read_pos__u32);
      FLEA_DBG_PRINTF("hs_msg in flight buffer to be sent: header = ");
      for(unsigned i = 0; i < FLEA_DTLS_HANDSH_HDR_LEN; i++)
      {
        FLEA_DBG_PRINTF("%02x ", dtls_ctx__pt->flight_buf__bu8[i + dtls_ctx__pt->flight_buf_read_pos__u32]);
      }
      FLEA_DBG_PRINTF("\n");
      FLEA_DBG_PRINTF("hs_msg in flight buffer to be sent: content = ");
      for(unsigned i = 0; i < msg_len__u32; i++)
      {
        FLEA_DBG_PRINTF("%02x ", data_ptr__pu8[i]);
      }
      FLEA_DBG_PRINTF("\n");*/

      /* loop over the handshake msg fragments to send */
      do
      {
        /* create handshake header with fragment information.
        * then send the hdr | content-fragment.*/
        flea_u32_t to_go__u32;
        flea_u32_t to_go_countdown__u32;
        /* write hs_type, hs_length, and hs_seq */
        FLEA_CCALL(
          THR_flea_recprot_t__wrt_data(
            rec_prot__pt,
            CONTENT_TYPE_HANDSHAKE,
            &dtls_hs_hdr__au8[0],
            // &dtls_ctx__pt->flight_buf__bu8[dtls_ctx__pt->flight_buf_read_pos__u32],
            6
          )
        );

        to_go__u32 = FLEA_MIN(rem_msg_len__u32, limit__alu16);

        /*FLEA_DBG_PRINTF(" sending hs-msg fragment of length %u\n", to_go__u32);
        FLEA_DBG_PRINTF("hs_msg content fragment: header = ");
        for(unsigned i = 0; i < 6; i++)
        {
          FLEA_DBG_PRINTF("%02x ", dtls_ctx__pt->flight_buf__bu8[dtls_ctx__pt->flight_buf_read_pos__u32 + i]);
        }*/

        flea__encode_U24_BE(fragm_off__u32, frag_offs_and_len__alu8);
        flea__encode_U24_BE(to_go__u32, frag_offs_and_len__alu8 + 3);
        // TODO: ENSURE THAT RECORD CANNOT BE BE FLUSHED PREMATURELY (necessary?
        // why?).
        /* write the fragment offset and length */
        FLEA_CCALL(THR_flea_recprot_t__wrt_data(rec_prot__pt, CONTENT_TYPE_HANDSHAKE, frag_offs_and_len__alu8, 6));
        for(unsigned i = 0; i < 6; i++)
        {
          FLEA_DBG_PRINTF("%02x ", frag_offs_and_len__alu8[i]);
        }
        FLEA_DBG_PRINTF("\n");
        /* write the data */
        to_go_countdown__u32 = to_go__u32;
        while(to_go_countdown__u32)
        {
          // TODO: use linearize or let wrt_data accept a qheap handle
          flea_al_u16_t to_go_inner__alu16 = FLEA_MIN(to_go_countdown__u32, 64);
          qheap_qh_peek(
            hs_ctx__pt->dtls_ctx__t.qheap__pt,
            hs_ctx__pt->dtls_ctx__t.current_flight_buf__qhh,
            data_pos__u32,
            send_portion__bu8,
            64
          );
          // FLEA_CCALL(THR_flea_recprot_t__wrt_data(rec_prot__pt, CONTENT_TYPE_HANDSHAKE, data_ptr__pu8, to_go__u32));
          FLEA_CCALL(
            THR_flea_recprot_t__wrt_data(
              rec_prot__pt,
              CONTENT_TYPE_HANDSHAKE,
              send_portion__bu8,
              to_go_inner__alu16
            )
          );
          to_go_countdown__u32 -= to_go_inner__alu16;
          data_pos__u32        += to_go_inner__alu16;
          // hs_ctx__pt->dtls_ctx__t.flight_buf_read_pos__u32 += to_go_inner__alu16;
        }

        /*FLEA_DBG_PRINTF("hs_msg content fragment of length %u: content = ", to_go__u32);
        for(unsigned i = 0; i < to_go__u32; i++)
        {
          FLEA_DBG_PRINTF("%02x ", data_ptr__pu8[i]);
        }*/

        FLEA_DBG_PRINTF("\n");
        FLEA_CCALL(THR_flea_recprot_t__write_flush(rec_prot__pt));
        // data_ptr__pu8    += to_go__u32;
        rem_msg_len__u32 -= to_go__u32;
        fragm_off__u32   += to_go__u32;
      } while(rem_msg_len__u32);
      dtls_ctx__pt->flight_buf_read_pos__u32 += FLEA_DTLS_HANDSH_HDR_LEN + msg_len__u32;
    }
    else
    {
      break;
    }
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL_SECRET_ARR(send_portion__bu8, 64);
  );
} /* THR_flea_dtls_hndsh__try_send_out_from_flight_buf */

flea_err_e THR_flea_dtls_hndsh__append_ccs_to_flight_buffer_and_try_to_send_record(flea_tls_handshake_ctx_t* hs_ctx__pt)
{
  const flea_u8_t css_code__cu8 = FLEA_DTLS_FLIGHT_BUF_CCS_CODE;

  hs_ctx__pt->dtls_ctx__t.flight_buf_contains_ccs__u8 = 1;
  return THR_flea_dtls_hndsh__append_to_flight_buffer_and_try_to_send_record(
    hs_ctx__pt,
    &css_code__cu8,
    sizeof(css_code__cu8)
  );
}

flea_err_e THR_flea_dtls_hndsh__append_to_flight_buffer_and_try_to_send_record(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  const flea_u8_t*          data__pcu8,
  flea_u32_t                data_len__u32
)
{
  FLEA_THR_BEG_FUNC();
  hs_ctx__pt->dtls_ctx__t.is_in_sending_state__u8 = 1;
  FLEA_DBG_PRINTF("data to be appended to flight buf = ");

  for(unsigned i = 0; i < data_len__u32; i++)
  {
    FLEA_DBG_PRINTF("%02x ", data__pcu8[i]);
  }
  FLEA_DBG_PRINTF("\n");

  // FLEA_DBG_PRINTF("\nat write pos = %u\n", hs_ctx__pt->dtls_ctx__t.flight_buf_write_pos__u32);

  while(data_len__u32)
  {
    flea_u32_t to_go__u32;
    // flea_u32_t flight_buf_rem_free_len__u32;
    // flight_buf_rem_free_len__u32 = flea_dtls_hndsh__get_flight_buf_rem_free_size(hs_ctx__pt);
    // to_go__u32 = FLEA_MIN(flight_buf_rem_free_len__u32, data_len__u32);
    to_go__u32 = data_len__u32;
    // TODO: HANDLE THE CASE WHERE THE MESSAGE
    // IS TOO LARGE => START FREEING THE PREV-BUF
    // FLEA_DBG_PRINTF("flight buf write pos = %u\n", hs_ctx__pt->dtls_ctx__t.flight_buf_write_pos__u32);

    FLEA_DBG_PRINTF("appending to flight buf queue\n");
    if(qheap_qh_append_to_queue(
        hs_ctx__pt->dtls_ctx__t.qheap__pt,
        hs_ctx__pt->dtls_ctx__t.current_flight_buf__qhh,
        data__pcu8,
        to_go__u32
    ))
    {
      FLEA_THROW("could not write all data to flight buffer", FLEA_ERR_OUT_OF_MEM);
    }

    /*memcpy(
      &hs_ctx__pt->dtls_ctx__t.flight_buf__bu8[ hs_ctx__pt->dtls_ctx__t.flight_buf_write_pos__u32],
      data__pcu8,
      to_go__u32
    );*/
    data_len__u32 -= to_go__u32;
    data__pcu8    += to_go__u32;
    // hs_ctx__pt->dtls_ctx__t.flight_buf_write_pos__u32 += to_go__u32;
    FLEA_CCALL(THR_flea_dtls_hndsh__try_send_out_from_flight_buf(hs_ctx__pt, NULL));
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_dtls_hndsh__append_to_flight_buffer_and_try_to_send_record */

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

  hs_ctx__pt->dtls_ctx__t.send_msg_seq__s16 += 1; // is 0 when called for the first time

  flea__encode_U16_BE(hs_ctx__pt->dtls_ctx__t.send_msg_seq__s16, &hdr__au8[4]);
  flea__encode_U24_BE(0, &hdr__au8[6]);
  flea__encode_U24_BE(content_len__u32, &hdr__au8[9]);

  FLEA_CCALL(
    THR_flea_dtls_hndsh__append_to_flight_buffer_and_try_to_send_record(
      hs_ctx__pt,
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
  // hs_ctx__pt->dtls_ctx__t.send_msg_seq__s16++; // this is done in the
  // flight_buffer_writing
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__snd_hands_msg_hdr */

void flea_dtls_hndsh__set_flight_buffer_empty(flea_dtls_hdsh_ctx_t* dtls_hs_ctx__pt)
{
  // dtls_hs_ctx__pt->flight_buf_write_pos__u32   = 0;
  dtls_hs_ctx__pt->flight_buf_read_pos__u32 = 0;
  // TODO: struct to hold flight buffer hndl together with ccs flag
  dtls_hs_ctx__pt->flight_buf_contains_ccs__u8 = 0;
  qheap_qh_skip(
    dtls_hs_ctx__pt->qheap__pt,
    dtls_hs_ctx__pt->current_flight_buf__qhh,
    qheap_qh_get_queue_len(dtls_hs_ctx__pt->qheap__pt, dtls_hs_ctx__pt->current_flight_buf__qhh)
  );
}

flea_err_e THR_flea_dtls_hdsh__retransmit_flight_buf(flea_tls_handshake_ctx_t* hs_ctx__pt)
{
  flea_dtls_hdsh_ctx_t* dtls_hs_ctx__pt = &hs_ctx__pt->dtls_ctx__t;
  flea_tls_ctx_t* tls_ctx__pt = hs_ctx__pt->tls_ctx__pt;

  FLEA_THR_BEG_FUNC();
  dtls_hs_ctx__pt->flight_buf_read_pos__u32 = 0;
  // TODO: IF CURRENTLY HELD FLIGHT CONTAINS CCS, THEN REVERT THE OLD WRITE CONNECTION STATE NOW
  if(dtls_hs_ctx__pt->flight_buf_contains_ccs__u8)
  {
    // - store the current write connection of the rec_prot (except key block)
    // - restore the previous write conn. to the rec_prot
    // - the called function THR_flea_dtls_hndsh__try_send_out_from_flight_buf switches back to the current write conn after it sent out the CCS
    flea_dtls_save_write_conn_epoch_and_sqn(tls_ctx__pt, &tls_ctx__pt->dtls_retransm_state__t.current_conn_st__t);
// set...
    FLEA_CCALL(
      THR_flea_recprot_t__set_dtls_conn_state_and_epoch_and_sqn_in_write_conn(
        &tls_ctx__pt->rec_prot__t,
        &tls_ctx__pt->dtls_retransm_state__t.previous_conn_st__t,
        tls_ctx__pt->connection_end
      )
    );
  }
  FLEA_CCALL(
    THR_flea_dtls_hndsh__try_send_out_from_flight_buf(
      hs_ctx__pt,
      &tls_ctx__pt->dtls_retransm_state__t.current_conn_st__t
    )
  );
  FLEA_THR_FIN_SEC_empty();
}

#endif /* ifdef FLEA_HAVE_DTLS */
