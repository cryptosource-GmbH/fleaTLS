#include "internal/common/default.h"
#include "internal/common/tls/dtls_retransm_state.h"
#include "flea/bin_utils.h"

#include "internal/common/tls/tls_int.h"

#define FLEA_DTLS_FLIGHT_BUF_CCS_CODE         0xFF

#define FLEA_DTLS_RTRSM_STATE__NOT_ACTIVE     0
#define FLEA_DTLS_RTRSM_STATE__ACTIVE_INITIAL 1


#define FLEA_DTLS_RTRSM_ST_IS_ACTIVE(dtls_rtrsm_st__pt) \
  ((dtls_rtrsm_st__pt)->rtrsm_state__u8 != \
  FLEA_DTLS_RTRSM_STATE__NOT_ACTIVE)

flea_err_e THR_flea_dtls_rtrsm_t__ctor(
  flea_dtls_retransm_state_t* dtls_rtrsm_st__pt,
  flea_al_u8_t                rtrsm_supr_wndw_secs__alu8
)
{
  FLEA_THR_BEG_FUNC();
  dtls_rtrsm_st__pt->flight_buf_read_pos__u32    = 0;
  dtls_rtrsm_st__pt->flight_buf_contains_ccs__u8 = 0;
  dtls_rtrsm_st__pt->rtrsm_suppr_wndw_secs__u8   = rtrsm_supr_wndw_secs__alu8;
  FLEA_CCALL(THR_flea_timer_t__ctor(&dtls_rtrsm_st__pt->rtrsm_suppr_wndw_tmr__t));
  // TODO: QHEAP MUST BECOME "DYNAMIC"
  qheap_qh_ctor(
    &dtls_rtrsm_st__pt->qheap__t,
    (flea_u8_t*) dtls_rtrsm_st__pt->qh_mem_area__au32,
    sizeof(dtls_rtrsm_st__pt->qh_mem_area__au32),
    0
  );
  dtls_rtrsm_st__pt->qheap__pt = &dtls_rtrsm_st__pt->qheap__t;
  dtls_rtrsm_st__pt->current_flight_buf__qhh =
    qheap_qh_alloc_queue(dtls_rtrsm_st__pt->qheap__pt, QHEAP_FALSE);
  if(!dtls_rtrsm_st__pt->current_flight_buf__qhh)
  {
    FLEA_THROW("error allocating queue", FLEA_ERR_OUT_OF_MEM);
  }
  FLEA_CCALL(THR_flea_timer_t__ctor(&dtls_rtrsm_st__pt->timer__t));
  // TODO: MAKE PMTU-EST. AN ARGUMENT
  dtls_rtrsm_st__pt->pmtu_estimate__alu16 = 256;

#ifdef FLEA_STACK_MODE
  flea_byte_vec_t__ctor_empty_use_ext_buf(
    &dtls_rtrsm_st__pt->previous_conn_st__t.write_key_block__t,
    dtls_rtrsm_st__pt->previous_conn_st__t.write_key_block_mem__au8,
    sizeof(dtls_rtrsm_st__pt->previous_conn_st__t.write_key_block_mem__au8)
  );
  flea_byte_vec_t__ctor_empty_use_ext_buf(
    &dtls_rtrsm_st__pt->current_conn_st__t.write_key_block__t,
    dtls_rtrsm_st__pt->current_conn_st__t.write_key_block_mem__au8,
    sizeof(dtls_rtrsm_st__pt->current_conn_st__t.write_key_block_mem__au8)
  );
#else    /* ifdef FLEA_STACK_MODE */
  flea_byte_vec_t__ctor_empty_allocatable(&dtls_rtrsm_st__pt->previous_conn_st__t.write_key_block__t);
  flea_byte_vec_t__ctor_empty_allocatable(&dtls_rtrsm_st__pt->current_conn_st__t.write_key_block__t);
#endif   /* ifdef FLEA_STACK_MODE */

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_dtls_rtrsm_t__ctor */

void flea_dtls_rtrsm_st_t__reset(
  flea_dtls_retransm_state_t* dtls_rtrsm_st__pt
)
{
  dtls_rtrsm_st__pt->flight_buf_read_pos__u32    = 0;
  dtls_rtrsm_st__pt->flight_buf_contains_ccs__u8 = 0;

  FLEA_DBG_PRINTF("[rtrsm] reset() => rtrsm state set to NOT_ACTIVE\n");
  dtls_rtrsm_st__pt->rtrsm_state__u8 = FLEA_DTLS_RTRSM_STATE__NOT_ACTIVE;
  qheap_qh_skip(
    dtls_rtrsm_st__pt->qheap__pt,
    dtls_rtrsm_st__pt->current_flight_buf__qhh,
    qheap_qh_get_queue_len(dtls_rtrsm_st__pt->qheap__pt, dtls_rtrsm_st__pt->current_flight_buf__qhh)
  );
  /* start the post hs-completion timer window ( for the peer that might have to retransmitt the very final flight of handshake ) */
  flea_timer_t__start(&dtls_rtrsm_st__pt->timer__t);
}

/*
 * returns the available send length based on the current read position. Does not at all take into account whether there
 * is a completed handshake message within the data characterized by that length.
 */
flea_u32_t flea_dtls_rtrsm_st_t__flight_buf_avail_send_len(
  flea_dtls_retransm_state_t* rtrsm_st__pt
)
{
  return qheap_qh_get_queue_len(
    rtrsm_st__pt->qheap__pt,
    rtrsm_st__pt->current_flight_buf__qhh
  ) - rtrsm_st__pt->flight_buf_read_pos__u32;
}

flea_err_e THR_flea_dtls_rtrsm_st_t__try_send_out_from_flight_buf(
  flea_dtls_retransm_state_t*  dtls_rtrsm_st__pt,
  flea_tls__connection_end_t   conn_end__e,
  flea_recprot_t*              rec_prot__pt,
  flea_dtls_conn_state_data_t* conn_state_to_activate_after_ccs_mbn__pt
)
{
  FLEA_DECL_BUF(send_portion__bu8, flea_u8_t, 64); /* must at least be FLEA_DTLS_HANDSH_HDR_LEN */

  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(send_portion__bu8, 64);

  FLEA_DBG_PRINTF("starting THR_flea_dtls_hndsh__try_send_out_from_flight_buf()\n");
  while(1)
  {
    // read in the header
    flea_u32_t avail_len__u32 = flea_dtls_rtrsm_st_t__flight_buf_avail_send_len(
      dtls_rtrsm_st__pt
    );
    flea_u8_t first_byte;
    if(!qheap_qh_peek(
        dtls_rtrsm_st__pt->qheap__pt,
        dtls_rtrsm_st__pt->current_flight_buf__qhh,
        dtls_rtrsm_st__pt->flight_buf_read_pos__u32,
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

      FLEA_CCALL(THR_flea_recprot_t__send_change_cipher_spec_directly(rec_prot__pt));
      /* if this is a retransmission, we must now restore the actual current write connection state */


      FLEA_CCALL(THR_flea_recprot_t__write_flush(rec_prot__pt));
      dtls_rtrsm_st__pt->flight_buf_read_pos__u32++;

      if(conn_state_to_activate_after_ccs_mbn__pt)
      {
        /* activate the logically current connection again, the one that was active until now was due to retransmission of handshake messages in a flight containing a CCS. */
        FLEA_CCALL(
          THR_flea_recprot_t__set_dtls_conn_state_and_epoch_and_sqn_in_write_conn(
            rec_prot__pt,
            conn_state_to_activate_after_ccs_mbn__pt,
            conn_end__e
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
        dtls_rtrsm_st__pt->qheap__pt,
        dtls_rtrsm_st__pt->current_flight_buf__qhh,
        dtls_rtrsm_st__pt->flight_buf_read_pos__u32,
        dtls_hs_hdr__au8,
        sizeof(dtls_hs_hdr__au8)
      );
      // message type not needed.
      // determine this msg's length, then check whether it must be fragmented.
      // flea_u32_t msg_len__u32 = flea__decode_U24_BE(&FLIGHT_BUF_AT_CURRENT_READ_POS(hs_ctx__pt)[1]);
      flea_u32_t msg_len__u32 = flea__decode_U24_BE(&dtls_hs_hdr__au8[1]);
      rem_msg_len__u32 = msg_len__u32;
      // need information from record protocol about the maximal add data
      max_record_pt__alu16    = flea_recprot_t__get_current_max_record_pt_size(rec_prot__pt);
      max_pt_expansion__alu16 = flea_recprot_t__get_current_max_pt_expansion(rec_prot__pt);

      /* must have at least one byte of content: */
      if(msg_len__u32 + FLEA_DTLS_HANDSH_HDR_LEN >
        avail_len__u32)
      {
        /* hndsh msg is not yet completed */
        FLEA_THR_RETURN();
      }
      // TODO: DEFINE MIN PMTU-ESTIMATE to be used as lower limit when decreasing it so that the 2nd arg cannot become negative
      limit__alu16 = FLEA_MIN(
        max_record_pt__alu16 - FLEA_DTLS_HANDSH_HDR_LEN,
        dtls_rtrsm_st__pt->pmtu_estimate__alu16
        - (max_pt_expansion__alu16 + FLEA_DTLS_HANDSH_HDR_LEN + FLEA_DTLS_RECORD_HDR_LEN)
      );
      FLEA_DBG_PRINTF(
        " current PMTU est. = %u, record content limit = %u\n",
        dtls_rtrsm_st__pt->pmtu_estimate__alu16,
        limit__alu16
      );
      FLEA_CCALL(THR_flea_recprot_t__write_flush(rec_prot__pt));

      flea_u32_t data_pos__u32 = dtls_rtrsm_st__pt->flight_buf_read_pos__u32 + FLEA_DTLS_HANDSH_HDR_LEN;

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
            dtls_rtrsm_st__pt->qheap__pt,
            dtls_rtrsm_st__pt->current_flight_buf__qhh,
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
          // tls_ctx__pt->dtls_retransm_state__t.flight_buf_read_pos__u32 += to_go_inner__alu16;
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
      dtls_rtrsm_st__pt->flight_buf_read_pos__u32 += FLEA_DTLS_HANDSH_HDR_LEN + msg_len__u32;
    }
    else
    {
      break;
    }
  }
  FLEA_DBG_PRINTF("THR_flea_dtls_rtrsm_st_t__try_send_out_from_flight_buf ending\n");
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL_SECRET_ARR(send_portion__bu8, 64);
  );
} /* THR_flea_dtls_rtrsm_st_t__try_send_out_from_flight_buf */

void flea_dtls_rtrsm_st_t__empty_flight_buf(flea_dtls_retransm_state_t* dtls_retransm_state__pt)
{
  FLEA_DBG_PRINTF("[rtrsm] empty_flight_buf() => rtrsm state set to NOT_ACTIVE\n");
  dtls_retransm_state__pt->rtrsm_state__u8 = FLEA_DTLS_RTRSM_STATE__NOT_ACTIVE;
  dtls_retransm_state__pt->flight_buf_read_pos__u32    = 0;
  dtls_retransm_state__pt->flight_buf_contains_ccs__u8 = 0;
  qheap_qh_skip(
    dtls_retransm_state__pt->qheap__pt,
    dtls_retransm_state__pt->current_flight_buf__qhh,
    qheap_qh_get_queue_len(dtls_retransm_state__pt->qheap__pt, dtls_retransm_state__pt->current_flight_buf__qhh)
  );
}

flea_err_e THR_flea_dtls_rtrsm_st_t__append_ccs_to_flight_buffer_and_try_to_send_record(
  flea_dtls_retransm_state_t* dtls_rtrsm_st__pt,
  flea_tls__connection_end_t  conn_end__e,
  flea_recprot_t*             rec_prot__pt,
  flea_u8_t*                  is_in_sending_state__pu8
)
{
  const flea_u8_t css_code__cu8 = FLEA_DTLS_FLIGHT_BUF_CCS_CODE;

  dtls_rtrsm_st__pt->flight_buf_contains_ccs__u8 = 1;
  return THR_flea_dtls_rtrsm_st_t__append_to_flight_buffer(
    dtls_rtrsm_st__pt,
    conn_end__e,
    rec_prot__pt,
    is_in_sending_state__pu8,
    &css_code__cu8,
    sizeof(css_code__cu8)
  );
}

flea_err_e THR_flea_dtls_rtrsm_st_t__append_to_flight_buffer/*_and_try_to_send_record*/ (
  flea_dtls_retransm_state_t* dtls_rtrsm_st__pt,
  flea_tls__connection_end_t  conn_end__e,
  flea_recprot_t*             rec_prot__pt,
  flea_u8_t*                  is_in_sending_state__pu8,
  const flea_u8_t*            data__pcu8,
  flea_u32_t                  data_len__u32
)
{
  FLEA_THR_BEG_FUNC();

  *is_in_sending_state__pu8 = 1;
  FLEA_DBG_PRINTF("data to be appended to flight buf = ");

  for(unsigned i = 0; i < data_len__u32; i++)
  {
    FLEA_DBG_PRINTF("%02x ", data__pcu8[i]);
  }
  FLEA_DBG_PRINTF("\n");

  while(data_len__u32)
  {
    flea_u32_t to_go__u32;
    to_go__u32 = data_len__u32;
    // TODO: HANDLE THE CASE WHERE THE MESSAGE
    // IS TOO LARGE => START FREEING THE PREV-BUF

    FLEA_DBG_PRINTF("appending to flight buf queue\n");
    if(qheap_qh_append_to_queue(
        dtls_rtrsm_st__pt->qheap__pt,
        dtls_rtrsm_st__pt->current_flight_buf__qhh,
        data__pcu8,
        to_go__u32
    ))
    {
      FLEA_THROW("could not write all data to flight buffer", FLEA_ERR_OUT_OF_MEM);
    }

    data_len__u32 -= to_go__u32;
    data__pcu8    += to_go__u32;
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_dtls_hndsh__append_to_flight_buffer_and_try_to_send_record */

static flea_bool_t flea_dtls_rtrsm_st_t__decide_to_actually_retransm(
  flea_dtls_retransm_state_t* dtls_rtrsm_st__pt
)
{
  // TODO: MAKE THE SUPPR-WINDOW DEPENDEND ON THE CURRENT RECV-TMO, E.G. 1/4 OF IT BUT AT LEAST ONE SECOND
  if(FLEA_DTLS_RTRSM_ST_IS_ACTIVE(dtls_rtrsm_st__pt) &&
    (flea_timer_t__get_elapsed_millisecs(&dtls_rtrsm_st__pt->rtrsm_suppr_wndw_tmr__t) >=
    1000 * dtls_rtrsm_st__pt->rtrsm_suppr_wndw_secs__u8))
  {
    FLEA_DBG_PRINTF("[rtrsm] suppr-wndw-tmr elapsed, going into NOT_ACTIVE again\n");
    dtls_rtrsm_st__pt->rtrsm_state__u8 = FLEA_DTLS_RTRSM_STATE__NOT_ACTIVE;
  }


  if(!FLEA_DTLS_RTRSM_ST_IS_ACTIVE(dtls_rtrsm_st__pt))
  {
    dtls_rtrsm_st__pt->rtrsm_state__u8 = FLEA_DTLS_RTRSM_STATE__ACTIVE_INITIAL;
    FLEA_DBG_PRINTF("[rtrsm] entering ACTIVE rtrsm state, sending flight buf\n");
    flea_timer_t__start(&dtls_rtrsm_st__pt->rtrsm_suppr_wndw_tmr__t);
    return FLEA_TRUE;
  }
  return FLEA_FALSE;
}

flea_err_e THR_flea_dtls_rtrsm_st_t__transmit_flight_buf(
  flea_dtls_retransm_state_t* dtls_rtrsm_st__pt,
  flea_recprot_t*             rec_prot__pt,
  flea_tls__connection_end_t  conn_end__e,
  flea_bool_t                 is_retransmission__b
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_DBG_PRINTF("[rtrsm] THR_flea_dtls_rtrsm_st_t__transmit_flight_buf called\n");
  if(is_retransmission__b)
  {
    if(!flea_dtls_rtrsm_st_t__decide_to_actually_retransm(dtls_rtrsm_st__pt))
    {
      FLEA_DBG_PRINTF("  [rtrsm] suppressing retransmission\n");
      FLEA_THR_RETURN();
    }
  }
  else
  {
    dtls_rtrsm_st__pt->rtrsm_state__u8 = FLEA_DTLS_RTRSM_STATE__NOT_ACTIVE;
  }
  FLEA_DBG_PRINTF("  [rtrsm] carrying out (re)transmission\n");
  dtls_rtrsm_st__pt->flight_buf_read_pos__u32 = 0;

  FLEA_DBG_PRINTF(
    "[rtrsm] transmit_flight_buf(): trsm-buf-size = %u\n",
    (unsigned) qheap_qh_get_queue_len(dtls_rtrsm_st__pt->qheap__pt, dtls_rtrsm_st__pt->current_flight_buf__qhh)
  );
  // TODO: IF CURRENTLY HELD FLIGHT CONTAINS CCS, THEN REVERT THE OLD WRITE CONNECTION STATE NOW
  if(dtls_rtrsm_st__pt->flight_buf_contains_ccs__u8)
  {
    // - store the current write connection of the rec_prot (except key block)
    // - restore the previous write conn. to the rec_prot
    // - the called function THR_flea_dtls_hndsh__try_send_out_from_flight_buf switches back to the current write conn after it sent out the CCS
    flea_dtls_save_write_conn_epoch_and_sqn(rec_prot__pt, &dtls_rtrsm_st__pt->current_conn_st__t);
// set...
    FLEA_CCALL(
      THR_flea_recprot_t__set_dtls_conn_state_and_epoch_and_sqn_in_write_conn(
        rec_prot__pt,
        &dtls_rtrsm_st__pt->previous_conn_st__t,
        conn_end__e
      )
    );
  }
  FLEA_CCALL(
    THR_flea_dtls_rtrsm_st_t__try_send_out_from_flight_buf(
      dtls_rtrsm_st__pt,
      conn_end__e,
      rec_prot__pt,
      &dtls_rtrsm_st__pt->current_conn_st__t
    )
  );
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_dtls_rtrsm_st_t__retransmit_flight_buf */

void flea_dtls_rtrsm_st_t__dtor(flea_dtls_retransm_state_t* dtls_rtrsm_st__pt)
{
  if(dtls_rtrsm_st__pt->qheap__pt)
  {
    qheap_qh_free_queue(
      dtls_rtrsm_st__pt->qheap__pt,
      dtls_rtrsm_st__pt->current_flight_buf__qhh
    );
  }
  flea_timer_t__dtor(&dtls_rtrsm_st__pt->timer__t);
  flea_timer_t__dtor(&dtls_rtrsm_st__pt->rtrsm_suppr_wndw_tmr__t);
  flea_byte_vec_t__dtor(&dtls_rtrsm_st__pt->previous_conn_st__t.write_key_block__t);
  flea_byte_vec_t__dtor(&dtls_rtrsm_st__pt->current_conn_st__t.write_key_block__t);
}
