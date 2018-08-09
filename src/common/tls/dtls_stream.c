/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

// some comment29
#include "internal/common/tls/dtls_stream.h"
#include "internal/common/tls/tls_rec_prot.h"
#include "flea/alloc.h"
#include "qheap/queue_heap.h"
#include "internal/common/tls/tls_hndsh_ctx.h"
#include "internal/common/tls/tls_int.h"
#include "flea/bin_utils.h"

/*
 * recprot used in tls layer (tls_server, tls_client, tls_common):
 * for sending:
 * - THR_flea_recprot_t__send_record() for sending CCS (within THR_flea_tls__send_change_cipher_spec_directly())
 * - THR_flea_recprot_t__send_alert_and_throw() ==> can stay. alerts are small enought for
 *   single packet.
 * - THR_flea_recprot_t__send_alert() ==> "
 * - THR_flea_recprot_t__write_flush() ==> TODO: must be replaced, if it is really
 *   needed. Probably, introducing flight_sending_completed() calls will make
 *   explicit calls to write_flush() unnecessary.
 * - THR_flea_recprot_t__send_record() within THR_flea_tls_ctx_t__snd_appdat_inner() ==> TODO: must be replaced
 * - THR_flea_recprot_t__write_flush() within THR_flea_tls_ctx_t__flush_write_app_data() ==> TODO: must be replaced

 * - THR_flea_recprot_t__resize_send_plaintext_size() (resizing the send plaintext size) ==> TODO: must also be applied to the DTLS-package limit
 * - flea_recprot_t__set_max_pt_len()
 * - flea_recprot_t__have_done_initial_handshake() within flea_tls_ctx_t__compute_extensions_length() to check whether reneg content needs to be sent
 * - for setting new cipher suites ==> TODO: must be changed. When writing the
 *   records to the flight buffer, the cipher suite (connection state) is not yet applied. That
 *   means, once the the CCS was *written out* (not when it is appended to the flight buffer), the record protocol needs to switch to the new connection state. However, then it has to switch back to the previous to the previous connection state until the CCS is sent again. Alternative to write the "encrypted" records to the flight buffer is not possible: new records must be generated for resending.
 *
 * for reading:
 * - THR_flea_recprot_t__get_current_record_type()   ==> TODO: needs to be replaced
 * - THR_flea_recprot_t__read_data() for reading CCS ==> TODO: needs to be replaced
 * - for setting new cipher suites ==> TODO: when receiving records during a
 *   handshake, it can happen that a record sequentially after the CCS is
 *   received before the CCS. Thus the correct decryption of a record is only
 *   possible together with the knowledge whether it is sequentially before or
 *   after the CCS. However, it is known when the CCS is expected. Thus, the CCS
 *   will be read by the logic layer at the right time. But this means that
 *   records following the CCS cannot be decrypted until the CCS has been read
 *   by the logic layer. One possibility would be to buffer the undecrypted
 *   records, they can be ordered by the record sequence. <= NO, in a
 *   retransmission the record number changes! => perform trial decryption of
 *   each record, if it fails with the previous conn-state, try to decrypt it
 *   with the new conn-state once it is established.
 * - THR_flea_recprot_t__read_data() within THR_flea_tls_ctx_t__rd_appdat_inner() ==> TODO: needs to be replaced
 * - flea_recprot_t__discard_current_read_record() within THR_flea_tls_ctx_t__rd_appdat_inner() to reject renge request ==> TODO: needs to be replaced
 *
 *
 * on the tls_handsh_rdr level:
 * - TODO: in case of DTLS, the dtls_stream must feed the hash values of the dtls handhs. headers, and
 *   the tls_handsh_rdr must not at all feed the handhs. hdrs. to the hash
 *   computation
 */


/**
 *
 *  incoming state: - curr_hndsh_msg_seq__u16: indicates the current (or next)
 *                     handshake message index to be read
 *                  - curr_hndsh_msg_len__u16: the length of the current message
 *                  - curr_hndsh_msg_offs__u16: this many bytes have so far been read from the current msg
 *
 *
 *   msg_type=handsh_plain (with fragm_offs, not yet accessible, but right-extendable)
 *
 *
 *      +--------------+--------------+----------------------------+
 *      | u8: msg_type |   handsh-hdr | not yet rec. | received    |
 *      +--------------+--------------+----------------------------+
 *                                                   ^
 *                                                   |
 *                        fragm_offs-----------------+
 *
 *
 *   msg_type=handsh_plain  / accessed via tls_hndsh_rdr
 *      +--------------+--------------+----------------------------+
 *      | u8: msg_type |   handsh-hdr | received     | not yet rec.|
 *      +--------------+--------------+----------------------------+
 *                                           ^       ^             ^
 *                    state:                 |       |             |
 *                curr_rd_offs  -------------+       |             |
 *                     fragm_offs = 0                |             |
 *                                                   |             |
 *                from hdr:                          |             |
 *                    curr_msg_offs -----------------+             |
 *                    curr_msg_len --------------------------------+
 *
 *  When next adjacent fragment is received: update curr_msg_offs
 *  When reading content data: update read_offs
 *
 *  While the message has not been read at all:
 *    When next adjacent fragment is received: update fragm_len in hdr
 *
 *  Information whether the message has been read:
 *    state->curr_msg_seq == the seq. of the newly received record
 *
 *  Procedure when receiving a fragment:
 *    if state_curr_msg_seq == new_hs_fragm_seq:
 *      // the fragment belongs to the currently read message
 *      update curr_fragm_len
 *    if fragment can be right-chained to an existing one:
 *
 *     => new queue, write msg_type and handsh-hdr and fragment content
 *
 *
 *
 *
 *   msg_type=handsh_encr  / accessed via tls_hndsh_rdr
 *      +--------------+-----------------------------------------+
 *      | u8: msg_type | encrypted record: rec-hdr| content      |
 *      +--------------+-----------------------------------------+
 *
 *   msg_type=CCS(plain)  / accessed via dtls_hnds_ctx_t
 *      +--------------+
 *      | u8: msg_type |
 *      +--------------+
 *
 *   msg_type=app_data_encr / accessed via read_app_data (?) or received_record callback at the
 *                                  completion of the handshake
 *      +--------------+-----------------------------------------+
 *      | u8: msg_type | encrypted record                        |
 *      +--------------+-----------------------------------------+
 *        // TODO: when completing the handshake, before leaving the handshake function, invoke the received_record callback
 *
 *
 *
 *
 *
 */

#define FLEA_DTLS_HS_HDR_OFFS__MSG_TYPE   0
#define FLEA_DTLS_HS_HDR_OFFS__MSG_LEN    1
#define FLEA_DTLS_HS_HDR_OFFS__MSG_SEQ    4
#define FLEA_DTLS_HS_HDR_OFFS__FRAGM_OFFS 6
#define FLEA_DTLS_HS_HDR_OFFS__FRAGM_LEN  9

#define FLEA_DTLS_HS_HDR_LEN__MSG_TYPE    1
#define FLEA_DTLS_HS_HDR_LEN__MSG_LEN     3
#define FLEA_DTLS_HS_HDR_LEN__MSG_SEQ     2
#define FLEA_DTLS_HS_HDR_LEN__FRAGM_OFFS  3
#define FLEA_DTLS_HS_HDR_LEN__FRAGM_LEN   3

/* typedef enum
{
  flea_requ_ccs = 1,
  flea_requ_hndsh = 2
} flea_req_msg_type_e; */

typedef enum
{
  rec_type_hndsh_plain = 1,
  rec_type_encr_rec    = 2,
  rec_type_ccs         = 3
} flight_buf_rec_type_e;


static flea_err_e THR_flea_dtls_rd_strm__hndsh_hdr_info_from_queue(
  // flea_tls_handsh_reader_t*   handsh_rdr__pt,
  flea_dtls_hdsh_ctx_t*       dtls_hs_ctx__pt,
  qh_al_hndl_t                hndl__alqhh,
  flea_dtls_hndsh_hdr_info_t* result__pt
)
{
  // flea_dtls_hs_assmb_state_t* assmbl_state__pt = &dtls_hs_ctx__pt->incom_assmbl_state__t;
  // flea_byte_vec_t* incom_hndls__pt = &assmbl_state__pt->qheap_handles_incoming__t;
  qheap_queue_heap_t* heap__pt = dtls_hs_ctx__pt->qheap__pt;
  flea_u8_t* hdr_ptr__pu8;

  FLEA_DECL_BUF(hs_hdr_buf__bu8, flea_u8_t, FLEA_DTLS_HANDSH_HDR_LEN + 1);
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(hs_hdr_buf__bu8, FLEA_DTLS_HANDSH_HDR_LEN + 1);
  if(1 != qheap_qh_peek(heap__pt, hndl__alqhh, 0, hs_hdr_buf__bu8, 1))
  {
    FLEA_THROW("insufficient queue length to read type byte", FLEA_ERR_INT_ERR);
  }
  if(hs_hdr_buf__bu8[0] != rec_type_hndsh_plain)
  {
    memset(result__pt, 0, sizeof(*result__pt));
    FLEA_THR_RETURN();
  }
  if(1 + FLEA_DTLS_HANDSH_HDR_LEN !=
    qheap_qh_peek(heap__pt, hndl__alqhh, 0, hs_hdr_buf__bu8, FLEA_DTLS_HANDSH_HDR_LEN + 1))
  {
    FLEA_THROW("insufficient queue length to read handshake header", FLEA_ERR_INT_ERR);
  }

  /* HandshakeType msg_type;
     uint24 length;
     uint16 message_seq;                               // New field
     uint24 fragment_offset;                           // New field
     uint24 fragment_length;                           // New field
     */

  /*if((flea_u8_t ) rec_cont_type__e  == CONTENT_TYPE_HANDSHAKE )
    {*/
  hdr_ptr__pu8 = &hs_hdr_buf__bu8[1];
  // TODO: THIS SHOULD BE THE ONE AND ONLY VALUE WITH WHICH THE FUNCTION IS CALLED
  result__pt->msg_type__u8    = hdr_ptr__pu8[0];
  result__pt->msg_len__u32    = flea__decode_U24_BE(&hdr_ptr__pu8[1]);
  result__pt->msg_seq__u16    = flea__decode_U16_BE(&hdr_ptr__pu8[4]);
  result__pt->fragm_offs__u32 = flea__decode_U24_BE(&hdr_ptr__pu8[6]);
  /* this is the very first fragment and thus we can start outputting it */
  result__pt->fragm_len__u32 = flea__decode_U24_BE(&hdr_ptr__pu8[9]);
  FLEA_DBG_PRINTF("read hs-hdr:\n");
  FLEA_DBG_PRINTF(" msg_type = %02x\n", result__pt->msg_type__u8);
  FLEA_DBG_PRINTF(" msg_len = %02x\n", result__pt->msg_len__u32);
  FLEA_DBG_PRINTF(" msg_seq = %02x\n", result__pt->msg_seq__u16);
  FLEA_DBG_PRINTF(" fragm_offs = %02x\n", result__pt->fragm_offs__u32);
  FLEA_DBG_PRINTF(" fragm_len = %02x\n", result__pt->fragm_len__u32);
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(hs_hdr_buf__bu8);
  );
} /* THR_flea_dtls_rd_strm__hndsh_hdr_info_from_queue */

/**
 * return the index if the sought value is found, otherwise the length of the byte vector.
 */
#if 0
static flea_dtl_t flea_find_byte_in_byte_vec(
  const flea_byte_vec_t* vec__pt,
  flea_al_u8_t           byte
)
{
  flea_dtl_t j;

  for(j = 0; j < flea_byte_vec_t__GET_DATA_LEN(vec__pt); j += sizeof(qh_hndl_t))
  {
    if(flea_byte_vec_t__GET_DATA_PTR(vec__pt)[j] == byte)
    {
      break;
    }
  }
  return j;
}

#endif /* if 0 */

static flea_err_e THR_flea_dtls_rd_strm__merge_fragments(
  // flea_tls_handsh_reader_t* handsh_rdr__pt
  flea_dtls_hdsh_ctx_t* dtls_hs_ctx__pt
)
{
  flea_dtls_hs_assmb_state_t* assmbl_state__pt = &dtls_hs_ctx__pt->incom_assmbl_state__t;
  flea_byte_vec_t* incom_hndls__pt = &assmbl_state__pt->qheap_handles_incoming__t;
  qheap_queue_heap_t* heap__pt     = dtls_hs_ctx__pt->qheap__pt;
  flea_al_u8_t i;
  flea_bool_t try_again__b = FLEA_TRUE;

  FLEA_THR_BEG_FUNC();
  /* repeat the merging attempts as long as merging was successful */
  while(try_again__b)
  {
    flea_dtls_hs_assmb_state_t* assmbl_state__pt = &dtls_hs_ctx__pt->incom_assmbl_state__t;
    try_again__b = FLEA_FALSE;


    /* iterate over all queues as merge sources, i.e. as sources for data to append to other queues */
    for(i = 0; i < flea_byte_vec_t__GET_DATA_LEN(incom_hndls__pt); i += sizeof(qh_hndl_t))
    {
      flea_bool_t break_the_loops__b = FLEA_FALSE;
      flea_al_u8_t j;
      flea_dtls_hndsh_hdr_info_t src_hdr_info__t;
      qh_hndl_t src_hndl = flea_byte_vec_t__GET_DATA_PTR(incom_hndls__pt)[i];
      if(src_hndl == 0)
      {
        continue;
      }
      FLEA_DBG_PRINTF("reading src-hdr:\n");
      FLEA_CCALL(THR_flea_dtls_rd_strm__hndsh_hdr_info_from_queue(dtls_hs_ctx__pt, src_hndl, &src_hdr_info__t));
      if(src_hdr_info__t.msg_len__u32 == 0)
      {
        /* not a plaintext handshake message */
        continue;
      }
      if(src_hdr_info__t.fragm_offs__u32 == 0)
      {
        /* this message is itself the start of a handshake message, thus it cannot be appended to another */
        continue;
      }


/* check if the new fragment can be appended to the current queue */
#if 0
      if(assmbl_state__pt->curr_msg_len__u32 &&
        (assmbl_state__pt->curr_rd_offs_incl_hdr__u32 <
        assmbl_state__pt->curr_msg_len__u32) &&
        (assmbl_state__pt->curr_msg_seq__u16 == src_hdr_info__t.msg_seq__u16))
      {
        // TODO: INTEGRATE THE CHECK/UPDATE OF THE CURRENT QUEUE AS A FURHTER ITER OF THE J LOOP
      }
#endif /* if 0 */

      /* it is a non-initial fragment. look for the precursor. */
      for(j = 0; j <= flea_byte_vec_t__GET_DATA_LEN(incom_hndls__pt); j += sizeof(qh_hndl_t))
      {
        flea_u32_t skip_len__u32, copy_len__u32, copy_len_orig__u32;
        flea_u8_t new_trgt_fragm_len_encoded__au8[3];
        flea_u32_t new_fragm_len__u32;
        qh_hndl_t trgt_hndl;
        flea_dtls_hndsh_msg_state_info_t* curr_msg_state_info__pt = &assmbl_state__pt->curr_msg_state_info__t;
        flea_dtls_hndsh_hdr_info_t* curr_hdr_info__pt = &curr_msg_state_info__pt->msg_hdr_info__t;
        flea_bool_t is_iter_for_curr_msg__b = (j == flea_byte_vec_t__GET_DATA_LEN(incom_hndls__pt));
        flea_dtls_hndsh_hdr_info_t trgt_hdr_info__t;
        flea_u32_t trgt_fragm_end__u32, src_fragm_end__u32;
        if(j == i)
        {
          continue;
        }
        if(!is_iter_for_curr_msg__b)
        {
          trgt_hndl = flea_byte_vec_t__GET_DATA_PTR(incom_hndls__pt)[j];
        }
        // TODO: THE CHECK FOR THE LENGTH COMES LATER ON ANYWAY:
        else if(!curr_hdr_info__pt->msg_len__u32)//  || (curr_hdr_info__pt->msg_len__u32 == curr_msg_state_info__pt->rd_offs_incl_hdr__u32))
        {
          /* current message is not set */
          continue; // TODO: THE SUBSEQUENT CHECK OF THE HANDLE SHOULD SUFFICE => REMOVE THIS BRANCH
        }
        else
        {
          trgt_hndl = curr_msg_state_info__pt->hndl_qhh;
        }
        if(trgt_hndl == 0)
        {
          continue;
        }
        if(!is_iter_for_curr_msg__b)
        {
          FLEA_DBG_PRINTF("reading trgt-hdr:\n");
          FLEA_CCALL(THR_flea_dtls_rd_strm__hndsh_hdr_info_from_queue(dtls_hs_ctx__pt, trgt_hndl, &trgt_hdr_info__t));
        }
        else
        {
          FLEA_DBG_PRINTF("taking trgt-hdr from current msg\n");
          trgt_hdr_info__t = *curr_hdr_info__pt;
        }
        if((trgt_hdr_info__t.msg_len__u32 == 0) || (trgt_hdr_info__t.msg_seq__u16 != src_hdr_info__t.msg_seq__u16))
        {
          /* not a plaintext handshake message or not the correct msg. seq. nr. */
          continue;
        }
        if(trgt_hdr_info__t.msg_len__u32 == trgt_hdr_info__t.fragm_offs__u32 + trgt_hdr_info__t.fragm_len__u32)
        {
          /* the potential target is itself a final fragment */
          continue;
        }
        /* the source can be appended to the target, if the source's range contains at least one byte adjacent to the target's contents*/

        /*
         *    +---------------------------+
         *    |                           |
         *    +---------------------------+
         *    ^                           ^
         *    |                           |
         *  trgt->fragm_offs       trgt->fragm_offs + trgt->fragm_len
         *                            = trgt->end (points beyond the content)
         *
         *
         *                +--------------------------+
         *                |                          |
         *                +--------------------------+
         *                ^                          ^
         *                |                          |
         *          src->fragm_offs       src->fragm_offs + src->fragm_len
         *                                    = src->end
         *
         *         src->fragm_offs <= trgt->end && src->end > trgt->end
         */
        trgt_fragm_end__u32 = FLEA_DTLS_HNDSH_HDR_FRGM_END(&trgt_hdr_info__t);
        src_fragm_end__u32  = FLEA_DTLS_HNDSH_HDR_FRGM_END(&src_hdr_info__t);
        if((src_hdr_info__t.fragm_offs__u32 > trgt_fragm_end__u32) ||
          (src_fragm_end__u32 <= trgt_fragm_end__u32))
        {
          /* the source is not the adjacent fragment to the right */
          continue;
        }
        skip_len__u32 = trgt_fragm_end__u32 - src_hdr_info__t.fragm_offs__u32;
        /* skip over the type byte and the DTLS Handsh. header */
        qheap_qh_skip(heap__pt, src_hndl, skip_len__u32 + FLEA_DTLS_HANDSH_HDR_LEN + 1);
        copy_len_orig__u32 = copy_len__u32 = src_hdr_info__t.fragm_len__u32 - skip_len__u32;
        FLEA_DBG_PRINTF("copy_len = %u\n", copy_len_orig__u32);
        FLEA_DBG_PRINTF("skip_len = %u\n", skip_len__u32);
        FLEA_DBG_PRINTF(
          "trgt Q-len before appending content = %u\n",
          (unsigned) qheap_qh_get_queue_len(heap__pt, trgt_hndl)
        );
        FLEA_DBG_PRINTF("appending content = ");

        // TODO: USE QUEUE-CHAIN FUNCTION
        while(copy_len__u32)
        {
          flea_u8_t buf__au8[8];
          flea_al_u8_t to_go__alu8 = FLEA_MIN(copy_len__u32, sizeof(buf__au8));
          if(to_go__alu8 != qheap_qh_read(heap__pt, src_hndl, buf__au8, to_go__alu8))
          {
            FLEA_THROW("invalid return code from queue read during queue merge", FLEA_ERR_INT_ERR);
          }
          for(unsigned int i = 0; i < to_go__alu8; i++)
          {
            FLEA_DBG_PRINTF("%02x ", buf__au8[i]);
          }

          qheap_qh_append_to_queue(heap__pt, trgt_hndl, buf__au8, to_go__alu8);
          copy_len__u32 -= to_go__alu8;
        }
        FLEA_DBG_PRINTF("\n");
        FLEA_DBG_PRINTF(
          "trgt Q-len after appending content = %u\n",
          (unsigned) qheap_qh_get_queue_len(heap__pt, trgt_hndl)
        );
        qheap_qh_free_queue(heap__pt, src_hndl);
        new_fragm_len__u32 = trgt_hdr_info__t.fragm_len__u32 + copy_len_orig__u32;
        flea__encode_U24_BE(new_fragm_len__u32, new_trgt_fragm_len_encoded__au8);

        FLEA_DBG_PRINTF(
          "dtls: merge_fragms: merging (increased fragment length from %u (%u including header) by %u to %u ( for including header see below)from total msg len %u (without hdr) , with rd_offs = %u) queue to ",
          trgt_hdr_info__t.fragm_len__u32,
          curr_msg_state_info__pt->fragm_len_incl_hs_hdr__u32,
          copy_len_orig__u32,
          new_fragm_len__u32,
          curr_hdr_info__pt->msg_len__u32,
          curr_msg_state_info__pt->rd_offs_incl_hdr__u32
        );
        if(!is_iter_for_curr_msg__b)
        {
          FLEA_DBG_PRINTF("other stored queue\n");
          if(sizeof(new_trgt_fragm_len_encoded__au8) !=
            qheap_qh_rewrite(
              heap__pt,
              trgt_hndl,
              FLEA_DTLS_HS_HDR_OFFS__FRAGM_LEN + 1 /*offset*/,
              new_trgt_fragm_len_encoded__au8,
              sizeof(new_trgt_fragm_len_encoded__au8)
          ))
          {
            FLEA_THROW("invalid result from queue rewrite", FLEA_ERR_INT_ERR);
          }
        }
        else
        {
          FLEA_DBG_PRINTF("currently acitve queue\n");
          curr_hdr_info__pt->fragm_len__u32 = new_fragm_len__u32; // TODO: NEEDED AT ALL?
          curr_msg_state_info__pt->fragm_len_incl_hs_hdr__u32 += copy_len_orig__u32;
          FLEA_DBG_PRINTF("updated: curr_hdr_info__pt->fragm_len__u32  = %u\n", curr_hdr_info__pt->fragm_len__u32);
          FLEA_DBG_PRINTF(
            "updated: curr_msg_state_info__pt->fragm_len_incl_hs_hdr__u32 = %u\n",
            curr_msg_state_info__pt->fragm_len_incl_hs_hdr__u32
          );
        }
        /* delete the source from the handle list */
        flea_byte_vec_t__GET_DATA_PTR(incom_hndls__pt)[i] = 0;

        /*after successfull merging, the procedure needs to be restarted */
        break_the_loops__b = FLEA_TRUE;
        break;
      }
      if(break_the_loops__b)
      {
        /* merging was successfull, try again */

        try_again__b = FLEA_TRUE;

        break;
      }
    }
  } // end try_again loop
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_dtls_rd_strm__merge_fragments */

// static flea_err_e THR_flea_dtls_rd_strm__rd_ccs(

/**
 * read the next record and place it into the array of queues.
 */
static flea_err_e THR_flea_dtls_rd_strm__rd_dtls_rec_from_wire(
  // flea_tls_handsh_reader_t* handsh_rdr__pt,
  flea_dtls_hdsh_ctx_t* dtls_hs_ctx__pt,
  // flea_rw_stream_t*         rec_prot_stream__pt
  flea_recprot_t*       rec_prot__pt
)
{
  flea_tls_rec_cont_type_e cont_type__e;
  flea_al_u8_t i;
  flea_al_u16_t curr_rec_cont_len__alu16;
  qheap_queue_heap_t* heap__pt = dtls_hs_ctx__pt->qheap__pt;
// TODO: MAKE DYNAMIC: + enc_hs, (plain_alert,) enc_alert, plain_ccs
  flea_u8_t rec_type__u8; // = (flea_u8_t) rec_type_hndsh_plain;
  flea_dtls_hs_assmb_state_t* assmbl_state__pt = &dtls_hs_ctx__pt->incom_assmbl_state__t;
  flea_byte_vec_t* incom_hndls__pt = &assmbl_state__pt->qheap_handles_incoming__t;
  qh_al_hndl_t hndl_alqhh;

  FLEA_THR_BEG_FUNC();
  /* trigger the reading of a new record */
  // TODO: COVER THE CASE OF A YET UNDECRYPTABLE RECORD
  //  - in case of DTLS, a record with "epoch + 1" is just kept as an encrypted record
  //  - set a flag in the rec_prot
  //  - add rec_prot macro which can querry this

  // TODO: ADD RESULT-ARG TO LEARN WHETHER RECORD COULD BE DECRYPTED FOR DTLS.
  FLEA_CCALL(THR_flea_recprot_t__get_current_record_type(rec_prot__pt, &cont_type__e, flea_read_full));
  if(FLEA_RP__IS_DTLS_REC_FROM_FUT_EPOCH(rec_prot__pt))
  {
    rec_type__u8 = rec_type_encr_rec;
  }
  else
  {
    switch(cont_type__e)
    {
        case CONTENT_TYPE_HANDSHAKE:
          rec_type__u8 = (flea_u8_t) rec_type_hndsh_plain;
          break;
        case CONTENT_TYPE_CHANGE_CIPHER_SPEC:
          rec_type__u8 = (flea_u8_t) rec_type_ccs;
          break;
        case CONTENT_TYPE_APPLICATION_DATA:
          // TODO: plain (=> invoke callback) or encrypted (store in incom. flight state, output after *completed handshake*, then destroy the incom. flight state)
          break;
        case CONTENT_TYPE_ALERT:
          // cannot happen. an encrypted alert is generically stored (unencrypted alert is directly handled by rec_prot )
          break;
        default:
          break;
    }
  }
  /* get the length of the current record */
  curr_rec_cont_len__alu16 = flea_recprot_t__GET_CURR_REC_PT_SIZE(rec_prot__pt);
  hndl_alqhh = qheap_qh_alloc_queue(heap__pt, FLEA_FALSE);
  if(hndl_alqhh == 0)
  {
    FLEA_THROW("could not allocate memory queue", FLEA_ERR_OUT_OF_MEM);
  }

  qheap_qh_append_to_queue(heap__pt, hndl_alqhh, &rec_type__u8, 1);
  // TODO: USE BETTER WAY TO WRITE THE RECORD CONTENT TO THE QUEUE (TURN THE RECORD CONTENT INTO A QUEUE ITSELF)
  //
  if(rec_type__u8 == rec_type_encr_rec)
  {
    FLEA_CCALL(THR_flea_recprot_t__write_encr_rec_to_queue(rec_prot__pt, dtls_hs_ctx__pt->qheap__pt, hndl_alqhh));
  }
  else
  {
    while(curr_rec_cont_len__alu16)
    {
      flea_u8_t small_buf[8];
      flea_dtl_t to_go__dtl = FLEA_MIN(curr_rec_cont_len__alu16, sizeof(small_buf));

      if(rec_type__u8 == rec_type_ccs)
      {
        if(to_go__dtl != 1)
        {
          FLEA_THROW("invalid read length for CCS read from the rec_prot", FLEA_ERR_INT_ERR);
        }
      }
      FLEA_CCALL(THR_flea_recprot_t__read_data(rec_prot__pt, cont_type__e, small_buf, &to_go__dtl, flea_read_full));


      // TODO: SHORT WRITES TO THE QUEUE ARE NOT OPTIMAL
      qheap_qh_append_to_queue(heap__pt, hndl_alqhh, small_buf, to_go__dtl);
      curr_rec_cont_len__alu16 -= to_go__dtl;
    }
  }

  /* set the handle in the handle list. try to find an empty position. otherwise append it. */
  for(i = 0; i < flea_byte_vec_t__GET_DATA_LEN(incom_hndls__pt); i += sizeof(qh_hndl_t))
  {
    qh_hndl_t chk_hndl = flea_byte_vec_t__GET_DATA_PTR(incom_hndls__pt)[i];
    if(chk_hndl == 0)
    {
      flea_byte_vec_t__GET_DATA_PTR(incom_hndls__pt)[i] = hndl_alqhh;
      break;
    }
  }
  if(i >= flea_byte_vec_t__GET_DATA_LEN(incom_hndls__pt))
  {
    FLEA_CCALL(THR_flea_byte_vec_t__push_back(incom_hndls__pt, hndl_alqhh));
  }


  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_dtls_rd_strm__rd_dtls_rec_from_wire */

static flea_err_e THR_flea_dtls_rd_strm__start_new_msg(
  // flea_tls_handsh_reader_t* handsh_rdr__pt,
  flea_dtls_hdsh_ctx_t*    dtls_hs_ctx__pt,
  flea_recprot_t*          rec_prot__pt,
  flea_tls_rec_cont_type_e rec_cont_type__e
  // flea_rw_stream_t*         rec_prot_stream__pt,
  // flea_u8_t*                handsh_type__pu8,
  // flea_u32_t*               msg_len__pu32,
  // flea_u8_t*                handsh_hdr_mbn__pu8,
  // flea_tls_rec_cont_type_e  rec_cont_type__e
)
{
// TODO: CAN USE THE HEADER FROM THE ARGUMENT (SEE BELOW) RIGHT AWAY AND REMOVE
// THIS ONE
// flea_u8_t hdr__au8[FLEA_DTLS_HANDSH_HDR_LEN];

  FLEA_DECL_BUF(hs_hdr_buf__bu8, flea_u8_t, FLEA_DTLS_HANDSH_HDR_LEN + 1);
  // flea_al_u8_t hdr_size__alu8 = sizeof(hdr__au8);
  // flea_dtls_hdsh_ctx_t *dtls_hs_ctx__pt = handsh_rdr__pt->dtls_hs_ctx__pt;
  flea_dtls_hs_assmb_state_t* assmbl_state__pt = &dtls_hs_ctx__pt->incom_assmbl_state__t;
  flea_byte_vec_t* incom_hndls__pt = &assmbl_state__pt->qheap_handles_incoming__t;
  qheap_queue_heap_t* heap__pt     = dtls_hs_ctx__pt->qheap__pt;
  flea_dtls_hndsh_msg_state_info_t* curr_msg_state__pt = &assmbl_state__pt->curr_msg_state_info__t;
  flea_al_u16_t i;
  flight_buf_rec_type_e req_msg_type__e;
  // TODO: HANDLE TIMEOUT =>
  //                    IF NOT RECORD FROM NEXT EXPECTED FLIGHT WAS YET RECEIVED
  //                      THEN RESEND THE FLIGHT BUFFER:
  //                        RESET THE READ POSITION.
  //                        DECREASE EST. PMTU
  //
  //          TODO:  IF RECEIVING A RECORD FROM THE PREVIOUS (COMPLETED) FLIGHT,
  //          THEN ALSO RESEND THE LAST FLIGHT
  FLEA_THR_BEG_FUNC();
  switch(rec_cont_type__e)
  {
      case CONTENT_TYPE_HANDSHAKE:
      {
        req_msg_type__e = rec_type_hndsh_plain;
        FLEA_DBG_PRINTF("THR_flea_dtls_rd_strm__start_new_msg called with expected record content 'HANDSHAKE'\n");
        break;
      }
      case CONTENT_TYPE_CHANGE_CIPHER_SPEC:
      {
        req_msg_type__e = rec_type_ccs;
        FLEA_DBG_PRINTF("THR_flea_dtls_rd_strm__start_new_msg called with expected record content 'CCS'\n");
        break;
      }
      default:
        FLEA_THROW("unhandled content type for start_new_msg", FLEA_ERR_INT_ERR);
  }

  FLEA_ALLOC_BUF(hs_hdr_buf__bu8, FLEA_DTLS_HANDSH_HDR_LEN + 1);
  if(sizeof(qh_hndl_t) != 1)
  {
    FLEA_THROW("invalid size of qheap handle type", FLEA_ERR_INT_ERR);
  }

  if(curr_msg_state__pt->rd_offs_incl_hdr__u32)
  {
    flea_al_u16_t seq__alu16;
    flea_dtls_hndsh_hdr_info_t* curr_hdr_info__pt = &curr_msg_state__pt->msg_hdr_info__t;

    if(curr_msg_state__pt->rd_offs_incl_hdr__u32 != curr_msg_state__pt->fragm_len_incl_hs_hdr__u32) // curr_msg_state__pt->msg_hdr_info__t.msg_len__u32)
    {
      FLEA_THROW(
        "invalid state: attempting to read new HS msg when current one has not been completeley read",
        FLEA_ERR_INT_ERR
      );
    }
    qheap_qh_free_queue(
      dtls_hs_ctx__pt->qheap__pt,
      dtls_hs_ctx__pt->incom_assmbl_state__t.curr_msg_state_info__t.hndl_qhh
    );
    /* the message with curr_msg_seq has already been processed (read) */
    seq__alu16 = curr_hdr_info__pt->msg_seq__u16;
    if(req_msg_type__e == rec_type_hndsh_plain)
    {
      FLEA_DBG_PRINTF("THR_flea_dtls_rd_strm__start_new_msg: incrementing rec. seq.\n");
      seq__alu16 += 1;
    }
    memset(curr_msg_state__pt, 0, sizeof(*curr_msg_state__pt));
    curr_hdr_info__pt->msg_seq__u16 = seq__alu16;
    // assmbl_state__pt->curr_msg_seq__u16++;

    /*assmbl_state__pt->curr_fragm_len__u32  = 0;
    assmbl_state__pt->curr_fragm_offs__u32 = 0;
    assmbl_state__pt->curr_msg_len__u32    = 0;*/

    // curr_msg_state__pt->curr_hndl_qhh = 0;
    // assmbl_state__pt->curr_hndl_qhh        = 0;

    // curr_msg_state__pt->rd_offs_incl_hdr__u32    = 0;
  }
  /* scan through the incoming queue handles and look if the subsequent handshake msg number is available */
  while(1) // TODO: RESENDING / BREAKING OFF WHEN TIMEOUT EXCEEDED
  {
    for(i = 0; i < flea_byte_vec_t__GET_DATA_LEN(incom_hndls__pt); i += sizeof(qh_hndl_t))
    {
      qh_hndl_t hndl = flea_byte_vec_t__GET_DATA_PTR(incom_hndls__pt)[i];
      if(hndl == 0)
      {
        continue;
      }
      /* scan the header of this queue */
      // TODO: USE LINEARIZE FROM QH
      qheap_qh_peek(heap__pt, hndl, 0, hs_hdr_buf__bu8, 1);

      /* HandshakeType msg_type;
         uint24 length;
         uint16 message_seq;                               // New field
         uint24 fragment_offset;                           // New field
         uint24 fragment_length;                           // New field
         */

      /*if((flea_u8_t ) rec_cont_type__e  == CONTENT_TYPE_HANDSHAKE )
      {*/
      flea_u8_t* hdr_ptr__pu8 = &hs_hdr_buf__bu8[1];
      // TODO: THIS SHOULD BE THE ONE AND ONLY VALUE WITH WHICH THE FUNCTION IS CALLED
      if((req_msg_type__e == rec_type_hndsh_plain) && (hs_hdr_buf__bu8[0] == rec_type_hndsh_plain))
      {
        flea_u32_t fragm_offs__u32;
        flea_u16_t msg_seq__u16;
        // flea_u8_t frag_len_enc__au8[3];
        flea_dtls_hndsh_msg_state_info_t* curr_msg_state_info__pt = &assmbl_state__pt->curr_msg_state_info__t;
        flea_dtls_hndsh_hdr_info_t* curr_msg_hdr_info__pt         = &curr_msg_state_info__pt->msg_hdr_info__t;
        qheap_qh_peek(heap__pt, hndl, 0, hs_hdr_buf__bu8, FLEA_DTLS_HANDSH_HDR_LEN + 1);
        /* check if the handshake msg header whether it the next message in the row */
        msg_seq__u16 = flea__decode_U16_BE(&hdr_ptr__pu8[FLEA_DTLS_HS_HDR_OFFS__MSG_SEQ]);
        if(curr_msg_hdr_info__pt->msg_seq__u16 != msg_seq__u16)
        {
          continue;
        }
        /* it is the correct next msg. check if is the the first fragment. */
        fragm_offs__u32 = flea__decode_U24_BE(&hdr_ptr__pu8[6]);
        if(fragm_offs__u32 != 0)
        {
          continue;
        }
        /* this is the very first fragment and thus we can start outputting it */
        curr_msg_hdr_info__pt->msg_len__u32   = flea__decode_U24_BE(&hdr_ptr__pu8[FLEA_DTLS_HS_HDR_OFFS__MSG_LEN]);
        curr_msg_hdr_info__pt->msg_type__u8   = hdr_ptr__pu8[FLEA_DTLS_HS_HDR_OFFS__MSG_TYPE];
        curr_msg_hdr_info__pt->fragm_len__u32 = flea__decode_U24_BE(&hdr_ptr__pu8[FLEA_DTLS_HS_HDR_OFFS__FRAGM_LEN]);
        curr_msg_state__pt->fragm_len_incl_hs_hdr__u32 = curr_msg_hdr_info__pt->fragm_len__u32
          + FLEA_DTLS_HANDSH_HDR_LEN;
        curr_msg_hdr_info__pt->fragm_offs__u32 = fragm_offs__u32;
        curr_msg_state_info__pt->hndl_qhh      = hndl;
        /* now read away the type-byte */
        qheap_qh_skip(heap__pt, hndl, 1);

        /* rewrite the fragm len to be equal to the msg len */
        if(FLEA_DTLS_HS_HDR_LEN__FRAGM_LEN !=
          qheap_qh_rewrite(
            heap__pt,
            hndl,
            FLEA_DTLS_HS_HDR_OFFS__FRAGM_LEN /*offset*/,
            hdr_ptr__pu8 + FLEA_DTLS_HS_HDR_OFFS__MSG_LEN,
            FLEA_DTLS_HS_HDR_LEN__FRAGM_LEN
        ))
        {
          FLEA_THROW("invalid result from queue rewrite", FLEA_ERR_INT_ERR);
        }

        /*if(handsh_hdr_mbn__pu8)
        {
          memcpy(handsh_hdr_mbn__pu8, hdr_ptr__pu8, FLEA_DTLS_HANDSH_HDR_LEN);
        }*/

        // *handsh_type__pu8 = hdr_ptr__pu8[0];
        // *msg_len__pu32    = curr_msg_hdr_info__pt->msg_len__u32;

        /*handsh_rdr__pt->hlp__t.msg_seq__u16 =
          handsh_rdr__pt->hlp__t.fragm_offset__u32
          handsh_rdr__pt->hlp__t.fragm_length__u32*/

        /* invalidate the handle */
        flea_byte_vec_t__GET_DATA_PTR(incom_hndls__pt)[i] = 0;
        FLEA_THR_RETURN();
      }
      else if((req_msg_type__e == rec_type_ccs) && (hs_hdr_buf__bu8[0] == rec_type_ccs))
      {
        flea_dtls_hndsh_msg_state_info_t* curr_msg_state_info__pt = &assmbl_state__pt->curr_msg_state_info__t;
        /* skip over the type byte */

        qheap_qh_skip(heap__pt, hndl, 1);
        curr_msg_state_info__pt->hndl_qhh = hndl;
        curr_msg_state__pt->fragm_len_incl_hs_hdr__u32    = qheap_qh_get_queue_len(heap__pt, hndl);
        flea_byte_vec_t__GET_DATA_PTR(incom_hndls__pt)[i] = 0;
        /* automatically expect again a handshake message */
        dtls_hs_ctx__pt->incom_assmbl_state__t.req_next_rec_cont_type__e = CONTENT_TYPE_HANDSHAKE;
        FLEA_THR_RETURN();
      }
      // }
    } /* end loop running through the incoming fragment handles */
      /* the sought msg was not found */

    FLEA_CCALL(THR_flea_dtls_rd_strm__rd_dtls_rec_from_wire(dtls_hs_ctx__pt, rec_prot__pt));
    FLEA_CCALL(THR_flea_dtls_rd_strm__merge_fragments(dtls_hs_ctx__pt));
  } /* end loop until next msg is available */

  //
  // FLEA_CCALL(THR_flea_rw_stream_t__read_full(stream__pt, hdr__au8, hdr_size__alu8));

  // first, check sequence
  //   if older than current: resend
  //   if newer or equal than current: insert into flight buffer
  //                                  (this means the flight buffer has to be
  //                                  kept)

  /* (((flea_u32_t) hdr__au8[1]) << 16) | (((flea_u32_t) hdr__au8[2]) << 8)
   | (((flea_u32_t) hdr__au8[3]));*/


  /* these fields are all irrelevant on this layer. fragmentation information was already corrected by the underlying assembly layer. */

  /*handsh_rdr__pt->hlp__t.msg_seq__u16      = flea__decode_U16_BE(&hdr__au8[4]);
  handsh_rdr__pt->hlp__t.fragm_offset__u32 = flea__decode_U24_BE(&hdr__au8[6]);
  handsh_rdr__pt->hlp__t.fragm_length__u32 = flea__decode_U24_BE(&hdr__au8[9]);*/

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(hs_hdr_buf__bu8);
  );
} /* THR_flea_tls_hndsh_rdr__read_handsh_hdr_dtls */

void flea_dtls_rd_strm__expect_ccs(
  flea_dtls_hdsh_ctx_t* dtls_hs_ctx__pt
)
{
  dtls_hs_ctx__pt->incom_assmbl_state__t.req_next_rec_cont_type__e = CONTENT_TYPE_CHANGE_CIPHER_SPEC;
}

// stream to be used by handsh_rdr and by TLS logic layer directly
static flea_err_e THR_dtls_rd_strm_rd_func(
  void*                   custom_obj__pv,
  flea_u8_t*              target_buffer__pu8,
  flea_dtl_t*             nb_bytes_to_read__pdtl,
  flea_stream_read_mode_e read_mode__e
)
{
  // in the custom object we need to provide
  //  - requested record type
  //
  //  the record type of the current rec can be determined from ...?
  //
  //  if hndsh msg is requested, output / read in / assemble ...
  //  if ccs is requested, return the CCS (there may only be one)
  //  alerts are processed when available
  //    ( TODO: stored encrypted alerts must be decrypted once possible)
  //  app_data is decrypted once possible and fed to callback
  flea_dtls_rd_stream_hlp_t* hlp__pt    = (flea_dtls_rd_stream_hlp_t*) custom_obj__pv;
  flea_dtls_hdsh_ctx_t* dtls_hs_ctx__pt = hlp__pt->dtls_hs_ctx__pt;

  flea_dtls_hs_assmb_state_t* assmbl_state__pt = &dtls_hs_ctx__pt->incom_assmbl_state__t;
  flea_dtl_t rem_read_len__dtl = *nb_bytes_to_read__pdtl;
  flea_dtls_hndsh_msg_state_info_t* curr_msg_state_info__pt = &assmbl_state__pt->curr_msg_state_info__t;

  // flea_dtls_hndsh_hdr_info_t* curr_msg_hs_hdr_info__pt      = &curr_msg_state_info__pt->msg_hdr_info__t;

  FLEA_THR_BEG_FUNC();
  // READ MODE IS IGNORED SINCE THIS FUNCTION IS ONLY USED DURING THE HANDSH
  while(rem_read_len__dtl) // TODO: MUST BE U32 ?
  {
    flea_u32_t did_read__u32;
    flea_u32_t rem_in_curr_msg__u32 = curr_msg_state_info__pt->msg_hdr_info__t.msg_len__u32 + FLEA_DTLS_HANDSH_HDR_LEN
      - curr_msg_state_info__pt->rd_offs_incl_hdr__u32;
    // curr_msg_state_info__pt->fragm_len_incl_hs_hdr__u32
    if(!curr_msg_state_info__pt->msg_hdr_info__t.msg_len__u32 || !rem_in_curr_msg__u32)
    {
      /* a new handshake msg is implicitly requested */
      FLEA_CCALL(
        THR_flea_dtls_rd_strm__start_new_msg(
          dtls_hs_ctx__pt,
          hlp__pt->rec_prot__pt,
          dtls_hs_ctx__pt->incom_assmbl_state__t.req_next_rec_cont_type__e
        )
      );
    }
    // if(!curr_msg_state_info__pt->fragm_len_incl_hs_hdr__u32)

    /*if(!curr_msg_state_info__pt->msg_hdr_info__t.msg_len__u32) // there are also msgs with length 0
    {
      FLEA_THROW("assertion for length of current msg failed", FLEA_ERR_INT_ERR);
    }*/
    if(!curr_msg_state_info__pt->hndl_qhh)
    {
      FLEA_THROW("assertion for hndl of current msg failed", FLEA_ERR_INT_ERR);
    }

    FLEA_DBG_PRINTF(
      "read_request = %u\nq-len before => after read: %u => ",
      rem_read_len__dtl,
      (unsigned) qheap_qh_get_queue_len(dtls_hs_ctx__pt->qheap__pt, curr_msg_state_info__pt->hndl_qhh)
    );
// dbg =>
    if(rem_read_len__dtl == 827)
    {
      FLEA_DBG_PRINTF("BREAKPOINT\n");
    }
// <= dbg


    did_read__u32 = qheap_qh_read(
      dtls_hs_ctx__pt->qheap__pt,
      curr_msg_state_info__pt->hndl_qhh,
      target_buffer__pu8,
      rem_read_len__dtl
    );
    FLEA_DBG_PRINTF(
      "%u\n",
      (unsigned) qheap_qh_get_queue_len(dtls_hs_ctx__pt->qheap__pt, curr_msg_state_info__pt->hndl_qhh)
    );

    /*FLEA_DBG_PRINTF("dtls_rd_funct: outputting: ");
    FLEA_DBG_PRINT_BYTE_ARRAY(target_buffer__pu8, rem_read_len__dtl);*/

    FLEA_DBG_PRINTF(
      "dtls rd func: msg_type = %u, did_read = %u, read_offs (before read) = %u, msg_len =%u, fragm_len_incl_hdr = %u\n",
      assmbl_state__pt->curr_msg_state_info__t.msg_hdr_info__t.msg_type__u8,
      did_read__u32,
      curr_msg_state_info__pt->rd_offs_incl_hdr__u32,
      assmbl_state__pt->curr_msg_state_info__t.msg_hdr_info__t.msg_len__u32,
      curr_msg_state_info__pt->fragm_len_incl_hs_hdr__u32

    );
    FLEA_DBG_PRINTF("dtls rd func: output = ");
    FLEA_DBG_PRINT_BYTE_ARRAY(target_buffer__pu8, did_read__u32);
    rem_read_len__dtl -= did_read__u32;
    curr_msg_state_info__pt->rd_offs_incl_hdr__u32 += did_read__u32;
    target_buffer__pu8 += did_read__u32;
    if(rem_read_len__dtl)
    {
      FLEA_DBG_PRINTF("dtls_stream read function: requiring more data, reading new record from wire\n");
      FLEA_CCALL(THR_flea_dtls_rd_strm__rd_dtls_rec_from_wire(dtls_hs_ctx__pt, hlp__pt->rec_prot__pt));
      FLEA_CCALL(THR_flea_dtls_rd_strm__merge_fragments(dtls_hs_ctx__pt));
    }
    // TODO: NEED TO FREE THE QUEUE HERE IF EMPTY? CAN PERFORM THE CURRENT QUEUE RESET HERE, FREE THE QUEUE. IN STARTE NEW MSG FUNCTION, ONLY ASSERT THAT THE CURR MSG IS EMPTY
  }
// WE READ ALL THE REQUESTED DATA:
  *nb_bytes_to_read__pdtl = *nb_bytes_to_read__pdtl;
  FLEA_THR_FIN_SEC_empty();
} /* THR_dtls_rd_strm_rd_func */

// dtls assembly layer for the handshake only
// TODO: ADD CONTENT TYPE ARGUMENT TO SPECIFY EXPECTED MSG (HS/CCS)
flea_err_e THR_flea_rw_stream_t__ctor_dtls_rd_strm(
  flea_rw_stream_t*          stream__pt,
  flea_dtls_rd_stream_hlp_t* hlp__pt,
  flea_dtls_hdsh_ctx_t*      dtls_hs_ctx__pt,
  flea_recprot_t*            rec_prot__pt
)
{
  FLEA_THR_BEG_FUNC();

  hlp__pt->dtls_hs_ctx__pt = dtls_hs_ctx__pt;
  dtls_hs_ctx__pt->incom_assmbl_state__t.req_next_rec_cont_type__e = CONTENT_TYPE_HANDSHAKE;
  hlp__pt->rec_prot__pt = rec_prot__pt;
  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor(
      stream__pt,
      hlp__pt,
      NULL,
      NULL,
      THR_dtls_rd_strm_rd_func,
      NULL,
      NULL,
      0
    )
  );

  FLEA_THR_FIN_SEC_empty();
}
