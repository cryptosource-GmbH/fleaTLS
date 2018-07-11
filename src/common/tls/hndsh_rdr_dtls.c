/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/tls/handsh_reader.h"
#include "internal/common/tls/tls_rec_prot.h"
#include "flea/bin_utils.h"
#include "internal/common/tls/hndsh_rdr_dtls.h"
#include "internal/common/tls/tls_hndsh_ctx.h"

// TODO: GET RID OF THIS FILE

#ifdef FLEA_HAVE_DTLS
# if 0

static flea_err_e THR_flea_dtls_hndsh_rdr__read_handsh_hdr(
  flea_tls_handsh_reader_t* handsh_rdr__pt,
  flea_rw_stream_t*         stream__pt,
  flea_u8_t*                handsh_type__pu8,
  flea_u32_t*               msg_len__pu32,
  flea_u8_t                 handsh_hdr_mbn__pu8[4]
)
{
  FLEA_THR_BEG_FUNC();

// TODO: CAN USE THE HEADER FROM THE ARGUMENT (SEE BELOW) RIGHT AWAY AND REMOVE
// THIS ONE
  flea_u8_t hdr__au8[FLEA_DTLS_HANDSH_HDR_LEN];
  flea_al_u8_t hdr_size__alu8 = sizeof(hdr__au8);


  // get current record content type to force the initial read, or just read the
  // first byte separately
  // TODO: HANDLE TIMEOUT =>
  //                    IF NOT RECORD FROM NEXT EXPECTED FLIGHT WAS YET RECEIVED
  //                      THEN RESEND THE FLIGHT BUFFER:
  //                        RESET THE READ POSITION.
  //                        DECREASE EST. PMTU
  //
  //          TODO:  IF RECEIVING A RECORD FROM THE PREVIOUS (COMPLETED) FLIGHT,
  //          THEN ALSO RESEND THE LAST FLIGHT
  //
  FLEA_CCALL(THR_flea_rw_stream_t__read_full(stream__pt, hdr__au8, hdr_size__alu8));
  *handsh_type__pu8 = hdr__au8[0];
  *msg_len__pu32    = flea__decode_U24_BE(&hdr__au8[1]);

  // first, check sequence
  //   if older than current: resend
  //   if newer or equal than current: insert into flight buffer
  //                                  (this means the flight buffer has to be
  //                                  kept)

  /* (((flea_u32_t) hdr__au8[1]) << 16) | (((flea_u32_t) hdr__au8[2]) << 8)
   | (((flea_u32_t) hdr__au8[3]));*/

  if(handsh_hdr_mbn__pu8)
  {
    memcpy(handsh_hdr_mbn__pu8, hdr__au8, sizeof(hdr__au8));
  }

  /*HandshakeType msg_type;
     uint24 length;
     uint16 message_seq;                               // New field
     uint24 fragment_offset;                           // New field
     uint24 fragment_length;                           // New field
     */
  handsh_rdr__pt->hlp__t.msg_seq__u16      = flea__decode_U16_BE(&hdr__au8[4]);
  handsh_rdr__pt->hlp__t.fragm_offset__u32 = flea__decode_U24_BE(&hdr__au8[6]);
  handsh_rdr__pt->hlp__t.fragm_length__u32 = flea__decode_U24_BE(&hdr__au8[9]);

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_dtls_hndsh_rdr__read_handsh_hdr */

flea_err_e THR_flea_tls_hndsh_rdr__ctor_dtls(
  flea_tls_handsh_reader_t* handsh_rdr__pt,
  flea_dtls_hdsh_ctx_t*     dtls_ctx__pt,
  flea_recprot_t*           rec_prot__pt
  // TODO: NEED EXPTECTED MESSAGE TYPE: HS OR CCS,
  // BETTER DO THIS BEFORE THE CURRENT.
  //
  // TODO: THE ASSEMBLY MUST BE ACCROSS THE WHOLE FLIGHT, WHILE THIS OBJECT IS
  // JUST FOR A SINGLE HS-MSG
  // => implement a stream above the tls_record_stream
)
{
  flea_u32_t read_limit__u32;
  bool received_hdr_from_current_flight__b = FLEA_FALSE;

  FLEA_THR_BEG_FUNC();
// TODO: THIS FUNCTION IS INVOKED FOR EACH NEW HANDSHAKE MESSAGE
// BUT THE RESENDING CAN ONLY BE DONE WHILE THE PREVIOUS FLIGHT IS STILL IN THE
// FLIGHT BUFFER, I.E. NO RECORDS FORM THE NEW FLIGHT HAVE BEEN RECEIVED SO FAR
//
// TODO: if (flight_buf_write_pos__u32 != 0 ||
// this-is-the-first-receive-of-server (? see below)) then start_timer.
// Note: server only started if first packet has been received?
  while(!received_hdr_from_current_flight__b)
  {
    /* try to read the first handshake msg fragment which carries a seq-no from
     * the new flight.
     * then the msg length and the message type is known (necessary for member for
     * functions). */

    FLEA_CCALL(
      THR_flea_dtls_hndsh_rdr__read_handsh_hdr(
        handsh_rdr__pt,
        &handsh_rdr__pt->rec_prot_rd_stream__t,
        &handsh_rdr__pt->hlp__t.handshake_msg_type__u8,
        &read_limit__u32,
        handsh_rdr__pt->hlp__t.handsh_hdr__au8
      )
    );
    // TODO: rec_last_flight_msg_seq__s16 must be updated to rec_msg_seq__s16
    // after a complete flight has been received. => tls logic layer must invoke
    // new function ...flight_completed()
    // This can be done implicitly when sending a handshake or CCS message the next time (but not for alert sending, if this happens at all).
    if(handsh_rdr__pt->hlp__t.msg_seq__u16 > dtls_ctx__pt->rec_last_flight_final_msg_seq__s16)
    {
      /* this message is not from the current flight, ignore it */
      received_hdr_from_current_flight__b = FLEA_TRUE;
    }
    else
    {
      flea_recprot_t__discard_current_read_record(rec_prot__pt);
    }
    // TODO: CHECK T/O. if T/O, then resend last flight if still have flight_buf (dtls_ctx__pt->flight_buf_write_pos__u32 != 0)
  }
  dtls_ctx__pt->flight_buf_read_pos__u32  = 0;
  dtls_ctx__pt->flight_buf_write_pos__u32 = 0;

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_hndsh_rdr__ctor_dtls */

# endif /* if 0 */
#endif /* ifdef FLEA_HAVE_DTLS */
