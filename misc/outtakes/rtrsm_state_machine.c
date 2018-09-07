/* retransmission state machine with the purpose of triggering retransmission for each retransmitted incomding record / hs-msg. The idea is to look for the case where
 * 1) a retransmission is determined through either
 *  - a record from the previous epoch with unknown hs-msg sqn is seen,
 *  - or a record with a handshake msg fragment from a handshake msg that has
 *    already been completely received previously is seen
 *
 * 2) a later ... */
#define FLEA_DTLS_RTRSM_STATE__NOT_ACTIVE     0
#define FLEA_DTLS_RTRSM_STATE__ACTIVE_INITIAL 1

/**
 * When in FLEA_DTLS_RTRSM_STATE__IN_RTRSM_INITIAL and receiving any
 * handshake msg with a higher hs-sqn than the message which triggered the
 * retransmission, then we enter this state.
 */
#define FLEA_DTLS_RTRSM_ST__ACTIVE_OVER_SAVED 2

/**
 * This value indicates the unknown hs-sqn of a message which was received within belongs to the previous read_epoch.
 */
#define FLEA_DTLS_RTRSM_TRIGG_HS_MSG_SQN__INVALID 0xFF

// TODO: CHECK FOR LEAVING RTRSM WHEN WE RECEIVE A HS-SQN NEWER THAN THE LATEST SEEN SO FAR
// TODO: CLEAR ALL THE STATE VARIABLES USED HERE DURING RESET()
if(dtls_rtrsm_st__pt->rtrsm_state__u8 == FLEA_DTLS_RTRSM_STATE__ACTIVE_INITIAL)
{
  /* check if we received a handshake message which is later than the one that triggered the current retransmitting_state */
  if(dtls_rtrsm_st__pt->trigg_hs_msg_sqn__u8 == FLEA_DTLS_RTRSM_TRIGG_HS_MSG_SQN__INVALID)
  {
    if(hs_seq_of_triggering_msg__alu8 != FLEA_DTLS_RTRSM_TRIGG_HS_MSG_SQN__INVALID)
    {
      /* the new message is later than the triggering one (since it is from the current epoch), we are thus over the triggering one within the incoming retransmission */
      dtls_rtrsm_st__pt->rtrsm_state__u8 = FLEA_DTLS_RTRSM_ST__ACTIVE_OVER_SAVED;
    }
  }
  else   /* the stored triggering msg is from the current epoch and its sqn is known */
  {
    if((hs_seq_of_triggering_msg__alu8 == FLEA_DTLS_RTRSM_TRIGG_HS_MSG_SQN__INVALID) ||
      (hs_seq_of_triggering_msg__alu8 < dtls_rtrsm_st__pt->trigg_hs_msg_sqn__u8))
    {
      /* the newly received msg is even prior to the stored triggering msg => we assume that this is due to record reordering. it is not per se more probable that this another retransmission than that this is effect is due to record reodering over the wire. in any case, before retransmitting again, we want to be sure that we really received at least one subsequent msg. thus we assume that the observed incoming record order is due to record reordering and make the corresponding updates.  */
      dtls_rtrsm_st__pt->trigg_hs_msg_sqn__u8 = hs_seq_of_triggering_msg__alu8;
      dtls_rtrsm_st__pt->rtrsm_state__u8      = FLEA_DTLS_RTRSM_ST__ACTIVE_OVER_SAVED;
    }
    else if(hs_seq_of_triggering_msg__alu8 > dtls_rtrsm_st__pt->trigg_hs_msg_sqn__u8)   /* new msg-sqn is from current epoch */
    {
      /* the new message is later than the triggering one (within the same epoch), we are thus over the triggering one within the incoming retransmission */
      dtls_rtrsm_st__pt->rtrsm_state__u8 = FLEA_DTLS_RTRSM_ST__ACTIVE_OVER_SAVED;
    }
    /* uncovered case is where the sqn of the new msg is known and equal to the saved triggering sqn => nothin to do */
  }
  /* when on function entry in the ACTIVE_INITIAL state, we don't retransmit at all */
  return FLEA_FALSE;
}
else if(dtls_rtrsm_st__pt->rtrsm_state__u8 == FLEA_DTLS_RTRSM_ST__ACTIVE_OVER_SAVED)
{
  if(dtls_rtrsm_st__pt->trigg_hs_msg_sqn__u8 == FLEA_DTLS_RTRSM_TRIGG_HS_MSG_SQN__INVALID)
  {
    /* since we are in the "ACTIVE_OVER" state, one hs-msg from the new epoch must have already been received in
     * the meantime (i.e. since entering the ACTIVE_INITIAL state. */
    if(hs_seq_of_triggering_msg__alu8 == FLEA_DTLS_RTRSM_TRIGG_HS_MSG_SQN__INVALID)
    {
      /* the new message is from the previous epoch, thus it indicates a new retransmission */
      dtls_rtrsm_st__pt->rtrsm_state__u8 = FLEA_DTLS_RTRSM_STATE__NOT_ACTIVE;
      return FLEA_TRUE;
    }
    /* if the new message is not from the previous epoch, we don't retransmit again */
    return FLEA_FALSE;
  }
  else    /* the saved triggering msg is from the current epoch */
  {
    if(/* (A) */ (hs_seq_of_triggering_msg__alu8 == FLEA_DTLS_RTRSM_TRIGG_HS_MSG_SQN__INVALID) ||
      /*B*/ (hs_seq_of_triggering_msg__alu8 <= dtls_rtrsm_st__pt->trigg_hs_msg_sqn__u8))
    {
      /* (A) the new msg is from the previous epoch, thus it is a further retransmission */

      /* (B) the new msg is another retransmission, since we were already over the stored trigg_hs_msg_sqn__u8
       *    (however, due to record reordering over the "wire", we might again see a record from the same retransmission)
       * */
      dtls_rtrsm_st__pt->rtrsm_state__u8 = FLEA_DTLS_RTRSM_STATE__NOT_ACTIVE;
      return FLEA_TRUE;
    }
    return FLEA_FALSE;
  }
}
