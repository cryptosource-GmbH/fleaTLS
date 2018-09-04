#include "internal/common/tls/dtls_retransm_state.h"


/*
 * returns the available send length based on the current read position. Does not at all take into account whether there
 * is a completed handshake message within the data characterized by that length.
 */
flea_u32_t flea_dtls_rtrsm_st_t__flight_buf_avail_send_len(
  flea_dtls_retransm_state_t* rtrsm_st__pt
)
{
  // flea_tls_ctx_t* tls_ctx__pt = hs_ctx__pt->tls_ctx__pt;

  return /*tls_ctx__pt->dtls_retransm_state__t.flight_buf_write_pos__u32*/ qheap_qh_get_queue_len(
    rtrsm_st__pt->qheap__pt,
    rtrsm_st__pt->current_flight_buf__qhh
  ) - rtrsm_st__pt->flight_buf_read_pos__u32;
}
