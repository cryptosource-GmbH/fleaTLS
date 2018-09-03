/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/tls/tls_hndsh_ctx.h"
#include "flea/alloc.h"
#include "internal/common/tls/tls_int.h"

flea_err_e THR_flea_tls_handshake_ctx_t__ctor(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  // flea_recprot_t*           rec_prot__pt,
  flea_tls_ctx_t*           tls_ctx__pt,
  flea_bool_t               is_reneg__b
)
{
  // TODO: MAKE FLIGHT BUFFER SIZE CONTROLLABLE VIA API OR DYNAMICALLY
  FLEA_THR_BEG_FUNC();
#if defined FLEA_HAVE_DTLS
  hs_ctx__pt->dtls_ctx__t.hs_ctx__pt = hs_ctx__pt;
  hs_ctx__pt->dtls_ctx__t.current_timeout_secs__u8 = 1;
  FLEA_CCALL(THR_flea_timer_t__ctor(&hs_ctx__pt->tls_ctx__pt->dtls_retransm_state__t.timer__t));
  hs_ctx__pt->dtls_ctx__t.send_msg_seq__s16 = -1;
  // TODO: MAKE PMTU-EST. AN ARGUMENT
  tls_ctx__pt->dtls_retransm_state__t.pmtu_estimate__alu16 = 256;
  // TODO: QHEAP MUST BECOME "DYNAMIC"
  qheap_qh_ctor(
    &tls_ctx__pt->dtls_retransm_state__t.qheap__t,
    (flea_u8_t*) tls_ctx__pt->dtls_retransm_state__t.qh_mem_area__au32,
    sizeof(tls_ctx__pt->dtls_retransm_state__t.qh_mem_area__au32),
    0
  );
  tls_ctx__pt->dtls_retransm_state__t.qheap__pt = &tls_ctx__pt->dtls_retransm_state__t.qheap__t;
  tls_ctx__pt->dtls_retransm_state__t.current_flight_buf__qhh =
    qheap_qh_alloc_queue(tls_ctx__pt->dtls_retransm_state__t.qheap__pt, QHEAP_FALSE);
  if(!tls_ctx__pt->dtls_retransm_state__t.current_flight_buf__qhh)
  {
    FLEA_THROW("error allocating queue", FLEA_ERR_OUT_OF_MEM);
  }
# if defined FLEA_HEAP_MODE
  // TODO: ONLY FOR DTLS:
  flea_byte_vec_t__ctor_empty_allocatable(&hs_ctx__pt->dtls_ctx__t.incom_assmbl_state__t.qheap_handles_incoming__t);
  // FLEA_ALLOC_MEM(hs_ctx__pt->dtls_ctx__t.flight_buf__bu8, FLEA_DTLS_FLIGHT_BUF_SIZE);
# else
  flea_byte_vec_t__ctor_empty_use_ext_buf(
    &hs_ctx__pt->dtls_ctx__t.incom_assmbl_state__t.qheap_handles_incoming__t,
    hs_ctx__pt->dtls_ctx__t.incom_assmbl_state__t.qheap_handles_incoming_memory__au8,
    sizeof(hs_ctx__pt->dtls_ctx__t.incom_assmbl_state__t.qheap_handles_incoming_memory__au8)
  );
# endif /* if defined FLEA_HEAP_MODE */

  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor_dtls_rd_strm(
      &hs_ctx__pt->dtls_ctx__t.incom_assmbl_state__t.dtls_assmbld_rd_stream__t,
      &hs_ctx__pt->dtls_ctx__t.incom_assmbl_state__t.dtls_rd_strm_hlp__t,
      &hs_ctx__pt->dtls_ctx__t,
      &tls_ctx__pt->rec_prot__t
    )
  );
#endif /* if defined FLEA_HAVE_DTLS */

  hs_ctx__pt->is_reneg__b = is_reneg__b;
  hs_ctx__pt->tls_ctx__pt = tls_ctx__pt;

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_handshake_ctx_t__ctor */

void flea_tls_handshake_ctx_t__dtor(flea_tls_handshake_ctx_t* hs_ctx__pt)
{
  flea_tls_ctx_t* tls_ctx__pt = hs_ctx__pt->tls_ctx__pt;

  qheap_qh_free_queue(
    tls_ctx__pt->dtls_retransm_state__t.qheap__pt,
    tls_ctx__pt->dtls_retransm_state__t.current_flight_buf__qhh
  );
#if defined FLEA_HEAP_MODE
  // FLEA_FREE_MEM_CHK_NULL(hs_ctx__pt->dtls_ctx__t.flight_buf__bu8);
# ifdef FLEA_HAVE_DTLS
  flea_timer_t__dtor(&hs_ctx__pt->tls_ctx__pt->dtls_retransm_state__t.timer__t);
  flea_byte_vec_t__dtor(&hs_ctx__pt->dtls_ctx__t.incom_assmbl_state__t.qheap_handles_incoming__t);
# endif
#endif /* if defined FLEA_HEAP_MODE */
}
