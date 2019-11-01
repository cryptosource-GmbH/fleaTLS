/* fleaTLS cryptographic library
Copyright (C) 2015-2019 cryptosource GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

#include "internal/common/default.h"
#include "internal/common/tls/tls_hndsh_ctx.h"
#include "flea/alloc.h"
#include "internal/common/tls/tls_int.h"

flea_err_e THR_flea_tls_handshake_ctx_t__ctor(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  // flea_recprot_t*           rec_prot__pt,
  flea_tls_ctx_t*           tls_ctx__pt,
  flea_bool_t is_reneg__b
#ifdef                      FLEA_HAVE_DTLS
  ,
  const flea_dtls_cfg_t*    dtls_cfg_mbn__pt
#endif
)
{
  // TODO: MAKE FLIGHT BUFFER SIZE CONTROLLABLE VIA API OR DYNAMICALLY
  FLEA_THR_BEG_FUNC();

  hs_ctx__pt->is_reneg__b = is_reneg__b;
  hs_ctx__pt->tls_ctx__pt = tls_ctx__pt;
#if defined FLEA_HAVE_DTLS
  if(FLEA_TLS_CTX_IS_DTLS(tls_ctx__pt))
  {
    if(!dtls_cfg_mbn__pt)
    {
      FLEA_THROW("must provide dtls_cfg_t for DTLS", FLEA_ERR_INV_ARG);
    }
    hs_ctx__pt->dtls_ctx__t.current_timeout_secs__u8 = dtls_cfg_mbn__pt->initial_recv_tmo_secs__u8;
    hs_ctx__pt->dtls_ctx__t.hs_ctx__pt        = hs_ctx__pt;
    hs_ctx__pt->dtls_ctx__t.send_msg_seq__s16 = -1;
  }
  // FLEA_CCALL(THR_flea_dtls_rtrsm_t__ctor(&hs_ctx__pt->tls_ctx__pt->dtls_retransm_state__t));
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

  flea_dtls_rtrsm_st_t__reset(&hs_ctx__pt->tls_ctx__pt->dtls_retransm_state__t);

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_handshake_ctx_t__ctor */

void flea_tls_handshake_ctx_t__dtor(flea_tls_handshake_ctx_t* hs_ctx__pt)
{
  // flea_dtls_rtrsm_st_t__dtor(&hs_ctx__pt->tls_ctx__pt->dtls_retransm_state__t);
#if defined FLEA_HEAP_MODE
  // FLEA_FREE_MEM_CHK_NULL(hs_ctx__pt->dtls_ctx__t.flight_buf__bu8);
# ifdef FLEA_HAVE_DTLS
  flea_byte_vec_t__dtor(&hs_ctx__pt->dtls_ctx__t.incom_assmbl_state__t.qheap_handles_incoming__t);

# endif
#endif /* if defined FLEA_HEAP_MODE */
}
