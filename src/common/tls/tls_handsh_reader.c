/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/tls/handsh_reader.h"
#include "flea/types.h"
#include "flea/error.h"
#include "flea/error_handling.h"
#include "flea/rw_stream.h"
#include "internal/common/tls/tls_rec_prot.h"
#include "flea/bin_utils.h"
#include "internal/common/tls/hndsh_rdr_tls.h"
#include "internal/common/tls/hndsh_rdr_dtls.h"

#ifdef FLEA_HAVE_TLS

// TODO: INCORPORATE THE TLS_RDR FUNCTIONS FROM HNDSH_RDR_TLS.H
flea_err_e THR_flea_tls_handsh_reader_t__ctor(
  flea_tls_handsh_reader_t* handsh_rdr__pt,
  flea_recprot_t*           rec_prot__pt,
  flea_bool_t               is_dtls__b
)
{
  FLEA_THR_BEG_FUNC();
  handsh_rdr__pt->is_dtls__b = is_dtls__b;

  /*if(is_dtls__b)
  {
    FLEA_CCALL(THR_flea_tls_hndsh_rdr__ctor_dtls(handsh_rdr__pt, rec_prot__pt));
  }
  else
  {*/
  FLEA_CCALL(THR_flea_tls_hndsh_rdr__ctor_tls(handsh_rdr__pt, rec_prot__pt));
  // }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_handsh_reader_t__ctor */

flea_u32_t flea_tls_handsh_reader_t__get_msg_rem_len(flea_tls_handsh_reader_t* handsh_rdr__pt)
{
  return handsh_rdr__pt->handshake_read_stream__t.read_rem_len__u32;
}

flea_rw_stream_t* flea_tls_handsh_reader_t__get_read_stream(flea_tls_handsh_reader_t* handsh_rdr__pt)
{
  // TODO: THIS STREAM MUST WORK ON THE ASSEMBLY BUFFER
  // => Implement a new stream (not right away)
  return &handsh_rdr__pt->handshake_read_stream__t;
}

flea_al_u8_t flea_tls_handsh_reader_t__get_handsh_msg_type(flea_tls_handsh_reader_t* handsh_rdr__pt)
{
  // TODO: NEEDS TO BLOCK FOR FIRST HS-HDR THAT HAS NEXT EXPECTED SEQ
  return handsh_rdr__pt->hlp__t.handshake_msg_type__u8;
}

flea_err_e THR_flea_tls_handsh_reader_t__set_hash_ctx(
  flea_tls_handsh_reader_t* handsh_rdr__pt,
  flea_tls_prl_hash_ctx_t*  p_hash_ctx__pt
)
{
  FLEA_THR_BEG_FUNC();
  handsh_rdr__pt->hlp__t.p_hash_ctx__pt = p_hash_ctx__pt;
  // TODO: ADAPT LENGTH 4 FOR DTLS
  FLEA_CCALL(THR_flea_tls_prl_hash_ctx_t__update(p_hash_ctx__pt, handsh_rdr__pt->hlp__t.handsh_hdr__au8, 4));
  FLEA_THR_FIN_SEC_empty();
}

void flea_tls_handsh_reader_t__unset_hasher(flea_tls_handsh_reader_t* handsh_rdr__pt)
{
  handsh_rdr__pt->hlp__t.p_hash_ctx__pt = NULL;
}

#endif /* ifdef FLEA_HAVE_TLS */
