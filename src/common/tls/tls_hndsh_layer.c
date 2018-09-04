/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/tls/tls_hndsh_layer.h"
#include "internal/common/tls/hndsh_msg_tls.h"
#include "internal/common/tls/hndsh_msg_dtls.h"
#include "internal/common/tls/tls_int.h"
#include "internal/common/tls/tls_hndsh_ctx.h"

// TODO: RENAME THESE FUNCTION AS ...hndsh_layer...

flea_err_e THR_flea_tls__snd_hands_msg_hdr(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_tls_prl_hash_ctx_t*  p_hash_ctx_mbn__pt,
  HandshakeType             type,
  flea_u32_t                content_len__u32
)
{
  flea_tls_ctx_t* tls_ctx__pt = hs_ctx__pt->tls_ctx__pt;

  // flea_u8_t enc_for_hash__au8[4];
  if(FLEA_TLS_CTX_IS_DTLS(tls_ctx__pt))
  {
    return THR_flea_dtls_hdsh__snd_hands_msg_hdr(hs_ctx__pt, p_hash_ctx_mbn__pt, type, content_len__u32);
  }
  else
  {
    return THR_flea_tls_hdsh__snd_hands_msg_hdr(hs_ctx__pt, p_hash_ctx_mbn__pt, type, content_len__u32);
  }
} /* THR_flea_tls__snd_hands_msg_hdr */

flea_err_e THR_flea_tls__snd_hands_msg_content(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_tls_prl_hash_ctx_t*  p_hash_ctx_mbn__pt,
  const flea_u8_t*          msg_bytes,
  flea_u32_t                msg_bytes_len
)
{
  flea_recprot_t* rec_prot__pt = &hs_ctx__pt->tls_ctx__pt->rec_prot__t;

  flea_tls_ctx_t* tls_ctx__pt = hs_ctx__pt->tls_ctx__pt;

  FLEA_THR_BEG_FUNC();

  if(FLEA_TLS_CTX_IS_DTLS(hs_ctx__pt->tls_ctx__pt))
  {
    FLEA_CCALL(
      THR_flea_dtls_rtrsm_st_t__append_to_flight_buffer_and_try_to_send_record(
        &tls_ctx__pt->dtls_retransm_state__t,
        tls_ctx__pt->connection_end,
        &tls_ctx__pt->rec_prot__t,
        &hs_ctx__pt->dtls_ctx__t.is_in_sending_state__u8,
        msg_bytes,
        msg_bytes_len
      )
    );
  }
  else
  {
    FLEA_CCALL(
      THR_flea_recprot_t__wrt_data(
        rec_prot__pt,
        CONTENT_TYPE_HANDSHAKE,
        msg_bytes,
        msg_bytes_len
      )
    );
  }
  if(p_hash_ctx_mbn__pt)
  {
    FLEA_CCALL(THR_flea_tls_prl_hash_ctx_t__update(p_hash_ctx_mbn__pt, msg_bytes, msg_bytes_len));
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__snd_hands_msg_content */

flea_err_e THR_flea_tls__send_change_cipher_spec(
  flea_tls_handshake_ctx_t* hs_ctx__pt
)
{
  FLEA_THR_BEG_FUNC();
  flea_tls_ctx_t* tls_ctx__pt = hs_ctx__pt->tls_ctx__pt;

#ifdef FLEA_HAVE_DTLS
  if(FLEA_TLS_CTX_IS_DTLS(hs_ctx__pt->tls_ctx__pt))
  {
    FLEA_CCALL(
      THR_flea_dtls_rtrsm_st_t__append_ccs_to_flight_buffer_and_try_to_send_record(
        &tls_ctx__pt->
        dtls_retransm_state__t,
        tls_ctx__pt->connection_end,
        &tls_ctx__pt->rec_prot__t,
        &hs_ctx__pt->dtls_ctx__t.is_in_sending_state__u8
      )
    );
  }
  else
#endif /* ifdef FLEA_HAVE_DTLS */
  {
    FLEA_CCALL(
      THR_flea_recprot_t__send_change_cipher_spec_directly(&hs_ctx__pt->tls_ctx__pt->rec_prot__t)
    );
  }

  FLEA_THR_FIN_SEC_empty();
}
