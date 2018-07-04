/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "internal/common/tls/tls_rec_prot.h"
#include "internal/common/tls/parallel_hash.h"
#include "internal/common/tls/handsh_read_stream.h"
#include "internal/common/tls/tls_int.h"
#include "internal/common/tls/tls_hndsh_ctx.h"
// #include "internal/common/tls/tls_hndsh_layer.h"
#include "internal/common/tls/hndsh_msg_tls.h"

flea_err_e THR_flea_tls_hdsh__snd_hands_msg_hdr(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_tls_prl_hash_ctx_t*  p_hash_ctx_mbn__pt,
  HandshakeType             type,
  flea_u32_t                content_len__u32
)
{
  flea_u8_t hdr__au8[FLEA_TLS_HANDSH_HDR_LEN];
  // flea_u8_t enc_for_hash__au8[4];
  flea_recprot_t* rec_prot__pt = &hs_ctx__pt->tls_ctx__pt->rec_prot__t;

  FLEA_THR_BEG_FUNC();
  hdr__au8[0] = type;

  hdr__au8[1] = content_len__u32 >> 16;
  hdr__au8[2] = content_len__u32 >> 8;
  hdr__au8[3] = content_len__u32;

  FLEA_CCALL(
    THR_flea_recprot_t__wrt_data(
      rec_prot__pt,
      CONTENT_TYPE_HANDSHAKE,
      hdr__au8,
      sizeof(hdr__au8)
    )
  );
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
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__snd_hands_msg_hdr */
