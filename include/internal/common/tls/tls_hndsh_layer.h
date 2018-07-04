/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "flea/types.h"
#include "internal/common/tls/tls_ctx_fwd.h"
#include "internal/common/tls/parallel_hash.h"

#ifndef _flea_tls_hndsh_layer__H_
# define _flea_tls_hndsh_layer__H_


flea_err_e THR_flea_tls__snd_hands_msg_hdr(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_tls_prl_hash_ctx_t*  p_hash_ctx_mbn__pt,
  HandshakeType             type,
  flea_u32_t                content_len__u32
);

flea_err_e THR_flea_tls__snd_hands_msg_content(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_tls_prl_hash_ctx_t*  p_hash_ctx_mbn__pt,
  const flea_u8_t*          msg_bytes,
  flea_u32_t                msg_bytes_len
);


#endif /* h-guard */
