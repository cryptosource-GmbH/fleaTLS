/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_hndsh_msg_tls__H_
# define _flea_hndsh_msg_tls__H_

# include "flea/types.h"
# include "internal/common/tls/tls_ctx_fwd.h"
# include "internal/common/tls/parallel_hash.h"

flea_err_e THR_flea_tls_hdsh__snd_hands_msg_hdr(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_tls_prl_hash_ctx_t*  p_hash_ctx_mbn__pt,
  HandshakeType             type,
  flea_u32_t                content_len__u32
) FLEA_ATTRIB_UNUSED_RESULT;


# ifdef __cplusplus
extern "C" {
# endif


# ifdef __cplusplus
}
# endif
#endif /* h-guard */
