/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_hndsh_msg_dtls__H_
# define _flea_hndsh_msg_dtls__H_

# include "flea/types.h"
# include "internal/common/tls/tls_ctx_fwd.h"
# include "internal/common/tls/parallel_hash.h"
# include "internal/common/tls/tls_hndsh_ctx_fwd.h"

# ifdef __cplusplus
extern "C" {
# endif


flea_err_e THR_flea_dtls_hdsh__snd_hands_msg_hdr(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_tls_prl_hash_ctx_t*  p_hash_ctx_mbn__pt,
  HandshakeType             type,
  flea_u32_t                content_len__u32
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_dtls_hndsh__append_to_flight_buffer_and_try_to_send_record(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  const flea_u8_t*          data__pcu8,
  flea_u32_t                data_len__u32
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_dtls_hndsh__append_ccs_to_flight_buffer_and_try_to_send_record(flea_tls_handshake_ctx_t* hs_ctx__pt)
FLEA_ATTRIB_UNUSED_RESULT;

void flea_dtls_hndsh__set_flight_buffer_empty(flea_dtls_hdsh_ctx_t* dtls_hs_ctx__pt);


flea_err_e THR_flea_dtls_hdsh__retransmit_flight_buf(flea_tls_handshake_ctx_t* hs_ctx__pt) FLEA_ATTRIB_UNUSED_RESULT;

# ifdef __cplusplus
}
# endif
#endif /* h-guard */
