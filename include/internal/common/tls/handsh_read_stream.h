/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_handsh_read_stream__H_
# define _flea_handsh_read_stream__H_

# include "flea/types.h"
# include "flea/rw_stream.h"
# include "flea/hash.h"
# include "internal/common/tls/parallel_hash.h"
# include "internal/common/tls/tls_const.h"

# ifdef __cplusplus
extern "C" {
# endif

# ifdef FLEA_HAVE_TLS


typedef struct
{
  flea_rw_stream_t*        rec_prot_read_stream__pt;
  flea_u8_t                handshake_msg_type__u8;
  flea_tls_prl_hash_ctx_t* p_hash_ctx__pt;
  flea_u8_t                handsh_hdr__au8[FLEA_XTLS_MAX_HANDSH_HDR_LEN];
} flea_tls_handsh_reader_hlp_t;

flea_err_e THR_flea_rw_stream_t__ctor_tls_handsh_reader(
  flea_rw_stream_t*             handsh_read_stream__pt,
  flea_tls_handsh_reader_hlp_t* hlp__pt,
  flea_rw_stream_t*             underlying_read_stream__pt,
  flea_u32_t                    msg_len__u32
) FLEA_ATTRIB_UNUSED_RESULT;

# endif // ifdef FLEA_HAVE_TLS
# ifdef __cplusplus
}
# endif

#endif /* h-guard */
