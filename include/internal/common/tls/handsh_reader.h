#ifndef _flea_handsh_reader__H_
#define _flea_handsh_reader__H_

#include "flea/types.h"
#include "flea/rw_stream.h"
#include "internal/common/tls/handsh_read_stream.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct
{
  // flea_u8_t                    handshake_msg_type__u8;
  flea_rw_stream_t             handshake_read_stream__t;
  flea_tls_handsh_reader_hlp_t hlp__t;
} flea_tls_handsh_reader_t;


#ifdef __cplusplus
}
#endif

#endif /* h-guard */
