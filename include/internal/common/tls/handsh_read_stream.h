/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_handsh_read_stream__H_
#define _flea_handsh_read_stream__H_

#include "flea/types.h"
#include "flea/rw_stream.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct
{
  flea_rw_stream_t* underlying_read_stream__pt;
  flea_u32_t        remaining_bytes__u32;
  flea_u8_t         handshake_msg_type__u8;
} flea_tls_handsh_reader_hlp_t;

flea_err_t THR_flea_rw_stream_t__ctor_tls_handsh_reader(
  flea_rw_stream_t*             handsh_read_stream__pt,
  flea_tls_handsh_reader_hlp_t* hlp__pt,
  flea_rw_stream_t*             underlying_read_stream__pt,
  flea_u32_t                    msg_len__u32
);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
