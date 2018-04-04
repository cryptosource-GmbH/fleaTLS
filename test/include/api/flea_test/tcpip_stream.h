/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_test_linux_sock__H_
#define _flea_test_linux_sock__H_

#include "flea/types.h"
#include "flea/rw_stream.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  flea_dtl_t alloc_len__dtl;
  flea_dtl_t used_len__dtl;
  flea_u8_t  buffer__au8[1400];
} write_buf_t;

typedef struct
{
  flea_dtl_t alloc_len__dtl;
  flea_dtl_t used_len__dtl;
  flea_dtl_t offset__dtl;
  flea_u8_t  buffer__au8[1400];
} read_buf_t;
typedef struct
{
  int         socket_fd__int;
  read_buf_t  read_buf__t;
  write_buf_t write_buf__t;
  flea_u16_t  port__u16;
  const char* hostname;
  flea_bool_t is_dns_name;
  unsigned    timeout_millisecs;
} linux_socket_stream_ctx_t;

flea_err_e THR_flea_pltfif_tcpip__create_rw_stream_client(
  flea_rw_stream_t*          stream__pt,
  linux_socket_stream_ctx_t* sock_stream_ctx,
  flea_u16_t                 port__u16,
  unsigned                   timeout_millisecs,
  const char*                hostname,
  flea_bool_t                is_dns_name
);
flea_err_e THR_flea_pltfif_tcpip__create_rw_stream_server(
  flea_rw_stream_t*          stream__pt,
  linux_socket_stream_ctx_t* sock_stream_ctx,
  int                        sock_fd,
  unsigned                   timeout_millisecs
);


#ifdef __cplusplus
}
#endif

#endif /* h-guard */
