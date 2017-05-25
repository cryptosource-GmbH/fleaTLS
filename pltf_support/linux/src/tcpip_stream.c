/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/rw_stream.h"
#include "flea/error_handling.h"
#include "flea/error.h"

#include "pltf_support/tcpip_stream.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h> // inet_addr
#include <unistd.h>    // for close

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
} linux_socket_stream_ctx_t;

static linux_socket_stream_ctx_t stc_sock_stream__t;

static void init_sock_stream(
  linux_socket_stream_ctx_t* sock_stream__pt,
  flea_u16_t                 port__u16
)
{
  memset(sock_stream__pt, 0, sizeof(*sock_stream__pt));
  sock_stream__pt->read_buf__t.alloc_len__dtl  = sizeof(sock_stream__pt->read_buf__t.buffer__au8);
  sock_stream__pt->write_buf__t.alloc_len__dtl = sizeof(sock_stream__pt->write_buf__t.buffer__au8);
  sock_stream__pt->port__u16 = port__u16;
}

static flea_err_t THR_open_socket_server(void* ctx__pv)
{
  FLEA_THR_BEG_FUNC();
  linux_socket_stream_ctx_t* ctx__pt = (linux_socket_stream_ctx_t*) ctx__pv;
  struct sockaddr_in addr;
  int listen_fd = -1, client_fd = 0;
  listen_fd = socket(AF_INET, SOCK_STREAM, 0);

  if(listen_fd == -1)
  {
    FLEA_THROW("error opening linux socket", FLEA_ERR_INV_STATE);
  }
  // TODO: maybe change this. It SO_REUSEADDR enables us to reuse the same port
  // even though it is still blocked and waiting for a timeout when not properly
  // closed
  if(setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1}, sizeof(int)) < 0)
  {
    FLEA_THROW("setsockopt(SO_REUSEADDR) failed", FLEA_ERR_INV_STATE);
  }


  memset(&addr, 0, sizeof(addr));
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_family      = AF_INET;
  addr.sin_port        = htons(ctx__pt->port__u16);

  if((bind(listen_fd, (struct sockaddr*) &addr, sizeof(addr))) < 0)
  {
    FLEA_THROW("Socket bind failed", FLEA_ERR_TLS_GENERIC);
  }

  // TODO: second is "backlog" argument. 3 is taken from an example, check if it makes sense
  listen(listen_fd, 3);

  // while(1)
  client_fd = accept(listen_fd, (struct sockaddr*) NULL, NULL);
  if(client_fd < 0)
  {
    FLEA_THROW("Socket accept failed", FLEA_ERR_TLS_GENERIC);
  }

  // TODO: check if we need to close socket_fd ??? (in examples never done)
  ctx__pt->socket_fd__int = client_fd;
  FLEA_THR_FIN_SEC(
    if(listen_fd == -1)
  {
    close(client_fd);
  }
  );
} /* THR_open_socket_server */

static flea_err_t THR_open_socket_client(void* ctx__pv)
{
  FLEA_THR_BEG_FUNC();
  linux_socket_stream_ctx_t* ctx__pt = (linux_socket_stream_ctx_t*) ctx__pv;
  struct sockaddr_in addr;
  int socket_fd = -1;
  socket_fd = socket(AF_INET, SOCK_STREAM, 0);

  if(socket_fd == -1)
  {
    FLEA_THROW("error opening linux socket", FLEA_ERR_INV_STATE);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  addr.sin_family      = AF_INET;
  addr.sin_port        = htons(ctx__pt->port__u16);

  if(connect(socket_fd, (struct sockaddr*) &addr, sizeof(addr)) < 0)
  {
    // addr.sin_port = htons(4445);
    // if(connect(socket_fd, (struct sockaddr*) &addr, sizeof(addr)) < 0)
    {
      FLEA_THROW("coult not open client TCP/IP socket", FLEA_ERR_FAILED_STREAM_WRITE);
    }
  }
  ctx__pt->socket_fd__int = socket_fd;
  FLEA_THR_FIN_SEC(
    if(socket_fd == -1)
  {
    close(socket_fd);
  }
  );
} /* THR_open_socket */

void close_socket(void* ctx__pv)
{
  linux_socket_stream_ctx_t* ctx__pt = (linux_socket_stream_ctx_t*) ctx__pv;

  close(ctx__pt->socket_fd__int);
}

static flea_err_t THR_send_socket_inner(
  int              socket_fd,
  const flea_u8_t* source_buffer__pcu8,
  flea_dtl_t       nb_bytes_to_write__dtl
)
{
  FLEA_THR_BEG_FUNC();

  if(send(socket_fd, source_buffer__pcu8, nb_bytes_to_write__dtl, 0) < 0)
  {
    FLEA_THROW("Send failed!", FLEA_ERR_TLS_GENERIC);
  }
  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_write_socket(
  void*            ctx__pv,
  const flea_u8_t* source_buffer__pcu8,
  flea_dtl_t       nb_bytes_to_write__dtl
)
{
  FLEA_THR_BEG_FUNC();
  linux_socket_stream_ctx_t* ctx__pt = (linux_socket_stream_ctx_t*) ctx__pv;
  while(nb_bytes_to_write__dtl)
  {
    ctx__pt->write_buf__t.buffer__au8[ctx__pt->write_buf__t.used_len__dtl++] = *source_buffer__pcu8;
    source_buffer__pcu8++;
    nb_bytes_to_write__dtl--;
    if(ctx__pt->write_buf__t.used_len__dtl == ctx__pt->write_buf__t.alloc_len__dtl)
    {
      FLEA_CCALL(
        THR_send_socket_inner(
          ctx__pt->socket_fd__int,
          ctx__pt->write_buf__t.buffer__au8,
          ctx__pt->write_buf__t.used_len__dtl
        )
      );
      ctx__pt->write_buf__t.used_len__dtl = 0;
    }
  }
  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_write_flush_socket(void* ctx__pv)
{
  linux_socket_stream_ctx_t* ctx__pt = (linux_socket_stream_ctx_t*) ctx__pv;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_send_socket_inner(
      ctx__pt->socket_fd__int,
      ctx__pt->write_buf__t.buffer__au8,
      ctx__pt->write_buf__t.used_len__dtl
    )
  );
  ctx__pt->write_buf__t.used_len__dtl = 0;
  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_read_socket(
  void*                   ctx__pv,
  flea_u8_t*              target_buffer__pu8,
  flea_dtl_t*             nb_bytes_to_read__pdtl,
  flea_stream_read_mode_e rd_mode__e
)
{
  linux_socket_stream_ctx_t* ctx__pt = (linux_socket_stream_ctx_t*) ctx__pv;
  ssize_t did_read_ssz;
  int flags = 0;
  flea_dtl_t rem_len__dtl    = *nb_bytes_to_read__pdtl;
  flea_dtl_t read_total__dtl = 0;

  FLEA_THR_BEG_FUNC();
  if(rem_len__dtl == 0)
  {
    FLEA_THR_RETURN();
  }
  if(rd_mode__e == flea_read_nonblocking)
  {
    flags |= MSG_DONTWAIT;
  }
  do
  {
    did_read_ssz = recv(ctx__pt->socket_fd__int, target_buffer__pu8, rem_len__dtl, flags);
    if(did_read_ssz < 0)
    {
      if((rd_mode__e == flea_read_nonblocking) &&
        ((did_read_ssz == EAGAIN) || (did_read_ssz == EWOULDBLOCK) || (did_read_ssz == 0)))
      {
        FLEA_THR_RETURN();
      }
      FLEA_THROW("recv err", FLEA_ERR_FAILED_STREAM_READ);
    }
    else if(did_read_ssz == 0)
    {
      FLEA_THROW("recv err", FLEA_ERR_FAILED_STREAM_READ);
    }
    if(rd_mode__e == flea_read_full)
    {
      target_buffer__pu8 += did_read_ssz;
      rem_len__dtl       -= did_read_ssz;
      read_total__dtl    += did_read_ssz;
    }
  } while((rd_mode__e == flea_read_full) && rem_len__dtl);
  *nb_bytes_to_read__pdtl = read_total__dtl;
  // TODO: ^REPLACE BY
  // *nb_bytes_to_read__pdtl -= rem_len__dtl;
  FLEA_THR_FIN_SEC_empty();
} /* THR_read_socket */

#if 0
static flea_err_t THR_read_socket(
  void*       ctx__pv,
  flea_u8_t*  target_buffer__pu8,
  flea_dtl_t* nb_bytes_to_read__pdtl,
  flea_bool_t force_read__b
)
{
  linux_socket_stream_ctx_t* ctx__pt = (linux_socket_stream_ctx_t*) ctx__pv;
  flea_dtl_t rem_len__dtl = *nb_bytes_to_read__pdtl;
  read_buf_t* buf__pt     = &ctx__pt->read_buf__t;

  FLEA_THR_BEG_FUNC();
  // first draw from read buffer.
  // then directly read from socket, read more and place it into read buffer.
  // need pointer to read_pos in read buffer to avoid often shifting contents after
  // read from buffer.
  if(rem_len__dtl && (buf__pt->offset__dtl < buf__pt->used_len__dtl))
  {
    flea_dtl_t left__dtl  = buf__pt->used_len__dtl - buf__pt->offset__dtl;
    flea_dtl_t to_go__dtl = FLEA_MIN(left__dtl, rem_len__dtl);
    memcpy(target_buffer__pu8, buf__pt->buffer__au8 + buf__pt->offset__dtl, to_go__dtl);
    target_buffer__pu8   += to_go__dtl;
    rem_len__dtl         -= to_go__dtl;
    buf__pt->offset__dtl += to_go__dtl;
  }
  if(rem_len__dtl)
  {
    flea_bool_t no_read_at_all__b = FLEA_TRUE;
    do
    {
      buf__pt->offset__dtl   = 0;
      buf__pt->used_len__dtl = 0;
      ssize_t did_read_ssz = recv(ctx__pt->socket_fd__int, buf__pt->buffer__au8, buf__pt->alloc_len__dtl, 0);
      if(did_read_ssz < 0)
      {
        FLEA_THROW("recv err", FLEA_ERR_TLS_GENERIC);
      }
      if(did_read_ssz > 0)
      {
        no_read_at_all__b = FLEA_FALSE;
      }
      buf__pt->used_len__dtl = did_read_ssz;
      flea_dtl_t to_go__dtl = FLEA_MIN(did_read_ssz, rem_len__dtl);
      memcpy(target_buffer__pu8, buf__pt->buffer__au8, to_go__dtl);
      buf__pt->offset__dtl = to_go__dtl;
      target_buffer__pu8  += to_go__dtl;
      rem_len__dtl        -= to_go__dtl;
    } while(rem_len__dtl && (force_read__b || no_read_at_all__b));
  }
  *nb_bytes_to_read__pdtl -= rem_len__dtl;

  FLEA_THR_FIN_SEC_empty();
} /* THR_read_socket */

#endif /* if 0 */

flea_err_t THR_flea_pltfif_tcpip__create_rw_stream_server(
  flea_rw_stream_t* stream__pt,
  flea_u16_t        port__u16
)
{
  FLEA_THR_BEG_FUNC();
  flea_rw_stream_open_f open__f         = THR_open_socket_server;
  flea_rw_stream_close_f close__f       = close_socket;
  flea_rw_stream_write_f write__f       = THR_write_socket;
  flea_rw_stream_flush_write_f flush__f = THR_write_flush_socket;
  flea_rw_stream_read_f read__f         = THR_read_socket;
  init_sock_stream(&stc_sock_stream__t, port__u16);
  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor(
      stream__pt,
      (void*) &stc_sock_stream__t,
      open__f,
      close__f,
      read__f,
      write__f,
      flush__f,
      0
    )
  );
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_pltfif_tcpip__create_rw_stream_client(
  flea_rw_stream_t* stream__pt,
  flea_u16_t        port__u16
)
{
  FLEA_THR_BEG_FUNC();
  flea_rw_stream_open_f open__f         = THR_open_socket_client;
  flea_rw_stream_close_f close__f       = close_socket;
  flea_rw_stream_write_f write__f       = THR_write_socket;
  flea_rw_stream_flush_write_f flush__f = THR_write_flush_socket;
  flea_rw_stream_read_f read__f         = THR_read_socket;
  init_sock_stream(&stc_sock_stream__t, port__u16);
  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor(
      stream__pt,
      (void*) &stc_sock_stream__t,
      open__f,
      close__f,
      read__f,
      write__f,
      flush__f,
      0
    )
  );
  FLEA_THR_FIN_SEC_empty();
}
