/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/rw_stream.h"
#include "flea/error_handling.h"
#include "flea/error.h"


#include "pltf_support/tcpip_stream.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <arpa/inet.h> // inet_addr
#include <unistd.h>    // for close
#include <netdb.h>


// static linux_socket_stream_ctx_t stc_sock_stream__t;

static void init_sock_stream_client(
  linux_socket_stream_ctx_t* sock_stream__pt,
  flea_u16_t                 port__u16,
  unsigned                   timeout_secs,
  const char*                hostname,
  flea_bool_t                is_dns_name
)
{
  memset(sock_stream__pt, 0, sizeof(*sock_stream__pt));
  sock_stream__pt->read_buf__t.alloc_len__dtl  = sizeof(sock_stream__pt->read_buf__t.buffer__au8);
  sock_stream__pt->write_buf__t.alloc_len__dtl = sizeof(sock_stream__pt->write_buf__t.buffer__au8);
  sock_stream__pt->port__u16    = port__u16;
  sock_stream__pt->timeout_secs = timeout_secs;
  sock_stream__pt->hostname     = hostname;
  sock_stream__pt->is_dns_name  = is_dns_name;
}

static void init_sock_stream_server(
  linux_socket_stream_ctx_t* sock_stream__pt,
  int                        sock_fd,
  unsigned                   timeout_secs
)
{
  memset(sock_stream__pt, 0, sizeof(*sock_stream__pt));
  sock_stream__pt->read_buf__t.alloc_len__dtl  = sizeof(sock_stream__pt->read_buf__t.buffer__au8);
  sock_stream__pt->write_buf__t.alloc_len__dtl = sizeof(sock_stream__pt->write_buf__t.buffer__au8);
  sock_stream__pt->socket_fd__int = sock_fd;
  sock_stream__pt->timeout_secs   = timeout_secs;
}

#if 0
static flea_err_t THR_open_socket_server(void* ctx__pv)
{
  FLEA_THR_BEG_FUNC();

  linux_socket_stream_ctx_t* ctx__pt = (linux_socket_stream_ctx_t*) ctx__pv;
  struct timeval tv;
  tv.tv_sec  = 5; /* 5 seconds timeout for receiving a request */
  tv.tv_usec = 0;
  setsockopt(
    ctx__pt->socket_fd__int,
    SOL_SOCKET,
    SO_RCVTIMEO,
    (struct timeval*) &tv,
    sizeof(struct timeval)
  );
  FLEA_THR_FIN_SEC_empty();
} /* THR_open_socket_server */

#endif /* if 0 */
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

  char ip[100];
  if(ctx__pt->is_dns_name)
  {
    struct hostent* he;
    struct in_addr** addr_list;
    if((he = gethostbyname(ctx__pt->hostname)) == NULL)
    {
      // get the host info
      FLEA_THROW("gethostbyname error", FLEA_ERR_INT_ERR);
    }

    addr_list = (struct in_addr**) he->h_addr_list;
    if(addr_list[0] == NULL)
    {
      FLEA_THROW("gethostbyname error", FLEA_ERR_INT_ERR);
    }
    strcpy(ip, inet_ntoa(*addr_list[0]));
    addr.sin_addr.s_addr = inet_addr(ip);
  }
  else
  {
    addr.sin_addr.s_addr = inet_addr(ctx__pt->hostname);
  }
  addr.sin_family = AF_INET;
  addr.sin_port   = htons(ctx__pt->port__u16);

  if(connect(socket_fd, (struct sockaddr*) &addr, sizeof(addr)) < 0)
  {
    // addr.sin_port = htons(4445);
    // if(connect(socket_fd, (struct sockaddr*) &addr, sizeof(addr)) < 0)
    {
      FLEA_THROW("coult not open client TCP/IP socket", FLEA_ERR_FAILED_TO_OPEN_CONNECTION);
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

static void close_socket(void* ctx__pv)
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

  if(send(socket_fd, source_buffer__pcu8, nb_bytes_to_write__dtl, MSG_NOSIGNAL) < 0)
  {
    FLEA_THROW("Send failed!", FLEA_ERR_FAILED_STREAM_WRITE);
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
      size_t send_len = ctx__pt->write_buf__t.used_len__dtl;
      ctx__pt->write_buf__t.used_len__dtl = 0;
      FLEA_CCALL(
        THR_send_socket_inner(
          ctx__pt->socket_fd__int,
          ctx__pt->write_buf__t.buffer__au8,
          send_len
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

  size_t send_len = ctx__pt->write_buf__t.used_len__dtl;

  ctx__pt->write_buf__t.used_len__dtl = 0;
  ctx__pt->write_buf__t.used_len__dtl = 0;
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_send_socket_inner(
      ctx__pt->socket_fd__int,
      ctx__pt->write_buf__t.buffer__au8,
      send_len
    )
  );
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
  struct timeval tv;

  FLEA_THR_BEG_FUNC();
  if(rem_len__dtl == 0)
  {
    FLEA_THR_RETURN();
  }
  if(rd_mode__e == flea_read_nonblocking)
  {
    flags |= MSG_DONTWAIT;
  }
  tv.tv_sec  = ctx__pt->timeout_secs;
  tv.tv_usec = 0;

  /* ^- in principle this is not sufficient, as the a read for many byte could
   * exceed the timeout by returning bytes successively with a delay in
   * between that is shorter than the timout set here. this corner case is, however, not
   * relevant to this example implementation.
   */
  setsockopt(
    ctx__pt->socket_fd__int,
    SOL_SOCKET,
    SO_RCVTIMEO,
    (struct timeval*) &tv,
    sizeof(struct timeval)
  );
  do
  {
    // if timeout mode
    did_read_ssz = recv(ctx__pt->socket_fd__int, target_buffer__pu8, rem_len__dtl, flags);
    if(did_read_ssz < 0)
    {
      if((rd_mode__e == flea_read_nonblocking) &&
        ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
      {
        *nb_bytes_to_read__pdtl = 0;
        FLEA_THR_RETURN();
      }
      else if(((errno == EAGAIN) || (errno == EWOULDBLOCK)))
      {
        FLEA_THROW("recv timout error", FLEA_ERR_TIMEOUT_ON_STREAM_READ);
      }

      FLEA_THROW("recv err", FLEA_ERR_FAILED_STREAM_READ);
    }
    else if(did_read_ssz == 0)
    {
      FLEA_THROW("recv err", FLEA_ERR_FAILED_STREAM_READ);
    }
    // if(rd_mode__e == flea_read_full)
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
  flea_rw_stream_t*          stream__pt,
  linux_socket_stream_ctx_t* sock_stream_ctx,
  int                        sock_fd,
  unsigned                   timeout_secs

)
{
  FLEA_THR_BEG_FUNC();
  flea_rw_stream_open_f open__f         = NULL; // THR_open_socket_server;
  flea_rw_stream_close_f close__f       = close_socket;
  flea_rw_stream_write_f write__f       = THR_write_socket;
  flea_rw_stream_flush_write_f flush__f = THR_write_flush_socket;
  flea_rw_stream_read_f read__f         = THR_read_socket;
  // init_sock_stream(&stc_sock_stream__t, port__u16, NULL);
  init_sock_stream_server(sock_stream_ctx, sock_fd, timeout_secs);
  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor(
      stream__pt,
      (void*) sock_stream_ctx,
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
  flea_rw_stream_t*          stream__pt,
  linux_socket_stream_ctx_t* sock_stream_ctx,
  flea_u16_t                 port__u16,
  unsigned                   timeout_secs,
  const char*                hostname,
  flea_bool_t                is_dns_name
)
{
  FLEA_THR_BEG_FUNC();
  flea_rw_stream_open_f open__f         = THR_open_socket_client;
  flea_rw_stream_close_f close__f       = close_socket;
  flea_rw_stream_write_f write__f       = THR_write_socket;
  flea_rw_stream_flush_write_f flush__f = THR_write_flush_socket;
  flea_rw_stream_read_f read__f         = THR_read_socket;
  init_sock_stream_client(sock_stream_ctx, port__u16, timeout_secs, hostname, is_dns_name);
  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor(
      stream__pt,
      (void*) sock_stream_ctx,
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
