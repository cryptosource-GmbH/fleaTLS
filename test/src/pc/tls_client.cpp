/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h> // Linux specific

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h> // inet_addr
#include <unistd.h>    // for close

#include "pc/test_util.h"
#include "flea/tls.h"
#include "pc/test_pc.h"
#include "pc/linux_sock.h"

/*static int create_socket()
 * {
 * int socket_fd;
 *  socket_fd = socket(AF_INET , SOCK_STREAM , 0);
 *
 *  if (socket_fd == -1)
 *  {
 *      printf("Could not create socket");
 *  }
 * return socket_fd;
 * }*/
// TODO: socket generisch halten: send/recv funktionen function pointer
flea_err_t THR_flea_start_tls_client(property_set_t const& cmdl_args)
{
  flea_rw_stream_t rw_stream__t;

#if 0
  int socket_fd;
  struct sockaddr_in addr;

  socket_fd = create_socket();

  memset(&addr, 0, sizeof(addr));
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  addr.sin_family      = AF_INET;
  addr.sin_port        = htons(4444);
#endif

  /*addr.sin_addr.s_addr = inet_addr("31.15.64.162");
   * addr.sin_family = AF_INET;
   * addr.sin_port = htons( 443 );*/
  // TODO: MISSING INIT OF CTX
  flea_tls_ctx_t tls_ctx;
  char app_data_www[] = "GET index.html HTTP/1.1\nHost: 127.0.0.1";
  FLEA_THR_BEG_FUNC();
  flea_tls_ctx_t__INIT(&tls_ctx);
#if 0
  if(connect(socket_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
  {
    addr.sin_port = htons(4445);
    if(connect(socket_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
    {
      printf("connect error\n");
      FLEA_THROW("Something went wrong!", FLEA_ERR_TLS_GENERIC);
    }
  }
#endif
  int socket_fd;
  FLEA_CCALL(THR_flea_test_linux__create_rw_stream(&rw_stream__t, &socket_fd));
  FLEA_CCALL(flea_tls_ctx_t__ctor(&tls_ctx, &rw_stream__t, NULL, 0, socket_fd));
  FLEA_CCALL(THR_flea_tls__client_handshake(socket_fd, &tls_ctx, &rw_stream__t));
  // flea_err_t err = flea_tls_handshake(socket_fd, &tls_ctx);


  FLEA_CCALL(THR_flea_tls__send_app_data(&tls_ctx, (flea_u8_t *) app_data_www, strlen(app_data_www)));
  // FLEA_CCALL(THR_flea_tls__send_alert(&tls_ctx, FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY, FLEA_TLS_ALERT_LEVEL_WARNING));

  // TODO: dtor

  // close (socket_fd);
  FLEA_THR_FIN_SEC(
    flea_rw_stream_t__dtor(&rw_stream__t);
  );
} // THR_flea_start_tls_client

int flea_start_tls_client(property_set_t const& cmdl_args)
{
  flea_err_t err;

  if((err = THR_flea_start_tls_client(cmdl_args)))
  {
    FLEA_PRINTF_TEST_OUTP_2_SWITCHED("error %04x during tls client test\n", err);
    return 1;
  }
  else
  {
    FLEA_PRINTF_TEST_OUTP_1_SWITCHED("tls test passed\n");
    return 0;
  }
}
