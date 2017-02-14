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

// TODO: socket generisch halten: send/recv funktionen function pointer
flea_err_t THR_flea_start_tls_client(property_set_t const& cmdl_args)
{
  flea_rw_stream_t rw_stream__t;


  // TODO: MISSING INIT OF CTX
  flea_tls_ctx_t tls_ctx;
  char app_data_www[] = "GET index.html HTTP/1.1\nHost: 127.0.0.1";

  FLEA_THR_BEG_FUNC();
  flea_tls_ctx_t__INIT(&tls_ctx);
  FLEA_CCALL(THR_flea_test_linux__create_rw_stream(&rw_stream__t));
  FLEA_CCALL(flea_tls_ctx_t__ctor(&tls_ctx, &rw_stream__t, NULL, 0));
  FLEA_CCALL(THR_flea_tls__client_handshake(&tls_ctx));


  FLEA_CCALL(THR_flea_tls__send_app_data(&tls_ctx, (flea_u8_t*) app_data_www, strlen(app_data_www)));
  // FLEA_CCALL(THR_flea_tls__send_alert(&tls_ctx, FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY, FLEA_TLS_ALERT_LEVEL_WARNING));

  // TODO: dtor, close TLS connection

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
