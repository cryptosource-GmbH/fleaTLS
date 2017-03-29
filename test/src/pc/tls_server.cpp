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
#include "pltf_support/tcpip_stream.h"
#include "tls_server_certs.h"

flea_err_t THR_flea_start_tls_server(property_set_t const& cmdl_args)
{
  flea_rw_stream_t rw_stream__t;


  // TODO: MISSING INIT OF CTX
  flea_tls_ctx_t tls_ctx;

  // char app_data_www[] = "GET index.html HTTP/1.1\nHost: 127.0.0.1";


  #define SERVER_CERT_1024


  flea_ref_cu8_t cert_chain[2];
  flea_ref_cu8_t server_key__t;
#ifdef SERVER_CERT_1024
  cert_chain[1].data__pcu8 = trust_anchor_1024__au8;
  cert_chain[1].len__dtl   = sizeof(trust_anchor_1024__au8);
  cert_chain[0].data__pcu8 = server_cert_1024__au8;
  cert_chain[0].len__dtl   = sizeof(server_cert_1024__au8);
  server_key__t.data__pcu8 = server_key_1024__au8;
  server_key__t.len__dtl   = sizeof(server_key_1024__au8);
#else
  cert_chain[1].data__pcu8 = trust_anchor_2048__au8;
  cert_chain[1].len__dtl   = sizeof(trust_anchor_2048__au8);
  cert_chain[0].data__pcu8 = server_cert_2048__au8;
  cert_chain[0].len__dtl   = sizeof(server_cert_2048__au8);
  server_key__t.data__pcu8 = server_key_2048__au8;
  server_key__t.len__dtl   = sizeof(server_key_2048__au8);
#endif // ifdef SERVER_CERT_1024

  // now read data and echo it back
  flea_u8_t buf[1000];
  flea_al_u16_t buf_len = sizeof(buf);
  FLEA_THR_BEG_FUNC();
  flea_tls_ctx_t__INIT(&tls_ctx);
  FLEA_CCALL(THR_flea_pltfif_tcpip__create_rw_stream_server(&rw_stream__t));
  // FLEA_CCALL(flea_tls_ctx_t__ctor(&tls_ctx, &rw_stream__t, NULL, 0));
  FLEA_CCALL(THR_flea_tls_ctx_t__ctor_server(&tls_ctx, &rw_stream__t, cert_chain, 2, &server_key__t));

  while(1)
  {
    flea_err_t retval = THR_flea_tls_ctx_t__read_app_data(&tls_ctx, buf, &buf_len, flea_read_blocking);
    if(retval == FLEA_ERR_TLS_SESSION_CLOSED)
    {
      FLEA_THR_RETURN();
    }
    else if(retval)
    {
      FLEA_THROW("rethrowing error from read_app_data", retval);
    }
    printf("before read_app_data\n");
    buf[buf_len] = 0;
    printf("received data: %s\n", buf);
    printf("read_app_data returned\n");
    FLEA_CCALL(THR_flea_tls_ctx_t__send_app_data(&tls_ctx, buf, buf_len));
    buf_len = sizeof(buf);
  }
  // FLEA_CCALL(THR_flea_tls__send_app_data(&tls_ctx, (flea_u8_t *) app_data_www, strlen(app_data_www)));
  // FLEA_CCALL(THR_flea_tls__send_alert(&tls_ctx, FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY, FLEA_TLS_ALERT_LEVEL_WARNING));


  FLEA_THR_FIN_SEC(
    flea_rw_stream_t__dtor(&rw_stream__t);
    flea_tls_ctx_t__dtor(&tls_ctx);
  );
} // THR_flea_start_tls_server

int flea_start_tls_server(property_set_t const& cmdl_args)
{
  flea_err_t err;

  if((err = THR_flea_start_tls_server(cmdl_args)))
  {
    FLEA_PRINTF_TEST_OUTP_2_SWITCHED("error %04x during tls server test\n", err);
    return 1;
  }
  else
  {
    FLEA_PRINTF_TEST_OUTP_1_SWITCHED("tls test passed\n");
    return 0;
  }
}
