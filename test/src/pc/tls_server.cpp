/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"

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


#include "pltf_support/tcpip_stream.h"
#include "pc/test_util.h"
#include "flea/tls.h"
#include "pc/test_pc.h"
#include "pltf_support/tcpip_stream.h"
#include "tls_server_certs.h"
#include "flea/array_util.h"

using namespace std;


#ifdef FLEA_HAVE_TLS


flea_err_t THR_flea_start_tls_server(
  property_set_t const& cmdl_args,
  bool                is_https_server
)
{
  flea_rw_stream_t rw_stream__t;
  flea_cert_store_t trust_store__t;

  flea_tls_ctx_t tls_ctx;

  flea_ref_cu8_t cert_chain[10];
  flea_ref_cu8_t server_key__t;
  flea_al_u16_t cert_chain_len = FLEA_NB_ARRAY_ENTRIES(cert_chain);

  flea_ref_cu16_t cipher_suites_ref;
  flea_u8_t buf[1000];
  flea_al_u16_t buf_len = sizeof(buf);
  tls_test_cfg_t tls_cfg;

  FLEA_THR_BEG_FUNC();

  flea_rw_stream_t__INIT(&rw_stream__t);
  flea_tls_ctx_t__INIT(&tls_ctx);
  flea_cert_store_t__INIT(&trust_store__t);
  FLEA_CCALL(THR_flea_cert_store_t__ctor(&trust_store__t));
  FLEA_CCALL(
    THR_flea_tls_tool_set_tls_cfg(
      &trust_store__t,
      cert_chain,
      &cert_chain_len,
      &server_key__t,
      cmdl_args,
      tls_cfg
    )
  );
  if(cert_chain_len == 0)
  {
    throw test_utils_exceptn_t("missing own certificate for tls server");
  }

  FLEA_CCALL(THR_flea_pltfif_tcpip__create_rw_stream_server(&rw_stream__t, cmdl_args.get_property_as_u32("port")));

  cipher_suites_ref.data__pcu16 = &tls_cfg.cipher_suites[0];
  cipher_suites_ref.len__dtl    = tls_cfg.cipher_suites.size();
  FLEA_CCALL(
    THR_flea_tls_ctx_t__ctor_server(
      &tls_ctx,
      &rw_stream__t,
      cert_chain,
      cert_chain_len,
      &trust_store__t,
      &server_key__t,
      &cipher_suites_ref
    )
  );
  std::cout << "handshake done" << std::endl;
  std::flush(std::cout);
  if(!is_https_server)
  {
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
  }
  else
  {
    buf_len = sizeof(buf);
    const char* response_hdr_1 =
      "HTTP/1.1 200 OK\r\nDate: Mon, 27 Jul 2009 12:28:53 GMT\r\nServer: Apache/2.2.14 (Win32)\r\nLast-Modified: Wed, 22 Jul 2009 19:15:56 GMT\r\nContent-Length: 50\r\nContent-Type: text/html\r\nConnection: Closed\r\n\r\n<html><head><body>this is text</body></head></html>";
    flea_err_t retval = THR_flea_tls_ctx_t__read_app_data(&tls_ctx, buf, &buf_len, flea_read_blocking);
    if(retval == FLEA_ERR_TLS_SESSION_CLOSED)
    {
      FLEA_THR_RETURN();
    }
    else if(retval)
    {
      FLEA_THROW("rethrowing error from read_app_data", retval);
    }
    buf[buf_len] = 0;
    FLEA_CCALL(THR_flea_tls_ctx_t__send_app_data(&tls_ctx, (const flea_u8_t*) response_hdr_1, strlen(response_hdr_1)));
  }


  FLEA_THR_FIN_SEC(
    flea_rw_stream_t__dtor(&rw_stream__t);
    flea_cert_store_t__dtor(&trust_store__t);
    flea_tls_ctx_t__dtor(&tls_ctx);
  );
} // THR_flea_start_tls_server

int flea_start_tls_server(property_set_t const& cmdl_args)
{
  flea_err_t err;

  if((err = THR_flea_start_tls_server(cmdl_args, false)))
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

int flea_start_https_server(property_set_t const& cmdl_args)
{
  flea_err_t err;

  while(1)
  {
    if((err = THR_flea_start_tls_server(cmdl_args, true)))
    {
      FLEA_PRINTF_TEST_OUTP_2_SWITCHED("error %04x during https server test\n", err);
    }
    else
    {
      FLEA_PRINTF_TEST_OUTP_1_SWITCHED("tls test passed\n");
    }
  }
}

#endif // ifdef FLEA_HAVE_TLS
