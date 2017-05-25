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

  const flea_u16_t cipher_suites [] = {FLEA_TLS_RSA_WITH_AES_128_CBC_SHA, FLEA_TLS_RSA_WITH_AES_256_CBC_SHA, FLEA_TLS_RSA_WITH_AES_128_GCM_SHA256};
  flea_ref_cu16_t cipher_suites_ref = {cipher_suites, FLEA_NB_ARRAY_ENTRIES(cipher_suites)};
  // now read data and echo it back
  flea_u8_t buf[1000];
  flea_al_u16_t buf_len = sizeof(buf);

  FLEA_THR_BEG_FUNC();

  vector<vector<flea_u8_t> > trusted_certs = cmdl_args.get_bin_file_list_property("trusted");
  vector<flea_u8_t> server_key = cmdl_args.get_bin_file("own_private_key");
  std::vector<std::vector<unsigned char> > own_certs    = cmdl_args.get_bin_file_list_property("own_certs");
  std::vector<std::vector<unsigned char> > own_ca_chain = cmdl_args.get_bin_file_list_property("own_ca_chain");

  flea_tls_ctx_t__INIT(&tls_ctx);
  flea_cert_store_t__INIT(&trust_store__t);
  FLEA_CCALL(THR_flea_cert_store_t__ctor(&trust_store__t));

  if(trusted_certs.size() == 0)
  {
    throw test_utils_exceptn_t("need to provide at least one trusted cert");
  }
  for(auto& cert_vec : trusted_certs)
  {
    FLEA_CCALL(
      THR_flea_cert_store_t__add_trusted_cert(
        &trust_store__t,
        &cert_vec[0],
        cert_vec.size()
      )
    );
  }
  if(own_certs.size() != 1)
  {
    throw test_utils_exceptn_t("own_certs so far only supports a single cert");
  }

  if(own_ca_chain.size() + 1 > FLEA_NB_ARRAY_ENTRIES(cert_chain))
  {
    throw test_utils_exceptn_t("number of ca certs too large");
  }

  cert_chain[0].data__pcu8 = &(own_certs[0])[0];
  cert_chain[0].len__dtl   = own_certs[0].size();
  for(unsigned i = 0; i < own_ca_chain.size(); i++)
  {
    std::cout << "adding to own_ca_chain" << std::endl;
    cert_chain[i + 1].data__pcu8 = &(own_ca_chain[i])[0];
    cert_chain[i + 1].len__dtl   = own_ca_chain[i].size();
  }


  server_key__t.data__pcu8 = &server_key[0];
  server_key__t.len__dtl   = server_key.size();

  FLEA_CCALL(THR_flea_pltfif_tcpip__create_rw_stream_server(&rw_stream__t, cmdl_args.get_property_as_u32("port")));

  FLEA_CCALL(
    THR_flea_tls_ctx_t__ctor_server(
      &tls_ctx,
      &rw_stream__t,
      cert_chain,
      own_ca_chain.size() + 1,
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
