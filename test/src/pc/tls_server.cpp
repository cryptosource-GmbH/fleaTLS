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
#include <fcntl.h>

#include "pltf_support/tcpip_stream.h"
#include "pc/test_util.h"
#include "flea/tls.h"
#include "flea/tls_server.h"
#include "pc/test_pc.h"
#include "pltf_support/tcpip_stream.h"
#include "tls_server_certs.h"
#include "flea/array_util.h"
#include "flea/alloc.h"
#include "flea/tls_session_mngr.h"

using namespace std;


#ifdef FLEA_HAVE_TLS

enum class action_t { none, quit };

std::vector<std::string> stdin_input_lines;
std::string stdin_current_line;

# define FLEA_TEST_APP_USER_ABORT 0x300
static flea_err_t THR_check_keyb_input(/*fd_set & keyb_fds*/)
{
  // action_t result = action_t::none;
  FLEA_THR_BEG_FUNC();
  // FLEA_THR_RETURN();

  /*fd_set keyb_fds;
   *
   * FD_ZERO(&keyb_fds);
   * FD_SET(fileno(stdin), &keyb_fds);
   * struct timeval timeout = { 0, 0 };
   * select(fileno(stdin) + 1, &keyb_fds, NULL, NULL, &timeout);
   */
  // this is what really causes non-blocking reads:
  // fcntl(0, F_SETFL, fcntl(0, F_GETFL) | O_NONBLOCK);
  fcntl(fileno(stdin), F_SETFL, fcntl(fileno(stdin), F_GETFL) | O_NONBLOCK);
  // if(FD_ISSET(fileno(stdin), &keyb_fds))
  {
    flea_u8_t buf[4096];
    // std::cout << "calling read for stdin\n";
    ssize_t did_read = read(STDIN_FILENO, buf, sizeof(buf));

    fcntl(fileno(stdin), F_SETFL, fcntl(fileno(stdin), F_GETFL) & ~O_NONBLOCK);
    // if(FD_ISSET(fileno(stdin), &keyb_fds))
    if(did_read == -1)
    {
      // throw test_utils_exceptn_t("error reading from stdin");
      FLEA_THR_RETURN();
    }
    buf[did_read] = 0;
    // std::cout << "read " << did_read << " chars of user input: " + std::string((char*) buf) + "\n";
    for(ssize_t i = 0; i < did_read; i++)
    {
      if(buf[i] == '\n')
      {
        if(stdin_current_line != "")
        {
          stdin_input_lines.push_back(stdin_current_line);
        }
        stdin_current_line = "";
      }
      else
      {
        stdin_current_line.push_back(buf[i]);
      }
    }
  }
  if(stdin_input_lines.size())
  {
    std::string const& s = stdin_input_lines[0];
    if(s == "q" || s == "Q")
    {
      // std::cout << "check keyboard: user abort\n";
      // result = action_t::quit;
      FLEA_THROW("user abort requested", (flea_err_t) FLEA_TEST_APP_USER_ABORT);
    }
    else
    {
      std::cout << "processing user input = " << s << std::endl;
    }
    stdin_input_lines.erase(stdin_input_lines.begin());
  }
  FLEA_THR_FIN_SEC_empty();
  // if(result !=
} // THR_check_keyb_input

static flea_err_t THR_unix_tcpip_listen_accept(
  int      listen_fd,
  int*     fd,
  unsigned timeout_secs
)
{
  FLEA_THR_BEG_FUNC();
  int client_fd = -1;
  listen(listen_fd, 3);

  struct timeval tv;
  tv.tv_sec  = 1;
  tv.tv_usec = 0;
  setsockopt(
    listen_fd,
    SOL_SOCKET,
    SO_RCVTIMEO,
    (struct timeval*) &tv,
    sizeof(struct timeval)
  );

  do
  {
    // std::cout << "before accept\n";
    client_fd = accept(listen_fd, (struct sockaddr*) NULL, NULL);
    // std::cout << "after accept\n";
    FLEA_CCALL(THR_check_keyb_input());
  } while(client_fd == -1);

# if 0
  std::future<int> future = std::async(
    std::launch::async,
    [&](){
    return accept(listen_fd, (struct sockaddr*) NULL, NULL);
  }
    );
  std::future_status status;
  do
  {
    status = future.wait_for(std::chrono::seconds(1));

    /*if (status == std::future_status::deferred) {
     * std::cout << "deferred\n";
     * } else if (status == std::future_status::timeout) {
     * std::cout << "timeout\n";
     * } else if (status == std::future_status::ready) {
     * std::cout << "ready!\n";
     * }*/
    std::cout << "accept-loop, before check_keyb\n";
    FLEA_CCALL(THR_check_keyb_input(keyb_fds));
    std::cout << "accept-loop, after check_keyb\n";
  } while(status != std::future_status::ready);
  client_fd = future.get();
# endif // if 0
  if(client_fd < 0)
  {
    FLEA_THROW("Socket accept failed", FLEA_ERR_FAILED_TO_OPEN_CONNECTION);
  }
  *fd = client_fd;
  FLEA_THR_FIN_SEC_empty();
} // THR_unix_tcpip_listen_accept

static flea_err_t THR_server_cycle(
  property_set_t const     & cmdl_args,
  int                      listen_fd,
  bool                     is_https_server,
  flea_tls_session_mngr_t* sess_man__pt
)
{
  flea_u8_t buf[1000];
  flea_ref_cu8_t allowed_ecc_curves__rcu8;
  flea_ref_cu8_t allowed_sig_algs__rcu8;
  flea_ref_cu16_t cipher_suites_ref;
  flea_rw_stream_t rw_stream__t;
  flea_tls_server_ctx_t tls_ctx;

  flea_cert_store_t trust_store__t;


  flea_ref_cu8_t cert_chain[10];
  flea_ref_cu8_t server_key__t;
  flea_al_u16_t cert_chain_len = FLEA_NB_ARRAY_ENTRIES(cert_chain);

  tls_test_cfg_t tls_cfg;
  int sock_fd;

  flea_tls_shared_server_ctx_t shrd_server_ctx__t;

  FLEA_THR_BEG_FUNC();
  flea_rw_stream_t__INIT(&rw_stream__t);
  flea_tls_server_ctx_t__INIT(&tls_ctx);
  flea_cert_store_t__INIT(&trust_store__t);
  flea_tls_shared_server_ctx_t__INIT(&shrd_server_ctx__t);

  // flea_u8_t * dbg_leak = (flea_u8_t* )malloc(1);

  FLEA_CCALL(THR_flea_cert_store_t__ctor(&trust_store__t));
  if(cert_chain_len == 0)
  {
    throw test_utils_exceptn_t("missing own certificate for tls server");
  }

  FLEA_CCALL(
    THR_unix_tcpip_listen_accept(
      listen_fd,
      &sock_fd,
      cmdl_args.get_property_as_u32_default("read_timeout", 1)
    )
  );

  /** socket will be closed by rw_stream_t__dtor **/
  FLEA_CCALL(
    THR_flea_pltfif_tcpip__create_rw_stream_server(
      &rw_stream__t,
      sock_fd,
      cmdl_args.get_property_as_u32_default("read_timeout", 1)
    )
  );


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

  cipher_suites_ref.data__pcu16 = &tls_cfg.cipher_suites[0];
  cipher_suites_ref.len__dtl    = tls_cfg.cipher_suites.size();

  allowed_ecc_curves__rcu8.data__pcu8 = &tls_cfg.allowed_curves[0];
  allowed_ecc_curves__rcu8.len__dtl   = tls_cfg.allowed_curves.size();

  allowed_sig_algs__rcu8.data__pcu8 = &tls_cfg.allowed_sig_algs[0];
  allowed_sig_algs__rcu8.len__dtl   = tls_cfg.allowed_sig_algs.size();

  FLEA_CCALL(THR_flea_tls_shared_server_ctx_t__ctor(&shrd_server_ctx__t, &server_key__t));

  FLEA_CCALL(
    THR_flea_tls_server_ctx_t__ctor(
      &tls_ctx,
      &shrd_server_ctx__t,
      &rw_stream__t,
      cert_chain,
      cert_chain_len,
      &trust_store__t,
      &cipher_suites_ref,
      tls_cfg.rev_chk_mode__e,
      &tls_cfg.crls_refs[0],
      tls_cfg.crls.size(),
      sess_man__pt,
      reneg_spec_from_string(cmdl_args.get_property_as_string_default_empty("reneg_mode")),
      &allowed_ecc_curves__rcu8,
      &allowed_sig_algs__rcu8,
      (flea_tls_flag_e) tls_cfg.flags
    )
  );
  std::cout << "handshake done" << std::endl;
  std::flush(std::cout);
  FLEA_CCALL(THR_check_keyb_input());
  for(size_t i = 0; i < cmdl_args.get_property_as_u32_default("do_renegs", 0); i++)
  {
    /*flea_al_u16_t buf_len = sizeof(buf) - 1;
     * flea_err_t retval     = THR_flea_tls_ctx_t__read_app_data(&tls_ctx, buf, &buf_len, flea_read_nonblocking);
     * printf("reading app data prior to renegotiation returned: %04x\n", retval);*/
    std::cout << "renegotiation ...";
    FLEA_CCALL(
      THR_flea_tls_server_ctx_t__renegotiate(
        &tls_ctx,
        &trust_store__t,
        cert_chain,
        cert_chain_len,
        &cipher_suites_ref,
        tls_cfg.rev_chk_mode__e,
        &tls_cfg.crls_refs[0],
        tls_cfg.crls.size()
      )
    );
    std::cout << " ... done." << std::endl;
  }

  if(!is_https_server)
  {
    while(1)
    {
      flea_al_u16_t buf_len = sizeof(buf) - 1;
      FLEA_CCALL(THR_check_keyb_input());
      // flea_err_t retval     = THR_flea_tls_ctx_t__read_app_data(&tls_ctx, buf, &buf_len, flea_read_blocking);
      flea_err_t retval = THR_flea_tls_server_ctx_t__read_app_data(
        &tls_ctx,
        buf,
        &buf_len,
        tls_cfg.read_mode_for_app_data
        );
      if(retval == FLEA_ERR_TIMEOUT_ON_STREAM_READ)
      {
        printf("timeout during read app data\n");
        continue;
      }
      if(retval == FLEA_ERR_TLS_SESSION_CLOSED)
      {
        printf("session closed\n");
        FLEA_THR_RETURN();
      }
      else if(retval)
      {
        printf("received error code from read_app_data: %04x\n", retval);
        FLEA_THROW("rethrowing error from read_app_data", retval);
      }
      FLEA_CCALL(THR_check_keyb_input());
      buf[buf_len] = 0;
      printf("received data (len = %u): %s\n", buf_len, buf);
      printf("read_app_data returned\n");
      FLEA_CCALL(THR_flea_tls_server_ctx_t__send_app_data(&tls_ctx, buf, buf_len));
      usleep(10000);
    }
  }
  else
  {
    flea_al_u16_t buf_len      = sizeof(buf) - 1;
    const char* response_hdr_1 =
      "HTTP/1.1 200 OK\r\nDate: Mon, 27 Jul 2009 12:28:53 GMT\r\nServer: Apache/2.2.14 (Win32)\r\nLast-Modified: Wed, 22 Jul 2009 19:15:56 GMT\r\nContent-Length: 50\r\nContent-Type: text/html\r\nConnection: Closed\r\n\r\n<html><head><body>this is text</body></head></html>";
    FLEA_CCALL(THR_check_keyb_input());
    flea_err_t retval = THR_flea_tls_server_ctx_t__read_app_data(&tls_ctx, buf, &buf_len, flea_read_blocking);
    if(retval == FLEA_ERR_TLS_SESSION_CLOSED)
    {
      FLEA_THR_RETURN();
    }
    else if(retval)
    {
      FLEA_THROW("rethrowing error from read_app_data", retval);
    }
    FLEA_CCALL(THR_check_keyb_input());
    buf[buf_len] = 0;
    FLEA_CCALL(
      THR_flea_tls_server_ctx_t__send_app_data(
        &tls_ctx,
        (const flea_u8_t*) response_hdr_1,
        strlen(response_hdr_1)
      )
    );
  }
  FLEA_THR_FIN_SEC(
    flea_tls_server_ctx_t__dtor(&tls_ctx);
    flea_tls_shared_server_ctx_t__dtor(&shrd_server_ctx__t);
    flea_cert_store_t__dtor(&trust_store__t);
    flea_rw_stream_t__dtor(&rw_stream__t);
  );
} // THR_server_cycle

static flea_err_t THR_flea_start_tls_server(
  property_set_t const     & cmdl_args,
  bool                     is_https_server,
  flea_tls_session_mngr_t* sess_man__pt
)
{
  struct sockaddr_in addr;
  int listen_fd     = -1;// client_fd = 0;
  int one           = 1;
  flea_err_t err__t = FLEA_ERR_FINE;

  FLEA_THR_BEG_FUNC();

  listen_fd = socket(AF_INET, SOCK_STREAM, 0);

  if(listen_fd == -1)
  {
    FLEA_THROW("error opening linux socket", FLEA_ERR_INV_STATE);
  }
  // TODO: maybe change this. It SO_REUSEADDR enables us to reuse the same port
  // even though it is still blocked and waiting for a timeout when not properly
  // closed
  if(setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int)) < 0)
  {
    FLEA_THROW("setsockopt(SO_REUSEADDR) failed", FLEA_ERR_INV_STATE);
  }


  memset(&addr, 0, sizeof(addr));
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_family      = AF_INET;
  addr.sin_port        = htons(cmdl_args.get_property_as_u32("port"));

  if((bind(listen_fd, (struct sockaddr*) &addr, sizeof(addr))) < 0)
  {
    FLEA_THROW("Socket bind failed", FLEA_ERR_FAILED_TO_OPEN_CONNECTION);
  }
  // while(true)
  do
  {
    err__t = THR_server_cycle(cmdl_args, listen_fd, is_https_server, sess_man__pt);
    printf("connection aborted with error %04x\n", err__t);
    if(!err__t)
    {
      FLEA_PRINTF_TEST_OUTP_1_SWITCHED("tls test passed\n");
    }
    if(err__t == (flea_err_t) FLEA_TEST_APP_USER_ABORT)
    {
      std::cout << "user abort requested" << std::endl;
      break;
    }

    /* if(!cmdl_args.have_index("stay"))
     * {
     * break;
     * }*/
  } while(cmdl_args.have_index("stay"));


  FLEA_THR_FIN_SEC_empty(
  );
} // THR_flea_start_tls_server

int flea_start_tls_server(property_set_t const& cmdl_args)
{
  flea_err_t err;

  // int result = 0;

  flea_tls_session_mngr_t sess_man__t;

  FLEA_THR_BEG_FUNC();
  flea_tls_session_mngr_t__INIT(&sess_man__t);
  FLEA_CCALL(THR_flea_tls_session_mngr_t__ctor(&sess_man__t));
  if((err = THR_flea_start_tls_server(cmdl_args, false, &sess_man__t)))
  {
    /** this case currently only captures errors during the opening of the listening
     * socket
     */
    FLEA_PRINTF_TEST_OUTP_2_SWITCHED("error %04x during tls server test\n", err);
    // return 1;
    // result = 1;
    FLEA_THROW("error during tls server test", err);
  }
  else
  {
    // FLEA_PRINTF_TEST_OUTP_1_SWITCHED("tls test passed\n");
    // return 0;
  }
  FLEA_THR_FIN_SEC(
    flea_tls_session_mngr_t__dtor(&sess_man__t);
  );
}

int flea_start_https_server(property_set_t const& cmdl_args)
{
  flea_err_t err;

  while(1)
  {
    if((err = THR_flea_start_tls_server(cmdl_args, true, NULL)))
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
