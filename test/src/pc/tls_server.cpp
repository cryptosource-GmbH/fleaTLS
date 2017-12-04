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
#include <memory>

#include "pltf_support/tcpip_stream.h"
#include "pc/test_util.h"
#include "pc/linux_util.h"
#include "flea/tls.h"
#include "flea/tls_server.h"
#include "pc/test_pc.h"
#include "pc/file_based_rw_stream.h"
#include "pltf_support/tcpip_stream.h"
#include "tls_server_certs.h"
#include "flea/array_util.h"
#include "flea/alloc.h"
#include "flea/tls_session_mngr.h"

using namespace std;


#ifdef FLEA_HAVE_TLS

# define CHECK_PTHREAD_ERR(f) if(f) throw test_utils_exceptn_t("error with pthread call");

enum class action_t { none, quit };

std::vector<std::string> stdin_input_lines;
std::string stdin_current_line;

# define FLEA_TEST_APP_USER_ABORT 0x300

static flea_err_t THR_check_user_abort(server_params_t* serv_par__pt)
{
  FLEA_THR_BEG_FUNC();

  CHECK_PTHREAD_ERR(pthread_mutex_lock(&serv_par__pt->mutex));
  bool abort = serv_par__pt->abort__b != 0;
  CHECK_PTHREAD_ERR(pthread_mutex_unlock(&serv_par__pt->mutex));
  if(abort)
  {
    serv_par__pt->write_output_string("server thread received user abort request\n");
    FLEA_THROW("user abort requested", (flea_err_t) FLEA_TEST_APP_USER_ABORT);
  }
  FLEA_THR_FIN_SEC(
  );
}

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

static int unix_tcpip_listen_accept(
  int      listen_fd,
  unsigned read_timeout_ms
)
{
  FLEA_THR_BEG_FUNC();

  struct timeval tv;

  set_timeval_from_millisecs(&tv, read_timeout_ms);
  setsockopt(
    listen_fd,
    SOL_SOCKET,
    SO_RCVTIMEO,
    (struct timeval*) &tv,
    sizeof(struct timeval)
  );

  return accept(listen_fd, (struct sockaddr*) NULL, NULL);


  FLEA_THR_FIN_SEC_empty();
} // THR_unix_tcpip_listen_accept

static flea_err_t THR_flea_tls_server_thread_inner(server_params_t* serv_par__pt)
{
  flea_rw_stream_t rw_stream__t;
  flea_u8_t buf[65000];
  flea_tls_server_ctx_t tls_ctx;

  file_based_rw_stream_ctx_t fb_rws_ctx;


  FLEA_THR_BEG_FUNC();
  flea_tls_server_ctx_t__INIT(&tls_ctx);
  flea_rw_stream_t__INIT(&rw_stream__t);

  if(serv_par__pt->dir_for_file_based_input != "")
  {
    std::string filename_to_be_rpld_by_stdin = serv_par__pt->filename_to_be_rpld_by_stdin;
    if(filename_to_be_rpld_by_stdin == "")
    {
      throw test_utils_exceptn_t("need to provide the property --path_rpl_stdin");
    }
    FLEA_CCALL(
      THR_flea_test_file_based_rw_stream_t__ctor(
        &rw_stream__t,
        &fb_rws_ctx,
        serv_par__pt->dir_for_file_based_input,
        filename_to_be_rpld_by_stdin
      )
    );
  }
  else
  {
    /** socket will be closed by rw_stream_t__dtor **/
    FLEA_CCALL(
      THR_flea_pltfif_tcpip__create_rw_stream_server(
        &rw_stream__t,
        &serv_par__pt->sock_stream_ctx,
        serv_par__pt->sock_fd,
        serv_par__pt->read_timeout
      )
    );
  }

  FLEA_CCALL(
    THR_flea_tls_server_ctx_t__ctor(
      &tls_ctx,
      serv_par__pt->shrd_ctx__pt,
      &rw_stream__t,
      serv_par__pt->cert_chain__pcu8,
      serv_par__pt->cert_chain_len__alu16,
      serv_par__pt->cert_store__pt,
      serv_par__pt->cipher_suites_ref__prcu16,
      serv_par__pt->crl_der__pt,
      serv_par__pt->nb_crls__u16,
      serv_par__pt->sess_mngr__pt,
      serv_par__pt->allowed_ecc_curves__pe,
      serv_par__pt->allowed_ecc_curves_len__alu16,
      serv_par__pt->allowed_sig_algs__pe,
      serv_par__pt->nb_allowed_sig_algs__alu16,
      (flea_tls_flag_e) (serv_par__pt->flags__u32 | ((flea_u32_t) flea_tls_flag__sha1_cert_sigalg__allow))
    )
  );
  // std::cout << "handshake done" << std::endl;
  serv_par__pt->write_output_string("handshake done\n");
  flea_tls_test_tool_print_peer_cert_info(nullptr, &tls_ctx, serv_par__pt);
  // std::flush(std::cout);
  // FLEA_CCALL(THR_check_keyb_input());
  FLEA_CCALL(THR_check_user_abort(serv_par__pt));
  for(size_t i = 0; i < serv_par__pt->nb_renegs_to_exec; i++)
  {
    flea_bool_t reneg_done__b;

    /*flea_al_u16_t buf_len = sizeof(buf) - 1;
     * flea_err_t retval     = THR_flea_tls_ctx_t__read_app_data(&tls_ctx, buf, &buf_len, flea_read_nonblocking);
     * printf("reading app data prior to renegotiation returned: %04x\n", retval);*/
    // std::cout << "renegotiation ...";
    int reneg_allowed = flea_tls_server_ctx_t__is_reneg_allowed(&tls_ctx);
    serv_par__pt->write_output_string(
      "renegotiation exptected to be successfull = " + std::to_string(
        reneg_allowed
      ) + " ...\n"
    );
    FLEA_CCALL(
      THR_flea_tls_server_ctx_t__renegotiate(
        &tls_ctx,
        &reneg_done__b,
        serv_par__pt->cert_store__pt,
        serv_par__pt->cert_chain__pcu8,
        serv_par__pt->cert_chain_len__alu16,
        serv_par__pt->cipher_suites_ref__prcu16,
        serv_par__pt->crl_der__pt,
        serv_par__pt->nb_crls__u16
      )
    );
    if(reneg_done__b)
    {
      serv_par__pt->write_output_string(" ... done.\n");
    }
    else
    {
      serv_par__pt->write_output_string("... was rejected\n");
    }
    // std::cout << "" << std::endl;
  }

  /*if(!is_https_server)
   * {*/
  while(1)
  {
    // flea_al_u16_t buf_len         = sizeof(buf) - 1;
    flea_dtl_t buf_len = serv_par__pt->read_app_data_size >
      sizeof(buf) ? sizeof(buf) : serv_par__pt->read_app_data_size;
    if(buf_len == sizeof(buf))
    {
      buf_len -= 1;
    }
    // FLEA_CCALL(THR_check_keyb_input());
    FLEA_CCALL(THR_check_user_abort(serv_par__pt));
    flea_err_t retval = THR_flea_tls_server_ctx_t__read_app_data(
      &tls_ctx,
      buf,
      &buf_len,
      serv_par__pt->rd_mode__e
      );
    if(retval == FLEA_ERR_TIMEOUT_ON_STREAM_READ)
    {
      serv_par__pt->write_output_string("read_mode = " + std::to_string(serv_par__pt->rd_mode__e) + "\n");
      serv_par__pt->write_output_string("timeout during read app data\n");
      FLEA_THR_RETURN();
    }
    if(retval == FLEA_ERR_TLS_SESSION_CLOSED)
    {
      serv_par__pt->write_output_string("session closed\n");
      FLEA_THR_RETURN();
    }
    else if(retval)
    {
      serv_par__pt->write_output_string("received error code from read_app_data: " + num_to_string_hex(retval) + "\n");
      FLEA_THROW("rethrowing error from read_app_data", retval);
    }
    // FLEA_CCALL(THR_check_keyb_input());
    FLEA_CCALL(THR_check_user_abort(serv_par__pt));
    buf[buf_len] = 0;
    // serv_par__pt->write_output_string("received data len = " + num_to_string(buf_len) + "\n");
    // serv_par__pt->write_output_string("read_app_data returned\n");
    FLEA_CCALL(THR_flea_tls_server_ctx_t__send_app_data(&tls_ctx, buf, buf_len));
    FLEA_CCALL(THR_flea_tls_server_ctx_t__flush_write_app_data(&tls_ctx));
    usleep(10 * 1000);
  }

  FLEA_THR_FIN_SEC(
    flea_tls_server_ctx_t__dtor(&tls_ctx);
    flea_rw_stream_t__dtor(&rw_stream__t);
  );
} // THR_flea_tls_server_thread_inner

static void* flea_tls_server_thread(void* sv__pv)
{
  flea_err_t err__t;
  server_params_t* serv_par__pt = (server_params_t*) sv__pv;

  serv_par__pt->write_output_string("running server thread\n");
  if((err__t = THR_flea_tls_server_thread_inner(serv_par__pt)))
  {
    CHECK_PTHREAD_ERR(pthread_mutex_lock(&serv_par__pt->mutex));
    serv_par__pt->server_error__e = err__t;
    CHECK_PTHREAD_ERR(pthread_mutex_unlock(&serv_par__pt->mutex));
    serv_par__pt->write_output_string("error from server thread: 0x" + num_to_string_hex(err__t));
  }
  CHECK_PTHREAD_ERR(pthread_mutex_lock(&serv_par__pt->mutex));
  serv_par__pt->finished__b = FLEA_TRUE;
  CHECK_PTHREAD_ERR(pthread_mutex_unlock(&serv_par__pt->mutex));
  return NULL;
}

static flea_err_t THR_server_cycle(
  property_set_t const     & cmdl_args,
  int                      listen_fd,
  // bool                     is_https_server,
  flea_tls_session_mngr_t* sess_man__pt,
  std::string const        & dir_for_file_based_input
)
{
  flea_ec_dom_par_id_t* allowed_ecc_curves__pe;
  flea_al_u16_t allowed_ecc_curves_len__alu16;
  flea_tls_sigalg_e* allowed_sig_algs__pe;
  flea_al_u16_t nb_allowed_sig_algs__alu16;
  flea_ref_cu16_t cipher_suites_ref;

  flea_cert_store_t trust_store__t;


  flea_ref_cu8_t cert_chain[10];
  flea_ref_cu8_t server_key__t;
  flea_al_u16_t cert_chain_len = FLEA_NB_ARRAY_ENTRIES(cert_chain);

  tls_test_cfg_t tls_cfg;

  flea_tls_shared_server_ctx_t shrd_server_ctx__t;

  FLEA_THR_BEG_FUNC();
  flea_cert_store_t__INIT(&trust_store__t);
  flea_tls_shared_server_ctx_t__INIT(&shrd_server_ctx__t);

  bool stay = cmdl_args.have_index("stay");
  // flea_u8_t * dbg_leak = (flea_u8_t* )malloc(1);

  const unsigned thr_max = cmdl_args.get_property_as_u32_default("threads", 1);
  listen(listen_fd, thr_max);
  std::vector<std::unique_ptr<server_params_t> > serv_pars;
  bool stop = false;
  if(thr_max > 1)
  {
    stay = true;
  }
  bool create_new_threads = true;
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
  FLEA_CCALL(THR_flea_tls_shared_server_ctx_t__ctor(&shrd_server_ctx__t, &server_key__t));
  if(cert_chain_len == 0)
  {
    throw test_utils_exceptn_t("missing own certificate for tls server");
  }

  cipher_suites_ref.data__pcu16 = &tls_cfg.cipher_suites[0];
  cipher_suites_ref.len__dtl    = tls_cfg.cipher_suites.size();

  allowed_ecc_curves__pe        = &tls_cfg.allowed_curves[0];
  allowed_ecc_curves_len__alu16 = tls_cfg.allowed_curves.size();

  allowed_sig_algs__pe       = &tls_cfg.allowed_sig_algs[0];
  nb_allowed_sig_algs__alu16 = tls_cfg.allowed_sig_algs.size();

  // server_params_t serv_par__t;

  while(1)
  {
    if((serv_pars.size() < thr_max) && !stop && create_new_threads)
    {
      int sock_fd;
      unsigned read_timeout_ms = cmdl_args.get_property_as_u32_default("read_timeout", 1000);

      /*if(0 <= ((sock_fd = unix_tcpip_listen_accept(listen_fd, read_timeout_ms))))
      {*/
      std::cout << "creating threads: max = " << thr_max << ", running currently = " << serv_pars.size() << std::endl;
      server_params_t serv_par__t;
      serv_par__t.shrd_ctx__pt              = &shrd_server_ctx__t;
      serv_par__t.cert_chain__pcu8          = cert_chain;
      serv_par__t.cert_chain_len__alu16     = cert_chain_len;
      serv_par__t.cert_store__pt            = &trust_store__t;
      serv_par__t.cipher_suites_ref__prcu16 = &cipher_suites_ref;
      serv_par__t.crl_der__pt   = &tls_cfg.crls_refs[0];
      serv_par__t.nb_crls__u16  = tls_cfg.crls.size();
      serv_par__t.sess_mngr__pt = sess_man__pt;
      serv_par__t.allowed_ecc_curves__pe        = allowed_ecc_curves__pe;
      serv_par__t.allowed_ecc_curves_len__alu16 = allowed_ecc_curves_len__alu16;
      serv_par__t.allowed_sig_algs__pe       = allowed_sig_algs__pe;
      serv_par__t.nb_allowed_sig_algs__alu16 = nb_allowed_sig_algs__alu16;
      serv_par__t.flags__u32 = tls_cfg.flags;
      // serv_par__t.listen_fd         = listen_fd;
      serv_par__t.read_timeout       = read_timeout_ms;
      serv_par__t.nb_renegs_to_exec  = cmdl_args.get_property_as_u32_default("do_renegs", 0);
      serv_par__t.rd_mode__e         = tls_cfg.read_mode_for_app_data;
      serv_par__t.read_app_data_size = tls_cfg.read_size_for_app_data;
      serv_par__t.abort__b        = FLEA_FALSE;
      serv_par__t.server_error__e = FLEA_ERR_FINE;
      serv_par__t.finished__b     = FLEA_FALSE;
      if(dir_for_file_based_input == "")
      {
        if((0 <= ((sock_fd = unix_tcpip_listen_accept(listen_fd, read_timeout_ms)))))
        {
          serv_par__t.sock_fd = sock_fd;

          serv_par__t.dir_for_file_based_input = dir_for_file_based_input;

          serv_par__t.filename_to_be_rpld_by_stdin = cmdl_args.get_property_as_string_default_empty("path_rpl_stdin");

          if(cmdl_args.have_index("no_session_manager"))
          {
            serv_par__t.sess_mngr__pt = NULL;
          }


          serv_pars.push_back(std::unique_ptr<server_params_t>(new server_params_t(serv_par__t)));
          server_params_t* new_par__pt = serv_pars[serv_pars.size() - 1].get();
          pthread_mutex_init(&new_par__pt->mutex, NULL);
          if(pthread_create(&new_par__pt->thread, NULL, &flea_tls_server_thread, (void*) new_par__pt))
          {
            FLEA_THROW("error creating server thread", FLEA_ERR_FAILED_TEST);
          }
          if(!stay)
          {
            create_new_threads = false;
          }
        }
        else
        {
          std::cout << "flea server: failed listen/accept\n";
        }
      }
    }
    if((stop || !create_new_threads) && !serv_pars.size())
    {
      /* all threads are finished */
      break;
    }
    // pthread_t server_thread;
    bool completed = false;
    while(!completed)
    {
      // this while-loop deletes all finished threads
      bool do_del   = false;
      size_t to_del = 0;
      for(size_t i = 0; i < serv_pars.size(); i++)
      {
        server_params_t & serv_par__t = *serv_pars[i].get();
        CHECK_PTHREAD_ERR(pthread_mutex_lock(&serv_par__t.mutex));
        if(serv_par__t.string_to_print.size())
        {
          std::cout << "thread with idx: " << i << std::endl;
          std::cout << serv_par__t.string_to_print << "\n";
          serv_par__t.string_to_print = "";
        }
        // bool abort = serv_par__t.abort__b != 0;
        bool finished = serv_par__t.finished__b != 0;
        CHECK_PTHREAD_ERR(pthread_mutex_unlock(&serv_par__t.mutex));
        if(finished /*|| abort*/)
        {
          pthread_join(serv_par__t.thread, NULL);
          pthread_mutex_destroy(&serv_par__t.mutex);
          do_del = true;
          to_del = i;
          break;
        }
      }
      if(do_del)
      {
        serv_pars.erase(serv_pars.begin() + to_del);
      }
      else
      {
        completed = true;
      }
    }
    if((dir_for_file_based_input == "") && THR_check_keyb_input())
    {
      stop = true;
      for(size_t i = 0; i < serv_pars.size(); i++)
      {
        server_params_t & serv_par__t = *serv_pars[i].get();
        CHECK_PTHREAD_ERR(pthread_mutex_lock(&serv_par__t.mutex));
        serv_par__t.abort__b = FLEA_TRUE;
        CHECK_PTHREAD_ERR(pthread_mutex_unlock(&serv_par__t.mutex));
      }
    }

    usleep(1000);
  }

  FLEA_THR_FIN_SEC(
    flea_tls_shared_server_ctx_t__dtor(&shrd_server_ctx__t);
    flea_cert_store_t__dtor(&trust_store__t);
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

  std::string dir_for_file_based_input = cmdl_args.get_property_as_string_default_empty("stream_input_file_dir");
  if(dir_for_file_based_input == "")
  {
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
  }

  /*do
   * {*/
  err__t = THR_server_cycle(cmdl_args, listen_fd, /*is_https_server, */ sess_man__pt, dir_for_file_based_input);
  printf("connection aborted with error %04x\n", err__t);
  if(!err__t)
  {
    FLEA_PRINTF_TEST_OUTP_1_SWITCHED("tls test passed\n");
  }
  if(err__t == (flea_err_t) FLEA_TEST_APP_USER_ABORT)
  {
    std::cout << "user abort requested" << std::endl;
    // break;
  }

  /* if(!cmdl_args.have_index("stay"))
   * {
   * break;
   * }*/
  // } while(cmdl_args.have_index("stay"));


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
  FLEA_CCALL(
    THR_flea_tls_session_mngr_t__ctor(
      &sess_man__t,
      cmdl_args.get_property_as_u32_default("session_validity_seconds", 3600)
    )
  );
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
