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

#include "flea_test/tcpip_stream.h"
#include "pc/test_util.h"
#include "flea_test/linux_util.h"
#include "flea/tls.h"
#include "flea/tls_server.h"
#include "pc/test_pc.h"
#include "pc/file_based_rw_stream.h"
#include "flea_test/tcpip_stream.h"
#include "tls_server_certs.h"
#include "flea/array_util.h"
#include "flea/alloc.h"
#include "flea/tls_session_mngr.h"
#include "flea/pkcs8.h"

using namespace std;


#ifdef FLEA_HAVE_TLS
# ifdef FLEA_HAVE_TLS_SERVER

#  define CHECK_PTHREAD_ERR(f) if(f) throw test_utils_exceptn_t("error with pthread call");

enum class action_t { none, quit };

std::vector<std::string> stdin_input_lines;
std::string stdin_current_line;

#  define FLEA_TEST_APP_USER_ABORT 0x300

static flea_err_e THR_check_user_abort(server_params_t* serv_par__pt)
{
  FLEA_THR_BEG_FUNC();

  CHECK_PTHREAD_ERR(pthread_mutex_lock(&serv_par__pt->mutex));
  bool abort = serv_par__pt->abort__b != 0;
  CHECK_PTHREAD_ERR(pthread_mutex_unlock(&serv_par__pt->mutex));
  if(abort)
  {
    serv_par__pt->write_output_string("server thread received user abort request\n");
    FLEA_THROW("user abort requested", (flea_err_e) FLEA_TEST_APP_USER_ABORT);
  }
  FLEA_THR_FIN_SEC(
  );
}

static flea_err_e THR_check_keyb_input(/*fd_set & keyb_fds*/)
{
  FLEA_THR_BEG_FUNC();
  fcntl(fileno(stdin), F_SETFL, fcntl(fileno(stdin), F_GETFL) | O_NONBLOCK);
  {
    flea_u8_t buf[4096];
    ssize_t did_read = read(STDIN_FILENO, buf, sizeof(buf));

    fcntl(fileno(stdin), F_SETFL, fcntl(fileno(stdin), F_GETFL) & ~O_NONBLOCK);
    if(did_read == -1)
    {
      FLEA_THR_RETURN();
    }
    buf[did_read] = 0;
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
      FLEA_THROW("user abort requested", (flea_err_e) FLEA_TEST_APP_USER_ABORT);
    }
    else
    {
      std::cout << "processing user input = " << s << std::endl;
    }
    stdin_input_lines.erase(stdin_input_lines.begin());
  }
  FLEA_THR_FIN_SEC_empty();
} // THR_check_keyb_input

#  ifdef FLEA_HAVE_TLS_CS_PSK
static flea_err_e dummy_get_psk_cb(
  const void*      psk__pt,
  const flea_u8_t* identity__pu8,
  const flea_u16_t identity_len__u16,
  flea_byte_vec_t* psk_vec__pt
)
{
  FLEA_THR_BEG_FUNC();
  if(flea_memcmp_wsize(
      identity__pu8,
      identity_len__u16,
      ((flea_tls_psk_t*) psk__pt)->identity__pu8,
      ((flea_tls_psk_t*) psk__pt)->identity_len__u16
    ))
  {
    FLEA_THROW("psk identity unknown", FLEA_ERR_TLS_UNKNOWN_PSK_IDENTITY);
  }

  FLEA_CCALL(
    THR_flea_byte_vec_t__set_content(
      psk_vec__pt,
      ((flea_tls_psk_t*) psk__pt)->psk__pu8,
      ((flea_tls_psk_t*) psk__pt)->psk_len__u16
    )
  );


  FLEA_THR_FIN_SEC_empty();
}

#  endif // ifdef FLEA_HAVE_TLS_CS_PSK

static flea_err_e THR_flea_tls_server_thread_inner(server_params_t* serv_par__pt)
{
  flea_rw_stream_t rw_stream__t;
  flea_u8_t buf[65000];
  flea_tls_srv_ctx_t tls_ctx;

  file_based_rw_stream_ctx_t fb_rws_ctx;


  FLEA_THR_BEG_FUNC();
  flea_tls_srv_ctx_t__INIT(&tls_ctx);
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
#  ifdef FLEA_HAVE_TLS_CS_PSK
  if(serv_par__pt->get_psk_mbn_cb__f == NULL)
  {
#  endif
  FLEA_CCALL(
    THR_flea_tls_srv_ctx_t__ctor(
      &tls_ctx,
      &rw_stream__t,
      serv_par__pt->cert_store_mbn__pt,
      serv_par__pt->cert_chain__pcu8,
      serv_par__pt->cert_chain_len__alu16,
      serv_par__pt->private_key__pt,
      serv_par__pt->crl_der__pt,
      serv_par__pt->nb_crls__u16,
      serv_par__pt->allowed_cipher_suites__pe,
      serv_par__pt->nb_allowed_cipher_suites__alu16,
      serv_par__pt->allowed_ecc_curves__pe,
      serv_par__pt->allowed_ecc_curves_len__alu16,
      serv_par__pt->allowed_sig_algs__pe,
      serv_par__pt->nb_allowed_sig_algs__alu16,
      (flea_tls_flag_e) (serv_par__pt->flags__u32 | ((flea_u32_t) flea_tls_flag__sha1_cert_sigalg__allow)),
      serv_par__pt->sess_mngr__pt
    )
  );
#  ifdef FLEA_HAVE_TLS_CS_PSK
} // THR_flea_tls_server_thread_inner

else
{
  FLEA_CCALL(
    THR_flea_tls_srv_ctx_t__ctor_psk(
      &tls_ctx,
      &rw_stream__t,
      serv_par__pt->cert_store_mbn__pt,
      serv_par__pt->cert_chain__pcu8,
      serv_par__pt->cert_chain_len__alu16,
      serv_par__pt->private_key__pt,
      serv_par__pt->crl_der__pt,
      serv_par__pt->nb_crls__u16,
      serv_par__pt->allowed_cipher_suites__pe,
      serv_par__pt->nb_allowed_cipher_suites__alu16,
      serv_par__pt->allowed_ecc_curves__pe,
      serv_par__pt->allowed_ecc_curves_len__alu16,
      serv_par__pt->allowed_sig_algs__pe,
      serv_par__pt->nb_allowed_sig_algs__alu16,
      serv_par__pt->identity_hint_mbn__pu8,
      serv_par__pt->identity_hint_len__u16,
      serv_par__pt->get_psk_mbn_cb__f,
      serv_par__pt->psk_lookup_ctx_mbn__vp,
      (flea_tls_flag_e) (serv_par__pt->flags__u32 | ((flea_u32_t) flea_tls_flag__sha1_cert_sigalg__allow)),
      serv_par__pt->sess_mngr__pt
    )
  );
}
#  endif // ifdef FLEA_HAVE_TLS_CS_PSK
  serv_par__pt->write_output_string("handshake done\n");
  flea_tls_test_tool_print_peer_cert_info(nullptr, &tls_ctx, serv_par__pt);
  FLEA_CCALL(THR_check_user_abort(serv_par__pt));
  for(size_t i = 0; i < serv_par__pt->nb_renegs_to_exec; i++)
  {
    flea_bool_t reneg_done__b;

    int reneg_allowed = flea_tls_srv_ctx_t__is_reneg_allowed(&tls_ctx);
    serv_par__pt->write_output_string(
      "renegotiation exptected to be successfull = " + std::to_string(
        reneg_allowed
      ) + " ...\n"
    );
    FLEA_CCALL(
      THR_flea_tls_srv_ctx_t__renegotiate(
        &tls_ctx,
        &reneg_done__b,
        serv_par__pt->cert_store_mbn__pt,
        serv_par__pt->cert_chain__pcu8,
        serv_par__pt->cert_chain_len__alu16,
        serv_par__pt->private_key__pt,
        serv_par__pt->crl_der__pt,
        serv_par__pt->nb_crls__u16,
        serv_par__pt->allowed_cipher_suites__pe,
        serv_par__pt->nb_allowed_cipher_suites__alu16,
        serv_par__pt->allowed_ecc_curves__pe,
        serv_par__pt->allowed_ecc_curves_len__alu16,
        serv_par__pt->allowed_sig_algs__pe,
        serv_par__pt->nb_allowed_sig_algs__alu16
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
  }

  while(1)
  {
    flea_dtl_t buf_len = serv_par__pt->read_app_data_size >
      sizeof(buf) ? sizeof(buf) : serv_par__pt->read_app_data_size;
    if(buf_len == sizeof(buf))
    {
      buf_len -= 1;
    }
    FLEA_CCALL(THR_check_user_abort(serv_par__pt));
    flea_err_e retval = THR_flea_tls_srv_ctx_t__read_app_data(
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
      if(retval == FLEA_ERR_TLS_REC_CLOSE_NOTIFY)
      {
        serv_par__pt->write_output_string(
          "received close notify (error code " + num_to_string_hex(
            retval
          ) + ") from client, ending connection\n"
        );
      }
      else
      {
        serv_par__pt->write_output_string(
          "received error code from read_app_data: " + num_to_string_hex(retval)
          + "\n"
        );
      }
      FLEA_THROW("rethrowing error from read_app_data", retval);
    }
    FLEA_CCALL(THR_check_user_abort(serv_par__pt));
    buf[buf_len] = 0;
    if(serv_par__pt->is_https_server)
    {
      serv_par__pt->write_output_string("sending http response\n");
      const char* response_hdr_1 =
        "HTTP/1.1 200 OK\r\nDate: Fri, 2 Mar 2018 11:28:53 GMT\r\nServer: Apache/2.2.14 (Win32)\r\nLast-Modified: Wed, 22 Jul 2009 19:15:56 GMT\r\nContent-Length: %u\r\nContent-Type: text/html\r\nConnection: Closed\r\n\r\n";
      const char* content_fixed = "<html><head><body>"
                                  "___________________<br>"
                                  "***** cryptosource<br>"
                                  "*******************<br>"
                                  "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Cryptography. Security.<br>"
                                  "<br>"
                                  "fleaTLS https server<br>"
                                  "</body></head></html>";

      sprintf((char*) buf, response_hdr_1, strlen(content_fixed));

      FLEA_CCALL(THR_flea_tls_srv_ctx_t__send_app_data(&tls_ctx, (const flea_u8_t*) buf, strlen((const char*) buf)));
      FLEA_CCALL(
        THR_flea_tls_srv_ctx_t__send_app_data(
          &tls_ctx,
          (const flea_u8_t*) content_fixed,
          strlen((const char*) content_fixed)
        )
      );
    }
    else if(buf_len)
    {
      serv_par__pt->write_output_string("sending pingback response of length = " + std::to_string(buf_len));
      FLEA_CCALL(THR_flea_tls_srv_ctx_t__send_app_data(&tls_ctx, buf, buf_len));
    }
    FLEA_CCALL(THR_flea_tls_srv_ctx_t__flush_write_app_data(&tls_ctx));
    usleep(10 * 1000);
  }

  FLEA_THR_FIN_SEC(
    flea_tls_srv_ctx_t__dtor(&tls_ctx);
    flea_rw_stream_t__dtor(&rw_stream__t);
  );
} // THR_flea_tls_server_thread_inner

static void* flea_tls_server_thread(void* sv__pv)
{
  flea_err_e err__t;
  server_params_t* serv_par__pt = (server_params_t*) sv__pv;

  serv_par__pt->write_output_string("running server thread\n");
  if((err__t = THR_flea_tls_server_thread_inner(serv_par__pt)))
  {
    CHECK_PTHREAD_ERR(pthread_mutex_lock(&serv_par__pt->mutex));
    serv_par__pt->server_error__e = err__t;
    CHECK_PTHREAD_ERR(pthread_mutex_unlock(&serv_par__pt->mutex));
    serv_par__pt->write_output_string("return code from server thread: 0x" + num_to_string_hex(err__t));
  }
  CHECK_PTHREAD_ERR(pthread_mutex_lock(&serv_par__pt->mutex));
  serv_par__pt->finished__b = FLEA_TRUE;
  CHECK_PTHREAD_ERR(pthread_mutex_unlock(&serv_par__pt->mutex));
  return NULL;
}

static flea_err_e THR_server_cycle(
  property_set_t const     & cmdl_args,
  int                      listen_fd,
  flea_tls_session_mngr_t* sess_man__pt,
  std::string const        & dir_for_file_based_input,
  bool                     is_https_server
)
{
  flea_ec_dom_par_id_e* allowed_ecc_curves__pe;
  flea_al_u16_t allowed_ecc_curves_len__alu16;
  flea_tls_sigalg_e* allowed_sig_algs__pe;
  flea_al_u16_t nb_allowed_sig_algs__alu16;

  flea_cert_store_t trust_store__t;


  flea_ref_cu8_t cert_chain[10];
  flea_ref_cu8_t server_key__t;
  flea_al_u16_t cert_chain_len = FLEA_NB_ARRAY_ENTRIES(cert_chain);

  tls_test_cfg_t tls_cfg;

  flea_privkey_t server_key_obj__t;

#  ifdef FLEA_HAVE_TLS_CS_PSK
  std::vector<flea_u8_t> psk;
  flea_u8_t* psk_identity__pu8;
  flea_u16_t psk_identity_len__u16;
  flea_u8_t* psk_identity_hint__pu8;
  std::string psk_identity_hint_str;
  std::string psk_identity_str;
  flea_tls_psk_t psk__t;
  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(psk_vec__t, FLEA_TLS_PSK_MAX_PSK_LEN);
#  endif // ifdef FLEA_HAVE_TLS_CS_PSK

  FLEA_THR_BEG_FUNC();
  flea_cert_store_t__INIT(&trust_store__t);
  flea_privkey_t__INIT(&server_key_obj__t);

  bool stay = cmdl_args.have_index("stay");

  const unsigned thr_max = cmdl_args.get_property_as_u32("threads");
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
  FLEA_CCALL(THR_flea_privkey_t__ctor_pkcs8(&server_key_obj__t, server_key__t.data__pcu8, server_key__t.len__dtl));
  if(cert_chain_len == 0)
  {
    throw test_utils_exceptn_t("missing own certificate for tls server");
  }

  allowed_ecc_curves__pe        = &tls_cfg.allowed_curves[0];
  allowed_ecc_curves_len__alu16 = tls_cfg.allowed_curves.size();

  allowed_sig_algs__pe       = &tls_cfg.allowed_sig_algs[0];
  nb_allowed_sig_algs__alu16 = tls_cfg.allowed_sig_algs.size();


  while(1)
  {
    if((serv_pars.size() < thr_max) && !stop && create_new_threads)
    {
      int sock_fd = -1;
      unsigned read_timeout_ms = cmdl_args.get_property_as_u32("read_timeout");

      // std::cout << "creating threads: max = " << thr_max << ", running currently = " << serv_pars.size() << std::endl;
      server_params_t serv_par__t;

      /* sharing the server key over different threads like this is possible with fleaTLS */
      serv_par__t.private_key__pt       = &server_key_obj__t;
      serv_par__t.cert_chain__pcu8      = cert_chain;
      serv_par__t.cert_chain_len__alu16 = cert_chain_len;
      serv_par__t.cert_store_mbn__pt    =
        flea_cert_store_t__GET_NB_CERTS(&trust_store__t) ? &trust_store__t : NULL;
      serv_par__t.allowed_cipher_suites__pe       = &tls_cfg.cipher_suites[0];
      serv_par__t.nb_allowed_cipher_suites__alu16 = tls_cfg.cipher_suites.size();
      serv_par__t.crl_der__pt   = &tls_cfg.crls_refs[0];
      serv_par__t.nb_crls__u16  = tls_cfg.crls.size();
      serv_par__t.sess_mngr__pt = sess_man__pt;
      serv_par__t.allowed_ecc_curves__pe        = allowed_ecc_curves__pe;
      serv_par__t.allowed_ecc_curves_len__alu16 = allowed_ecc_curves_len__alu16;
      serv_par__t.allowed_sig_algs__pe       = allowed_sig_algs__pe;
      serv_par__t.nb_allowed_sig_algs__alu16 = nb_allowed_sig_algs__alu16;
      serv_par__t.flags__u32         = tls_cfg.flags;
      serv_par__t.read_timeout       = read_timeout_ms;
      serv_par__t.nb_renegs_to_exec  = cmdl_args.get_property_as_u32("do_renegs");
      serv_par__t.rd_mode__e         = tls_cfg.read_mode_for_app_data;
      serv_par__t.read_app_data_size = tls_cfg.read_size_for_app_data;
      serv_par__t.abort__b        = FLEA_FALSE;
      serv_par__t.server_error__e = FLEA_ERR_FINE;
      serv_par__t.finished__b     = FLEA_FALSE;
      serv_par__t.is_https_server = is_https_server;

#  ifdef FLEA_HAVE_TLS_CS_PSK
      serv_par__t.get_psk_mbn_cb__f = NULL;
#  endif

      if(dir_for_file_based_input == "")
      {
        sock_fd = unix_tcpip_accept(listen_fd, read_timeout_ms);
      }
      if((dir_for_file_based_input != "") || (0 <= sock_fd))
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


        if(cmdl_args.have_index("psk"))
        {
#  ifdef FLEA_HAVE_TLS_CS_PSK
          std::string psk_hex_str = cmdl_args.get_property_as_string("psk");
          psk_identity_str = cmdl_args.get_property_as_string("psk_identity");
          if(psk_hex_str.empty() || psk_identity_str.empty())
          {
            test_utils_exceptn_t("Please use non-empty values for --psk <secret> and --psk_identity <identity>");
          }
          psk = hex_to_bin(psk_hex_str);

          if(cmdl_args.have_index("psk_identity_hint"))
          {
            psk_identity_hint_str  = cmdl_args.get_property_as_string("psk_identity_hint");
            psk_identity_hint__pu8 = (flea_u8_t*) psk_identity_hint_str.c_str();
            new_par__pt->identity_hint_mbn__pu8 = psk_identity_hint__pu8;
            new_par__pt->identity_hint_len__u16 = cmdl_args.get_property_as_string("psk_identity_hint").size();
            FLEA_CCALL(THR_flea_byte_vec_t__set_content(&psk_vec__t, &psk[0], psk.size()));
            FLEA_CCALL(
              dummy_process_identity_hint(
                &psk_vec__t,
                new_par__pt->identity_hint_mbn__pu8,
                new_par__pt->identity_hint_len__u16
              )
            );
            psk = std::vector<flea_u8_t>(psk_vec__t.data__pu8, psk_vec__t.data__pu8 + psk_vec__t.len__dtl);
          }
          else
          {
            new_par__pt->identity_hint_mbn__pu8 = NULL;
            new_par__pt->identity_hint_len__u16 = 0;
          }

          psk_identity__pu8     = (flea_u8_t*) psk_identity_str.c_str();
          psk_identity_len__u16 = psk_identity_str.size();

          psk__t.psk__pu8          = &psk[0];
          psk__t.psk_len__u16      = psk.size();
          psk__t.identity__pu8     = psk_identity__pu8;
          psk__t.identity_len__u16 = psk_identity_len__u16;

          new_par__pt->psk_lookup_ctx_mbn__vp = (void*) &psk__t;
          new_par__pt->get_psk_mbn_cb__f      = &dummy_get_psk_cb;

#  else // ifdef FLEA_HAVE_TLS_CS_PSK
          test_utils_exceptn_t("psk compile switch has to be active for --psk option");
#  endif // ifdef FLEA_HAVE_TLS_CS_PSK
        }

        std::cout << "creating new server thread for connection: max = " << thr_max
                  << ", running currently (including newly created thread): " << serv_pars.size() << std::endl;
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
        // std::cout << "flea server: failed listen/accept\n";
      }
    }
    if((stop || !create_new_threads) && !serv_pars.size())
    {
      /* all threads are finished */
      break;
    }
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
        bool finished = serv_par__t.finished__b != 0;
        CHECK_PTHREAD_ERR(pthread_mutex_unlock(&serv_par__t.mutex));
        if(finished)
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
    // flea_tls_shared_server_ctx_t__dtor(&shrd_server_ctx__t);
    flea_privkey_t__dtor(&server_key_obj__t);
    flea_cert_store_t__dtor(&trust_store__t);
    flea_byte_vec_t__dtor(&psk_vec__t);
  );
} // THR_server_cycle

static flea_err_e THR_flea_start_tls_server(
  property_set_t const     & cmdl_args,
  bool                     is_https_server,
  flea_tls_session_mngr_t* sess_man__pt
)
{
  struct sockaddr_in addr;
  int listen_fd     = -1;// client_fd = 0;
  int one           = 1;
  flea_err_e err__t = FLEA_ERR_FINE;

  FLEA_THR_BEG_FUNC();

  std::string dir_for_file_based_input = cmdl_args.get_property_as_string_default_empty("stream_input_file_dir");
  if(dir_for_file_based_input == "")
  {
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(listen_fd == -1)
    {
      FLEA_THROW("error opening linux socket", FLEA_ERR_INV_STATE);
    }
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
  }

  err__t = THR_server_cycle(cmdl_args, listen_fd, sess_man__pt, dir_for_file_based_input, is_https_server);
  printf("connection aborted with error %04x\n", err__t);
  if(!err__t)
  {
    FLEA_PRINTF_TEST_OUTP_1_SWITCHED("tls test passed\n");
  }
  if(err__t == (flea_err_e) FLEA_TEST_APP_USER_ABORT)
  {
    std::cout << "user abort requested" << std::endl;
  }


  FLEA_THR_FIN_SEC_empty(
  );
} // THR_flea_start_tls_server

int flea_start_tls_server(property_set_t const& cmdl_args)
{
  flea_err_e err;


  flea_tls_session_mngr_t sess_man__t;

  FLEA_THR_BEG_FUNC();
  flea_tls_session_mngr_t__INIT(&sess_man__t);
  FLEA_CCALL(
    THR_flea_tls_session_mngr_t__ctor(
      &sess_man__t,
      cmdl_args.get_property_as_u32("session_validity_seconds")
    )
  );
  if((err = THR_flea_start_tls_server(cmdl_args, cmdl_args.get_as_bool_default_false("http"), &sess_man__t)))
  {
    /** this case currently only captures errors during the opening of the listening
     * socket
     */
    FLEA_PRINTF_TEST_OUTP_2_SWITCHED("error %04x during tls server test\n", err);
    FLEA_THROW("error during tls server test", err);
  }
  else
  {
    // FLEA_PRINTF_TEST_OUTP_1_SWITCHED("tls test passed\n");
  }
  FLEA_THR_FIN_SEC(
    flea_tls_session_mngr_t__dtor(&sess_man__t);
  );
}

int flea_start_https_server(property_set_t const& cmdl_args)
{
  flea_err_e err;

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
  return 0;
}

# endif // ifdef FLEA_HAVE_TLS_SERVER
#endif // ifdef FLEA_HAVE_TLS
