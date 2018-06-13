/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef __flea_test_util_cpp_H_
#define __flea_test_util_cpp_H_

#include "flea/types.h"
#include "flea/cert_store.h"
#include "flea/tls_client.h"
#include "flea/tls_server.h"
#include "self_test.h"
#include "flea/tls.h"
#include <vector>
#include <string>
#include <map>
#include <set>
#include "flea/tls_server.h"
#include "flea_test/tcpip_stream.h"
#include "flea_test/exceptn.h"
#include "flea_test/property_set.h"


#ifdef FLEA_HAVE_TLS
struct server_params_t
{
  flea_privkey_t*                   private_key__pt;
  const flea_ref_cu8_t*             cert_chain__pcu8;
  flea_al_u16_t                     cert_chain_len__alu16;
  const flea_cert_store_t*          cert_store_mbn__pt;
  const flea_tls_cipher_suite_id_t* allowed_cipher_suites__pe;
  flea_al_u16_t                     nb_allowed_cipher_suites__alu16;
  flea_ref_cu8_t*                   crl_der__pt;
  flea_u16_t                        nb_crls__u16;
  flea_tls_session_mngr_t*          sess_mngr__pt;
  flea_ec_dom_par_id_e*             allowed_ecc_curves__pe;
  flea_al_u16_t                     allowed_ecc_curves_len__alu16;
  flea_tls_sigalg_e*                allowed_sig_algs__pe;
  flea_al_u16_t                     nb_allowed_sig_algs__alu16;
  flea_u32_t                        flags__u32;
  flea_u32_t                        read_timeout;
  flea_u32_t                        nb_renegs_to_exec;
  flea_stream_read_mode_e           rd_mode__e;
  size_t                            read_app_data_size;
  linux_socket_stream_ctx_t         sock_stream_ctx;
  int                               sock_fd;
  volatile flea_bool_t              abort__b;
  volatile flea_bool_t              finished__b;
  volatile flea_err_e               server_error__e;
  pthread_mutex_t                   mutex;
  pthread_t                         thread;
  std::string                       string_to_print;
  std::string                       dir_for_file_based_input;
  std::string                       filename_to_be_rpld_by_stdin;
  bool                              is_https_server;
# ifdef FLEA_HAVE_TLS_CS_PSK
  flea_u8_t*                        identity_hint_mbn__pu8;
  flea_u16_t                        identity_hint_len__u16;
  flea_get_psk_cb_f                 get_psk_mbn_cb__f;
  void*                             psk_lookup_ctx_mbn__vp;
# endif // ifdef FLEA_HAVE_TLS_CS_PSK
  void write_output_string(std::string const& s)
  {
    pthread_mutex_lock(&this->mutex);
    this->string_to_print += s;
    pthread_mutex_unlock(&this->mutex);
  }
};

extern std::map<std::string, flea_tls_cipher_suite_id_t> cipher_suite_name_value_map__t;
extern std::map<std::string, flea_ec_dom_par_id_e> curve_id_name_value_map__t;
struct tls_test_cfg_t
{
  std::vector<std::vector<flea_u8_t> >     trusted_certs;
  std::vector<flea_u8_t>                   server_key_vec;
  std::vector<std::vector<unsigned char> > own_certs;
  std::vector<std::vector<unsigned char> > own_ca_chain;
  std::vector<flea_tls_cipher_suite_id_t>  cipher_suites;
  std::vector<flea_ec_dom_par_id_e>        allowed_curves;
  std::vector<flea_tls_sigalg_e>           allowed_sig_algs;
  std::vector<std::vector<flea_u8_t> >     crls;
  std::vector<flea_ref_cu8_t>              crls_refs;
  flea_stream_read_mode_e                  read_mode_for_app_data;
  size_t                                   read_size_for_app_data;
  flea_u32_t                               flags = (flea_tls_flag_e) 0;
  unsigned                                 timeout_secs_during_handshake = 0;
};

// std::string get_comma_seperated_list_of_supported_cipher_suites();

std::string get_comma_seperated_list_of_supported_sig_algs();

template <typename T>
std::string get_comma_seperated_list_of_allowed_values(std::map<std::string, T> const& map);

flea_err_e THR_flea_tls_tool_set_tls_cfg(
  flea_cert_store_t*  trust_store__pt,
  flea_ref_cu8_t*     cert_chain,
  flea_al_u16_t*      cert_chain_len,
  flea_ref_cu8_t*     server_key,
  property_set_t const& cmdl_args,
  tls_test_cfg_t      & cfg
);

void flea_tls_test_tool_print_peer_cert_info(
  flea_tls_clt_ctx_t* client_ctx_mbn__pt,
  flea_tls_srv_ctx_t* server_ctx_mbn__pt,
  server_params_t*    serv_par__pt
);

flea_err_e dummy_process_identity_hint(
  flea_byte_vec_t* psk_vec__pt,
  const flea_u8_t* psk_identity_hint__pu8,
  const flea_u16_t psk_identity_hint_len__u16
);


template <typename T>
std::string get_comma_seperated_list_of_allowed_values(std::map<std::string, T> const& map)
{
  std::string result;
  typename std::map<std::string, T>::const_iterator it;
  for(it = map.begin(); it != map.end(); it++)
  {
    if(result != "")
    {
      result += ",";
    }
    result += it->first;
  }
  return result;
}

flea_u32_t reneg_flag_from_string(std::string const& s);

flea_u32_t min_key_strength_from_string(std::string const& s);

#endif // ifdef FLEA_HAVE_TLS


#endif // ifndef __flea_test_util_cpp_H_
