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
#include <sstream>
#include "pltf_support/tcpip_stream.h"

typedef enum { dir_entries_with_path, dir_entries_only_leafs } dir_entry_extract_mode_t;

struct server_params_t
{
  flea_tls_shared_server_ctx_t* shrd_ctx__pt;
  const flea_ref_cu8_t*         cert_chain__pcu8;
  flea_al_u16_t                 cert_chain_len__alu16;
  const flea_cert_store_t*      cert_store__pt;
  flea_ref_cu16_t*              cipher_suites_ref__prcu16;
  flea_byte_vec_t*              crl_der__pt;
  flea_u16_t                    nb_crls__u16;
  flea_tls_session_mngr_t*      sess_mngr__pt;
  flea_ec_dom_par_id_t*         allowed_ecc_curves__pe;
  flea_al_u16_t                 allowed_ecc_curves_len__alu16;
  flea_tls_sigalg_e*            allowed_sig_algs__pe;
  flea_al_u16_t                 nb_allowed_sig_algs__alu16;
  flea_u16_t                    flags__u16;
  // int                           listen_fd;
  flea_u32_t                    read_timeout;
  flea_u32_t                    nb_renegs_to_exec;
  flea_stream_read_mode_e       rd_mode__e;
  size_t                        read_app_data_size;
  linux_socket_stream_ctx_t     sock_stream_ctx;
  int                           sock_fd;
  volatile flea_bool_t          abort__b;
  volatile flea_bool_t          finished__b;
  volatile flea_err_t           server_error__e;
  pthread_mutex_t               mutex;
  pthread_t                     thread;
  std::string                   string_to_print;
  std::string                   dir_for_file_based_input;
  std::string                   filename_to_be_rpld_by_stdin;
  void                          write_output_string(std::string const& s)
  {
    pthread_mutex_lock(&this->mutex);
    this->string_to_print += s;
    pthread_mutex_unlock(&this->mutex);
  }
};

class test_utils_exceptn_t : public std::exception
{
public:

  /**
   * Get the message of the exception.
   */
  const char* what() const throw() {return msg.c_str();}

  test_utils_exceptn_t(const std::string& m = "Unknown error"){set_msg(m);}

  virtual ~test_utils_exceptn_t() throw() { }

protected:
  void set_msg(const std::string& m){msg = "test_utils: " + m;}

private:
  std::string msg;
};

/*class property_spec_t: public std::pair<std::string, std::string>
 * {
 *
 * };*/

class properties_spec_t : public std::map<std::string, std::string>
{ };


class property_set_t : std::map<std::string, std::string>
{
public:

  typedef enum { value_in_property_str_is_required_e, value_in_property_str_is_not_required_e } property_string_form_t;

  property_set_t(
    std::string const      & filename,
    properties_spec_t const& spec = properties_spec_t()
  );
  property_set_t(
    int                    argc,
    const char**           argv,
    properties_spec_t const& spec = properties_spec_t()
  );
  std::string get_property_as_string(std::string const& index) const;
  std::string get_property_as_string_default_empty(std::string const& index) const;
  flea_u32_t get_property_as_u32(std::string const& index) const;
  flea_bool_t get_as_bool_required(std::string const& index) const
  {
    bool* default_val = nullptr;

    return get_property_as_bool(index, default_val);
  }

  flea_bool_t get_as_bool_default_true(std::string const& index) const
  {
    bool default_val = true;

    return get_property_as_bool(index, &default_val);
  }

  flea_bool_t get_as_bool_default_false(std::string const& index) const
  {
    bool default_val = false;

    return get_property_as_bool(index, &default_val);
  }

  bool have_index(std::string const& index) const;
  flea_u32_t get_property_as_u32_default(
    std::string const& index,
    flea_u32_t       default_val
  ) const;
  std::string const& get_filename() const
  {return m_filename;};

  std::vector<unsigned char> get_bin_file(std::string const& index) const;

  std::vector<std::vector<unsigned char> > get_bin_file_list_property(std::string const& index) const;
private:

  void throw_exception(
    std::string const& text,
    std::string const& property = ""
  ) const;
  void add_index_name_string_with_equation_mark(
    std::string const      & s,
    property_string_form_t form
  );
  flea_bool_t get_property_as_bool(
    std::string const& index,
    bool*            default_ptr
  ) const;
  void ensure_index(std::string const& index) const;
  std::string m_filename;
  properties_spec_t m_spec;
};
std::vector<flea_u8_t> parse_line(
  const char*   name,
  flea_u16_t    result_size,
  std::ifstream & input
);

std::vector<unsigned char> read_bin_file(std::string const& filename);

void write_bin_file(
  std::string const    & filename,
  const unsigned char* data,
  size_t               data_len
);

bool is_dir_existent(std::string const& dir_name);

std::vector<std::string> get_entries_of_dir(
  std::string const        & dir_name,
  dir_entry_extract_mode_t extr_mode,
  std::string const        & postfix = "",
  std::string const        & prefix = ""
);

flea_u32_t string_to_u32bit(std::string const& str);


struct tls_test_cfg_t
{
  std::vector<std::vector<flea_u8_t> >     trusted_certs;
  std::vector<flea_u8_t>                   server_key_vec;
  std::vector<std::vector<unsigned char> > own_certs;
  std::vector<std::vector<unsigned char> > own_ca_chain;
  std::vector<flea_u16_t>                  cipher_suites;
  std::vector<flea_ec_dom_par_id_t>        allowed_curves;
  std::vector<flea_tls_sigalg_e>           allowed_sig_algs;
  std::vector<std::vector<flea_u8_t> >     crls;
  // flea_rev_chk_mode_e                      rev_chk_mode__e;
  std::vector<flea_byte_vec_t>             crls_refs;
  flea_stream_read_mode_e                  read_mode_for_app_data;
  size_t                                   read_size_for_app_data;
  flea_u16_t                               flags = 0;
  unsigned                                 timeout_secs_during_handshake = 0;
};
#ifdef FLEA_HAVE_ASYM_ALGS
flea_err_t THR_flea_tls_tool_set_tls_cfg(
  flea_cert_store_t*  trust_store__pt,
  flea_ref_cu8_t*     cert_chain,
  flea_al_u16_t*      cert_chain_len,
  flea_ref_cu8_t*     server_key,
  property_set_t const& cmdl_args,
  tls_test_cfg_t      & cfg
);
#endif

void flea_tls_test_tool_print_peer_cert_info(
  flea_tls_client_ctx_t* client_ctx_mbn__pt,
  flea_tls_server_ctx_t* server_ctx_mbn__pt,
  server_params_t*       serv_par__pt
);

std::vector<std::string> tokenize_string(
  std::string const& value,
  char             sep
);

std::vector<flea_u8_t> hex_to_bin(std::string const& hex);
std::string bin_to_hex(
  const unsigned char* bin,
  size_t               len
);

flea_u16_t reneg_flag_from_string(std::string const& s);


template <typename t>
inline std::string num_to_string(t num);

template <typename t>
inline std::string num_to_string(t num)
{
  std::stringstream ss;
  std::string str_is;
  ss << num;
  ss >> str_is;
  return str_is;
}

template <>
inline std::string num_to_string<unsigned char>(unsigned char num)
{
  unsigned uns_num = num;

  std::stringstream ss;
  std::string str_is;
  ss << uns_num;
  ss >> str_is;
  return str_is;
}

template <typename t>
inline std::string num_to_string_hex(t num);

template <typename t>
inline std::string num_to_string_hex(t num)
{
  std::stringstream ss;
  std::string str_is;
  ss << std::hex << num;
  ss >> str_is;
  return str_is;
}

template <>
inline std::string num_to_string_hex<unsigned char>(unsigned char num)
{
  unsigned uns_num = num;

  std::stringstream ss;
  std::string str_is;
  ss << std::hex << uns_num;
  ss >> str_is;
  return str_is;
}

std::vector<unsigned char> read_binary_from_std_in();

bool string_ends_with(
  std::string const &fullString,
  std::string const &ending
);

#endif // ifndef __flea_test_util_cpp_H_
