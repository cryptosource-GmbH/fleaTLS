/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef __flea_test_util_cpp_H_
#define __flea_test_util_cpp_H_

#include "flea/types.h"
#include "flea/cert_store.h"
#include "self_test.h"
#include "flea/tls.h"
#include <vector>
#include <string>
#include <map>
#include <set>

typedef enum { dir_entries_with_path, dir_entries_only_leafs } dir_entry_extract_mode_t;

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
  std::vector<std::vector<flea_u8_t> >     crls;
  flea_rev_chk_mode_e                      rev_chk_mode__e;
  std::vector<flea_byte_vec_t>             crls_refs;
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


std::vector<std::string> tokenize_string(
  std::string const& value,
  char             sep
);

#endif // ifndef __flea_test_util_cpp_H_
