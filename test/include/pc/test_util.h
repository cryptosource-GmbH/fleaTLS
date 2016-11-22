/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef __flea_test_util_cpp_H_
#define __flea_test_util_cpp_H_

#include "flea/types.h"
#include "self_test.h"
#include <vector>
#include <string>
#include <map>

typedef enum { dir_entries_with_path, dir_entries_only_leafs } dir_entry_extract_mode_t;

  class test_utils_exceptn_t : public std::exception
  {
  public:
      /**
      * Get the message of the exception.
      */
      const char* what() const throw() { return msg.c_str(); }
      test_utils_exceptn_t(const std::string& m = "Unknown error") { set_msg(m); }
      virtual ~test_utils_exceptn_t() throw() {}
   protected:
      void set_msg(const std::string& m) { msg = "test_utils: " + m; }
   private:
      std::string msg;

  };

class property_set_t : std::map<std::string, std::string>
{
  public:

    typedef enum { value_in_property_str_is_required_e, value_in_property_str_is_not_required_e } property_string_form_t;

    property_set_t(std::string const& filename);
    property_set_t(int argc, const char** argv);
    std::string get_property_as_string(std::string const& index) const;
    flea_u32_t get_property_as_u32(std::string const& index) const;
    flea_bool_t get_as_bool_required(std::string const& index) const 
    { 
      bool *default_val = nullptr;
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
    flea_u32_t get_property_as_u32_default(std::string const& index, flea_u32_t default_val) const;
    std::string const& get_filename() const
    { return m_filename; };

  private:

    void add_index_name_string_with_equation_mark(std::string const& s, property_string_form_t form);
    flea_bool_t get_property_as_bool(std::string const& index, bool *default_ptr) const;
    void ensure_index(std::string const& index) const;
    std::string m_filename;
};
std::vector<flea_u8_t> parse_line(const char* name, flea_u16_t result_size, std::ifstream & input);

std::vector<unsigned char> read_bin_file(std::string const& filename);

bool is_dir_existent(std::string const& dir_name);

std::vector<std::string> get_entries_of_dir(std::string const& dir_name, dir_entry_extract_mode_t extr_mode, std::string const& postfix = "", std::string const& prefix = "");

flea_u32_t string_to_u32bit(std::string const& str);

#endif 
