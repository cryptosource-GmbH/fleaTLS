/* fleaTLS cryptographic library
Copyright (C) 2015-2019 cryptosource GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

#ifndef _flea_property_set__H_
#define _flea_property_set__H_

#include <map>
#include <vector>
#include <string>
#include <sstream>
#include "flea/types.h"
#include "flea/cert_store.h"

typedef enum { dir_entries_with_path, dir_entries_only_leafs } dir_entry_extract_mode_t;

struct properties_spec_entry_t
{
  properties_spec_entry_t(std::string const& desc)
    : description(desc),
    arg_placeholder("")
  { };
  properties_spec_entry_t()
    : description(""),
    arg_placeholder("")
  { };
  properties_spec_entry_t(
    std::string const& desc,
    std::string const& arg
  )
    : description(desc),
    arg_placeholder(arg)
  { };
  properties_spec_entry_t(
    std::string const& desc,
    std::string const& arg,
    std::string const& default_value
  )
    : description(desc),
    arg_placeholder(arg),
    default_value(default_value),
    have_default_value(true)
  { };
  properties_spec_entry_t & set_group(std::string g)
  {
    group = g;
    return *this;
  };
  std::string description;
  std::string arg_placeholder;
  std::string default_value;
  std::string group;
  bool        have_default_value = false;
};

class properties_spec_t : public std::map<std::string, properties_spec_entry_t>
{
public:
  std::string get_help_str() const;

  unsigned have_default_value(std::string const& index) const;

  std::string get_default_value(std::string const& index) const;
private:
  unsigned get_max_key_and_arg_len() const;
  std::multimap<std::string, std::string> get_help_str_map() const;
};


class property_set_t : std::map<std::string, std::string>
{
public:

  typedef enum { value_in_property_str_is_required_e, value_in_property_str_is_not_required_e } property_string_form_t;

  std::string get_help_str() const;
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

  void add_index_whitelist_check(
    std::string const& name,
    std::string const& value
  );

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
std::vector<flea_u8_t> parse_hex_prop_line(
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
  std::string const        & prefix  = ""
);

flea_u32_t string_to_u32bit(std::string const& str);


std::vector<std::string> tokenize_string(
  std::string const& value,
  char             sep,
  bool             crop_ws = false
);

std::vector<flea_u8_t> hex_to_bin(std::string const& hex);
std::string bin_to_hex(
  const unsigned char* bin,
  size_t               len
);


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


#endif /* h-guard */
