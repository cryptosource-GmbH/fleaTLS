/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include <string>
#include <cstring>
#include <fstream>
#include <iostream>
#include <exception>
#include <sstream>
#include "pc/test_util.h"

/* linux only ==> */
#include <sys/types.h>
#include <dirent.h>
/* <== linux only */

using namespace std;

std::vector<flea_u8_t> hex_to_bin(std::string const& hex)
{
  std::vector<flea_u8_t> result;
  unsigned cnt = 0;
  flea_u8_t current_char = 0;

  for(char c : hex)
  {
    flea_u8_t offset = 0;
    if(c == ' ')
    {
      continue;
    }
    if(c >= 0x30 && c <= 0x39)
    {
      offset = 0x30;
    }
    else if(c >= 0x41 && c <= 0x46)
    {
      offset = 0x41 - 10;
    }
    else if(c >= 0x61 && c <= 0x66)
    {
      offset = 0x61 - 10;
    }
    else
    {
      throw test_utils_exceptn_t("illegal character in hex string '" + hex + "'");
    }
    current_char |= c - offset;
    if(cnt % 2) // one byte completed
    {
      result.push_back(current_char);
      current_char = 0;
    }
    else
    {
      current_char <<= 4;
    }
    cnt++;
  }
  if(cnt % 2)
  {
    throw test_utils_exceptn_t("odd number of nibles: " + hex);
  }
  return result;
} // hex_to_bin

std::string bin_to_hex(
  const unsigned char* bin,
  size_t               len
)
{
  std::string result;
  for(size_t i = 0; i < len; i++)
  {
    char byte_chars [3] = {0, 0, 0};
    sprintf(byte_chars, "%02x", bin[i]);

    result += std::string(const_cast<const char*>(byte_chars));

    /*if(with_ws)
     * {
     * result += " ";
     * }*/
  }
  return result;
}

std::vector<flea_u8_t> parse_line(
  const char*   name,
  flea_u16_t    result_size,
  std::ifstream & input
)
{
  std::string line_start = std::string(name) + " = ";
  std::string line;
  if(!getline(input, line))
  {
    throw test_utils_exceptn_t("error parsing line from file");
  }
  if(line.find(line_start) != 0)
  {
    std::cout << "line error, name = " << std::string(name) << std::endl;
    throw test_utils_exceptn_t("line error, name = " + std::string(name));
  }
  std::string value = line.substr(line_start.size());
  if(value.size() % 2)
  {
    std::cout << "size of string not multiple of 2" << std::endl;
  }
  std::vector<flea_u8_t> result;
  if(result_size)
  {
    result.resize(result_size);
  }
  else
  {
    result.resize(value.size() / 2);
    result_size = result.size();
  }
  int offset = result_size - (value.size() + 1) / 2;
  if(offset < 0)
  {
    std::cerr << "value size error: name = " << std::string(name) << ", result_size = " << result_size
              << ", value.size() = " << value.size() << ", offset = " << offset << std::endl;
    throw test_utils_exceptn_t("string parsing error in test configuration");
  }
  for(unsigned i = 0; i < value.size(); i++)
  {
    unsigned shift     = i % 2 ? 0 : 4;
    unsigned char byte = 0;
    if(((unsigned) value[i]) >= 0x30 + 0 && ((unsigned) value[i]) <= 0x30 + 9)
    {
      byte = value[i] - 0x30;
    }
    else if(((unsigned) value[i]) >= 0x41 + 0 && ((unsigned) value[i]) <= 0x41 + 6)
    {
      byte = value[i] - 0x41 + 10;
    }
    else if(((unsigned) value[i]) >= 0x61 + 0 && ((unsigned) value[i]) <= 0x61 + 6)
    {
      byte = value[i] - 0x61 + 10;
    }
    else
    {
      std::memset(&result[0], 0, result.size());
      std::cout << "value encoding error: '" << value[i] << "'" << std::endl;
      throw std::exception();
    }
    result[i / 2 + offset] |= byte << shift;
  }
  return result;
} // parse_line

namespace {
  bool string_ends_with(
    std::string const &fullString,
    std::string const &ending
  )
  {
    if(fullString.length() >= ending.length())
    {
      return (0 == fullString.compare(fullString.length() - ending.length(), ending.length(), ending));
    }
    else
    {
      return false;
    }
  }

  std::string remove_ws(std::string const& s)
  {
    std::string result;
    for(char c : s)
    {
      if(c != ' ')
      {
        result.push_back(c);
      }
    }
    return result;
  }

  bool is_string_only_whitespaces(std::string const& str)
  {
    std::string::const_iterator it;
    for(it = str.begin(); it != str.end(); it++)
    {
      if(*it != ' ')
      {
        return false;
      }
    }
    return true;
  }

  std::vector<std::string> read_file_line_wise(std::string const& filename)
  {
    // TODO: MUST HANDLE NON EXISTING FILE
    std::ifstream input(filename);
    if(!input)
    {
      throw test_utils_exceptn_t("could not open file " + filename);
    }
    std::vector<std::string> result;
    for(std::string line; getline(input, line);)
    {
      result.push_back(line);
    }
    return result;
  }

  bool is_string_only_numeric(std::string const& str)
  {
    for(unsigned i = 0; i < str.size(); i++)
    {
      if(str[i] != '0' &&
        str[i] != '1' &&
        str[i] != '2' &&
        str[i] != '3' &&
        str[i] != '4' &&
        str[i] != '5' &&
        str[i] != '6' &&
        str[i] != '7' &&
        str[i] != '8' &&
        str[i] != '9')
      {
        return false;
      }
    }
    return true;
  }

  flea_u32_t string_to_u32bit_unchecked(std::string const& str)
  {
    std::istringstream is(str);
    flea_u32_t result;
    is >> result;
    return result;
  }
}

std::vector<std::string> tokenize_string(
  std::string const& value,
  char             sep
)
{
  size_t pos = 0;

  std::vector<std::string> result;
  while(pos < value.size())
  {
    auto comma_pos = value.find(sep, pos);
    // std::cout << "comma_pos = " << comma_pos << std::endl;
    string file_name;
    if(comma_pos == std::string::npos)
    {
      file_name = value.substr(pos, value.size() - pos);
    }
    else
    {
      file_name = value.substr(pos, comma_pos - pos);
    }
    // std::cout << "file name would be '" << file_name << "'" << std::endl;
    result.push_back(file_name);
    if(comma_pos == std::string::npos)
    {
      break;
    }
    pos = comma_pos + 1;
  }
  return result;
}

flea_u32_t string_to_u32bit(std::string const& str)
{
  if(!is_string_only_numeric(str))
  {
    throw test_utils_exceptn_t("error parsing string '" + str + "' as numeric value");
  }

  return string_to_u32bit_unchecked(str);
}

std::vector<unsigned char> read_bin_file(std::string const& filename)
{
  std::ifstream file(filename.c_str(), ios::in | ios::binary | ios::ate);
  if(!file.is_open())
  {
    throw test_utils_exceptn_t("could not open file '" + filename + "'");
  }
  std::ifstream::pos_type size;
  size = file.tellg();
  std::vector<unsigned char> result(size);
  file.seekg(0, ios::beg);
  file.read((char*) (&result[0]), size);
  file.close();
  return result;
}

void write_bin_file(
  std::string const    & filename,
  const unsigned char* data,
  size_t               data_len
)
{
  fstream myfile(filename, ios::out | ios::binary);

  myfile.write((const char*) &data[0], data_len);
  myfile.close();
}

bool is_dir_existent(std::string const& dir_name)
{
  DIR* dir = opendir(dir_name.c_str());

  if(dir)
  {
    /* Directory exists. */
    closedir(dir);
    return true;
  }
  return false;
}

std::vector<std::string> get_entries_of_dir(
  std::string const        & dir_name,
  dir_entry_extract_mode_t extr_mode,
  std::string const        & postfix,
  std::string const        & prefix
)
{
  std::vector<std::string> result;
  DIR* dir;
  struct dirent* ent;
  if((dir = opendir(dir_name.c_str())) != NULL)
  {
    /* print all the files and directories within directory */
    while((ent = readdir(dir)) != NULL)
    {
      // printf ("%s\n", ent->d_name);
      std::string s(ent->d_name);
      if(s.find(".") == 0)
      {
        continue;
      }
      if((prefix != "") && s.find(prefix) != 0)
      {
        continue;
      }
      if((postfix != "") && !string_ends_with(s, postfix))
      {
        continue;
      }
      std::string prefix = "";
      if(extr_mode == dir_entries_with_path)
      {
        prefix = dir_name + "/";
      }
      result.push_back(prefix + s);
      // std::vector<unsigned char> cert = read_bin_file(dir_name + "/" + s);
      // if(FLEA_ERR_FINE != THR_flea_x509_verify_cert_signature(&cert[0], cert.size(), &cert[0], cert.size()))
    }
    closedir(dir);
  }
  else
  {
    /* could not open directory */
    // perror ("");

    /*FLEA_PRINTF_1_SWITCHTED("could not open test data directory\n");
     * FLEA_PRINTF_1_SWITCHTED("be sure to run unit tests from main folder as build/unit_tests\n");*/
    throw test_utils_exceptn_t(
            "could not open directory " + dir_name + ", be sure to run unit tests from main folder as build/unit_tests"
    );
  }
  return result;
} // get_entries_of_dir

void property_set_t::add_index_name_string_with_equation_mark(
  std::string const      & s,
  property_string_form_t form
)
{
  size_t equ_pos = s.find("=");

  std::string value, name;
  if(equ_pos == std::string::npos)
  {
    if(form == value_in_property_str_is_required_e)
    {
      throw test_utils_exceptn_t("could not parse s '" + s + "' in file " + m_filename);
    }
    name = remove_ws(s);
  }
  else
  {
    name = s.substr(0, equ_pos);
    if(equ_pos == s.size())
    {
      return;
    }
    value = s.substr(equ_pos + 1, s.size());
    name  = remove_ws(name);
    value = remove_ws(value);
  }

  if(m_spec.size() != 0)
  {
    if(m_spec.find(name) == m_spec.end())
    {
      throw_exception(std::string("error with unspecified property"), name);
    }
  }
  (*this)[name] = value;
} // property_set_t::add_index_name_string_with_equation_mark

property_set_t::property_set_t(
  int                    argc,
  const char**           argv,
  properties_spec_t const& spec
)
  : m_spec(spec)
{
  for(unsigned i = 1; i < static_cast<unsigned>(argc); i++)
  {
    std::string arg_string(argv[i]);
    if(arg_string.find("--") != 0)
    {
      throw test_utils_exceptn_t("invalid command line arg " + arg_string);
    }
    arg_string = arg_string.substr(2, arg_string.size() - 2);
    // std::cout << "parse arg = " << arg_string << std::endl;
    add_index_name_string_with_equation_mark(arg_string, value_in_property_str_is_not_required_e);
  }
}

property_set_t::property_set_t(
  std::string const      & filename,
  properties_spec_t const& spec
)
  : m_filename(filename),
  m_spec(spec)
{
  vector<string> lines = read_file_line_wise(filename);
  for(string line: lines)
  {
    if((line.find("#") == 0) || is_string_only_whitespaces(line))
    {
      continue;
    }
    add_index_name_string_with_equation_mark(line, value_in_property_str_is_required_e);

    /*
     * size_t equ_pos = line.find("=");
     * if(equ_pos == std::string::npos)
     * {
     * throw test_utils_exceptn_t("could not parse line '" + line + "' in file " + filename);
     * }
     * string name = line.substr(0, equ_pos);
     * if(equ_pos == line.size())
     * {
     * return;
     * }
     * string value = line.substr(equ_pos + 1, line.size());
     * name = remove_ws(name);
     * value = remove_ws(value);
     * (*this)[name] = value;
     */
  }
}

void property_set_t::throw_exception(
  std::string const& text,
  std::string const& property
) const
{
  if(property == "")
  {
    throw test_utils_exceptn_t("error in file " + m_filename + ": " + text);
  }
  else
  {
    std::string value_inf;
    if(have_index(property))
    {
      value_inf = " with value '" + get_property_as_string(property) + "'";
    }
    throw test_utils_exceptn_t(
            "error in file " + m_filename + " with property '" + property + "'" + value_inf + ": " + text
    );
  }
}

flea_bool_t property_set_t::get_property_as_bool(
  std::string const& index,
  bool*            default_val
) const
{
  if(default_val == nullptr)
  {
    ensure_index(index);
  }
  else if(!have_index(index))
  {
    return *default_val;
  }
  if(find(index)->second == "true")
  {
    return FLEA_TRUE;
  }
  else if(find(index)->second == "false")
  {
    return FLEA_FALSE;
  }

  /*else //if(default_val != nullptr)
   * {
   * //return *default_val;
   * }*/
  else
  {
    // throw test_utils_exceptn_t("could not parse property '" + index + "' as boolean in file " + m_filename);
    throw_exception(std::string("could not parse propery"), index);
    return FLEA_FALSE; // to make compiler happy, never reached
  }
}

std::string property_set_t::get_property_as_string(std::string const& index) const
{
  ensure_index(index);
  return find(index)->second;
}

std::string property_set_t::get_property_as_string_default_empty(std::string const& index) const
{
  if(!have_index(index))
  {
    return std::string("");
  }
  return find(index)->second;
}

bool property_set_t::have_index(std::string const& index) const
{
  return (find(index) != this->end());
}

void property_set_t::ensure_index(std::string const& index) const
{
  if(!have_index(index))
  {
    throw test_utils_exceptn_t("did not find index '" + index + "' in file " + m_filename);
  }
}

flea_u32_t property_set_t::get_property_as_u32_default(
  std::string const& index,
  flea_u32_t       default_val
) const
{
  if(have_index(index))
  {
    return get_property_as_u32(index);
  }
  return default_val;
}

flea_u32_t property_set_t::get_property_as_u32(std::string const& index) const
{
  ensure_index(index);
  string value = find(index)->second;
  if(!value.size())
  {
    throw test_utils_exceptn_t(
            std::string("value of property '") + index + std::string(
              "' in file "
            ) + m_filename + " is not numeric as expected"
    );
  }
  return string_to_u32bit(value);
}

std::vector<unsigned char> property_set_t::get_bin_file(std::string const& index) const
{
  string value = get_property_as_string(index);

  return read_bin_file(value);
}

std::vector<std::vector<unsigned char> > property_set_t::get_bin_file_list_property(std::string const& index) const
{
  std::vector<std::vector<unsigned char> > result;
  if(!have_index(index))
  {
    return result;
  }

  string value = get_property_as_string(index);

  std::vector<string> strings = tokenize_string(value, ',');
  for(auto s : strings)
  {
    result.push_back(read_bin_file(s));
  }
  return result;
}

flea_u16_t reneg_flag_from_string(std::string const& s)
{
  if(s == "no_reneg")
  {
    return FLEA_TLS_CFG_FLAG__RENEG_MODE__DISALLOW_RENEG;
  }
  else if(s == "only_secure_reneg" || s == "")
  {
    return FLEA_TLS_CFG_FLAG__RENEG_MODE__ALLOW_SECURE_RENEG;
  }
  else if(s == "allow_insecure_reneg")
  {
    return FLEA_TLS_CFG_FLAG__RENEG_MODE__ALLOW_INSECURE_RENEG;
  }
  throw test_utils_exceptn_t("invalid value '" + s + "' for argument 'reneg'");
}

// std::vector<unsigned char> get_file_binary
