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

#include "internal/common/default.h"
#include <string>
#include <cstring>
#include <iostream>
#include <exception>
#include <sstream>
#include "pc/test_util.h"


using namespace std;


#ifdef FLEA_HAVE_TLS

flea_u32_t min_key_strength_from_string(std::string const& s)
{
  if(s == "0")
  {
    return (flea_u32_t) flea_tls_flag_e::flea_tls_flag__sec__0bit;
  }
  else if(s == "80")
  {
    return (flea_u32_t) flea_tls_flag_e::flea_tls_flag__sec__80bit;
  }
  else if(s == "112")
  {
    return (flea_u32_t) flea_tls_flag_e::flea_tls_flag__sec__112bit;
  }
  else if(s == "128")
  {
    return (flea_u32_t) flea_tls_flag_e::flea_tls_flag__sec__128bit;
  }
  else if(s == "192")
  {
    return (flea_u32_t) flea_tls_flag_e::flea_tls_flag__sec__192bit;
  }
  else if(s == "256")
  {
    return (flea_u32_t) flea_tls_flag_e::flea_tls_flag__sec__256bit;
  }
  else
  {
    throw test_utils_exceptn_t("invalid value '" + s + "' for min_key_length, must be one out of 0,80,112,128,192,256");
  }
}

flea_u32_t reneg_flag_from_string(std::string const& s)
{
  if(s == "no_reneg")
  {
    return flea_tls_flag__reneg_mode__disallow_reneg;
  }
  else if(s == "only_secure_reneg")
  {
    return flea_tls_flag__reneg_mode__allow_secure_reneg;
  }
  else if(s == "allow_insecure_reneg")
  {
    return flea_tls_flag__reneg_mode__allow_insecure_reneg;
  }
  throw test_utils_exceptn_t("invalid value '" + s + "' for argument 'reneg'");
}

#endif // ifdef FLEA_HAVE_TLS
