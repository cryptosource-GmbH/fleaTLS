/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include <string>
#include <cstring>
#include <iostream>
#include <exception>
#include <sstream>
#include "pc/test_util.h"


using namespace std;


#ifdef FLEA_HAVE_TLS
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
