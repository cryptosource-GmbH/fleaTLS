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
#include "flea/types.h"
#include "flea/error_handling.h"
#include "pc/test_pc.h"
#include "flea/cert_verify.h"
#include <iostream>
#include "flea/x509.h"
/* linux only ==> */
#include <sys/types.h>
#include <dirent.h>
/* <== linux only */


#ifdef FLEA_HAVE_ASYM_SIG
flea_err_e THR_fleatest_iterate_cert_files_and_verify_as_self_signed(
  std::string const          &dir_name,
  bool                       expect_error,
  std::vector<unsigned char> issuer
)
{
  DIR* dir;
  struct dirent* ent;
  unsigned err_count = 0;

  if((dir = opendir(dir_name.c_str())) != NULL)
  {
    /* print all the files and directories within directory */
    while((ent = readdir(dir)) != NULL)
    {
      std::string s(ent->d_name);
      if(s == "." || s == "..")
      {
        continue;
      }
      // printf("%s\n", ent->d_name);

      /*if(s.find("cert") != 0)
      {
        continue;
      }*/
      std::vector<unsigned char> cert = read_bin_file(dir_name + "/" + s);
      // std::cout << "calling cert verify\n";
      const flea_u8_t* issuer_cert = &cert[0];
      flea_u32_t issuer_cert_len   = cert.size();
      if(issuer.size())
      {
        issuer_cert     = &issuer[0];
        issuer_cert_len = issuer.size();
      }
      // if(FLEA_ERR_FINE != THR_flea_x509_verify_cert_signature(&cert[0], cert.size(), &cert[0], cert.size()))
      if(FLEA_ERR_FINE !=
        THR_flea_x509_verify_cert_signature(
          &cert[0],
          cert.size(),
          issuer_cert,
          issuer_cert_len,
          flea_x509_validation_empty_flags
        ))
      {
        if(!expect_error)
        {
          err_count++;
        }
      }
      else
      {
        if(expect_error)
        {
          err_count++;
        }
      }
    }
    closedir(dir);
  }
  else
  {
    /* could not open directory */
    // perror ("");
    FLEA_PRINTF_TEST_OUTP_1_SWITCHED("could not open certificate test data directory\n");
    FLEA_PRINTF_TEST_OUTP_1_SWITCHED("be sure to run unit tests from main folder as build/unit_tests\n");
    return FLEA_ERR_FAILED_TEST;
  }
  if(err_count)
  {
    return FLEA_ERR_FAILED_TEST;
  }
  else
  {
    return FLEA_ERR_FINE;
  }
} // THR_iterate_files

#endif // ifdef FLEA_HAVE_ASYM_SIG
