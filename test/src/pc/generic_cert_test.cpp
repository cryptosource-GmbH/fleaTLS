/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

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
