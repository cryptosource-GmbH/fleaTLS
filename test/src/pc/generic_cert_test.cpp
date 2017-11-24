#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/error_handling.h"
#include "pc/test_pc.h"
#include "flea/cert_verify.h"
#include <iostream>
/* linux only ==> */
#include <sys/types.h>
#include <dirent.h>
/* <== linux only */

flea_err_t THR_fleatest_iterate_cert_files_and_verify_as_self_signed(
  std::string const &dir_name,
  bool              expect_error
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
      if(FLEA_ERR_FINE != THR_flea_x509_verify_cert_signature(&cert[0], cert.size(), &cert[0], cert.size()))
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
