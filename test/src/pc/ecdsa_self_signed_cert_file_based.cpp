/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/types.h"
#include "self_test.h"
#include <string>
#include <vector>
#include <cstring>
#include <fstream>
#include <iostream>
#include "pc/test_util.h"
#include "flea/error_handling.h"
#include "flea/cert_verify.h"

/* linux only ==> */
#include <sys/types.h>
#include <dirent.h>
/* <== linux only */


#if defined FLEA_HAVE_ASYM_SIG && defined FLEA_HAVE_ECDSA && FLEA_ECC_MAX_MOD_BIT_SIZE >= 224

const char *test_file_dirs[] = { "misc/testdata/certs/self_ec_certs_only_for_sig_ver/secp224r1__implict_dp/" };

static flea_err_t THR_iterate_files(std::string const &dir_name)
{
  DIR *dir;
  struct dirent *ent;
  unsigned err_count = 0;

  if((dir = opendir(dir_name.c_str())) != NULL)
  {
    /* print all the files and directories within directory */
    while((ent = readdir(dir)) != NULL)
    {
      // printf ("%s\n", ent->d_name);
      std::string s(ent->d_name);
      if(s.find("cert") != 0)
      {
        continue;
      }
      std::vector<unsigned char> cert = read_bin_file(dir_name + "/" + s);
      if(FLEA_ERR_FINE != THR_flea_x509_verify_cert_signature(&cert[0], cert.size(), &cert[0], cert.size()))
      {
        err_count++;
      }
    }
    closedir(dir);
  }
  else
  {
    /* could not open directory */
    // perror ("");
    FLEA_PRINTF_TEST_OUTP_1_SWITCHED("could not open ecdsa certificate test data directory\n");
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

// TODO: MOVE ALL OF THESE TESTS TO PATH TESTS WITH ONLY A TRUST ANCHOR, AND ADD OPTION IN FLEA TO VERIFY
// TRUST ANCHOR'S SIGNATURE
flea_err_t THR_test_ecdsa_self_signed_certs_file_based()
{
  FLEA_THR_BEG_FUNC();
# if FLEA_ECC_MAX_MOD_BIT_SIZE >= 256
  FLEA_CCALL(THR_iterate_files(std::string(test_file_dirs[0])));
# endif
  FLEA_THR_FIN_SEC_empty();
}

#endif /* #ifdef FLEA_HAVE_ECDSA */
