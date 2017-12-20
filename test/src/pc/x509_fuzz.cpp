#include "self_test.h"
#include "flea/error_handling.h"
#include "pc/test_pc.h"

const char* test_file_dir = {"misc/testdata/certs/fuzzed_certs"};
flea_err_e THR_flea_test_fuzzed_certs()
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_fleatest_iterate_cert_files_and_verify_as_self_signed(test_file_dir, true));
  FLEA_THR_FIN_SEC_empty();
}
