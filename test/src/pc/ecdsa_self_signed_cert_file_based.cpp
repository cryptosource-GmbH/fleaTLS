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
#include "pc/test_pc.h"
#include "flea/error_handling.h"
#include "flea/cert_verify.h"


#if defined FLEA_HAVE_ASYM_SIG && defined FLEA_HAVE_ECDSA && FLEA_ECC_MAX_MOD_BIT_SIZE >= 224

const char* test_file_dirs[] = {"misc/testdata/certs/self_ec_certs_only_for_sig_ver/secp224r1__implict_dp/"};


flea_err_t THR_test_ecdsa_self_signed_certs_file_based()
{
  FLEA_THR_BEG_FUNC();
# if FLEA_ECC_MAX_MOD_BIT_SIZE >= 256
  FLEA_CCALL(THR_fleatest_iterate_cert_files_and_verify_as_self_signed(std::string(test_file_dirs[0]), false));
# endif
  FLEA_THR_FIN_SEC_empty();
}

#endif /* #ifdef FLEA_HAVE_ECDSA */
