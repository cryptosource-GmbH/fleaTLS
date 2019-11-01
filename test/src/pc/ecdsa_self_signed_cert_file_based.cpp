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


flea_err_e THR_test_ecdsa_self_signed_certs_file_based()
{
  FLEA_THR_BEG_FUNC();
# if FLEA_ECC_MAX_MOD_BIT_SIZE >= 256
  FLEA_CCALL(THR_fleatest_iterate_cert_files_and_verify_as_self_signed(std::string(test_file_dirs[0]), false));
# endif
  FLEA_THR_FIN_SEC_empty();
}

#endif /* #ifdef FLEA_HAVE_ECDSA */
