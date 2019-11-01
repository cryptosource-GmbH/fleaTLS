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

#include "self_test.h"
#include "flea/error_handling.h"
#include "pc/test_pc.h"

#ifdef FLEA_HAVE_ASYM_SIG
const char* test_file_dir = {"misc/testdata/certs/fuzzed_certs"};
flea_err_e THR_flea_test_fuzzed_certs()
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_fleatest_iterate_cert_files_and_verify_as_self_signed(test_file_dir, true));
  FLEA_THR_FIN_SEC_empty();
}

#endif // ifdef FLEA_HAVE_ASYM_SIG
