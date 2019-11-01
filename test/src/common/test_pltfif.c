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
#include "internal/common/lib_int.h"
#include "flea/error_handling.h"
#include "flea/lib.h"
#include "self_test.h"

flea_err_e THR_flea_test_gmt_time()
{
  flea_gmt_time_t time__t;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_lib__get_gmt_time_now(&time__t));

  FLEA_THR_FIN_SEC_empty();
}
