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
#include "flea/alloc.h"
#include "flea/types.h"

#ifdef FLEA_USE_BUF_DBG_CANARIES
static flea_u8_t flea_dbg_canaries_flag = 0;

void flea_dbg_canaries__signal_canary_error()
{
  flea_dbg_canaries_flag = 1;
}

void flea_dbg_canaries__clear_canary_error()
{
  flea_dbg_canaries_flag = 0;
}

int flea_dbg_canaries__is_canary_error_set()
{
  return flea_dbg_canaries_flag != 0;
}

#endif /* ifdef FLEA_USE_BUF_DBG_CANARIES */
