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
#include "flea/error_handling.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "internal/common/math/mpi.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "self_test.h"


#ifdef FLEA_USE_BUF_DBG_CANARIES

static flea_err_e THR_test_dbg_canaries_write_after_u32()
{
  // this function violates the canary values


  FLEA_DECL_BUF(test_buf_u32, flea_u32_t, 2);
  FLEA_THR_BEG_FUNC();


  FLEA_ALLOC_BUF(test_buf_u32, 2);

  test_buf_u32[2] += 1;


  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(test_buf_u32);
  );
}

static flea_err_e THR_test_dbg_canaries_write_before_u32()
{
  // this function violates the canary values

  FLEA_DECL_BUF(test_buf, flea_u32_t, 5);
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(test_buf, 5);

  test_buf[-1] += 1;


  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(test_buf);

  );
}

static flea_err_e THR_test_dbg_canaries_write_after()
{
  // this function violates the canary values

  FLEA_DECL_BUF(test_buf, flea_u8_t, 5);

  FLEA_DECL_BUF(test_buf_u32, flea_u32_t, 2);
  FLEA_THR_BEG_FUNC();

  FLEA_ALLOC_BUF(test_buf, 5);

  FLEA_ALLOC_BUF(test_buf_u32, 2);

  test_buf[6] += 1;


  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(test_buf_u32);
    FLEA_FREE_BUF(test_buf); // testing also FLEA_FREE_BUF() macro
  );
}

static flea_err_e THR_test_dbg_canaries_write_before()
{
  // this function violates the canary values

  FLEA_DECL_BUF(test_buf, flea_u8_t, 5);
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(test_buf, 5);

  test_buf[-1] += 1;


  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(test_buf);

  );
}

flea_err_e THR_flea_test_dbg_canaries()
{
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_test_dbg_canaries_write_before());
  if(!FLEA_IS_DBG_CANARY_ERROR_SIGNALLED())
  {
    FLEA_THROW("canary overwrite not detected", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CLEAR_DBG_CANARY_ERROR();
  FLEA_CCALL(THR_test_dbg_canaries_write_after());
  if(!FLEA_IS_DBG_CANARY_ERROR_SIGNALLED())
  {
    FLEA_THROW("canary overwrite not detected", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CLEAR_DBG_CANARY_ERROR();
  FLEA_CCALL(THR_test_dbg_canaries_write_before_u32());
  if(!FLEA_IS_DBG_CANARY_ERROR_SIGNALLED())
  {
    FLEA_THROW("canary overwrite not detected", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CLEAR_DBG_CANARY_ERROR();
  FLEA_CCALL(THR_test_dbg_canaries_write_after_u32());
  if(!FLEA_IS_DBG_CANARY_ERROR_SIGNALLED())
  {
    FLEA_THROW("canary overwrite not detected", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CLEAR_DBG_CANARY_ERROR();


  FLEA_THR_FIN_SEC_empty();
}

#else // #ifdef FLEA_USE_BUF_DBG_CANARIES

flea_err_e THR_flea_test_dbg_canaries()
{
  return FLEA_ERR_FINE;
}

#endif // #else of #ifdef FLEA_USE_BUF_DBG_CANARIES
