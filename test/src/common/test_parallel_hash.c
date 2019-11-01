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
#include "flea/error.h"
#include "flea/alloc.h"
#include "self_test.h"
#include "internal/common/tls/parallel_hash.h"
#include "flea/hash.h"
#include "flea/array_util.h"

#ifdef FLEA_HAVE_TLS

flea_err_e THR_flea_test_parallel_hash()
{
  flea_hash_id_e hash_ids[] = {flea_sha256,

# ifdef FLEA_HAVE_SHA384_512
                               flea_sha384, flea_sha512
# endif
  };
  flea_u8_t hash_ids_len = FLEA_NB_ARRAY_ENTRIES(hash_ids);
  flea_tls_prl_hash_ctx_t p_hash_ctx;

  flea_hash_ctx_t hash_ctx_sha256;
  flea_hash_ctx_t hash_ctx_sha256_copy;


  const flea_u8_t* msg1 = (flea_u8_t*) "test message";
  const flea_u8_t* msg2 = (flea_u8_t*) "another test message";
  flea_u8_t hash_ctx_sha256_out[32];
  flea_u8_t p_hash_ctx_sha256_out[32];

  FLEA_THR_BEG_FUNC();
  flea_tls_prl_hash_ctx_t__INIT(&p_hash_ctx);
  flea_hash_ctx_t__INIT(&hash_ctx_sha256);
  flea_hash_ctx_t__INIT(&hash_ctx_sha256_copy);

  /*
   *  Test one update
   */


  FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&hash_ctx_sha256, flea_sha256));
  FLEA_CCALL(THR_flea_tls_prl_hash_ctx_t__ctor(&p_hash_ctx, hash_ids, hash_ids_len));

  FLEA_CCALL(THR_flea_hash_ctx_t__update(&hash_ctx_sha256, msg1, strlen((const char*) msg1) - 1));
  FLEA_CCALL(THR_flea_tls_prl_hash_ctx_t__update(&p_hash_ctx, msg1, strlen((const char*) msg1) - 1));

  FLEA_CCALL(THR_flea_hash_ctx_t__final(&hash_ctx_sha256, hash_ctx_sha256_out));
  FLEA_CCALL(THR_flea_tls_prl_hash_ctx_t__final(&p_hash_ctx, flea_sha256, FLEA_FALSE, p_hash_ctx_sha256_out));

  if(0 != memcmp(hash_ctx_sha256_out, p_hash_ctx_sha256_out, 32))
  {
    FLEA_THROW("parallel hash not generating valid output on test1", FLEA_ERR_FAILED_TEST);
  }


  /*
   * Test two updates and copy
   */

  flea_hash_ctx_t__dtor(&hash_ctx_sha256);
  // flea_hash_ctx_t__INIT(&hash_ctx_sha256);
  flea_tls_prl_hash_ctx_t__dtor(&p_hash_ctx);
  // flea_tls_prl_hash_ctx_t__INIT(&p_hash_ctx);

  FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&hash_ctx_sha256, flea_sha256));
  FLEA_CCALL(THR_flea_tls_prl_hash_ctx_t__ctor(&p_hash_ctx, hash_ids, hash_ids_len));

  FLEA_CCALL(THR_flea_hash_ctx_t__update(&hash_ctx_sha256, msg1, strlen((const char*) msg1) - 1));
  FLEA_CCALL(THR_flea_tls_prl_hash_ctx_t__update(&p_hash_ctx, msg1, strlen((const char*) msg1) - 1));

  FLEA_CCALL(THR_flea_hash_ctx_t__ctor_copy(&hash_ctx_sha256_copy, &hash_ctx_sha256));

  FLEA_CCALL(THR_flea_hash_ctx_t__final(&hash_ctx_sha256, hash_ctx_sha256_out));
  FLEA_CCALL(THR_flea_tls_prl_hash_ctx_t__final(&p_hash_ctx, flea_sha256, FLEA_TRUE, p_hash_ctx_sha256_out));

  if(0 != memcmp(hash_ctx_sha256_out, p_hash_ctx_sha256_out, 32))
  {
    FLEA_THROW("parallel hash not generating valid output on test2", FLEA_ERR_FAILED_TEST);
  }

  FLEA_CCALL(THR_flea_hash_ctx_t__update(&hash_ctx_sha256_copy, msg2, strlen((const char*) msg2) - 1));
  FLEA_CCALL(THR_flea_tls_prl_hash_ctx_t__update(&p_hash_ctx, msg2, strlen((const char*) msg2) - 1));

  FLEA_CCALL(THR_flea_hash_ctx_t__final(&hash_ctx_sha256_copy, hash_ctx_sha256_out));
  FLEA_CCALL(THR_flea_tls_prl_hash_ctx_t__final(&p_hash_ctx, flea_sha256, FLEA_FALSE, p_hash_ctx_sha256_out));

  if(0 != memcmp(hash_ctx_sha256_out, p_hash_ctx_sha256_out, 32))
  {
    FLEA_THROW("parallel hash not generating valid output on test3", FLEA_ERR_FAILED_TEST);
  }


  FLEA_THR_FIN_SEC(
    flea_hash_ctx_t__dtor(&hash_ctx_sha256);
    flea_hash_ctx_t__dtor(&hash_ctx_sha256_copy);
    flea_tls_prl_hash_ctx_t__dtor(&p_hash_ctx);
  );
} /* THR_flea_test_parallel_hash */

#endif /* ifdef FLEA_HAVE_TLS */
