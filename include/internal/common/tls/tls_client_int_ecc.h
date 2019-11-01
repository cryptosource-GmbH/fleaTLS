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

#ifndef _flea_tls_client_int_ecc__H_
# define _flea_tls_client_int_ecc__H_

# include "internal/common/tls/tls_int.h"

# ifdef __cplusplus
extern "C" {
# endif


# ifdef FLEA_HAVE_TLS


flea_err_e THR_flea_tls__snd_clt_kex_ecdhe(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_tls_prl_hash_ctx_t*  p_hash_ctx__pt
) FLEA_ATTRIB_UNUSED_RESULT;


# endif // ifdef FLEA_HAVE_TLS


# ifdef __cplusplus
}
# endif
#endif /* h-guard */
