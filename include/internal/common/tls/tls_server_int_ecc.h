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

#ifndef _flea_tls_server_int_ecc__H_
# define _flea_tls_server_int_ecc__H_

# include "internal/common/default.h"
# include "flea/tls.h"
# include "flea/privkey.h"
# include "internal/common/tls/tls_ctx_fwd.h"
# include "internal/common/tls/parallel_hash.h"

# ifdef __cplusplus
extern "C" {
# endif


# ifdef FLEA_HAVE_TLS_CS_ECDHE
flea_err_e THR_flea_tls__send_server_kex_ecc(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_tls_prl_hash_ctx_t*  p_hash_ctx__pt,
  flea_privkey_t*           ecdhe_priv_key__pt
) FLEA_ATTRIB_UNUSED_RESULT;

# endif // ifdef FLEA_HAVE_TLS_CS_ECDHE

# ifdef __cplusplus
}
# endif
#endif /* h-guard */
