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

#ifndef _flea_tls_session_mngr__H_
# define _flea_tls_session_mngr__H_

# include "internal/common/default.h"
# include "flea/types.h"
# include "internal/common/tls/tls_session_int_fwd.h"
# include "flea/tls_fwd.h"

# ifdef __cplusplus
extern "C" {
# endif


/**
 * Destroy a TLS session manager object. All tls_server_ctx_t objects that use this session manager instance must be
 * properly destroyed before the TLS session manager is destroyed.
 *
 * @param session_mngr the session manager object to destroy
 */
void flea_tls_session_mngr_t__dtor(flea_tls_session_mngr_t* session_mngr);

/**
 * Init a session manager object.
 *
 * @param sm pointer to the the session manager object
 */
# ifdef FLEA_HEAP_MODE
#  define flea_tls_session_mngr_t__INIT(sm) memset(sm, 0, sizeof(flea_tls_session_mngr_t))
# else
#  ifdef FLEA_HAVE_MUTEX
#   define flea_tls_session_mngr_t__INIT(sm) do {(sm)->is_mutex_init__u8 = 0;} while(0)
#  else
#   define flea_tls_session_mngr_t__INIT(sm)
#  endif
# endif // ifdef FLEA_HEAP_MODE

/**
 * Create a TLS session manager object to be used in a fleaTLS server for
 * supporting session resumption.
 *
 * @param session_mngr the session manager object to create.
 * @param session_validity_period_seconds the number of seconds for which a
 * session remains valid (and thus resumable) after its initial creation.
 */
flea_err_e THR_flea_tls_session_mngr_t__ctor(
  flea_tls_session_mngr_t* session_mngr,
  flea_u32_t               session_validity_period_seconds
) FLEA_ATTRIB_UNUSED_RESULT;


# ifdef __cplusplus
}
# endif
#endif /* h-guard */
