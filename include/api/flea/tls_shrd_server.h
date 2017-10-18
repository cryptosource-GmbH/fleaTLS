/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_shrd_server__H_
#define _flea_tls_shrd_server__H_

#include "internal/common/default.h"
#include "flea/tls.h"
#include "flea/privkey.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  flea_private_key_t private_key__t;
} flea_tls_shared_server_ctx_t;

#define flea_tls_shared_server_ctx_t__INIT(__p) do {memset((__p), 0, sizeof(*(__p)));} while(0)

flea_err_t THR_flea_tls_shared_server_ctx_t__ctor(
  flea_tls_shared_server_ctx_t* shrd_server_ctx__pt,
  flea_ref_cu8_t*               server_key__pt
);

void flea_tls_shared_server_ctx_t__dtor(flea_tls_shared_server_ctx_t* shrd_server_ctx__pt);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
