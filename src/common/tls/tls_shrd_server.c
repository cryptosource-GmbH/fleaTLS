/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "flea/tls_shrd_server.h"
#include "flea/pkcs8.h"

flea_err_t THR_flea_tls_shared_server_ctx_t__ctor(
  flea_tls_shared_server_ctx_t* shrd_server_ctx__pt,
  flea_ref_cu8_t*               server_key__pt
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_private_key_t__ctor_pkcs8(
      &shrd_server_ctx__pt->private_key__t,
      server_key__pt->data__pcu8,
      server_key__pt->len__dtl
    )
  );
  FLEA_THR_FIN_SEC_empty();
}

void flea_tls_shared_server_ctx_t__dtor(flea_tls_shared_server_ctx_t* shrd_server_ctx__pt)
{
  flea_private_key_t__dtor(&shrd_server_ctx__pt->private_key__t);
}
