/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_cert_path__H_
#define _flea_tls_cert_path__H_

#include "flea/types.h"
#include "flea/tls.h"
#include "internal/common/tls/handsh_reader.h"
#include "flea/cert_store.h"

#ifdef __cplusplus
extern "C" {
#endif


flea_err_t THR_flea_tls__cert_path_validation(
  flea_tls_ctx_t*          tls_ctx__pt,
  flea_rw_stream_t*        rd_strm__pt,
  const flea_cert_store_t* trust_store__pt,
  flea_public_key_t*       pubkey_to_construct__pt
);


#ifdef __cplusplus
}
#endif
#endif /* h-guard */
