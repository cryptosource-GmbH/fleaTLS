/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_cert_path__H_
#define _flea_tls_cert_path__H_

#include "flea/types.h"
// #include "internal/common/tls/tls_int.h"
#include "internal/common/tls/tls_ctx_fwd.h"
// #include "flea/tls.h"
#include "internal/common/tls/handsh_reader.h"
#include "flea/cert_store.h"
#include "internal/common/tls_key_usage.h"
#include "internal/common/hostn_ver_int.h"
#include "flea/tls.h"

#ifdef FLEA_HAVE_TLS
# ifdef __cplusplus
extern "C" {
# endif

typedef struct
{
  flea_tls_kex_e                        kex_type__e;
  flea_u8_t                             client_cert_type_mask__u8;
  flea_tls__connection_end_t            validate_server_or_client__e;
  const flea_hostn_validation_params_t* hostn_valid_params__pt;
  // flea_ref_cu16_t*                      allowed_sig_algs_mbn__prcu16;
  flea_tls_sigalg_e*                    allowed_sig_algs_mbn__pe;
  flea_al_u16_t                         nb_allowed_sig_algs__alu16;
} flea_tls_cert_path_params_t;

flea_err_e THR_flea_tls__cert_path_validation(
  flea_tls_ctx_t*                    tls_ctx__pt,
  flea_tls_handsh_reader_t*          hs_rdr__pt,
  const flea_cert_store_t*           trust_store__pt,
  flea_public_key_t*                 pubkey_to_construct__pt,
  flea_tls_cert_path_params_t const* cert_path_params__pct
);


# ifdef __cplusplus
}
# endif
#endif // ifdef FLEA_HAVE_TLS
#endif /* h-guard */
