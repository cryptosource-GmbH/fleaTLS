/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls__H_
#define _flea_tls__H_

#include "internal/common/default.h"
#include "flea/types.h"
// #include "internal/common/tls/tls_common.h"
#include "flea/byte_vec.h"
#include "flea/crl.h"
// #include "internal/common/tls/tls_int.h"
// #include "flea/tls_session_mngr.h"
// #include "flea/tls_client_session.h"

#ifdef FLEA_HAVE_TLS
# ifdef __cplusplus
extern "C" {
# endif

typedef enum
{
  flea_tls_flag__read_timeout_during_handshake = 1
} flea_tls_flag_e;

// defines for max sizes to allocate on the stack
// TODO: use values in algo_config.h?
// #define FLEA_TLS_MAX_RECORD_DATA_SIZE 16384 // 2^14 max record sizeof
// # define FLEA_TLS_MAX_PADDING_SIZE 255 // each byte must hold the padding value => 255 is max

// TODO: split up secure_reneg into ..._cert_fixed, cert_variable
typedef enum
{
  flea_tls_no_reneg,
  flea_tls_only_secure_reneg,
  flea_tls_allow_insecure_reneg
} flea_tls_renegotiation_spec_e;

typedef struct
{
  flea_rev_chk_mode_e    rev_chk_mode__e;
  const flea_byte_vec_t* crl_der__pt;
  flea_u16_t             nb_crls__u16;
} flea_revoc_chk_cfg_t;


# ifdef __cplusplus
}
# endif

#endif // ifdef FLEA_HAVE_TLS

#endif /* h-guard */
