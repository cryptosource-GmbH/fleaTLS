/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_dtls__H_
# define _flea_dtls__H_

# include "internal/common/default.h"

# ifdef __cplusplus
extern "C" {
# endif

typedef struct
{
  flea_u8_t initial_recv_tmo_secs__u8;
} flea_dtls_cfg_t;

extern const flea_dtls_cfg_t flea_dtls_default_cfg__t;

# ifdef __cplusplus
}
# endif
#endif /* h-guard */
