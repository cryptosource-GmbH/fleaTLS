#include "flea/dtls.h"

#ifdef FLEA_HAVE_DTLS

const flea_dtls_cfg_t flea_dtls_default_cfg__t = {
  .initial_recv_tmo_secs__u8 = 1
};
#endif /* ifdef FLEA_HAVE_DTLS */
