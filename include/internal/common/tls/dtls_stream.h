/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */
#ifndef _flea_dtls_stream__H_
# define _flea_dtls_stream__H_

# include "internal/common/default.h"
# include "internal/common/tls/tls_hndsh_ctx_fwd.h"
# include "internal/common/tls/tls_rec_prot.h"
# include "internal/common/tls/tls_rec_prot_rdr.h"

# ifdef __cplusplus
extern "C" {
# endif

# define FLEA_DTLS_HANDSH_HDR_FRGM_LEN__OFFS 9

typedef struct
{
  flea_dtls_hdsh_ctx_t*       dtls_hs_ctx__pt;
  flea_recprot_t*             rec_prot__pt;
  flea_tls_rec_prot_rdr_hlp_t rec_prot_rdr_hlp__t;
} flea_dtls_rd_stream_hlp_t;

flea_err_e THR_flea_rw_stream_t__ctor_dtls_rd_strm(
  flea_rw_stream_t*          stream__pt,
  flea_dtls_rd_stream_hlp_t* hlp__pt,
  flea_dtls_hdsh_ctx_t*      dtls_ctx__pt,
  flea_recprot_t*            rec_prot__pt
);


void flea_dtls_rd_strm__expect_ccs(
  flea_dtls_hdsh_ctx_t* dtls_hs_ctx__pt
);


void flea_dtls_rd_strm__expect_hndhs(
  flea_dtls_hdsh_ctx_t* dtls_hs_ctx__pt
);

// TODO:
flea_err_e THR_flea_rw_stream_t__flight_completely_read(
  flea_rw_stream_t* stream__pt
);

# ifdef __cplusplus
}
# endif
#endif /* h-guard */
