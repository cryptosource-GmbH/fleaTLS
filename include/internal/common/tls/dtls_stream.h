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
) FLEA_ATTRIB_UNUSED_RESULT;


void flea_dtls_rd_strm__expect_ccs(
  flea_dtls_hdsh_ctx_t* dtls_hs_ctx__pt
);


void flea_dtls_rd_strm__expect_hndhs(
  flea_dtls_hdsh_ctx_t* dtls_hs_ctx__pt
);

// TODO:
flea_err_e THR_flea_rw_stream_t__flight_completely_read(
  flea_rw_stream_t* stream__pt
) FLEA_ATTRIB_UNUSED_RESULT;

# ifdef __cplusplus
}
# endif
#endif /* h-guard */
