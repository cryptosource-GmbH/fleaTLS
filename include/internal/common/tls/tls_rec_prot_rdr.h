/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_rec_prot_rdr__H_
#define _flea_tls_rec_prot_rdr__H_

#include "flea/types.h"
#include "flea/rw_stream.h"
#include "internal/common/tls/tls_rec_prot_fwd.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  flea_tls_rec_prot_t* rec_prot__pt;
  flea_u8_t            record_type__u8;
} flea_tls_rec_prot_rdr_hlp_t;


flea_err_e THR_flea_rw_stream_t__ctor_rec_prot(
  flea_rw_stream_t*            rec_prot_read_str__pt,
  flea_tls_rec_prot_rdr_hlp_t* hlp__pt,
  flea_tls_rec_prot_t*         rec_prot__pt,
  flea_al_u8_t                 record_type__alu8
);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
