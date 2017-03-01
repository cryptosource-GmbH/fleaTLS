/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/tls/tls_rec_prot_rdr.h"
#include "internal/common/tls_rec_prot.h"
#include "flea/types.h"
#include "flea/error.h"
#include "flea/error_handling.h"
#include "flea/rw_stream.h"

static flea_err_t THR_flea_rec_prot_rdr_t__read(
  void*                   custom_obj__pv,
  flea_u8_t*              target_buffer__pu8,
  flea_dtl_t*             nb_bytes_to_read__pdtl,
  flea_stream_read_mode_e force_read__b
)
{
  flea_tls_rec_prot_rdr_hlp_t* hlp__pt = (flea_tls_rec_prot_rdr_hlp_t*) custom_obj__pv;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__read_data(
      hlp__pt->rec_prot__pt,
      hlp__pt->record_type__u8,
      target_buffer__pu8,
      nb_bytes_to_read__pdtl
    )
  );
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_rw_stream_t__ctor_rec_prot(
  flea_rw_stream_t*            rec_prot_read_str__pt,
  flea_tls_rec_prot_rdr_hlp_t* hlp__pt,
  flea_tls_rec_prot_t*         rec_prot__pt,
  flea_al_u8_t                 record_type__alu8
)
{
  FLEA_THR_BEG_FUNC();
  hlp__pt->record_type__u8 = record_type__alu8;
  hlp__pt->rec_prot__pt    = rec_prot__pt;
  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor(
      rec_prot_read_str__pt,
      (void*) hlp__pt,
      NULL,
      NULL,
      THR_flea_rec_prot_rdr_t__read,
      NULL,
      NULL,
      0
    )
  );
  FLEA_THR_FIN_SEC_empty();
}
