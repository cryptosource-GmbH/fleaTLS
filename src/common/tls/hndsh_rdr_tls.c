/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/tls/hndsh_rdr_tls.h"
#include "internal/common/tls/handsh_reader.h"
#include "internal/common/tls/tls_rec_prot.h"
#include "flea/bin_utils.h"

#ifdef FLEA_HAVE_TLS

static flea_err_e THR_flea_tls_hndsh_rdr__read_handsh_hdr(
  flea_rw_stream_t* stream__pt,
  flea_u8_t*        handsh_type__pu8,
  flea_u32_t*       msg_len__pu32,
  flea_u8_t         handsh_hdr_mbn__pu8[4]
)
{
  FLEA_THR_BEG_FUNC();
  flea_u8_t hdr__au8[FLEA_TLS_HANDSH_HDR_LEN];
  flea_al_u8_t hdr_size__alu8 = sizeof(hdr__au8);


  // get current record content type to force the initial read, or just read the
  // first byte separately
  FLEA_CCALL(THR_flea_rw_stream_t__read_full(stream__pt, hdr__au8, hdr_size__alu8));
  *handsh_type__pu8 = hdr__au8[0];
  *msg_len__pu32    = flea__decode_U24_BE(&hdr__au8[1]);

  /* (((flea_u32_t) hdr__au8[1]) << 16) | (((flea_u32_t) hdr__au8[2]) << 8)
   | (((flea_u32_t) hdr__au8[3]));*/

  if(handsh_hdr_mbn__pu8)
  {
    memcpy(handsh_hdr_mbn__pu8, hdr__au8, sizeof(hdr__au8));
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_tls_hndsh_rdr__ctor_tls(
  flea_tls_handsh_reader_t* handsh_rdr__pt,
  flea_recprot_t*           rec_prot__pt
)
{
  flea_u32_t read_limit__u32;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    // can stay
    THR_flea_rw_stream_t__ctor_rec_prot(
      handsh_rdr__pt->rec_content_rd_stream__pt,
      &handsh_rdr__pt->rec_prot_rdr_hlp__t,
      rec_prot__pt,
      CONTENT_TYPE_HANDSHAKE
    )
  );

  FLEA_CCALL(
    THR_flea_tls_hndsh_rdr__read_handsh_hdr(
      handsh_rdr__pt->rec_content_rd_stream__pt,
      &handsh_rdr__pt->hlp__t.handshake_msg_type__u8,
      &read_limit__u32,
      handsh_rdr__pt->hlp__t.handsh_hdr__au8
    )
  );
  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor_tls_handsh_reader(
      &handsh_rdr__pt->handshake_read_stream__t,
      &handsh_rdr__pt->hlp__t,
      handsh_rdr__pt->rec_content_rd_stream__pt,
      read_limit__u32
    )
  );
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_handsh_reader_t__ctor */

#endif /* ifdef FLEA_HAVE_TLS */
