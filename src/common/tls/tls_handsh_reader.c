/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/tls/handsh_reader.h"
#include "flea/types.h"
#include "flea/error.h"
#include "flea/error_handling.h"
#include "flea/rw_stream.h"
#include "internal/common/tls/tls_rec_prot.h"
#include "flea/bin_utils.h"

#ifdef FLEA_HAVE_TLS
flea_err_e THR_flea_tls__read_handsh_hdr(
  flea_tls_handsh_reader_t* handsh_rdr__pt,
  flea_rw_stream_t*         stream__pt,
  flea_u8_t*                handsh_type__pu8,
  flea_u32_t*               msg_len__pu32,
  flea_u8_t                 handsh_hdr_mbn__pu8[4]
)
{
  FLEA_THR_BEG_FUNC();
  flea_u8_t hdr__au8[FLEA_XTLS_MAX_HANDSH_HDR_LEN];
  flea_al_u8_t hdr_size__alu8 = FLEA_TLS_HANDSH_HDR_LEN;
  if(handsh_rdr__pt->is_dtls__b)
  {
    hdr_size__alu8 = FLEA_DTLS_HANDSH_HDR_LEN;
  }

  /*HandshakeType msg_type;
     uint24 length;
     uint16 message_seq;                               // New field
     uint24 fragment_offset;                           // New field
     uint24 fragment_length;                           // New field
     */

  // get current record content type to force the initial read, or just read the
  // first byte separately
  FLEA_CCALL(THR_flea_rw_stream_t__read_full(stream__pt, hdr__au8, hdr_size__alu8));
  *handsh_type__pu8 = hdr__au8[0];
  *msg_len__pu32    = flea__decode_U24_BE(&hdr__au8[1]);

  /* (((flea_u32_t) hdr__au8[1]) << 16) | (((flea_u32_t) hdr__au8[2]) << 8)
   | (((flea_u32_t) hdr__au8[3]));*/
# ifdef FLEA_HAVE_DTLS
  if(handsh_rdr__pt->is_dtls__b)
  {
    handsh_rdr__pt->hlp__t.msg_seq__u16      = flea__decode_U16_BE(&hdr__au8[4]);
    handsh_rdr__pt->hlp__t.fragm_offset__u32 = flea__decode_U24_BE(&hdr__au8[6]);
    handsh_rdr__pt->hlp__t.fragm_length__u32 = flea__decode_U24_BE(&hdr__au8[9]);
  }
# endif /* ifdef FLEA_HAVE_DTLS */

  if(handsh_hdr_mbn__pu8)
  {
    memcpy(handsh_hdr_mbn__pu8, hdr__au8, sizeof(hdr__au8));
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__read_handsh_hdr */

flea_err_e THR_flea_tls_handsh_reader_t__ctor(
  flea_tls_handsh_reader_t* handsh_rdr__pt,
  flea_recprot_t*           rec_prot__pt,
  flea_bool_t               is_dtls__b
)
{
  flea_u32_t read_limit__u32;

  handsh_rdr__pt->is_dtls__b = is_dtls__b;
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    // can stay
    THR_flea_rw_stream_t__ctor_rec_prot(
      &handsh_rdr__pt->rec_prot_rd_stream__t,
      &handsh_rdr__pt->rec_prot_rdr_hlp__t,
      rec_prot__pt,
      CONTENT_TYPE_HANDSHAKE
    )
  );

  FLEA_CCALL(
    THR_flea_tls__read_handsh_hdr(
      handsh_rdr__pt,
      &handsh_rdr__pt->rec_prot_rd_stream__t,
      &handsh_rdr__pt->hlp__t.handshake_msg_type__u8,
      &read_limit__u32,
      handsh_rdr__pt->hlp__t.handsh_hdr__au8
    )
  );
  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor_tls_handsh_reader(
      &handsh_rdr__pt->handshake_read_stream__t,
      &handsh_rdr__pt->hlp__t,
      &handsh_rdr__pt->rec_prot_rd_stream__t,
      read_limit__u32
    )
  );
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_handsh_reader_t__ctor */

flea_u32_t flea_tls_handsh_reader_t__get_msg_rem_len(flea_tls_handsh_reader_t* handsh_rdr__pt)
{
  return handsh_rdr__pt->handshake_read_stream__t.read_rem_len__u32;
}

flea_rw_stream_t* flea_tls_handsh_reader_t__get_read_stream(flea_tls_handsh_reader_t* handsh_rdr__pt)
{
  // TODO: THIS STREAM MUST WORK ON THE ASSEMBLY BUFFER
  // => Implement a new stream (not right away)
  return &handsh_rdr__pt->handshake_read_stream__t;
}

flea_al_u8_t flea_tls_handsh_reader_t__get_handsh_msg_type(flea_tls_handsh_reader_t* handsh_rdr__pt)
{
  return handsh_rdr__pt->hlp__t.handshake_msg_type__u8;
}

flea_err_e THR_flea_tls_handsh_reader_t__set_hash_ctx(
  flea_tls_handsh_reader_t* handsh_rdr__pt,
  flea_tls_prl_hash_ctx_t*  p_hash_ctx__pt
)
{
  FLEA_THR_BEG_FUNC();
  handsh_rdr__pt->hlp__t.p_hash_ctx__pt = p_hash_ctx__pt;
  // TODO: ADAPT LENGTH 4 FOR DTLS
  FLEA_CCALL(THR_flea_tls_prl_hash_ctx_t__update(p_hash_ctx__pt, handsh_rdr__pt->hlp__t.handsh_hdr__au8, 4));
  FLEA_THR_FIN_SEC_empty();
}

void flea_tls_handsh_reader_t__unset_hasher(flea_tls_handsh_reader_t* handsh_rdr__pt)
{
  handsh_rdr__pt->hlp__t.p_hash_ctx__pt = NULL;
}

#endif /* ifdef FLEA_HAVE_TLS */
