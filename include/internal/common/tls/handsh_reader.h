/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_handsh_reader__H_
# define _flea_handsh_reader__H_

# include "internal/common/default.h"
# include "flea/types.h"
# include "flea/rw_stream.h"
# include "internal/common/tls/handsh_read_stream.h"
# include "internal/common/tls/tls_rec_prot_rdr.h"
# include "internal/common/tls/tls_rec_prot_fwd.h"
# include "internal/common/tls/parallel_hash.h"
# include "internal/common/tls/tls_hndsh_ctx.h"

# ifdef __cplusplus
extern "C" {
# endif

# ifdef FLEA_HAVE_TLS

typedef struct
{
  flea_rw_stream_t             handshake_read_stream__t;
  flea_tls_handsh_reader_hlp_t hlp__t;

  flea_tls_rec_prot_rdr_hlp_t  rec_prot_rdr_hlp__t;
  flea_rw_stream_t*            rec_content_rd_stream__pt;
  flea_rw_stream_t             rec_prot_rd_stream__t;   // TODO: RELOCATE SO THAT THIS CAN BE MERGED WITH dtls_assmbld_rd_stream__t WHICH IS CURRENTLY PART OF THE DTLS_HS_ASSMB_STATE. place in hs-ctx
  flea_u8_t                    is_dtls__b;
  flea_u8_t                    rec_content_type__u8;
#  ifdef FLEA_HAVE_DTLS
  flea_dtls_hdsh_ctx_t*        dtls_hs_ctx__pt;
#  endif
} flea_tls_handsh_reader_t;

#  define flea_tls_handsh_reader_t__INIT(__p) FLEA_MEMSET(__p, 0, sizeof(*(__p)))

#  define flea_tls_handsh_reader_t__dtor(__p)

flea_err_e THR_flea_tls_handsh_reader_t__ctor(
  flea_tls_handsh_reader_t* handsh_rdr__pt,
  flea_recprot_t*           rec_prot__pt,
  flea_bool_t is_dtls__b
#  ifdef                    FLEA_HAVE_DTLS
  ,
  flea_dtls_hdsh_ctx_t*     dtls_hs_ctx__pt,
  flea_tls_rec_cont_type_e  cont_type__e
#  endif
);

flea_u32_t flea_tls_handsh_reader_t__get_msg_rem_len(flea_tls_handsh_reader_t* handsh_rdr__pt);

/**
 * Discard the remaining message ( read it off the stream ).
 */
flea_err_e THR_flea_tls_handsh_reader_t__skip_rem_msg(flea_tls_handsh_reader_t* handsh_rdr__pt);

flea_rw_stream_t* flea_tls_handsh_reader_t__get_read_stream(flea_tls_handsh_reader_t* handsh_rdr__pt);

flea_al_u8_t flea_tls_handsh_reader_t__get_handsh_msg_type(flea_tls_handsh_reader_t* handsh_rdr__pt);

flea_err_e THR_flea_tls_handsh_reader_t__set_hash_ctx(
  flea_tls_handsh_reader_t* handsh_rdr__pt,
  flea_tls_prl_hash_ctx_t*  p_hash_ctx__pt
);

void flea_tls_handsh_reader_t__unset_hasher(flea_tls_handsh_reader_t* handsh_rdr__pt);

# endif // ifdef FLEA_HAVE_TLS

# ifdef __cplusplus
}
# endif

#endif /* h-guard */
