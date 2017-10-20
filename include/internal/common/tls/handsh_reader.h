#ifndef _flea_handsh_reader__H_
#define _flea_handsh_reader__H_

#include "flea/types.h"
#include "flea/rw_stream.h"
#include "internal/common/tls/handsh_read_stream.h"
#include "internal/common/tls/tls_rec_prot_rdr.h"
#include "internal/common/tls/tls_rec_prot_fwd.h"
#include "internal/common/tls/parallel_hash.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct
{
  flea_rw_stream_t             handshake_read_stream__t;
  flea_tls_handsh_reader_hlp_t hlp__t;

  flea_tls_rec_prot_rdr_hlp_t  rec_prot_rdr_hlp__t;
  flea_rw_stream_t             rec_prot_rd_stream__t;
} flea_tls_handsh_reader_t;

#define flea_tls_handsh_reader_t__INIT_VALUE {.handshake_read_stream__t.custom_obj__pv = NULL}
#define flea_tls_handsh_reader_t__INIT(__p)

#define flea_tls_handsh_reader_t__dtor(__p)

flea_err_t THR_flea_tls_handsh_reader_t__ctor(
  flea_tls_handsh_reader_t* handsh_rdr__pt,
  flea_tls_rec_prot_t*      rec_prot__pt
);

flea_err_t THR_flea_tls__read_handsh_hdr(
  flea_rw_stream_t* stream__pt,
  flea_u8_t*        handsh_type__pu8,
  flea_u32_t*       msg_len__pu32,
  flea_u8_t         handsh_hdr_mbn__pu8[4]
);

flea_u32_t flea_tls_handsh_reader_t__get_msg_rem_len(flea_tls_handsh_reader_t* handsh_rdr__pt);

flea_rw_stream_t* flea_tls_handsh_reader_t__get_read_stream(flea_tls_handsh_reader_t* handsh_rdr__pt);

flea_al_u8_t flea_tls_handsh_reader_t__get_handsh_msg_type(flea_tls_handsh_reader_t* handsh_rdr__pt);

flea_err_t THR_flea_tls_handsh_reader_t__set_hash_ctx(
  flea_tls_handsh_reader_t*     handsh_rdr__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt
);

void flea_tls_handsh_reader_t__unset_hasher(flea_tls_handsh_reader_t* handsh_rdr__pt);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
