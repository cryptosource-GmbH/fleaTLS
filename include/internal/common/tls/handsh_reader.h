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

#ifndef _flea_handsh_reader__H_
# define _flea_handsh_reader__H_

# include "flea/types.h"
# include "flea/rw_stream.h"
# include "internal/common/tls/handsh_read_stream.h"
# include "internal/common/tls/tls_rec_prot_rdr.h"
# include "internal/common/tls/tls_rec_prot_fwd.h"
# include "internal/common/tls/parallel_hash.h"

# ifdef __cplusplus
extern "C" {
# endif

# ifdef FLEA_HAVE_TLS

typedef struct
{
  flea_rw_stream_t             handshake_read_stream__t;
  flea_tls_handsh_reader_hlp_t hlp__t;

  flea_tls_rec_prot_rdr_hlp_t  rec_prot_rdr_hlp__t;
  flea_rw_stream_t             rec_prot_rd_stream__t;
} flea_tls_handsh_reader_t;

#  define flea_tls_handsh_reader_t__INIT(__p) FLEA_MEMSET(__p, 0, sizeof(*(__p)))

#  define flea_tls_handsh_reader_t__dtor(__p)

flea_err_e THR_flea_tls_handsh_reader_t__ctor(
  flea_tls_handsh_reader_t* handsh_rdr__pt,
  flea_recprot_t*           rec_prot__pt
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_tls__read_handsh_hdr(
  flea_rw_stream_t* stream__pt,
  flea_u8_t*        handsh_type__pu8,
  flea_u32_t*       msg_len__pu32,
  flea_u8_t         handsh_hdr_mbn__pu8[4]
) FLEA_ATTRIB_UNUSED_RESULT;

flea_u32_t flea_tls_handsh_reader_t__get_msg_rem_len(flea_tls_handsh_reader_t* handsh_rdr__pt);

flea_rw_stream_t* flea_tls_handsh_reader_t__get_read_stream(flea_tls_handsh_reader_t* handsh_rdr__pt);

flea_al_u8_t flea_tls_handsh_reader_t__get_handsh_msg_type(flea_tls_handsh_reader_t* handsh_rdr__pt);

flea_err_e THR_flea_tls_handsh_reader_t__set_hash_ctx(
  flea_tls_handsh_reader_t* handsh_rdr__pt,
  flea_tls_prl_hash_ctx_t*  p_hash_ctx__pt
) FLEA_ATTRIB_UNUSED_RESULT;

void flea_tls_handsh_reader_t__unset_hasher(flea_tls_handsh_reader_t* handsh_rdr__pt);

# endif // ifdef FLEA_HAVE_TLS

# ifdef __cplusplus
}
# endif

#endif /* h-guard */
