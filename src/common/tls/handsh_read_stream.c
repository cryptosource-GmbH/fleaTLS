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

#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/error.h"
#include "flea/error_handling.h"
#include "internal/common/tls/handsh_read_stream.h"

#ifdef FLEA_HAVE_TLS

static flea_err_e THR_flea_tls_handsh_read_stream_t__read(
  void*                   custom_obj__pv,
  flea_u8_t*              target_buffer__pu8,
  flea_dtl_t*             nb_bytes_to_read__pdtl,
  flea_stream_read_mode_e rd_mode__e
)
{
  flea_tls_handsh_reader_hlp_t* rdr_hlp__pt = (flea_tls_handsh_reader_hlp_t*) custom_obj__pv;

  FLEA_THR_BEG_FUNC();
  if(rd_mode__e == flea_read_full)
  {
    /* this special case is needed */
    FLEA_CCALL(
      THR_flea_rw_stream_t__read_full(
        rdr_hlp__pt->rec_prot_read_stream__pt,
        target_buffer__pu8,
        *nb_bytes_to_read__pdtl
      )
    );
  }
  else
  {
    FLEA_CCALL(
      THR_flea_rw_stream_t__read(
        rdr_hlp__pt->rec_prot_read_stream__pt,
        target_buffer__pu8,
        nb_bytes_to_read__pdtl,
        rd_mode__e
      )
    );
  }
  if(rdr_hlp__pt->p_hash_ctx__pt)
  {
    FLEA_CCALL(
      THR_flea_tls_prl_hash_ctx_t__update(
        rdr_hlp__pt->p_hash_ctx__pt,
        target_buffer__pu8,
        *nb_bytes_to_read__pdtl
      )
    );
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_handsh_read_stream_t__read */

flea_err_e THR_flea_rw_stream_t__ctor_tls_handsh_reader(
  flea_rw_stream_t*             handsh_read_stream__pt,
  flea_tls_handsh_reader_hlp_t* hlp__pt,
  flea_rw_stream_t*             rec_prot_read_stream__pt,
  flea_u32_t                    msg_len__u32
)
{
  FLEA_THR_BEG_FUNC();
  hlp__pt->rec_prot_read_stream__pt = rec_prot_read_stream__pt;
  hlp__pt->p_hash_ctx__pt = NULL;
  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor(
      handsh_read_stream__pt,
      (void*) hlp__pt,
      NULL,
      NULL,
      THR_flea_tls_handsh_read_stream_t__read,
      NULL,
      NULL,
      msg_len__u32
    )
  );
  FLEA_THR_FIN_SEC_empty();
}

#endif /* ifdef FLEA_HAVE_TLS */
