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


#ifndef _flea_handsh_read_stream__H_
#define _flea_handsh_read_stream__H_

#include "flea/types.h"
#include "flea/rw_stream.h"
#include "flea/hash.h"
#include "internal/common/tls/parallel_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef FLEA_HAVE_TLS

typedef struct
{
  flea_rw_stream_t*        rec_prot_read_stream__pt;
  flea_u8_t                handshake_msg_type__u8;
  flea_tls_prl_hash_ctx_t* p_hash_ctx__pt;
  flea_u8_t                handsh_hdr__au8[4];
} flea_tls_handsh_reader_hlp_t;

flea_err_e THR_flea_rw_stream_t__ctor_tls_handsh_reader(
  flea_rw_stream_t*             handsh_read_stream__pt,
  flea_tls_handsh_reader_hlp_t* hlp__pt,
  flea_rw_stream_t*             underlying_read_stream__pt,
  flea_u32_t                    msg_len__u32
);

#endif // ifdef FLEA_HAVE_TLS
#ifdef __cplusplus
}
#endif

#endif /* h-guard */
