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

#include "flea/types.h"
#include "internal/common/tls/tls_ctx_fwd.h"
#include "internal/common/tls/parallel_hash.h"

#ifndef _flea_tls_hndsh_layer__H_
# define _flea_tls_hndsh_layer__H_


flea_err_e THR_flea_tls__snd_hands_msg_hdr(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_tls_prl_hash_ctx_t*  p_hash_ctx_mbn__pt,
  HandshakeType             type,
  flea_u32_t                content_len__u32
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_tls__snd_hands_msg_content(
  flea_tls_handshake_ctx_t* hs_ctx__pt,
  flea_tls_prl_hash_ctx_t*  p_hash_ctx_mbn__pt,
  const flea_u8_t*          msg_bytes,
  flea_u32_t                msg_bytes_len
) FLEA_ATTRIB_UNUSED_RESULT;

flea_err_e THR_flea_tls__send_change_cipher_spec(
  flea_tls_handshake_ctx_t* hs_ctx__pt
) FLEA_ATTRIB_UNUSED_RESULT;

#endif /* h-guard */
