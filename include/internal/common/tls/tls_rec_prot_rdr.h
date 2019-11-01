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

#ifndef _flea_tls_rec_prot_rdr__H_
# define _flea_tls_rec_prot_rdr__H_

# include "flea/types.h"
# include "flea/rw_stream.h"
# include "internal/common/tls/tls_rec_prot_fwd.h"

# ifdef __cplusplus
extern "C" {
# endif

typedef struct
{
  flea_recprot_t* rec_prot__pt;
  flea_u8_t       record_type__u8;
} flea_tls_rec_prot_rdr_hlp_t;


flea_err_e THR_flea_rw_stream_t__ctor_rec_prot(
  flea_rw_stream_t*            rec_prot_read_str__pt,
  flea_tls_rec_prot_rdr_hlp_t* hlp__pt,
  flea_recprot_t*              rec_prot__pt,
  flea_al_u8_t                 record_type__alu8
) FLEA_ATTRIB_UNUSED_RESULT;

# ifdef __cplusplus
}
# endif

#endif /* h-guard */
