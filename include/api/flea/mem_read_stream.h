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

#ifndef _flea_mem_read_stream__H_
# define _flea_mem_read_stream__H_

# include "flea/rw_stream.h"

# ifdef __cplusplus
extern "C" {
# endif

/**
 * Helper type for memory-based flea_rw_stream_t type.
 */
typedef struct
{
  const flea_u8_t* data__pcu8;
  flea_dtl_t       len__dtl;
  flea_dtl_t       offs__dtl;
} flea_mem_read_stream_help_t;


flea_err_e THR_flea_rw_stream_t__ctor_memory(
  flea_rw_stream_t*            rw_stream__pt,
  const flea_u8_t*             source_mem__pcu8,
  flea_dtl_t                   source_mem_len__dtl,
  flea_mem_read_stream_help_t* hlp_uninit__pt
) FLEA_ATTRIB_UNUSED_RESULT;

# ifdef __cplusplus
}
# endif

#endif /* h-guard */
