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

#ifndef _flea_rw_stream_int__H_
#define _flea_rw_stream_int__H_

#include "flea/rw_stream.h"
#include "internal/common/rw_stream_types.h"

#ifdef __cplusplus
extern "C" {
#endif


flea_err_e THR_flea_rw_stream_t__ctor_detailed(
  flea_rw_stream_t*            stream,
  void*                        custom_obj,
  flea_rw_stream_open_f        open_func,
  flea_rw_stream_close_f       close_func,
  flea_rw_stream_read_f        read_func,
  flea_rw_stream_write_f       write_func,
  flea_rw_stream_flush_write_f flush_write_func,
  flea_u32_t                   read_limit,
  flea_rw_stream_type_e        strm_type
);

flea_rw_stream_type_e flea_rw_stream_t__get_strm_type(const flea_rw_stream_t* rw_stream);


#ifdef __cplusplus
}
#endif

#endif /* h-guard */
