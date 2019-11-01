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

#ifndef _flea_file_based_rw_stream__H_
#define _flea_file_based_rw_stream__H_

#include "flea/rw_stream.h"

#include <vector>
#include <string>

/*#ifdef __cplusplus
extern "C" {
#endif*/


struct file_based_rw_stream_ctx_t
{
  std::vector<unsigned char> messages;
  size_t                     read_pos = 0;
};


flea_err_e THR_flea_test_file_based_rw_stream_t__ctor(
  flea_rw_stream_t*           stream__pt,
  file_based_rw_stream_ctx_t* fb_rws_ctx,
  std::string const           & dir_with_input_files,
  std::string const           & filename_to_be_rpld_by_stdin
);


/*#ifdef __cplusplus
}
#endif*/
#endif /* h-guard */
