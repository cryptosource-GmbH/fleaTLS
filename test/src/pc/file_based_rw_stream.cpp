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

#include "pc/file_based_rw_stream.h"
#include "flea/error_handling.h"
#include "pc/test_util.h"
#include <iostream>
#include <algorithm>

static flea_err_e file_based_stream_read__f(
  void*                   custom_obj__pv,
  flea_u8_t*              target_buffer__pu8,
  flea_dtl_t*             nb_bytes_to_read__pdtl,
  flea_stream_read_mode_e rd_mode__e
)
{
  file_based_rw_stream_ctx_t* fbs = (file_based_rw_stream_ctx_t*) custom_obj__pv;
  size_t request_len = *nb_bytes_to_read__pdtl;

  /* cyclic reading of the provided data: */
  std::cout << "reading " << request_len << " bytes from file-based stream\n";
  while(request_len)
  {
    size_t left_in_messages = fbs->messages.size() - fbs->read_pos;
    flea_dtl_t to_go        = request_len < left_in_messages ? request_len : left_in_messages;
    memcpy(target_buffer__pu8, &fbs->messages[fbs->read_pos], to_go);
    fbs->read_pos      += to_go;
    target_buffer__pu8 += to_go;
    request_len        -= to_go;
    if(fbs->read_pos >= fbs->messages.size())
    {
      fbs->read_pos = 0;
    }
  }
  return FLEA_ERR_FINE;
}

static flea_err_e output_ignore__f(
  void*,
  const flea_u8_t*,
  flea_dtl_t
)
{
  return FLEA_ERR_FINE;
}

flea_err_e THR_flea_test_file_based_rw_stream_t__ctor(
  flea_rw_stream_t*           stream__pt,
  file_based_rw_stream_ctx_t* fb_rws_ctx,
  std::string const           & dir_with_input_files,
  std::string const           & filename_to_be_rpld_by_stdin
)
{
  FLEA_THR_BEG_FUNC();


  std::vector<std::string> dir_ents = get_entries_of_dir(dir_with_input_files, dir_entries_with_path);
  std::sort(dir_ents.begin(), dir_ents.end());
  std::vector<unsigned char> bin;
  for(std::string e : dir_ents)
  {
    if(!string_ends_with(e, filename_to_be_rpld_by_stdin))
    {
      std::cout << "reading bin file = " << e << "\n";
      // read the file
      bin = read_bin_file(e);
    }
    else
    {
      // read from stdin
      bin = read_binary_from_std_in();
    }
    fb_rws_ctx->messages.insert(fb_rws_ctx->messages.end(), bin.begin(), bin.end());
  }

  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor(
      stream__pt,
      static_cast<void*>(fb_rws_ctx),
      nullptr,
      nullptr,
      file_based_stream_read__f,
      output_ignore__f,
      nullptr,
      0
    )
  );


  FLEA_THR_FIN_SEC_empty();
} // THR_flea_test_file_based_rw_stream_t__ctor
