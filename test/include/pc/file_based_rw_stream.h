/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

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
