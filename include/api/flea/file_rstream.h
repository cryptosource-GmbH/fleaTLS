/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_file_rstream__H_
# define _flea_file_rstream__H_

# ifdef FLEA_HAVE_STDLIB_FILESYSTEM
#  include "internal/common/default.h"
#  include "flea/error.h"
#  include "flea/types.h"
#  include "flea/rw_stream.h"
#  include <stdio.h>

#  ifdef __cplusplus
extern "C" {
#  endif

typedef struct
{
  FILE* file__pt;
} flea_cfile_read_stream_hlp_t;

/**
 * Create a read stream from a C file pointer. The stream behaves as follows:
 * Any read request in modes flea_read_blocking or flea_read_full that force
 * data to be read beyond the end of the file or the read limit cause
 * FLEA_ERR_STREAM_EOF to be thrown. A non-blocking read with a non-zero number
 * of requested bytes that returns less bytes than requested indicates the end
 * of file.
 *
 * @param read_stream the stream context object to create
 * @param hlp helper object that may be uninitialized
 * @param file_open_for_reading file pointer that has already been opened for
 * reading
 * @param read_limit the maximal number of bytes that can be read from the file.
 * The smaller of this value and the file's actual size is the actually
 * available read size.
 * @param do_close_file_in_dtor if set to FLEA_TRUE, then the
 * file_open_for_reading will be closed when the dtor is called on this read stream object.
 */
flea_err_e THR_flea_rw_stream_t__ctor_cfile_reader(
  flea_rw_stream_t*             read_stream,
  flea_cfile_read_stream_hlp_t* hlp,
  FILE*                         file_open_for_reading,
  flea_dtl_t                    read_limit,
  flea_bool_t                   do_close_file_in_dtor
) FLEA_ATTRIB_UNUSED_RESULT;

#  ifdef __cplusplus
}
#  endif

# endif // ifdef FLEA_HAVE_STDLIB_FILESYSTEM

#endif /* h-guard */
