/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/file_rstream.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include <stdio.h>

#ifdef FLEA_HAVE_STDLIB_FILESYSTEM


/*static THR_flea_file_read_stream__open()
{

  FILE* fp = NULL;
  char name_buf__su8 [35];
  FLEA_THR_BEG_FUNC();
  if((int) (sizeof(name_buf__su8) - 1) < snprintf(name_buf__su8, sizeof(name_buf__su8), "%s/%04x", local_slot_dir__cs, slot_id__alu16))
  {
    FLEA_THROW("error encoding the file name", FLEA_ERR_INT_ERR);
  }
  fp = fopen(name_buf__su8, "rb");
  if(!fp)
  {
    FLEA_THROW("error opening file for reading", FLEA_ERR_FILE_READ_FAILED);
  }
}*/

static void flea_file_read_stream__close(void* hlp__pv)
{
  flea_cfile_read_stream_hlp_t* hlp__pt = (flea_cfile_read_stream_hlp_t*) hlp__pv;

  fclose(hlp__pt->file__pt);
}

static flea_err_e THR_flea_file_read_stream__read(
  void*                   hlp__pv,
  flea_u8_t*              target_buffer,
  flea_dtl_t*             nb_bytes_to_read,
  flea_stream_read_mode_e read_mode
)
{
  FLEA_THR_BEG_FUNC();

  flea_cfile_read_stream_hlp_t* hlp__pt = (flea_cfile_read_stream_hlp_t*) hlp__pv;
  flea_dtl_t did_read__dtl = fread(target_buffer, 1, *nb_bytes_to_read, hlp__pt->file__pt);
  if(((read_mode == flea_read_full) && (did_read__dtl != *nb_bytes_to_read)) ||
    ((read_mode == flea_read_blocking) && (*nb_bytes_to_read) && (did_read__dtl == 0)))
  {
    FLEA_THROW("end of file reached", FLEA_ERR_STREAM_EOF);
  }
  *nb_bytes_to_read = did_read__dtl;

  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_rw_stream_t__ctor_cfile_reader(
  flea_rw_stream_t*             read_stream__pt,
  flea_cfile_read_stream_hlp_t* hlp__pt,
  FILE*                         file_open_for_reading__pt,
  flea_dtl_t                    read_limit__dtl,
  flea_bool_t                   do_close_file_in_dtor__b
)
{
  FLEA_THR_BEG_FUNC();
  hlp__pt->file__pt = file_open_for_reading__pt;
  FLEA_CCALL(
    THR_flea_rw_stream_t__ctor(
      read_stream__pt,
      (void*) hlp__pt,
      NULL, /* open_f */
      do_close_file_in_dtor__b ? flea_file_read_stream__close : NULL,
      THR_flea_file_read_stream__read,
      NULL,
      NULL,
      read_limit__dtl
    )
  );

  FLEA_THR_FIN_SEC_empty();
}

#endif /* ifdef FLEA_HAVE_STDLIB_FILESYSTEM */
