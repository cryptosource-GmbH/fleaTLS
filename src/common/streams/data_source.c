/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/data_source.h"
#include "flea/error_handling.h"

static flea_err_t THR_flea_data_source__memory__read(
  void       *custom_obj__pv,
  flea_dtl_t *nb_bytes_to_read__pdtl,
  flea_u8_t  *target_buffer__pu8
)
{
  flea_dtl_t to_read__dtl;
  flea_data_source_mem_help_t *buffer__pt;

  FLEA_THR_BEG_FUNC();
  buffer__pt   = ((flea_data_source_mem_help_t *) custom_obj__pv);
  to_read__dtl = *nb_bytes_to_read__pdtl;
  if(to_read__dtl > buffer__pt->len__dtl)
  {
    to_read__dtl = buffer__pt->len__dtl;
  }
  memcpy(target_buffer__pu8, &buffer__pt->data__pcu8[buffer__pt->offs__dtl], to_read__dtl);
  buffer__pt->offs__dtl  += to_read__dtl;
  buffer__pt->len__dtl   -= to_read__dtl;
  *nb_bytes_to_read__pdtl = to_read__dtl;

  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_flea_data_source__memory__skip(
  void       *custom_obj__pv,
  flea_dtl_t to_skip__dtl
)
{
  flea_data_source_mem_help_t *buffer__pt;

  FLEA_THR_BEG_FUNC();
  buffer__pt = ((flea_data_source_mem_help_t *) custom_obj__pv);
  if(to_skip__dtl > buffer__pt->len__dtl)
  {
    FLEA_THROW("out of data when attemting to skip", FLEA_ERR_FAILED_STREAM_READ);
  }

  buffer__pt->offs__dtl += to_skip__dtl;
  buffer__pt->len__dtl  -= to_skip__dtl;
  FLEA_THR_FIN_SEC_empty();
}

flea_bool_t flea_data_source_t__is_memory_data_source(const flea_data_source_t *source__pt)
{
  return source__pt->read_func__f == THR_flea_data_source__memory__read;
}

const flea_u8_t * flea_data_source_t__get_memory_pointer_to_current(const flea_data_source_t *source__pt)
{
  flea_data_source_mem_help_t *buffer__pt;

  buffer__pt = ((flea_data_source_mem_help_t *) source__pt->custom_obj__pv);
  if(!flea_data_source_t__is_memory_data_source(source__pt))
  {
    return NULL;
  }
  return &buffer__pt->data__pcu8[buffer__pt->offs__dtl];
}

flea_err_t THR_flea_data_source_t__ctor_memory(
  flea_data_source_t          *source__t,
  const flea_u8_t             *source_mem__pcu8,
  flea_dtl_t                  source_mem_len__dtl,
  flea_data_source_mem_help_t *buffer_uninit__pt
)
{
  FLEA_THR_BEG_FUNC();
  buffer_uninit__pt->data__pcu8 = source_mem__pcu8;
  buffer_uninit__pt->offs__dtl  = 0;
  buffer_uninit__pt->len__dtl   = source_mem_len__dtl;
  source__t->custom_obj__pv     = (void *) buffer_uninit__pt;
  source__t->read_func__f       = THR_flea_data_source__memory__read;
  source__t->skip_func__f       = THR_flea_data_source__memory__skip;

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_data_source_t__read(
  flea_data_source_t *source__pt,
  flea_dtl_t         *nb_bytes_to_read__pdtl,
  flea_u8_t          *target_mem__pu8
)
{
  FLEA_THR_BEG_FUNC();
  if(*nb_bytes_to_read__pdtl == 0)
  {
    FLEA_THR_RETURN();
  }
  FLEA_CCALL(source__pt->read_func__f(source__pt->custom_obj__pv, nb_bytes_to_read__pdtl, target_mem__pu8));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_data_source_t__skip(
  flea_data_source_t *source__pt,
  flea_dtl_t         to_skip__dtl
)
{
  return source__pt->skip_func__f(source__pt->custom_obj__pv, to_skip__dtl);
}

flea_err_t THR_flea_data_source_t__read_byte(
  flea_data_source_t *source__pt,
  flea_u8_t          *out_mem__pu8
)
{
  FLEA_THR_BEG_FUNC();
  flea_dtl_t nb_bytes_to_read__dtl = 1;
  FLEA_CCALL(THR_flea_data_source_t__read(source__pt, &nb_bytes_to_read__dtl, out_mem__pu8));
  if(nb_bytes_to_read__dtl != 1)
  {
    // this should not happen
    FLEA_THROW("could not read byte", FLEA_ERR_FAILED_STREAM_READ);
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_data_source_t__force_read(
  flea_data_source_t *source__pt,
  flea_dtl_t         nb_bytes_to_read__dtl,
  flea_u8_t          *target_mem__pu8
)
{
  FLEA_THR_BEG_FUNC();
  while(nb_bytes_to_read__dtl)
  {
    flea_dtl_t do_read__dtl = nb_bytes_to_read__dtl;
    FLEA_CCALL(THR_flea_data_source_t__read(source__pt, &do_read__dtl, target_mem__pu8));
    nb_bytes_to_read__dtl -= do_read__dtl;
    target_mem__pu8       += do_read__dtl;
  }

  FLEA_THR_FIN_SEC_empty();
}

void flea_data_source_t__dtor(flea_data_source_t *source__pt)
{ }
