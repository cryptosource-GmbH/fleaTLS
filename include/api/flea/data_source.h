/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_data_source__H_
#define _flea_data_source__H_

#include "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif
  

typedef struct 
{
  const flea_u8_t* data__pcu8;
  flea_dtl_t len__dtl;  
  flea_dtl_t offs__dtl;
} flea_data_source_mem_help_t;

  typedef flea_err_t (*flea_data_source_read_f)(void *custom_obj__pv, flea_dtl_t *nb_bytes_to_read__pdtl, flea_u8_t* target_buffer__pu8);
  typedef flea_err_t (*flea_data_source_skip_f)(void *custom_obj__pv, flea_dtl_t to_skip__dtl);
  typedef struct
  {
    void * custom_obj__pv;
    flea_data_source_read_f read_func__f;
    flea_data_source_skip_f skip_func__f;
    
  } flea_data_source_t;

#define flea_data_source_t__INIT_VALUE {.custom_obj__pv = 0 }
#define flea_data_source_t__INIT(__p) do {} while(0)

flea_bool_t flea_data_source_t__is_memory_data_source(const flea_data_source_t* source__pt);

const flea_u8_t* flea_data_source_t__get_memory_pointer_to_current(const flea_data_source_t* source__pt);

flea_err_t THR_flea_data_source_t__read(flea_data_source_t* source__t, flea_dtl_t* nb_bytes_to_read__pdtl, flea_u8_t* target_mem__pu8);

flea_err_t THR_flea_data_source_t__read_byte(flea_data_source_t* source__pt, flea_u8_t* out_mem__pu8);

/**
 * Blocks until requested number of bytes is read
 */
flea_err_t THR_flea_data_source_t__force_read(flea_data_source_t* source__pt, flea_dtl_t nb_bytes_to_read__dtl, flea_u8_t* target_mem__pu8);

flea_err_t THR_flea_data_source_t__skip(flea_data_source_t* source__pt, flea_dtl_t to_skip__dtl);

// TODO: use al_u8 for byte!
flea_err_t THR_flea_data_source_t__ctor_memory(flea_data_source_t* source__t, const flea_u8_t* source_mem__pcu8, flea_dtl_t source_mem_len__dtl, flea_data_source_mem_help_t* buffer_uninit__pt);

void flea_data_source_t__dtor(flea_data_source_t *source__pt);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
