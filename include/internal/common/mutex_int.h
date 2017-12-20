/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_mutex_int__H_
#define _flea_mutex_int__H_

#include "internal/common/default.h"

#ifdef FLEA_HAVE_MUTEX

# include "flea/mutex.h"
# include "flea/types.h"

void flea_mutex__set_funcs(const flea_mutex_func_set_t* funcs__pt);

flea_err_e THR_flea_mutex__init(FLEA_MUTEX_TYPE* mutex__pt);

void flea_mutex__destroy(FLEA_MUTEX_TYPE* mutex__pt);

flea_err_e THR_flea_mutex__lock(FLEA_MUTEX_TYPE* mutex__pt);

flea_err_e THR_flea_mutex__unlock(FLEA_MUTEX_TYPE* mutex__pt);

void flea_mutex__set_funcs(const flea_mutex_func_set_t* funcs__pt);

# define FLEA_DECL_MUTEX(__mutex_name)        FLEA_MUTEX_TYPE __mutex_name

# define FLEA_DECL_STATIC_MUTEX(__mutex_name) static FLEA_DECL_MUTEX(__mutex_name)

# define THR_FLEA_MUTEX_INIT(__mutex_ptr)     THR_flea_mutex__init(__mutex_ptr)

# define FLEA_MUTEX_DESTR(__mutex_ptr)        flea_mutex__destroy(__mutex_ptr)

# define THR_FLEA_MUTEX_LOCK(__mutex_ptr)     THR_flea_mutex__lock(__mutex_ptr)

# define THR_FLEA_MUTEX_UNLOCK(__mutex_ptr)   THR_flea_mutex__unlock(__mutex_ptr)


#else // ifdef FLEA_HAVE_MUTEX

# define FLEA_DECL_MUTEX(__mutex_name)
# define FLEA_DECL_STATIC_MUTEX(__mutex_name)

# define THR_FLEA_MUTEX_INIT(__mutex_ptr) FLEA_ERR_FINE

# define FLEA_MUTEX_DESTR(__mutex_ptr)

# define THR_FLEA_MUTEX_LOCK(__mutex_ptr)   FLEA_ERR_FINE

# define THR_FLEA_MUTEX_UNLOCK(__mutex_ptr) FLEA_ERR_FINE

#endif // ifdef FLEA_HAVE_MUTEX

#endif /* h-guard */
