/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"

#ifdef FLEA_HAVE_MUTEX

# include "flea/mutex.h"
# include "internal/common/mutex_int.h"
# include "flea/types.h"

static flea_mutex_func_set_t flea_gl_mutex_func_set_t;

void flea_mutex__set_funcs(const flea_mutex_func_set_t* funcs__pt)
{
  flea_gl_mutex_func_set_t = *funcs__pt;
}

flea_err_e THR_flea_mutex__init(flea_mutex_t* mutex__pt)
{
  if(flea_gl_mutex_func_set_t.init(mutex__pt))
  {
    return FLEA_ERR_MUTEX_INIT;
  }
  return FLEA_ERR_FINE;
}

void flea_mutex__destroy(flea_mutex_t* mutex__pt)
{
  flea_gl_mutex_func_set_t.destr(mutex__pt);
}

flea_err_e THR_flea_mutex__lock(flea_mutex_t* mutex__pt)
{
  if(flea_gl_mutex_func_set_t.lock(mutex__pt))
  {
    return FLEA_ERR_MUTEX_LOCK;
  }
  return FLEA_ERR_FINE;
}

flea_err_e THR_flea_mutex__unlock(flea_mutex_t* mutex__pt)
{
  if(flea_gl_mutex_func_set_t.unlock(mutex__pt))
  {
    return FLEA_ERR_MUTEX_LOCK;
  }
  return FLEA_ERR_FINE;
}

#endif /* ifdef FLEA_HAVE_MUTEX */
