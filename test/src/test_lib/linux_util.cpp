/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "flea_test/linux_util.h"
#include "internal/common/default.h"
#include "internal/common/lib_int.h"
#include "flea/error_handling.h"
#include <time.h>
#ifdef FLEA_HAVE_MUTEX
# include <pthread.h>
#endif

void set_timeval_from_millisecs(
  struct timeval* tv,
  size_t          time_millisecs
)
{
  tv->tv_sec  = time_millisecs / 1000;
  tv->tv_usec = (time_millisecs % 1000) * 1000;
}

flea_err_e THR_flea_linux__get_current_time(flea_gmt_time_t* time__t)
{
  time_t t;
  struct tm* ts;

  t  = time(NULL);
  ts = gmtime(&t);
  time__t->year    = ts->tm_year + 1900;
  time__t->month   = ts->tm_mon + 1;
  time__t->day     = ts->tm_mday;
  time__t->hours   = ts->tm_hour;
  time__t->seconds = ts->tm_sec % 60;
  time__t->minutes = ts->tm_min;
  return FLEA_ERR_FINE;
}

#ifdef FLEA_HAVE_MUTEX
int flea_linux__pthread_mutex_init(pthread_mutex_t* mutex__pt)
{
  return pthread_mutex_init(mutex__pt, NULL);
}

#endif // ifdef FLEA_HAVE_MUTEX