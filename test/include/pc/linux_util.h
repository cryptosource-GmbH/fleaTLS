#ifndef _flea_linux_util__H_
#define _flea_linux_util__H_

#include <sys/types.h>
#include <sys/time.h> // Linux specific
#include "flea/types.h"
#include "flea/asn1_date.h"

#ifdef __cplusplus
extern "C" {
#endif

void set_timeval_from_millisecs(
  struct timeval* tv,
  size_t          time_millisecs
);


flea_err_t THR_flea_linux__get_current_time(flea_gmt_time_t* time__t);

#ifdef FLEA_HAVE_MUTEX
int flea_linux__pthread_mutex_init(pthread_mutex_t* mutex__pt);
#endif
#ifdef __cplusplus
}
#endif


#endif /* h-guard */
