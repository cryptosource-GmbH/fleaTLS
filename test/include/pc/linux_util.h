#ifndef _flea_linux_util__H_
#define _flea_linux_util__H_

#include <sys/types.h>
#include <sys/time.h> // Linux specific

#ifdef __cplusplus
extern "C" {
#endif

void set_timeval_from_millisecs(
  struct timeval* tv,
  size_t          time_millisecs
);


#ifdef __cplusplus
}
#endif

#endif /* h-guard */
