#include "pc/linux_util.h"

void set_timeval_from_millisecs(
  struct timeval* tv,
  size_t          time_millisecs
)
{
  tv->tv_sec  = time_millisecs / 1000;
  tv->tv_usec = (time_millisecs % 1000) * 1000;
}
