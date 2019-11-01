/* fleaTLS cryptographic library
Copyright (C) 2015-2019 cryptosource GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

#include "flea_test/linux_util.h"
#include "internal/common/default.h"
#include "internal/common/lib_int.h"
#include "flea/error_handling.h"
#include <time.h>
#include <sys/socket.h>
#ifdef FLEA_HAVE_MUTEX
# include <pthread.h>
#endif

int unix_tcpip_accept(
  int      listen_fd,
  unsigned read_timeout_ms
)
{
  struct timeval tv;

  if(read_timeout_ms)
  {
    set_timeval_from_millisecs(&tv, read_timeout_ms);
    setsockopt(
      listen_fd,
      SOL_SOCKET,
      SO_RCVTIMEO,
      (struct timeval*) &tv,
      sizeof(struct timeval)
    );
  }
  return accept(listen_fd, (struct sockaddr*) NULL, NULL);
} // THR_unix_tcpip_listen_accept

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
