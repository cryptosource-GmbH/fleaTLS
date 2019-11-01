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

#ifndef _flea_linux_util__H_
#define _flea_linux_util__H_

#include <sys/types.h>
#include <sys/time.h> // Linux specific
#include "flea/types.h"
#include "flea/asn1_date.h"

#ifdef __cplusplus
extern "C" {
#endif

int unix_tcpip_accept(
  int      listen_fd,
  unsigned read_timeout_ms
);

void set_timeval_from_millisecs(
  struct timeval* tv,
  size_t          time_millisecs
);


flea_err_e THR_flea_linux__get_current_time(flea_gmt_time_t* time__t);

#ifdef FLEA_HAVE_MUTEX
int flea_linux__pthread_mutex_init(pthread_mutex_t* mutex__pt);
#endif
#ifdef __cplusplus
}
#endif


#endif /* h-guard */
