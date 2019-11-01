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

#ifndef _flea_assert__H_
#define _flea_assert__H_

#include "internal/common/default.h"
#include "flea/error_handling.h"

#ifdef FLEA_NO_DEV_ASSERTIONS
# define FLEA_DEV_ASSERT(x)
#else
# define FLEA_DEV_ASSERT(x) \
  do { \
    if(!(x)) { \
      __FLEA_EVTL_PRINT_ERR(__func__, "assertion failed"); \
      exit(1); \
    } while(0)
#endif // ifdef FLEA_NO_DEV_ASSERTIONS

#endif /* h-guard */
