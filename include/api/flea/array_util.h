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

#ifndef _flea_array_util_H_
#define _flea_array_util_H_

#define FLEA_SET_ARR(__dst, __val, __count) \
  memset(__dst, __val, sizeof((__dst)[0]) * (__count))

#define FLEA_CP_ARR(__dst, __src, __count) \
  memcpy(__dst, __src, sizeof((__dst)[0]) * (__count))

#define FLEA_NB_ARRAY_ENTRIES_WLEN(__arr, __size_in_bytes) ((__size_in_bytes) / sizeof((__arr)[0]))

#define FLEA_NB_ARRAY_ENTRIES(__arr)                       FLEA_NB_ARRAY_ENTRIES_WLEN((__arr), sizeof(__arr))

#endif /* h-guard */
