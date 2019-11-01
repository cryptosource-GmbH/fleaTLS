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


#ifndef _flea_alloc_int__H_
#define _flea_alloc_int__H_

#ifndef FLEA_USE_BUF_DBG_CANARIES

# define FLEA_NB_STACK_BUF_ENTRIES(__name)     FLEA_NB_ARRAY_ENTRIES(__name)

# define __FLEA_GET_ALLOCATED_BUF_NAME(__name) __name

# define FLEA_BUF_SET_CANANRIES(__name, __size)

# define FLEA_BUF_CHK_DBG_CANARIES(__name)

# ifdef FLEA_HEAP_MODE

#  define FLEA_DECL_BUF(__name, __type, __static_size) \
  __type * __name = NULL

#  define FLEA_ALLOC_BUF(__name, __dynamic_size) \
  FLEA_ALLOC_MEM_ARR(__name, __dynamic_size)

#  define FLEA_FREE_BUF_FINAL(__name) \
  FLEA_FREE_MEM_CHK_NULL(__name)

#  define FLEA_FREE_BUF(__name) \
  FLEA_FREE_MEM_CHK_SET_NULL(__name)

#  define FLEA_FREE_BUF_FINAL_SECRET_ARR(__name, __type_len) \
  do { \
    if(__name) { \
      flea_memzero_secure((flea_u8_t*) __name, (__type_len) * sizeof(__name[0])); \
      FLEA_FREE_MEM(__name); \
    } \
  } while(0)

# elif defined FLEA_STACK_MODE // #ifdef FLEA_HEAP_MODE

#  define FLEA_DECL_BUF(__name, __type, __static_size) \
  __type __name [__static_size]

#  define FLEA_STACK_BUF_NB_ENTRIES(__name) (sizeof(__name) / sizeof(__name[0]))

#  define FLEA_ALLOC_BUF(__name, __dynamic_size)

#  define FLEA_FREE_BUF_FINAL(__name)

#  define FLEA_FREE_BUF(__name)

#  define FLEA_FREE_BUF_FINAL_SECRET_ARR(__name, __type_len) \
  do { \
    flea_memzero_secure((flea_u8_t*) __name, (__type_len) * sizeof(__name[0])); \
  } while(0)
# else // ifdef FLEA_HEAP_MODE
#  error neither heap nor stack buf defined
# endif // #ifdef FLEA_HEAP_MODE

#endif // #ifndef FLEA_USE_BUF_DBG_CANARIES

#endif /* h-guard */
