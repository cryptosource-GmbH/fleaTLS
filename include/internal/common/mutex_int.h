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


#ifndef _flea_mutex_int__H_
#define _flea_mutex_int__H_

#include "internal/common/default.h"

#ifdef FLEA_HAVE_MUTEX

# include "flea/mutex.h"
# include "flea/types.h"


void flea_mutex__set_funcs(const flea_mutex_func_set_t* funcs__pt);

flea_err_e THR_flea_mutex__init(flea_mutex_t* mutex__pt);

void flea_mutex__destroy(flea_mutex_t* mutex__pt);

flea_err_e THR_flea_mutex__lock(flea_mutex_t* mutex__pt);

flea_err_e THR_flea_mutex__unlock(flea_mutex_t* mutex__pt);

void flea_mutex__set_funcs(const flea_mutex_func_set_t* funcs__pt);

# define FLEA_DECL_MUTEX(__mutex_name)        flea_mutex_t __mutex_name

# define FLEA_DECL_STATIC_MUTEX(__mutex_name) static FLEA_DECL_MUTEX(__mutex_name)

# define THR_FLEA_MUTEX_INIT(__mutex_ptr)     THR_flea_mutex__init(__mutex_ptr)

# define FLEA_MUTEX_DESTR(__mutex_ptr)        flea_mutex__destroy(__mutex_ptr)

# define THR_FLEA_MUTEX_LOCK(__mutex_ptr)     THR_flea_mutex__lock(__mutex_ptr)

# define THR_FLEA_MUTEX_UNLOCK(__mutex_ptr)   THR_flea_mutex__unlock(__mutex_ptr)


#else // ifdef FLEA_HAVE_MUTEX

# define FLEA_DECL_MUTEX(__mutex_name)
# define FLEA_DECL_STATIC_MUTEX(__mutex_name)

# define THR_FLEA_MUTEX_INIT(__mutex_ptr) FLEA_ERR_FINE

# define FLEA_MUTEX_DESTR(__mutex_ptr)

# define THR_FLEA_MUTEX_LOCK(__mutex_ptr)   FLEA_ERR_FINE

# define THR_FLEA_MUTEX_UNLOCK(__mutex_ptr) FLEA_ERR_FINE

#endif // ifdef FLEA_HAVE_MUTEX

#endif /* h-guard */
