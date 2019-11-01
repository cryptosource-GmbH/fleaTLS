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

#ifndef _flea_byte_vec_macro__H_
#define _flea_byte_vec_macro__H_


#ifdef __cplusplus
extern "C" {
#endif

#define FLEA_BYTEVEC_STATE_ALLOCATABLE_MASK                (1)
#define FLEA_BYTEVEC_STATE_DEALLOCATABLE_MASK              (2)
#define FLEA_BYTEVEC_STATE_NEITHER_DE_NOR_ALLOCATABLE_MASK (0)

#define FLEA_BYTEVEC_STATE_SET_AS_ALLOCATABLE(state)     (state) |= FLEA_BYTEVEC_STATE_ALLOCATABLE_MASK
#define FLEA_BYTEVEC_STATE_SET_AS_DEALLOCATABLE(state)   (state) |= FLEA_BYTEVEC_STATE_DEALLOCATABLE_MASK

#define FLEA_BYTEVEC_STATE_SET_AS_UNALLOCATABLE(state)   (state) &= (~FLEA_BYTEVEC_STATE_ALLOCATABLE_MASK)
#define FLEA_BYTEVEC_STATE_SET_AS_UNDEALLOCATABLE(state) (state) &= (~FLEA_BYTEVEC_STATE_DEALLOCATABLE_MASK)

#define FLEA_BYTEVEC_STATE_IS_ALLOCATABLE(state)         ((state) & FLEA_BYTEVEC_STATE_ALLOCATABLE_MASK)
#define FLEA_BYTEVEC_STATE_IS_DEALLOCATABLE(state)       ((state) & FLEA_BYTEVEC_STATE_DEALLOCATABLE_MASK)


#ifdef __cplusplus
}
#endif
#endif /* h-guard */
