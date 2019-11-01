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


#ifndef _flea_queue_heap__H_
# define _flea_queue_heap__H_

# include "internal/common/default.h"
# include "flea/error.h"
# include "flea/types.h"

# ifdef __cplusplus
extern "C" {
# endif

/* +----------------------------------------------------------------------------------------------+
*  | q-hdr: len = 0|len1 noffs = ... |  len1 bytes | free-seg: len = 1|len2 noffs= not used |
*  +----------------------------------------------------------------------------------------------+
*
*  noffs = (abs offs from heap-ptr to next) ^ (offs to previous)
*
*  noffs = 0xFFFF (max value) means no further segments
*
*  noffs = 0 (or better 0xFFFE ?) means heap (only an initial segment can be at offs = 0)
*
*  backward traversal useful needed for popping:
*  even though first a forward traversal is needed, there is then no need to
*  remember the offsets of the earlier segments during the traversal
*
*  queue-list: offs = a to 1st seg => [len1, offs = a^b, with b] => [len2, b^c]
*
*  len = 0 is valid
*  len = 0xFFFF or 0x7FFF (max w/o free bit) => escape symbol, e.g. for
*  external ref data
*/

typedef flea_u16_t flea_qhl_t;
typedef flea_al_u16_t flea_al_qhl_t;
typedef flea_u16_t flea_qhh_t;
typedef flea_al_u16_t flea_al_qhh_t;

typedef struct
{
  // flea_qhh_t handle__qhl; // TODO: THIS ONE IS IMPLICIT BY THE POSITION
  /* offset from heap__pu8 where the first segment hdr is found */
  flea_qhl_t heap_offs__qhl;
} flea_queue_metadata_t;

# define FLEA_QH_IS_HANDLE_CACHE_QUEUE(x) (x & 1)
# define FLEA_QH_MAX_NB_QUEUES 8

typedef struct
{
  /* the whole available memory block */
  flea_u8_t*            memory__pu8;
  /* the heap area */
  flea_u8_t*            heap__pu8;
  flea_al_qhl_t         heap_len__qhl;
  flea_qhl_t            offs_of_longest_free__qhl;
  flea_queue_metadata_t queue_list__at[6];
} flea_queue_heap_t;

# define flea_queue_heap_t__INIT(__p) memset((__p), 0, sizeof(*(__p)))

flea_err_e flea_qh_ctor(
  flea_queue_heap_t* qh__pt,
  flea_u8_t*         memory__pu8,
  flea_qhl_t         memory_len__qhl,
  flea_al_u8_t       alignment_mask__alu8
);


flea_al_qhh_t flea_qh_alloc_queue(
  flea_queue_heap_t* qh__pt,
  flea_bool_t        is_cache__b
);


void flea_qh_free_queue(
  flea_queue_heap_t* qh__pt,
  flea_al_qhh_t      handle__qhh
);


flea_al_qhl_t flea_qh_append_to_queue(
  flea_queue_heap_t* qh__pt,
  flea_al_qhh_t      handle__qhh,
  const flea_u8_t*   data__pcu8,
  flea_qhl_t         data_len__alqhl
);

# ifdef __cplusplus
}
# endif
#endif /* h-guard */
