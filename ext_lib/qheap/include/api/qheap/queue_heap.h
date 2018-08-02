/* ##__QHEAP_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _qheap_queue_heap__H_
# define _qheap_queue_heap__H_

# include <string.h>
# include <stdint.h>

# ifdef __cplusplus
extern "C" {
# endif

# define QHEAP_TRUE             1
# define QHEAP_FALSE            0

# define QHEAP_QH_SEGM_HDR_SIZE 4

# define QHEAP_QH_IS_HANDLE_CACHE_QUEUE(x) (x & 1)
# define QHEAP_QH_MAX_NB_QUEUES 8

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

typedef uint16_t qh_size_t;
typedef uint_fast16_t qh_al_size_t;
typedef uint8_t qh_hndl_t;
typedef uint_fast8_t qh_al_hndl_t;

typedef uint8_t qheap_u8_t;
typedef uint_fast8_t qheap_al_u8_t;
typedef uint_fast16_t qheap_al_u16_t;
typedef uint_fast8_t qheap_bool_t;
typedef int qheap_err_e;

typedef struct
{
  // qh_hndl_t handle__qhl; // TODO: THIS ONE IS IMPLICIT BY THE POSITION
  /* offset from heap__pu8 where the first segment hdr is found */
  qh_size_t heap_offs__qhl;
} qheap_queue_metadata_t;

typedef void (* qh_queue_buf_operation_f)(
  void*        cust_obj__pv,
  uint8_t*     buffer__pu8,
  uint8_t*     queue_ptr__pu8,
  qh_al_size_t part_len__qsz
);

typedef struct
{
  /* the whole available memory block */
  qheap_u8_t*            memory__pu8;
  /* the heap area */
  qheap_u8_t*            heap__pu8;
  qh_al_size_t           heap_len__qhl;
  qh_size_t              offs_of_longest_free__qhl;
  qheap_queue_metadata_t queue_list__at[QHEAP_QH_MAX_NB_QUEUES];
  uint8_t                queue_rd_offs__u8[QHEAP_QH_MAX_NB_QUEUES];
} qheap_queue_heap_t;

# define qheap_queue_heap_t__INIT(__p) memset((__p), 0, sizeof(*(__p)))

void qheap_qh_ctor(
  qheap_queue_heap_t* qh__pt,
  qheap_u8_t*         memory__pu8,
  qh_size_t           memory_len__qhl,
  qheap_al_u8_t       alignment_mask__alu8
);


qh_al_hndl_t qheap_qh_alloc_queue(
  qheap_queue_heap_t* qh__pt,
  qheap_bool_t        is_cache__b
);


void qheap_qh_free_queue(
  qheap_queue_heap_t* qh__pt,
  qh_al_hndl_t        handle__qhh
);


/**
 * return the number of data bytes that could not be written to the queue.
 * returns zero if all data bytes were written as intended.
 */
qh_al_size_t qheap_qh_append_to_queue(
  qheap_queue_heap_t* qh__pt,
  qh_al_hndl_t        handle__qhh,
  const qheap_u8_t*   data__pcu8,
  qh_size_t           data_len__alqhl
);


void qheap_qh_get_free_counts(
  const qheap_queue_heap_t* qh__pct,
  qh_size_t*                free_internal_len__pqhl,
  qh_size_t*                free_sgm_cnt__pqhl
);

/**
 * @return the number of bytes read
 */
qh_al_size_t qheap_qh_peek(
  qheap_queue_heap_t* qh__pct,
  qh_al_hndl_t        handle__alqhh,
  qh_al_size_t        start__alqhl,
  uint8_t*            buf__pu8,
  qh_al_size_t        len__alqhl
);

/**
 * @return the number of bytes read
 */
qh_al_size_t qheap_qh_read(
  qheap_queue_heap_t* qh__pct,
  qh_al_hndl_t        handle__alqhh,
  uint8_t*            buf__pu8,
  qh_al_size_t        len__alqhl
);

/**
 * @return the number of bytes that were skipped
 */
qh_al_size_t qheap_qh_skip(
  qheap_queue_heap_t* qh__pct,
  qh_al_hndl_t        handle__alqhh,
  qh_al_size_t        len__alqhl
);

/**
 * @ return the number of bytes actually rewritten
 */
qh_al_size_t qheap_qh_rewrite(
  qheap_queue_heap_t* qh__pct,
  qh_al_hndl_t        handle__alqhh,
  qh_al_size_t        offset__alqsz,
  const uint8_t*      buf__pu8,
  qh_al_size_t        len__alqhl
);

qh_al_size_t qheap_qh_get_queue_len(
  const qheap_queue_heap_t* qh__pct,
  qh_al_hndl_t              handle__alqhh
);

# ifdef __cplusplus
}
# endif
#endif /* h-guard */
