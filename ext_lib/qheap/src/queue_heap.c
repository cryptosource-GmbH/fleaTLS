/* ##__QHEAP_LICENSE_TEXT_PLACEHOLDER__## */

#include "qheap/queue_heap.h"
#include "qheap/bin_util.h"
#include <stdlib.h> // TODO: <= DELETE THIS INCLUDE
#include <string.h>

// TODO: REMOVE:
#include <stdio.h>

#define QHEAP_ENCODE_QHL_T(val, ptr) QHEAP__ENCODE_U16_BE(val, ptr)

#define QHEAP_QH_MAX_QSEGM_LEN      0x7FFF
#define QHEAP_QH_MAX_QHEAP_LEN      (QHEAP_QH_MAX_QSEGM_LEN + QHEAP_QH_SEGM_HDR_SIZE)

#define QHEAP_QH_NOFFS_IE_LAST_SEQM 0xFFFF
#define QHEAP_QH_OFFS_INVALID       QHEAP_QH_NOFFS_IE_LAST_SEQM


#define QHEAP_QH_FREE_QUEUE_IDX 0

#if 0
# define QHEAP_QH_HNDL_FROM_IDX_AND_WHETHER_CACHE(idx, is_cache) ((((idx)) << 8) | (is_cache != 0))
# define QHEAP_QH_IS_CACHE_FROM_HNDL(hndl)                       (((hndl) & 0xFF) != 0)
# define QHEAP_QH_IDX_FROM_HNDL(hndl)                            (((hndl) >> 8))
#endif
#define QHEAP_QH_HNDL_FROM_IDX_AND_WHETHER_CACHE(idx, is_cache)  ((idx) | (((is_cache) != 0) << 7))
#define QHEAP_QH_IS_CACHE_FROM_HNDL(hndl)                        (((hndl) & 0x80) != 0)
#define QHEAP_QH_IDX_FROM_HNDL(hndl)                             (((hndl) & 0x7F))

#define QHEAP_QH_FREE_BIT_MASK     0x8000
#define QHEAP_QH_FREE_BIT_INV_MASK 0x7FFF


#define QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(ptr)   (QHEAP_QH_FREE_BIT_INV_MASK & QHEAP__DECODE_U16_BE(ptr))
#define QHEAP_QH_IS_FREE_SEGM(ptr)                (QHEAP_QH_FREE_BIT_MASK & QHEAP__DECODE_U16_BE(ptr))

#define QHEAP_QH_GET_FROM_SEGM_HDR_THE_NOFFS(ptr) QHEAP__DECODE_U16_BE((ptr) + 2)

#define QHEAP_QH_READ_OFFS_SHIFTDOWN_THRHLD 4

/**
 *
 * now: HDR: (QHEAP_QH_FREE_BIT_MASK | len (15-bit) ) | noffs
 *
 * LTR HDR: qidx | len | noffs |
 * qidx = 0: invalid (0-byte is sled-byte to slide into next hdr)
 * "qidx" & 0x80 ("qidx" is in fact a part of the heap-hdr): heap block
 * qidx = 1: free
 * qidx = 2: heap-hdr
 *
 * exampel quidx 4-bit, len = 15 bit, noffs 13 bit (4-byte aligned offsets) => 2
 * byte q-hdr
 */

/*
 *
 *
 *
 *             +-------------------------------+
 *             |                               v    last block of queue
 * +---------------+                           +---------------------+
 * |sgm1 len noffs |                           |sgm2 len  noffs=INV  |
 * +---------------+                           +---------------------+
 *
 *
 *
 *
 *
 *
 *
 * For Heap Hdr: use one of the low 2 bits of length to encode whether the data
 * contains poffs (previous offset of free segment) in the first two (or
 * whatever) data bytes
 *
 *
 */
static void qh_qbo_rewrite_queue_from_buf(
  void*        cstm_ob_state__pv,
  uint8_t*     buffer__pu8,
  uint8_t*     queue_ptr__pu8,
  qh_al_size_t part_len__qsz
)
{
  void* dummy = cstm_ob_state__pv;

  cstm_ob_state__pv = dummy; /* avoid compiler warning */
  memcpy(queue_ptr__pu8, buffer__pu8, part_len__qsz);
}

static void qh_qbo_copy_from_queue_to_buf(
  void*        cstm_ob_state__pv,
  uint8_t*     buffer__pu8,
  uint8_t*     queue_ptr__pu8,
  qh_al_size_t part_len__qsz
)
{
  void* dummy = cstm_ob_state__pv;

  cstm_ob_state__pv = dummy; /* avoid compiler warning */
  memcpy(buffer__pu8, queue_ptr__pu8, part_len__qsz);
}

static void write_qsegm_hdr_nonfree(
  qheap_queue_heap_t* qh__pt,
  qh_al_size_t        offset__alqhl,
  qh_al_size_t        segm_len_alqhl,
  qh_al_size_t        next_segm_offs__alqhl
)
{
  QHEAP_ENCODE_QHL_T(segm_len_alqhl, qh__pt->heap__pu8 + offset__alqhl);
  QHEAP_ENCODE_QHL_T(next_segm_offs__alqhl, qh__pt->heap__pu8 + offset__alqhl + sizeof(qh_size_t));
}

static void mark_segm_as_free(
  qheap_queue_heap_t* qh__pt,
  qh_al_size_t        offset__alqhl
)
{
  qh_al_size_t len__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + offset__alqhl);

  // TODO: ONLY FOR DEBUGGING:
  memset(qh__pt->heap__pu8 + offset__alqhl + QHEAP_QH_SEGM_HDR_SIZE, 0xF4, len__alqhl);

  len__alqhl |= QHEAP_QH_FREE_BIT_MASK;
  QHEAP_ENCODE_QHL_T(len__alqhl, qh__pt->heap__pu8 + offset__alqhl);
}

/**
 * @param segm_len__alqhl the external length of the free segment
 */
static void write_qsegm_hdr_free(
  qheap_queue_heap_t* qh__pt,
  qh_al_size_t        offset__alqhl,
  qh_al_size_t        segm_len__alqhl,
  qh_al_size_t        noffs__alqhl
)
{
  write_qsegm_hdr_nonfree(qh__pt, offset__alqhl, segm_len__alqhl, noffs__alqhl);
  mark_segm_as_free(qh__pt, offset__alqhl);
}

static qh_al_size_t qheap_qh_find_precursor_of_sgm(
  qheap_queue_heap_t* qh__pt,
  qheap_al_u16_t      qidx__alu16,
  qh_al_size_t        hdr_offs__alqhl
)
{
  qh_al_size_t new_offs__alqhl;
  qh_al_size_t curr_offs__alqhl = qh__pt->queue_list__at[qidx__alu16].heap_offs__qhl;

  if(curr_offs__alqhl == hdr_offs__alqhl)
  {
    return QHEAP_QH_OFFS_INVALID;
  }
  while(1)
  {
    // qh_al_size_t new_offs__alqhl;
    new_offs__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + curr_offs__alqhl);
    if(new_offs__alqhl == QHEAP_QH_OFFS_INVALID)
    {
      // this may not happen
      // printf("error: precursor of segment not found\n");
      break;
    }
    if(new_offs__alqhl == hdr_offs__alqhl)
    {
      break;
    }
    curr_offs__alqhl = new_offs__alqhl;
  }
  return curr_offs__alqhl;
}

/**
 * shorten_by must be smaller than the free blocks's internal length
 */
static void qheap_qh_shorten_free_block_at_start(
  qheap_queue_heap_t* qh__pt,
  qh_al_size_t        free_hdr_offs__alqhl,
  qh_al_size_t        shorten_by__alqhl
)
{
  qh_al_size_t right_free_len__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + free_hdr_offs__alqhl);
  qh_al_size_t right_noffs__alqhl    = QHEAP_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + free_hdr_offs__alqhl);
  qh_al_size_t new_free_offs__alqhl  = free_hdr_offs__alqhl + shorten_by__alqhl;
  qh_al_size_t new_free_len__alqhl   = right_free_len__alqhl - shorten_by__alqhl;

  if(new_free_offs__alqhl + QHEAP_QH_SEGM_HDR_SIZE <= qh__pt->heap_len__qhl)
  {
    /* TODO: find the precessor of this free block and adjust its noffs */
    qh_al_size_t prec__alqhl = qheap_qh_find_precursor_of_sgm(qh__pt, QHEAP_QH_FREE_QUEUE_IDX, free_hdr_offs__alqhl);
    if(prec__alqhl != QHEAP_QH_OFFS_INVALID)
    {
      qh_al_size_t prec_len__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + prec__alqhl);

      // qh_al_size_t prec_noffs__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + prec__alqhl);
      /* update the precursor segment's header */
      write_qsegm_hdr_free(qh__pt, prec__alqhl, prec_len__alqhl, new_free_offs__alqhl);

      /* update shifted free segment's header */
    }
    else
    {
      /* the shortened block is the first segment */
      qh__pt->queue_list__at[QHEAP_QH_FREE_QUEUE_IDX].heap_offs__qhl = new_free_offs__alqhl;
    }
    write_qsegm_hdr_free(qh__pt, new_free_offs__alqhl, new_free_len__alqhl, right_noffs__alqhl);
  }
}

void qheap_qh_ctor(
  qheap_queue_heap_t* qh__pt,
  qheap_u8_t*         memory__pu8,
  qh_size_t           memory_len__qhl,
  qheap_al_u8_t       alignment_value__alu8
)
{
  qheap_al_u16_t i;
  qheap_al_u8_t dummy;

  dummy = alignment_value__alu8;
  alignment_value__alu8 = dummy;


  if(memory_len__qhl > QHEAP_QH_MAX_QHEAP_LEN)
  {
    memory_len__qhl = QHEAP_QH_MAX_QHEAP_LEN;
  }

  /*if(memory_len__qhl < 100)
  {
    QHEAP_THROW("too small size for queue-heap memory block", QHEAP_ERR_BUFF_TOO_SMALL);
  }*/
  /* alignment mask is 0x3 for 32-bit alignement, 0x7 for 64-bit alignment... */
  /*align on 32-bit boundary */

  /*while(((long long unsigned )memory__pu8) & alignment_mask__alu8)
  {
    memory__pu8++;
    memory_len__qhl
  }*/
  qh__pt->memory__pu8   = memory__pu8;
  qh__pt->heap__pu8     = memory__pu8;
  qh__pt->heap_len__qhl = memory_len__qhl;


  for(i = 1; i < QHEAP_QH_MAX_NB_QUEUES; i++)
  {
    qh__pt->queue_list__at[i].heap_offs__qhl = QHEAP_QH_OFFS_INVALID;
  }
  qh__pt->queue_list__at[0].heap_offs__qhl = 0;
  write_qsegm_hdr_free(qh__pt, 0, memory_len__qhl - QHEAP_QH_SEGM_HDR_SIZE, QHEAP_QH_NOFFS_IE_LAST_SEQM);
  memset(qh__pt->heap__pu8 + QHEAP_QH_SEGM_HDR_SIZE, 0xF4, memory_len__qhl - QHEAP_QH_SEGM_HDR_SIZE);
}

/*
 * traverse the free-queue until a segement with the appropriate size is found.
 *
 * @param closest_from_left_to_mbinv__alqhl if this parameter is not set to QH_OFFS_INVALID, then the free block which
 * is closest to the left to that offset but still entirely before it (the
 * latter is not checked!) is determined. If there is no such block, then
 * QH_OFFS_INVALID is returned. If this
 * parameter is specified as different from QH_OFFS_INVALID, min_size__alqhl is completely ignored.
 */
static qh_al_size_t qheap_qh_find_first_free_sgm(
  qheap_queue_heap_t* qh__pt,
  qh_al_size_t        min_size__alqhl,
  qh_al_size_t        closest_from_left_to_mbinv__alqhl
)
{
  qh_al_size_t curr_offs__alqhl = qh__pt->queue_list__at[QHEAP_QH_FREE_QUEUE_IDX].heap_offs__qhl;

// qh_al_size_t result__alqhl = ;
  /* iterate through all free segments */
  while((curr_offs__alqhl != QHEAP_QH_OFFS_INVALID))
  {
    qh_al_size_t new_offs__alqhl, curr_len__alqhl;
    new_offs__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + curr_offs__alqhl);
    curr_len__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + curr_offs__alqhl);

    if(closest_from_left_to_mbinv__alqhl != QHEAP_QH_OFFS_INVALID)
    {
      if((new_offs__alqhl == QHEAP_QH_OFFS_INVALID) || (new_offs__alqhl > closest_from_left_to_mbinv__alqhl))
      {
        /* the subsequent block (if there is one) of this queue is located after the sought
         * position */
        if(curr_offs__alqhl > closest_from_left_to_mbinv__alqhl)
        {
          /* if we are already over the sought position, this means that there is not yet a free block before the current one. then we indicate this
           * thus.*/
          return QHEAP_QH_OFFS_INVALID;
        }

        return curr_offs__alqhl;
      }
    }
    else if(curr_len__alqhl >= min_size__alqhl)
    {
      return curr_offs__alqhl;
    }
    curr_offs__alqhl = new_offs__alqhl;
  }

  return QHEAP_QH_OFFS_INVALID;
} /* qheap_qh_find_first_free_sgm */

/**
 * merge free segments starting from the free segment (assumption!) at
 * curr_offs__alqhl.
 *
 * @param sgm_max__alqhl the number of segments to traverse. 0 means no limit
 */
static void qheap_merge_adjacent_free_segment(
  qheap_queue_heap_t* qh__pt,
  qh_size_t           curr_offs__alqhl,
  qh_al_size_t        sgm_max__alqhl
)
{
  qh_al_size_t sgm_cnt__alqhl = 0;

// qh_al_size_t result__alqhl = ;
  /* iterate through all free segments */
  while((!sgm_max__alqhl || (sgm_cnt__alqhl > sgm_max__alqhl)) && (curr_offs__alqhl != QHEAP_QH_OFFS_INVALID))
  {
    qh_al_size_t next_offs__alqhl, curr_len__alqhl;
    next_offs__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + curr_offs__alqhl);
    curr_len__alqhl  = QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + curr_offs__alqhl);
    if((next_offs__alqhl != QHEAP_QH_OFFS_INVALID) &&
      (next_offs__alqhl == curr_offs__alqhl + curr_len__alqhl + QHEAP_QH_SEGM_HDR_SIZE))
    {
      qh_al_size_t next_len__alqhl   = QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + next_offs__alqhl);
      qh_al_size_t next_noffs__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + next_offs__alqhl);
      /* merge the two blocks */
      write_qsegm_hdr_free(
        qh__pt,
        curr_offs__alqhl,
        curr_len__alqhl + QHEAP_QH_SEGM_HDR_SIZE + next_len__alqhl,
        next_noffs__alqhl
      );
      // curr_offs__alqhl = next_noffs__alqhl;

      /* curr_offs__alqhl is not updated, since there may be further free blocks
       * to be merged*/
    }
    else
    {
      /* nothing to merge for this block */
      curr_offs__alqhl = next_offs__alqhl;
    }
    sgm_cnt__alqhl++;
  }
} /* qheap_merge_adjacent_free_segments */

static void qheap_merge_all_adjacent_free_segments(qheap_queue_heap_t* qh__pt)
{
  qh_al_size_t curr_offs__alqhl = qh__pt->queue_list__at[QHEAP_QH_FREE_QUEUE_IDX].heap_offs__qhl;

  qheap_merge_adjacent_free_segment(qh__pt, curr_offs__alqhl, 0);
}

/*
 * make room (partially in / from ) a free segment. Global heap state is updated
 * accordingly. The requested_len__alqhl is attempted to be reserved. this input must include the length of a potentially
 * necessary new header.
 * @return the length of the allocated data, i.e., the number of bytes made
 * available from the free block
 */
static qh_al_size_t qheap_qh_shorten_at_start_or_delete_free_block(
  qheap_queue_heap_t* qh__pt,
  qh_al_size_t        free_hdr_offs__alqhl,
  qh_al_size_t        requested_len__alqhl,
  qh_al_size_t        requested_min_len__alqhl
)
{
  qh_al_size_t free_len__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + free_hdr_offs__alqhl);
  // qh_al_size_t right_noffs__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 +  free_hdr_offs__alqhl);
  qh_al_size_t result__alqhl = 0;

  if(requested_len__alqhl >= free_len__alqhl + QHEAP_QH_SEGM_HDR_SIZE)
  {
    /* the free segment is consumed including its header */
    qh_al_size_t prec__alqhl = qheap_qh_find_precursor_of_sgm(qh__pt, QHEAP_QH_FREE_QUEUE_IDX, free_hdr_offs__alqhl);
    qh_al_size_t subsequent_of_deleted__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_NOFFS(
      qh__pt->heap__pu8 + free_hdr_offs__alqhl
    );
    if(prec__alqhl != QHEAP_QH_OFFS_INVALID)
    {
      qh_al_size_t prec_len__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + prec__alqhl);
      write_qsegm_hdr_free(qh__pt, prec__alqhl, prec_len__alqhl, subsequent_of_deleted__alqhl);
    }
    else
    {
      /* the delete block is the first segment */
      qh__pt->queue_list__at[QHEAP_QH_FREE_QUEUE_IDX].heap_offs__qhl = subsequent_of_deleted__alqhl;
    }
    result__alqhl = free_len__alqhl + QHEAP_QH_SEGM_HDR_SIZE;
  }
  else if(free_len__alqhl >= requested_min_len__alqhl)
  {
    /* the new data does not replace the free block including its header,
     * so the free header must remain */
    result__alqhl = QHEAP_MIN(requested_len__alqhl, free_len__alqhl);
    /* shorten the free segment */
    qheap_qh_shorten_free_block_at_start(qh__pt, free_hdr_offs__alqhl, result__alqhl);
    // else it is an implict free space
  }
  return result__alqhl;
} /* qheap_qh_shorten_at_start_or_delete_free_block */

/*
 * @param min_content_size__alqhl the requested content size excluding any
 * header.
 */
static uint_fast32_t qheap_qh_find_and_alloc_next_free_seqm(
  qheap_queue_heap_t* qh__pt,
  qh_al_size_t        min_content_size__alqhl
)
{
  uint_fast32_t free_len__u32;
  // qh_size_t new_free_offs__u32;

  // TODO: adding the HDR_SIZE here is an overly restrictive requirement here. This is due to calling qheap_qh_shorten_at_start_or_delete_free_block with a size
  // including the header size is a problem if the free block is completely
  // deleted and then the new size is not actually filling the whole free space.
  // This will be solved once sled-0-bytes are implemented, because otherwise
  // non-full-header-length segments remain deserted.
  uint_fast32_t offs__u32 = qheap_qh_find_first_free_sgm(
    qh__pt,
    min_content_size__alqhl + QHEAP_QH_SEGM_HDR_SIZE,
    QHEAP_QH_OFFS_INVALID
  );

  if(offs__u32 == QHEAP_QH_OFFS_INVALID)
  {
    return QHEAP_QH_OFFS_INVALID;
  }
  free_len__u32 = QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + offs__u32);
  // new_free_offs__u32 = offs__u32+QHEAP_QH_SEGM_HDR_SIZE;
  free_len__u32 -= QHEAP_QH_SEGM_HDR_SIZE;
  qh_al_size_t requ_size__alqhl = min_content_size__alqhl + QHEAP_QH_SEGM_HDR_SIZE;

  /* the function may not fail because the requested size is even within the
   * free segment's internal length (TODO: ADD ASSERTION):
   */
  if(requ_size__alqhl !=
    qheap_qh_shorten_at_start_or_delete_free_block(qh__pt, offs__u32, requ_size__alqhl, requ_size__alqhl))
  {
    /*printf("assertion failed: requ_size__alqhl != qheap_qh_shorten_at_start_or_delete_free_block, EXITING\n");
    exit(1);*/
  }
  write_qsegm_hdr_nonfree(qh__pt, offs__u32, min_content_size__alqhl, QHEAP_QH_NOFFS_IE_LAST_SEQM);

  return offs__u32;
} /* qheap_qh_find_and_alloc_next_free_seqm */

qh_al_hndl_t qheap_qh_alloc_queue(
  qheap_queue_heap_t* qh__pt,
  qheap_bool_t        is_cache__b
)
{
  qheap_al_u16_t i = 0;
  qh_al_size_t offs__alqhl;

/* find a free handle, idx 0 is the free-block-chain */
  for(i = 1; i < QHEAP_QH_MAX_NB_QUEUES; i++)
  {
    if(qh__pt->queue_list__at[i].heap_offs__qhl == QHEAP_QH_OFFS_INVALID)
    {
      break;
    }
  }

  if(i == QHEAP_QH_MAX_NB_QUEUES)
  {
    return 0;
  }

  /* traverse the free memory to find a free segment */
  offs__alqhl = qheap_qh_find_and_alloc_next_free_seqm(qh__pt, 0);
  if(offs__alqhl == QHEAP_QH_OFFS_INVALID)
  {
    return 0;
  }

  qh__pt->queue_list__at[i].heap_offs__qhl = offs__alqhl;
  qh__pt->queue_rd_offs__u8[i] = 0;

  return QHEAP_QH_HNDL_FROM_IDX_AND_WHETHER_CACHE(i, is_cache__b);
}

/*void qheap_qh_jump_to_next_queue_hdr(qheap_queue_heap_t* qh__pt, qh_al_size_t * offs__pqhl)
{

}*/

/*
 * Create a new free sgm at the specified offset and with the specified length.
 * The function also inserts the segment correctly into the free chain.
 */
static void qheap_qh_install_new_free_sgm(
  qheap_queue_heap_t* qh__pt,
  qh_al_size_t        new_free_sgm_offs__alqhl,
  qh_al_size_t        new_free_sgm_len__alqhl
)
{
  qh_al_size_t prec__alqhl = qheap_qh_find_first_free_sgm(qh__pt, 0, new_free_sgm_offs__alqhl);
  qh_al_size_t free_q_successor__alqhl;

  if(prec__alqhl == QHEAP_QH_OFFS_INVALID)
  {
    /* there is no free segment before the current segment. This we insert the current segment as the very first free segment. */
    free_q_successor__alqhl = qh__pt->queue_list__at[QHEAP_QH_FREE_QUEUE_IDX].heap_offs__qhl;
    qh__pt->queue_list__at[QHEAP_QH_FREE_QUEUE_IDX].heap_offs__qhl = new_free_sgm_offs__alqhl;
  }
  else
  {
    qh_al_size_t prec_len__alqhl;
    free_q_successor__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + prec__alqhl);
    prec_len__alqhl         = QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + prec__alqhl);
    write_qsegm_hdr_free(qh__pt, prec__alqhl, prec_len__alqhl, new_free_sgm_offs__alqhl);
  }
  write_qsegm_hdr_free(qh__pt, new_free_sgm_offs__alqhl, new_free_sgm_len__alqhl, free_q_successor__alqhl);
}

void qheap_qh_free_queue(
  qheap_queue_heap_t* qh__pt,
  qh_al_hndl_t        handle__qhh
)
{
  qheap_al_u16_t idx__alu16 = QHEAP_QH_IDX_FROM_HNDL(handle__qhh);
  qh_al_size_t curr_offs__alqhl;

  if(idx__alu16 > QHEAP_QH_MAX_NB_QUEUES)
  {
    return;
  }

  curr_offs__alqhl = qh__pt->queue_list__at[idx__alu16].heap_offs__qhl;
  qh__pt->queue_list__at[idx__alu16].heap_offs__qhl = QHEAP_QH_OFFS_INVALID;
  while(1) // TODO: EXLUDE INVALID
  {
    qh_al_size_t new_offs__alqhl, curr_len__alqhl;
    new_offs__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + curr_offs__alqhl);
    curr_len__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + curr_offs__alqhl);
    // TODO: IF AFTER THE FREED SEGMENT THERE IS NO MORE SPACE FOR A SEGMENT
    // HEADER BECAUSE WE ARE AT THE END OF THE HEAP, THEN IT MAKES SENSE TO
    // ENLARGE THE NEW FREE SEGMENT TO REACH UNTIL THE END OF THE HEAP. This is
    // necessary since otherwise the unused space at the end can grow
    // arbitrarily, if smaller and smaller last (at heap's end) segments are
    // allocated
    // mark_segm_as_free(qh__pt, curr_offs__alqhl);

    qheap_qh_install_new_free_sgm(qh__pt, curr_offs__alqhl, curr_len__alqhl);
    if(new_offs__alqhl == QHEAP_QH_OFFS_INVALID)
    {
      break;
    }
    curr_offs__alqhl = new_offs__alqhl;
  }
  qheap_merge_all_adjacent_free_segments(qh__pt);
} /* qheap_qh_free_queue */

static void qheap_qh__eliminate_leading_empty_sgms(
  qheap_queue_heap_t* qh__pt,
  uint_fast16_t       q_idx__alu16
)
{
  qh_al_size_t first_sgm_offs__alqhl = qh__pt->queue_list__at[q_idx__alu16].heap_offs__qhl;
  qh_al_size_t total_len__alqhl      = 0;

// TODO: THIS SHOULD ONLY GO UNTIL A NON-EMPTY HAS BEEN ENCOUNTERED. THEN
// RETURN.
  while(first_sgm_offs__alqhl != QHEAP_QH_OFFS_INVALID)
  {
    qh_al_size_t curr_noffs__alqhl, curr_len__alqhl;
    curr_noffs__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + first_sgm_offs__alqhl);
    curr_len__alqhl   = QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + first_sgm_offs__alqhl);
    total_len__alqhl += curr_len__alqhl;
    if(((curr_len__alqhl == 0) || (qh__pt->queue_rd_offs__u8[q_idx__alu16] >= curr_len__alqhl))
      &&
      (curr_noffs__alqhl != QHEAP_QH_OFFS_INVALID))
    {
      qh__pt->queue_list__at[q_idx__alu16].heap_offs__qhl = curr_noffs__alqhl;
      qheap_qh_install_new_free_sgm(qh__pt, first_sgm_offs__alqhl, curr_len__alqhl);
      qh__pt->queue_rd_offs__u8[q_idx__alu16] -= curr_len__alqhl;
    }
    else
    {
      break;
    }
    first_sgm_offs__alqhl = curr_noffs__alqhl;
  }
  // TODO: MERGE ADJACENT FREE
}

#if 0
static qheap_qh__delete_completely_read_leading_non_last_sgm(
  qheap_queue_heap_t * qh__pt,
  uint_fast16_t idx__alu16
)
{
  qh_al_size_t first_sgm_hdr__alqhl, curr_len__alqhl;

  first_sgm_hdr__alqhl = qh__pt->queue_list__at[idx__alu16].heap_offs__qhl;

  qh_al_size_t noffs__alqhl;
  noffs__alqhl    = QHEAP_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + first_sgm_hdr__alqhl);
  curr_len__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + first_sgm_hdr__alqhl);
  if(noffs__alqhl != QHEAP_QH_OFFS_INVALID && qh__pt->queue_rd_offs__u8[idx__alu16] >= curr_len__alqhl)
  {
    qh_al_size_t next_sgm_len__alqhl =
      QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + noffs__alqhl);
    qh_al_size_t next_sgm_noffs__alqhl =
      QHEAP_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + noffs__alqhl);
  }
}
#endif /* if 0 */

qh_al_size_t qheap_qh_append_to_queue(
  qheap_queue_heap_t* qh__pt,
  qh_al_hndl_t        handle__qhh,
  const qheap_u8_t*   data__pcu8,
  qh_size_t           data_len__alqhl
)
{
  /* find the last seqment of the queue */
  qheap_al_u16_t idx__alu16 = QHEAP_QH_IDX_FROM_HNDL(handle__qhh);
  qh_al_size_t last_sgm_hdr__alqhl;

  last_sgm_hdr__alqhl = qh__pt->queue_list__at[idx__alu16].heap_offs__qhl;
  qh_al_size_t peek_hdr__alqhl;
  while(1)
  {
    qh_al_size_t new_offs__alqhl;
    new_offs__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + last_sgm_hdr__alqhl);
    if(new_offs__alqhl == QHEAP_QH_OFFS_INVALID)
    {
      break;
    }
    last_sgm_hdr__alqhl = new_offs__alqhl;
  }
  /* check if there is a free segment directly after the last queue segment: */
  /* look to the hdr right of the current segment */

  peek_hdr__alqhl = last_sgm_hdr__alqhl + QHEAP_QH_SEGM_HDR_SIZE + QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(
    qh__pt->heap__pu8 + last_sgm_hdr__alqhl
  );
  // TODO: COULD USE IMPLICITLY FREE BYTES DIRECTLY AFTER FINAL BLOCK AT THE END
  // OF THE HEAP
  //
  if(peek_hdr__alqhl + QHEAP_QH_SEGM_HDR_SIZE < qh__pt->heap_len__qhl)
  {
    if(QHEAP_QH_IS_FREE_SEGM(qh__pt->heap__pu8 + peek_hdr__alqhl))
    {
      qh_al_size_t to_append_to_last_sgm__alqhl = qheap_qh_shorten_at_start_or_delete_free_block(
        qh__pt,
        peek_hdr__alqhl,
        data_len__alqhl, // we wish to extend the segment, so no need for a new hdr
        1
      );
      qh_al_size_t last_sgm_len__alqhl =
        QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + last_sgm_hdr__alqhl);
      qh_al_size_t last_sgm_noffs__alqhl =
        QHEAP_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + last_sgm_hdr__alqhl);
      last_sgm_len__alqhl += to_append_to_last_sgm__alqhl;

      /* update the lengthend last segment header */
      write_qsegm_hdr_nonfree(qh__pt, last_sgm_hdr__alqhl, last_sgm_len__alqhl, last_sgm_noffs__alqhl);

      memcpy(qh__pt->heap__pu8 + peek_hdr__alqhl, data__pcu8, to_append_to_last_sgm__alqhl);
      data__pcu8      += to_append_to_last_sgm__alqhl;
      data_len__alqhl -= to_append_to_last_sgm__alqhl;
    }
  }

  /* iteratively search for free segments of rem_len, rem_len/2, rem_len/4 ...
   * */

  // LTR: keep an estimate of the maximally sized free segment, and use the
  // minimum of that and the data_len for the search:
  qh_al_size_t sought_segm_len__alqhl = data_len__alqhl;

  // qh_al_size_t last_sgm_noffs__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + last_sgm_hdr__alqhl);
  // blocks of size 1 cannot currently be used
  while(data_len__alqhl)
  {
    qh_al_size_t curr_offs__alqhl = qh__pt->queue_list__at[QHEAP_QH_FREE_QUEUE_IDX].heap_offs__qhl;

    /* iterate through all free segments */
    while((curr_offs__alqhl != QHEAP_QH_OFFS_INVALID) && data_len__alqhl)
    {
      qh_al_size_t new_offs__alqhl, curr_len__alqhl;
      new_offs__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + curr_offs__alqhl);
      curr_len__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + curr_offs__alqhl);
      if(curr_len__alqhl >= sought_segm_len__alqhl)
      {
        qh_al_size_t this_sgm_store__alqhl = qheap_qh_shorten_at_start_or_delete_free_block(
          qh__pt,
          curr_offs__alqhl,
          data_len__alqhl + QHEAP_QH_SEGM_HDR_SIZE,
          QHEAP_QH_SEGM_HDR_SIZE + 1
        );
        if(this_sgm_store__alqhl > QHEAP_QH_SEGM_HDR_SIZE)
        {
          this_sgm_store__alqhl -= QHEAP_QH_SEGM_HDR_SIZE;
          qh_al_size_t last_sgm_len__alqhl =
            QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + last_sgm_hdr__alqhl);
          //  UPDATE THE NOFFS OF THE SO FAR LAST SEGM. HEADER
          write_qsegm_hdr_nonfree(qh__pt, last_sgm_hdr__alqhl, last_sgm_len__alqhl, curr_offs__alqhl);
          last_sgm_hdr__alqhl = curr_offs__alqhl;

          // WRITE THE NEW SEGMENT'S HDR
          write_qsegm_hdr_nonfree(qh__pt, curr_offs__alqhl, this_sgm_store__alqhl, QHEAP_QH_OFFS_INVALID);

          memcpy(qh__pt->heap__pu8 + curr_offs__alqhl + QHEAP_QH_SEGM_HDR_SIZE, data__pcu8, this_sgm_store__alqhl);
          data__pcu8      += this_sgm_store__alqhl;
          data_len__alqhl -= this_sgm_store__alqhl;
        }
      }
      curr_offs__alqhl = new_offs__alqhl;
    }
    if(sought_segm_len__alqhl == 1)
    {
      break;
    }
    sought_segm_len__alqhl /= 2;
  }
  qheap_qh__eliminate_leading_empty_sgms(qh__pt, idx__alu16);
  return data_len__alqhl;

  // uint_fast32_t offs qheap_qh_find_next_free_seqm
} /* qheap_qh_append_to_queue */

static qh_al_size_t qheap_qh_process_queue_and_buf(
  qheap_queue_heap_t*      qh__pt,
  qh_al_hndl_t             handle__alqhh,
  qh_al_size_t             start__alqhl,
  uint8_t*                 buf__pu8, /* may be null */
  qh_al_size_t             len__alqhl,
  qheap_bool_t             do_advance_rd_offs__b,
  qh_queue_buf_operation_f op__f,
  void*                    cstm_ob_state__pv
)
{
  /*
   * start is always the data position to read from next
   */
  qheap_bool_t do_upd_rd_offs__b  = QHEAP_FALSE;
  qh_al_size_t result__alqhl      = 0;
  int32_t curr_sgm_data_offs__s32 = 0;
  uint_fast16_t idx__alu16        = QHEAP_QH_IDX_FROM_HNDL(handle__alqhh);
  qh_al_size_t curr_offs__alqhl   = qh__pt->queue_list__at[idx__alu16].heap_offs__qhl;
  qh_al_size_t curr_sgm_rd_offs   = qh__pt->queue_rd_offs__u8[idx__alu16];

  // curr_sgm_data_offs__s32 -= curr_sgm_rd_offs;
  // start__alqhl += curr_sgm_rd_offs;
  qh_al_size_t initial_sgm_rd_offs     = curr_sgm_rd_offs;
  qh_al_size_t prev_offs__alqhl        = QHEAP_QH_OFFS_INVALID;
  qheap_bool_t consumed_current_sgm__b = QHEAP_FALSE;
  qh_al_size_t curr_sgm_len__alqhl;
  qh_al_size_t curr_noffs__alqhl;

  /* start__alqhl always points to the offset where to read next */
  while((curr_offs__alqhl != QHEAP_QH_OFFS_INVALID) && len__alqhl)
  {
    /* determine the current segement's range */
    curr_sgm_len__alqhl = QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + curr_offs__alqhl);
    curr_noffs__alqhl   = QHEAP_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + curr_offs__alqhl);
    // printf("loop begin: start = %u, curr_sgm_rd_offs = %u, curr_sgm_data_offs__s32  = %u, curr_sgm_len__alqhl = %u\n", start__alqhl, curr_sgm_rd_offs, curr_sgm_data_offs__s32, curr_sgm_len__alqhl);
    if(start__alqhl + curr_sgm_rd_offs >= curr_sgm_data_offs__s32 + curr_sgm_len__alqhl) /* I  */
    {
      // printf("  skipping this segment, because start is behind it\n");
      /* this sgm is to be skipped completely */
      /* read offset can only be within the first segment! */
      curr_sgm_rd_offs = 0;

      /* more data is read. if there is a trailing element with non-zero length,
       * then now we must delete this one.
       */
// TODO: THE SEGMENT MUST BE DELETED IN CASE OF A CONSUMING PROCESSING
    }
    else
    {
      /* this sgm is (fully or partially) read */
      qh_al_size_t intra_sgm_off__alqhl = start__alqhl + curr_sgm_rd_offs - curr_sgm_data_offs__s32; /* read_offs > 0 contained in start__alqhl */
      qh_al_size_t sgm_rem_len__alqhl   = curr_sgm_len__alqhl - intra_sgm_off__alqhl;
      qh_al_size_t to_go__alqhl         = QHEAP_MIN(len__alqhl, sgm_rem_len__alqhl);
      // printf("  using this segment with intra_sgm_off__alqhl = %u, sgm_rem_len__alqhl = %u, to_go__alqhl = %u\n", intra_sgm_off__alqhl, sgm_rem_len__alqhl, to_go__alqhl  );
      if(op__f)
      {
        /*memcpy(
            buf__pu8,
            qh__pt->heap__pu8 + curr_offs__alqhl + QHEAP_QH_SEGM_HDR_SIZE + intra_sgm_off__alqhl,
            to_go__alqhl
            );*/
        op__f(
          cstm_ob_state__pv,
          buf__pu8,
          qh__pt->heap__pu8 + curr_offs__alqhl + QHEAP_QH_SEGM_HDR_SIZE + intra_sgm_off__alqhl,
          to_go__alqhl
        );
        buf__pu8 += to_go__alqhl;
      }
      len__alqhl    -= to_go__alqhl;
      result__alqhl += to_go__alqhl;
      start__alqhl  += to_go__alqhl /*- curr_sgm_rd_offs*/; // subtract rd_offs ?
      // read_offs__alqhl += to_go__alqhl;
      //
      if(to_go__alqhl == sgm_rem_len__alqhl)
      {
        curr_sgm_rd_offs = 0;
      }
      if(do_advance_rd_offs__b)
      {
        do_upd_rd_offs__b = QHEAP_TRUE;
        if(to_go__alqhl == sgm_rem_len__alqhl)
        {
          // curr_sgm_rd_offs = 0;

          /* the segment was consumed, check if is not the last element. then we have to delete it */
          if(curr_noffs__alqhl != QHEAP_QH_OFFS_INVALID)
          {
            qheap_qh_install_new_free_sgm(qh__pt, curr_offs__alqhl, curr_sgm_len__alqhl);
            /* if another free segment follows, merge them: */
            // qheap_merge_adjacent_free_segment(qh__pt, curr_offs__alqhl, 1); //
            // <= not enough
            // [TODO]: RUNNING THROUGH THE WHOLE FREE CHAIN EVERY TIME IS TOO HEAVY. IMPLEMENT
            // ENTRY-POINT-CACHE WITH XORLL
            qheap_merge_adjacent_free_segment(
              qh__pt,
              qh__pt->queue_list__at[QHEAP_QH_FREE_QUEUE_IDX].heap_offs__qhl,
              0
            );
            /* remove the segment from the predecessor */
            if(prev_offs__alqhl != QHEAP_QH_OFFS_INVALID)
            { // this should be impossible, we are in consuming read, thus there // can be no preceding segment to the current one => CHECK IF // READ_OFFS_THRSHLD enables this currently! However, it shouldn't.
              qh_al_size_t prev_sgm_len__alqhl =
                QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + curr_offs__alqhl);
              // qh_al_size_t prev_curr_noffs__alqhl        = QHEAP_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + curr_offs__alqhl);
              write_qsegm_hdr_nonfree(qh__pt, prev_offs__alqhl, prev_sgm_len__alqhl, curr_noffs__alqhl);
            }
            else
            {
              qh__pt->queue_list__at[idx__alu16].heap_offs__qhl = curr_noffs__alqhl;
              curr_offs__alqhl = QHEAP_QH_OFFS_INVALID;
            }

            /* if the last segment of the queue was deleted, place a new empty
             * segement for this queue */
            if(qh__pt->queue_list__at[idx__alu16].heap_offs__qhl == QHEAP_QH_OFFS_INVALID)
            {
              qh_al_size_t new_hdr__alqhl = qheap_qh_find_and_alloc_next_free_seqm(qh__pt, 0);
              qh__pt->queue_list__at[idx__alu16].heap_offs__qhl = new_hdr__alqhl;
            }
          }
          else
          {
            /* this is the last segment and was completely consumed. */
            // completely_consumed_first_sgm__b = 1;
            curr_sgm_rd_offs        = curr_sgm_len__alqhl;
            consumed_current_sgm__b = QHEAP_TRUE;
            break;
          }
        }
        else
        {
          /* segement was not consumed, this implies that the read request was
           * already satisfied */
          curr_sgm_rd_offs       += to_go__alqhl; // this much was read from the current segment (either all or a part)
          consumed_current_sgm__b = 1;
          /* leave the loop early to preserve curr- and prev-offs */
          break;
        }
      }
    }
    // in the initial iteration, the logical segment length was shorter

    curr_sgm_data_offs__s32 += curr_sgm_len__alqhl - initial_sgm_rd_offs;
    initial_sgm_rd_offs      = 0;
    prev_offs__alqhl         = curr_offs__alqhl;
    curr_offs__alqhl         = curr_noffs__alqhl;
  }
  // TODO: DISTINGUISH INCOMPLETELY CONSUMED WHICH MIGHT BE SHORTENED IF
  // POSSIBLE, OR A COMPLETELY CONSUMED WITH A TRAILING SEGMENT (WHICH CANNOT BE
  // EMPTY BY ASSUMPTION).
  if(consumed_current_sgm__b && (curr_sgm_rd_offs >= QHEAP_QH_READ_OFFS_SHIFTDOWN_THRHLD))
  {
    /* this case implies that the last processed segment was not completely
     * consumed */


    /* mv the header upwards and place a free header in front of it */
    // memmove((void*)(qh__pt->heap__pu8 + curr_offs__alqhl + curr_sgm_rd_offs), qh__pt->heap__pu8 + curr_offs__alqhl, QHEAP_QH_SEGM_HDR_SIZE);

    qh_al_size_t new_free_internal_len__alqhl = curr_sgm_rd_offs - QHEAP_QH_SEGM_HDR_SIZE;

    /*printf("curr_sgm_len__alqhl = %u\n", curr_sgm_len__alqhl );
    printf("new_free_internal_len__alqhl  = %u\n", new_free_internal_len__alqhl);*/
    qheap_qh_install_new_free_sgm(qh__pt, curr_offs__alqhl, new_free_internal_len__alqhl);
    qh_al_size_t shifted_up_hdr__alqhl     = curr_offs__alqhl + curr_sgm_rd_offs;
    qh_al_size_t shifted_up_hdr_len__alqhl = curr_sgm_len__alqhl - curr_sgm_rd_offs;
    write_qsegm_hdr_nonfree(qh__pt, shifted_up_hdr__alqhl, shifted_up_hdr_len__alqhl, curr_noffs__alqhl);

    /* update the previous "segment header", which must acually be the queue
     * list since we are here modifying the first segment!: */
    if(qh__pt->queue_list__at[idx__alu16].heap_offs__qhl != curr_offs__alqhl)
    {
      /*printf("error with assumption of no previous segment; EXITING");
      exit(1);*/
    }
    qh__pt->queue_list__at[idx__alu16].heap_offs__qhl = shifted_up_hdr__alqhl;


    curr_sgm_rd_offs = 0;
  }
  if(do_advance_rd_offs__b && do_upd_rd_offs__b)
  {
    qh__pt->queue_rd_offs__u8[idx__alu16] = curr_sgm_rd_offs;
  }
  return result__alqhl;
} /* qheap_qh_process_queue_and_buf */

qh_al_size_t qheap_qh_peek(
  qheap_queue_heap_t* qh__pct,
  qh_al_hndl_t        handle__alqhh,
  qh_al_size_t        start__alqhl,
  uint8_t*            buf__pu8,
  qh_al_size_t        len__alqhl
)
{
  return qheap_qh_process_queue_and_buf(
    qh__pct,
    handle__alqhh,
    start__alqhl,
    buf__pu8,
    len__alqhl,
    QHEAP_FALSE,
    qh_qbo_copy_from_queue_to_buf,
    NULL
  );
}

qh_al_size_t qheap_qh_read(
  qheap_queue_heap_t* qh__pct,
  qh_al_hndl_t        handle__alqhh,
  uint8_t*            buf__pu8,
  qh_al_size_t        len__alqhl
)
{
  return qheap_qh_process_queue_and_buf(
    qh__pct,
    handle__alqhh,
    0,
    buf__pu8,
    len__alqhl,
    QHEAP_TRUE,
    qh_qbo_copy_from_queue_to_buf,
    NULL
  );
}

qh_al_size_t qheap_qh_skip(
  qheap_queue_heap_t* qh__pct,
  qh_al_hndl_t        handle__alqhh,
  qh_al_size_t        len__alqhl
)
{
  return qheap_qh_process_queue_and_buf(qh__pct, handle__alqhh, 0, NULL, len__alqhl, QHEAP_TRUE, NULL, NULL);
}

qh_al_size_t qheap_qh_rewrite(
  qheap_queue_heap_t* qh__pct,
  qh_al_hndl_t        handle__alqhh,
  qh_al_size_t        offset__alqsz,
  const uint8_t*      buf__pu8,
  qh_al_size_t        len__alqhl
)
{
  // TODO: MAKE TWO VARIANTS OF THE BUF ARG AND THE OP ARG: ONE FOR CONST BUFS, ONE FOR NON-CONST BUFS. IN THE PROCESS FUNCTION, THE FIRST NON-ZERO OP-PTR IS USED WITH THE CORRESPONDING BUF-PTR
  return qheap_qh_process_queue_and_buf(
    qh__pct,
    handle__alqhh,
    offset__alqsz,
    (uint8_t*) buf__pu8,
    len__alqhl,
    QHEAP_FALSE,
    qh_qbo_rewrite_queue_from_buf,
    NULL
  );
}

static void qheap_qh_get_queue_counts(
  const qheap_queue_heap_t* qh__pct,
  uint_fast16_t             q_idx__alu16,
  qh_size_t*                internal_len__pqhl,
  qh_size_t*                sgm_cnt__pqhl
)
{
  qh_al_size_t curr_offs__alqhl = qh__pct->queue_list__at[q_idx__alu16].heap_offs__qhl;

  *sgm_cnt__pqhl      = 0;
  *internal_len__pqhl = 0;
// qh_al_size_t result__alqhl = ;
  /* iterate through all free segments */
  while((curr_offs__alqhl != QHEAP_QH_OFFS_INVALID))
  {
    qh_al_size_t new_offs__alqhl, curr_len__alqhl;
    new_offs__alqhl      = QHEAP_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pct->heap__pu8 + curr_offs__alqhl);
    curr_len__alqhl      = QHEAP_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pct->heap__pu8 + curr_offs__alqhl);
    *internal_len__pqhl += curr_len__alqhl;
    (*sgm_cnt__pqhl)++;
    curr_offs__alqhl = new_offs__alqhl;
  }
}

void qheap_qh_get_free_counts(
  const qheap_queue_heap_t* qh__pct,
  qh_size_t*                free_internal_len__pqhl,
  qh_size_t*                free_sgm_cnt__pqhl
)
{
  qheap_qh_get_queue_counts(qh__pct, QHEAP_QH_FREE_QUEUE_IDX, free_internal_len__pqhl, free_sgm_cnt__pqhl);
}

qh_al_size_t qheap_qh_get_queue_len(
  const qheap_queue_heap_t* qh__pct,
  qh_al_hndl_t              handle__alqhh
)
{
  qh_size_t sgm_cnt;
  qh_size_t len;

  qheap_qh_get_queue_counts(qh__pct, QHEAP_QH_IDX_FROM_HNDL(handle__alqhh), &len, &sgm_cnt);
  return len - qh__pct->queue_rd_offs__u8[QHEAP_QH_IDX_FROM_HNDL(handle__alqhh)];
}

/*void qheap_dbg_qh_print_heap(const qheap_queue_heap_t* qh__pt)
{ }*/
