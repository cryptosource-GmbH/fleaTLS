/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "flea/queue_heap.h"
#include "flea/bin_utils.h"
#include "flea/error_handling.h"
#include <string.h>

#define FLEA_ENCODE_QHL_T(val, ptr) flea__encode_U16_LE(val, ptr)

#define FLEA_QH_MAX_QSEGM_LEN      0xFFFF

#define FLEA_QH_NOFFS_IE_LAST_SEQM 0xFFFF
#define FLEA_QH_OFFS_INVALID       FLEA_QH_NOFFS_IE_LAST_SEQM

#define FELA_QH_MAX_Q

#define FLEA_QH_SEGM_HDR_SIZE  4

#define FLEA_QH_FREE_QUEUE_IDX 0

#define FLEA_QH_HNDL_FROM_IDX_AND_WHETHER_CACHE(idx, is_cache) ((((idx)) << 8) | (is_cache != 0))
#define FLEA_QH_IS_CACHE_FROM_HNDL(hndl)                       (((hndl) & 0xFF) != 0)
#define FLEA_QH_IDX_FROM_HNDL(hndl)                            (((hndl) >> 8))

#define FLEA_QH_FREE_BIT_MASK     0x8000
#define FLEA_QH_FREE_BIT_INV_MASK 0x7FFF


#define FLEA_QH_GET_FROM_SEGM_HDR_THE_LEN(ptr)   (FLEA_QH_FREE_BIT_INV_MASK & flea__decode_U16_BE(ptr))
#define FLEA_QH_IS_FREE_SEGM(ptr)                (FLEA_QH_FREE_BIT_MASK & flea__decode_U16_BE(ptr))

#define FLEA_QH_GET_FROM_SEGM_HDR_THE_NOFFS(ptr) flea__decode_U16_BE((ptr) + 2)

/**
 *
 * now: HDR: (FLEA_QH_FREE_BIT_MASK | len (15-bit) ) | noffs
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

static void write_qsegm_hdr_nonfree(
  flea_queue_heap_t* qh__pt,
  flea_al_qhl_t      offset__alqhl,
  flea_al_qhl_t      segm_len_alqhl,
  flea_al_qhl_t      next_segm_offs__alqhl
)
{
  FLEA_ENCODE_QHL_T(segm_len_alqhl, qh__pt->heap__pu8 + offset__alqhl + 1);
  FLEA_ENCODE_QHL_T(next_segm_offs__alqhl, qh__pt->heap__pu8 + offset__alqhl + 1 + sizeof(flea_qhl_t));
}

static void mark_segm_as_free(
  flea_queue_heap_t* qh__pt,
  flea_al_qhl_t      offset__alqhl
)
{
  flea_al_qhl_t len__alqhl = FLEA_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + offset__alqhl);

  len__alqhl |= FLEA_QH_FREE_BIT_MASK;
  FLEA_ENCODE_QHL_T(len__alqhl, qh__pt->heap__pu8 + offset__alqhl);
}

static void write_qsegm_hdr_free(
  flea_queue_heap_t* qh__pt,
  flea_al_qhl_t      offset__alqhl,
  flea_al_qhl_t      segm_len__alqhl,
  flea_al_qhl_t      noffs__alqhl
)
{
  write_qsegm_hdr_nonfree(qh__pt, offset__alqhl, segm_len__alqhl, noffs__alqhl);
  mark_segm_as_free(qh__pt, offset__alqhl);
}

static flea_al_qhl_t flea_qh_find_precursor_of_sgm(
  flea_queue_heap_t* qh__pt,
  flea_al_u16_t      qidx__alu16,
  flea_al_qhl_t      hdr_offs__alqhl
)
{
  flea_al_qhl_t new_offs__alqhl;
  flea_al_qhl_t curr_offs__alqhl = qh__pt->queue_list__at[qidx__alu16].heap_offs__qhl;

  if(curr_offs__alqhl == hdr_offs__alqhl)
  {
    return FLEA_QH_OFFS_INVALID;
  }
  while(1)
  {
    // flea_al_qhl_t new_offs__alqhl;
    new_offs__alqhl = FLEA_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + curr_offs__alqhl);
    if(new_offs__alqhl == FLEA_QH_OFFS_INVALID)
    {
      // this may not happen
      printf("error: precursor of segment not found\n");
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
static void flea_qh_shorten_free_block_at_start(
  flea_queue_heap_t* qh__pt,
  flea_al_qhl_t      free_hdr_offs__alqhl,
  flea_al_qhl_t      shorten_by__alqhl
)
{
  flea_al_qhl_t right_free_len__alqhl = FLEA_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + free_hdr_offs__alqhl);
  flea_al_qhl_t right_noffs__alqhl    = FLEA_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + free_hdr_offs__alqhl);
  flea_al_qhl_t new_free_offs__alqhl  = free_hdr_offs__alqhl + shorten_by__alqhl;
  flea_al_qhl_t new_free_len__alqhl   = right_free_len__alqhl - shorten_by__alqhl;

  if(new_free_offs__alqhl + FLEA_QH_SEGM_HDR_SIZE < qh__pt->heap_len__qhl)
  {
    /* TODO: find the precessor of this free block and adjust its noffs */
    flea_al_qhl_t prec__alqhl = flea_qh_find_precursor_of_sgm(qh__pt, FLEA_QH_FREE_QUEUE_IDX, free_hdr_offs__alqhl);
    if(prec__alqhl != FLEA_QH_OFFS_INVALID)
    {
      flea_al_qhl_t prec_len__alqhl = FLEA_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + prec__alqhl);

      // flea_al_qhl_t prec_noffs__alqhl = FLEA_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + prec__alqhl);
      /* update the precursor segment's header */
      write_qsegm_hdr_free(qh__pt, prec__alqhl, prec_len__alqhl, new_free_offs__alqhl);

      /* update shifted free segment's header */
      write_qsegm_hdr_free(qh__pt, new_free_offs__alqhl, new_free_len__alqhl, right_noffs__alqhl);
    }
    else
    {
      /* the shortened block is the first segment */
      qh__pt->queue_list__at[FLEA_QH_FREE_QUEUE_IDX].heap_offs__qhl = new_free_offs__alqhl;
    }
  }
}

flea_err_e flea_qh_ctor(
  flea_queue_heap_t* qh__pt,
  flea_u8_t*         memory__pu8,
  flea_qhl_t         memory_len__qhl,
  flea_al_u8_t       alignment_value__alu8
)
{
  flea_al_u16_t i;
  flea_al_u8_t dummy;

  FLEA_THR_BEG_FUNC();
  dummy = alignment_value__alu8;

  /*if(memory_len__qhl < 100)
  {
    FLEA_THROW("too small size for queue-heap memory block", FLEA_ERR_BUFF_TOO_SMALL);
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

  for(i = 0; i < FLEA_QH_MAX_NB_QUEUES; i++)
  {
    qh__pt->queue_list__at[i].heap_offs__qhl = FLEA_QH_OFFS_INVALID;
  }

  write_qsegm_hdr_free(qh__pt, 0, memory_len__qhl - FLEA_QH_SEGM_HDR_SIZE, FLEA_QH_NOFFS_IE_LAST_SEQM);

  FLEA_THR_FIN_SEC_empty();
}

/*
 * traverse the free-queue until a segement with the appropriate size is found
 */
static flea_al_qhl_t flea_qh_find_first_free_sgm(
  flea_queue_heap_t* qh__pt,
  flea_al_qhl_t      min_size__alqhl
)
{
  flea_al_qhl_t curr_offs__alqhl = qh__pt->queue_list__at[FLEA_QH_FREE_QUEUE_IDX].heap_offs__qhl;

// flea_al_qhl_t result__alqhl = ;
  /* iterate through all free segments */
  while((curr_offs__alqhl != FLEA_QH_OFFS_INVALID))
  {
    flea_al_qhl_t new_offs__alqhl, curr_len__alqhl;
    new_offs__alqhl = FLEA_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + curr_offs__alqhl);
    curr_len__alqhl = FLEA_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + curr_offs__alqhl);
    if(curr_len__alqhl >= min_size__alqhl)
    {
      return curr_offs__alqhl;
    }
    curr_offs__alqhl = new_offs__alqhl;
  }
  return FLEA_QH_OFFS_INVALID;

  /*flea_u32_t offs__u32 = 0;
  while(offs__u32 + FLEA_QH_SEGM_HDR_SIZE + min_size__alqhl < ((flea_u32_t) qh__pt->heap_len__qhl))
  {
    flea_al_qhl_t segm_len__alqhl;
    segm_len__alqhl = FLEA_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + offs__u32);
    //segm_nofss__alqhl = FLEA_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + offs__u32);
    if(FLEA_QH_IS_FREE_SEGM(qh__pt->heap__pu8 + offs__u32) && segm_len__alqhl >= min_size__alqhl)
    {
       return offs__u32;
    }
    offs__u32 += FLEA_QH_SEGM_HDR_SIZE + segm_len__alqhl;
  }*/

  return FLEA_QH_OFFS_INVALID;
}

/*
 * make room (partially in / from ) a free segment. Global heap state is updated
 * accordingly. The requested_len__alqhl attempted to be reserved. this input must include the length of a potentially
 * necessary new header.
 * @return the length of the allocated data, i.e., the number of bytes made
 * available from the free block
 */
static flea_al_qhl_t flea_qh_shorten_at_start_or_delete_free_block(
  flea_queue_heap_t* qh__pt,
  flea_al_qhl_t      free_hdr_offs__alqhl,
  flea_al_qhl_t      requested_len__alqhl
)
{
  flea_al_qhl_t free_len__alqhl = FLEA_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + free_hdr_offs__alqhl);
  // flea_al_qhl_t right_noffs__alqhl = FLEA_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 +  free_hdr_offs__alqhl);
  flea_al_qhl_t result__alqhl;

  if(requested_len__alqhl >= free_len__alqhl + FLEA_QH_SEGM_HDR_SIZE)
  {
    /* the free segment is consumed including its header */
    flea_al_qhl_t prec__alqhl = flea_qh_find_precursor_of_sgm(qh__pt, FLEA_QH_FREE_QUEUE_IDX, free_hdr_offs__alqhl);
    flea_al_qhl_t subsequent_of_deleted__alqhl = FLEA_QH_GET_FROM_SEGM_HDR_THE_NOFFS(
      qh__pt->heap__pu8 + free_hdr_offs__alqhl
    );
    if(prec__alqhl != FLEA_QH_OFFS_INVALID)
    {
      flea_al_qhl_t prec_len__alqhl = FLEA_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + prec__alqhl);
      write_qsegm_hdr_free(qh__pt, prec__alqhl, prec_len__alqhl, subsequent_of_deleted__alqhl);
    }
    else
    {
      /* the delete block is the first segment */
      qh__pt->queue_list__at[FLEA_QH_FREE_QUEUE_IDX].heap_offs__qhl = subsequent_of_deleted__alqhl;
    }
    result__alqhl = free_len__alqhl + FLEA_QH_SEGM_HDR_SIZE;
  }
  else
  {
    /* the new data does not replace the free block including its header,
     * so the free header must remain */
    result__alqhl = FLEA_MIN(requested_len__alqhl, free_len__alqhl);
    /* shorten the free segment */
    flea_qh_shorten_free_block_at_start(qh__pt, free_hdr_offs__alqhl, result__alqhl);
    // else it is an implict free space
  }
  return result__alqhl;
} /* flea_qh_shorten_at_start_or_delete_free_block */

/*
 * @param min_content_size__alqhl the requested content size excluding any
 * header.
 */
static flea_u32_t flea_qh_find_and_alloc_next_free_seqm(
  flea_queue_heap_t* qh__pt,
  flea_al_qhl_t      min_content_size__alqhl
)
{
  flea_u32_t free_len__u32;
  // flea_qhl_t new_free_offs__u32;

  // TODO: adding the HDR_SIZE here is an overly restrictive requirement here. This is due to calling flea_qh_shorten_at_start_or_delete_free_block with a size
  // including the header size is a problem if the free block is completely
  // deleted and then the new size is not actually filling the whole free space.
  // This will be solved once sled-0-bytes are implemented, because otherwise
  // non-full-header-length segments remain deserted.
  flea_u32_t offs__u32 = flea_qh_find_first_free_sgm(qh__pt, min_content_size__alqhl + FLEA_QH_SEGM_HDR_SIZE);

  if(offs__u32 == FLEA_QH_OFFS_INVALID)
  {
    return FLEA_QH_OFFS_INVALID;
  }
  free_len__u32 = FLEA_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + offs__u32);
  // new_free_offs__u32 = offs__u32+FLEA_QH_SEGM_HDR_SIZE;
  free_len__u32 -= FLEA_QH_SEGM_HDR_SIZE;

  /* the function may not fail because the requested size is even within the
   * free segment's internal length:
   */
  flea_qh_shorten_at_start_or_delete_free_block(qh__pt, offs__u32, min_content_size__alqhl + FLEA_QH_SEGM_HDR_SIZE);
  write_qsegm_hdr_nonfree(qh__pt, offs__u32, min_content_size__alqhl, FLEA_QH_NOFFS_IE_LAST_SEQM);

  return offs__u32;
}

flea_al_qhh_t flea_qh_alloc_queue(
  flea_queue_heap_t* qh__pt,
  flea_bool_t        is_cache__b
)
{
  flea_al_u16_t i = 0;
  flea_al_qhl_t offs__alqhl;

/* find a free handle, idx 0 is the free-block-chain */
  for(i = 1; i < FLEA_QH_MAX_NB_QUEUES; i++)
  {
    if(qh__pt->queue_list__at[i].heap_offs__qhl == FLEA_QH_OFFS_INVALID)
    {
      break;
    }
  }

  if(i == FLEA_QH_MAX_NB_QUEUES)
  {
    return 0;
  }

  /* traverse the free memory to find a free segment */
  offs__alqhl = flea_qh_find_and_alloc_next_free_seqm(qh__pt, 0);
  if(offs__alqhl == FLEA_QH_OFFS_INVALID)
  {
    return 0;
  }

  qh__pt->queue_list__at[i].heap_offs__qhl = offs__alqhl;

  return FLEA_QH_HNDL_FROM_IDX_AND_WHETHER_CACHE(i, is_cache__b);
}

/*void flea_qh_jump_to_next_queue_hdr(flea_queue_heap_t* qh__pt, flea_al_qhl_t * offs__pqhl)
{

}*/

void flea_qh_free_queue(
  flea_queue_heap_t* qh__pt,
  flea_al_qhh_t      handle__qhh
)
{
  flea_al_u16_t idx__alu16 = FLEA_QH_IDX_FROM_HNDL(handle__qhh);
  flea_al_qhl_t hdr_offs__alqhl;

  if(idx__alu16 > FLEA_QH_MAX_NB_QUEUES)
  {
    return;
  }

  hdr_offs__alqhl = qh__pt->queue_list__at[idx__alu16].heap_offs__qhl;
  qh__pt->queue_list__at[idx__alu16].heap_offs__qhl = FLEA_QH_OFFS_INVALID;
  while(1)
  {
    flea_al_qhl_t new_offs__alqhl;
    new_offs__alqhl = FLEA_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + hdr_offs__alqhl);
    // TODO: IF AFTER THE FREED SEGMENT THERE IS NO MORE SPACE FOR A SEGMENT
    // HEADER BECAUSE WE ARE AT THE END OF THE HEAP, THEN IT MAKES SENSE TO
    // ENLARGE THE NEW FREE SEGMENT TO REACH UNTIL THE END OF THE HEAP. This is
    // necessary since otherwise the unused space at the end can grow
    // arbitrarily, if smaller and smaller last (at heap's end) segments are
    // allocated
    mark_segm_as_free(qh__pt, hdr_offs__alqhl);
    if(new_offs__alqhl == FLEA_QH_OFFS_INVALID)
    {
      break;
    }
    hdr_offs__alqhl = new_offs__alqhl;
  }
  // TODO: MERGE ADJACENT FREE SEGMENTS
  // TODO:
}

/**
 * return the number of data bytes that could not be written to the queue.
 * returns zero if all data bytes were written as intended.
 */
flea_al_qhl_t flea_qh_append_to_queue(
  flea_queue_heap_t* qh__pt,
  flea_al_qhh_t      handle__qhh,
  const flea_u8_t*   data__pcu8,
  flea_qhl_t         data_len__alqhl
)
{
  /* find the last seqment of the queue */
  flea_al_u16_t idx__alu16 = FLEA_QH_IDX_FROM_HNDL(handle__qhh);
  flea_al_qhl_t last_sgm_hdr__alqhl;

  last_sgm_hdr__alqhl = qh__pt->queue_list__at[idx__alu16].heap_offs__qhl;
  flea_al_qhl_t peek_hdr__alqhl;
  while(1)
  {
    flea_al_qhl_t new_offs__alqhl;
    new_offs__alqhl = FLEA_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + last_sgm_hdr__alqhl);
    if(new_offs__alqhl == FLEA_QH_OFFS_INVALID)
    {
      break;
    }
    last_sgm_hdr__alqhl = new_offs__alqhl;
  }
  /* check if there is a free segment directly after the last queue segment: */
  /* look to the hdr right of the current segment */

  peek_hdr__alqhl = last_sgm_hdr__alqhl + FLEA_QH_SEGM_HDR_SIZE + FLEA_QH_GET_FROM_SEGM_HDR_THE_LEN(
    qh__pt->heap__pu8 + last_sgm_hdr__alqhl
  );
  // TODO: COULD USE IMPLICITLY FREE BYTES DIRECTLY AFTER FINAL BLOCK AT THE END
  // OF THE HEAP
  //
  if(peek_hdr__alqhl + FLEA_QH_SEGM_HDR_SIZE < qh__pt->heap_len__qhl)
  {
    if(FLEA_QH_IS_FREE_SEGM(qh__pt->heap__pu8 + peek_hdr__alqhl))
    {
      flea_al_qhl_t to_append_to_last_sgm__alqhl = flea_qh_shorten_at_start_or_delete_free_block(
        qh__pt,
        peek_hdr__alqhl,
        data_len__alqhl
      );
      flea_al_qhl_t last_sgm_len__alqhl   = FLEA_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + last_sgm_hdr__alqhl);
      flea_al_qhl_t last_sgm_noffs__alqhl =
        FLEA_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + last_sgm_hdr__alqhl);
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
  flea_al_qhl_t sought_segm_len__alqhl = data_len__alqhl;

  // flea_al_qhl_t last_sgm_noffs__alqhl = FLEA_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + last_sgm_hdr__alqhl);
  // blocks of size 1 cannot currently be used
  while(data_len__alqhl)
  {
    flea_al_qhl_t curr_offs__alqhl = qh__pt->queue_list__at[FLEA_QH_FREE_QUEUE_IDX].heap_offs__qhl;

    /* iterate through all free segments */
    while((curr_offs__alqhl != FLEA_QH_OFFS_INVALID) && data_len__alqhl)
    {
      flea_al_qhl_t new_offs__alqhl, curr_len__alqhl;
      new_offs__alqhl = FLEA_QH_GET_FROM_SEGM_HDR_THE_NOFFS(qh__pt->heap__pu8 + curr_offs__alqhl);
      curr_len__alqhl = FLEA_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + curr_offs__alqhl);
      if(curr_len__alqhl >= sought_segm_len__alqhl)
      {
        flea_al_qhl_t this_sgm_store__alqhl = flea_qh_shorten_at_start_or_delete_free_block(
          qh__pt,
          curr_offs__alqhl,
          data_len__alqhl
        );

        flea_al_qhl_t last_sgm_len__alqhl = FLEA_QH_GET_FROM_SEGM_HDR_THE_LEN(qh__pt->heap__pu8 + last_sgm_hdr__alqhl);
        //  UPDATE THE NOFFS OF THE SO FAR LAST SEGM. HEADER
        write_qsegm_hdr_nonfree(qh__pt, last_sgm_hdr__alqhl, last_sgm_len__alqhl, curr_offs__alqhl);
        last_sgm_hdr__alqhl = curr_offs__alqhl;

        // WRITE THE NEW SEGMENT'S HDR
        write_qsegm_hdr_nonfree(qh__pt, curr_offs__alqhl, this_sgm_store__alqhl, FLEA_QH_OFFS_INVALID);

        memcpy(qh__pt->heap__pu8 + curr_offs__alqhl, data__pcu8, this_sgm_store__alqhl);
        data__pcu8      += this_sgm_store__alqhl;
        data_len__alqhl -= this_sgm_store__alqhl;
      }
      curr_offs__alqhl = new_offs__alqhl;
    }
    if(sought_segm_len__alqhl == 1)
    {
      break;
    }
    sought_segm_len__alqhl /= 2;
  }
  return data_len__alqhl;

  // flea_u32_t offs flea_qh_find_next_free_seqm
} /* flea_qh_append_to_queue */
