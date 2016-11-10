
#include "internal/common/prng_weak_reseed.h"
#include "flea/crc.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"

#define FLEA_PRNG_WEAK_RESEED_POOL_IDX_MASK ((1 << FLEA_PRNG_WEAK_RESEED_LOG2_POOL_LEN) - 1)

void flea_weak_reseed_ctx_t__reset(flea_weak_reseed_ctx_t* ctx__pt, flea_u16_t crc_init_val__u16)
{
  memset(ctx__pt->pool__bu8, 0, FLEA_PRNG_WEAK_RESEED_POOL_LEN);
  ctx__pt->crc__u16 = crc_init_val__u16;
  //ctx__pt->have_pending__u8 = 0;
  //ctx__pt->is_full__u8 = 0;
  ctx__pt->idx__u8 = 0;
  ctx__pt->fill_idx__u16  = 0;
}
flea_err_t THR_flea_weak_reseed_ctx_t__ctor(flea_weak_reseed_ctx_t* ctx__pt, flea_u16_t crc_init_val__u16)
{
  FLEA_THR_BEG_FUNC();
#ifdef FLEA_USE_HEAP_BUF
  FLEA_ALLOC_MEM(ctx__pt->pool__bu8, FLEA_PRNG_WEAK_RESEED_POOL_LEN);
#endif 
  flea_weak_reseed_ctx_t__reset(ctx__pt, crc_init_val__u16);
  FLEA_THR_FIN_SEC_empty();

}
void flea_weak_reseed_ctx_t__dtor(flea_weak_reseed_ctx_t* ctx__pt)
{
#ifdef FLEA_USE_HEAP_BUF
  FLEA_FREE_MEM_CHK_SET_NULL(ctx__pt->pool__bu8);
#endif 
}
void flea_weak_reseed_ctx_t__reseed(flea_weak_reseed_ctx_t* ctx__pt, const flea_u8_t* seed__pcu8, flea_al_u8_t seed_len__alu8)
{
 // update CRC with next byte
 // write CRC to target idx
 flea_u16_t crc__u16 = ctx__pt->crc__u16;
 flea_dtl_t i;
 if(ctx__pt->fill_idx__u16 < FLEA_PRNG_WEAK_RESEED_POOL_LEN)
 {
   ctx__pt->fill_idx__u16 += seed_len__alu8;
   if(ctx__pt->fill_idx__u16 > FLEA_PRNG_WEAK_RESEED_LOG2_POOL_LEN)
   {
    ctx__pt->fill_idx__u16 = FLEA_PRNG_WEAK_RESEED_LOG2_POOL_LEN;
   }
 }
   
 
  for(i = 0; i < seed_len__alu8; i++)
  {
    flea_u8_t byte_high, byte_low;
    //flea_al_u8_t add_idx__alu8;
    flea_al_u8_t target_idx_high__alu8, target_idx_low__alu8;
    flea_u8_t new_byte = *(seed__pcu8++);
    target_idx_high__alu8 = crc__u16 & FLEA_PRNG_WEAK_RESEED_POOL_IDX_MASK;
    target_idx_low__alu8 = (crc__u16 >> 8) & FLEA_PRNG_WEAK_RESEED_POOL_IDX_MASK;
    ctx__pt->pool__bu8[ctx__pt->idx__u8] += new_byte;
    ctx__pt->idx__u8 = (ctx__pt->idx__u8 + 1) & FLEA_PRNG_WEAK_RESEED_POOL_IDX_MASK;
    crc__u16 = flea_crc16_ccit_compute(crc__u16, &new_byte, 1);
    byte_high = crc__u16 >> 8;   
    byte_low = (flea_u8_t) crc__u16;   

    ctx__pt->pool__bu8[target_idx_high__alu8] ^= byte_high; 
    ctx__pt->pool__bu8[target_idx_low__alu8] ^= byte_low;
  }
  ctx__pt->crc__u16 = crc__u16;
}
