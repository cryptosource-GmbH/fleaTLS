void flea_fortuna_ctx_t__reseed(flea_fortuna_ctx_t* ctx__pt, const flea_u8_t* seed__pcu8, flea_dtl_t seed_len__dtl)
{
  flea_fortuna_ctx_t__reseed_inner(ctx__pt, ctx__pt->weak_reseed_ctx__t.pool__bu8, ctx__pt->weak_reseed_ctx__t.fill_idx__u16);
  flea_fortuna_ctx_t__reseed_inner(ctx__pt, seed__pcu8, seed_len__dtl);
  flea_weak_reseed_ctx_t__reset(&ctx__pt->weak_reseed_ctx__t, ctx__pt->weak_reseed_ctx__t.crc__u16);
}

static void flea_fortuna_ctx_t__reseed_inner(flea_fortuna_ctx_t* ctx__pt, const flea_u8_t* seed__pcu8, flea_dtl_t seed_len__dtl)
{
    // first, complete the seed block

  flea_dtl_t nb_blocks__dtl, i;
  flea_al_u8_t free__alu8;
  flea_u8_t* pending_ptr__pu8;
  free__alu8 = FLEA_AES_BLOCK_LENGTH - ctx__pt->pending_seed_len__u8;
  flea_al_u8_t to_copy__alu8 = FLEA_MIN(seed_len__dtl, free__alu8);
  pending_ptr__pu8 = ctx__pt->reseed_buf__bu8 + ctx__pt->pending_seed_len__u8;
  flea_binutil__xor_bytes_in_place_U16l(pending_ptr__pu8, seed__pcu8, to_copy__alu8);

  ctx__pt->pending_seed_len__u8 += to_copy__alu8;
  seed_len__dtl -= to_copy__alu8;
  seed__pcu8 += to_copy__alu8;
   
  nb_blocks__dtl = seed_len__dtl / FLEA_AES_BLOCK_LENGTH;
  if(ctx__pt->pending_seed_len__u8 == FLEA_AES_BLOCK_LENGTH)
  {
   nb_blocks__dtl += 1;    
  }
  for(i = 0; i < nb_blocks__dtl; i++)
  {
    flea_u8_t* key_ptr__pu8;
    if(i != 0)
    {
      flea_binutil__xor_bytes_in_place_U16l(ctx__pt->reseed_buf__bu8, seed__pcu8, FLEA_AES_BLOCK_LENGTH);
      seed__pcu8 += FLEA_AES_BLOCK_LENGTH;
    }
    key_ptr__pu8 = &((flea_u8_t*) ctx__pt->cipher_ctx__t.expanded_key)[ctx__pt->round_key_index__u8*FLEA_AES_BLOCK_LENGTH];
    ctx__pt->cipher_ctx__t.block_crypt_f(&ctx__pt->cipher_ctx__t, ctx__pt->reseed_buf__bu8, ctx__pt->reseed_buf__bu8);
    flea_binutil__xor_bytes_in_place_U16l(key_ptr__pu8, ctx__pt->reseed_buf__bu8, FLEA_AES_BLOCK_LENGTH);
    // TODO: UPDATE ACCU1 or ACCU2
    /*ctx__pt->round_key_index__u8 = (ctx__pt->round_key_index__u8 + 1) % 16; // 15 is the number of round keys in AES256
    if(ctx__pt->round_key_index__u8 == 15)
    {
      ctx__pt->round_key_index__u8 = 7;
    }*/
  }
    
  seed_len__dtl %= FLEA_AES_BLOCK_LENGTH; 
  flea_binutil__xor_bytes_in_place_U16l(ctx__pt->reseed_buf__bu8, seed__pcu8, seed_len__dtl);
  ctx__pt->pending_seed_len__u8 = seed_len__dtl; 
}

// from randomize_no_flush
//
  // use pending reseeding bytes
  if(ctx__pt->pending_seed_len__u8 != 0)
  {
    flea_al_u8_t missing_seed__alu8 = FLEA_AES_BLOCK_LENGTH - ctx__pt->pending_seed_len__u8;
    // discard pending output
    ctx__pt->pending_output_len__u8 = 0;

    for(i = 0; i < missing_seed__alu8; i++)
    {
      flea_u8_t zero_byte;
      flea_fortuna_ctx_t__reseed(ctx__pt, &zero_byte, 1);
    }
  } 
