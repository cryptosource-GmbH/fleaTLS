void flea__encode_U64_BE(flea_u64_t to_enc, flea_u8_t res[8])
{
  flea_al_s8_t i;
  for(i = 7; i >= 0; i--)
  {
    res[i] = to_enc & 0xFF;
    to_enc >>= 8;
  }
}

void flea__encode_U64_LE(flea_u64_t to_enc, flea_u8_t res[8])
{
  flea_al_s8_t i;
  for(i = 0; i < 8; i++)
  {
    res[i] = to_enc & 0xFF;
    to_enc >>= 8;
  }
}

flea_u16_t flea_binutil__calc_weight_U16l(const flea_u8_t* bin, flea_u16_t length)
{
  flea_u16_t i, j, w = 0;
  for(i = 0; i < length; i++)
  {
    for(j = 0; j < 8; j++)
    {
      if(bin[i] & (1 << j))
      {
        w++;
      }
    }
  }  
  return w;
}
void flea_binutil__encode_U16_BE(flea_u16_t to_enc, flea_u8_t res[2])
{
  res[0] = to_enc >> 8;
  res[1] = to_enc & 0xFF;
}
flea_u16_t flea_binutil__decode_U16_BE(const flea_u8_t enc[2])
 {
    flea_u16_t result;
    result = enc[0] << 8;
    result |= enc[1];
    return result;
 }
void flea_enc_1_byte_hex(unsigned char x, char res [2])
{
	unsigned i;
	res[0] = x >> 4 & 0x0F;
	res[1] = x >> 0 & 0x0F;
	for(i = 0; i < 2; i++) {
	    if(res[i] <= 9) { res[i] += 0x30; }
	    else { res[i] += 0x41 - 10; }
	}
}
