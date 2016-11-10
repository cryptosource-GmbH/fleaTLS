// because of sha512_224 and _256 comments
static void flea_pk_api__set_pkcs1_digest_info__sha2(flea_u8_t* digest_info__p_u8, flea_hash_id_t hash_id__t)
{
  flea_u8_t di_1__u8, di_14__u8, di_18__u8;

  //memcpy(digest_info__p_u8, flea_pkcs1_digest_info__sha224__ac_u8, sizeof(flea_pkcs1_digest_info__sha224__ac_u8));
  if(hash_id__t == sha224)
  {
    return;
  }
  
  if(hash_id__t == sha256)
  {
   di_1__u8 = 0x31; 
   di_14__u8 = 0x01;
   di_18__u8 = 0x20;
  }
  else if(hash_id__t == sha384)
  {
    di_1__u8 = 0x41;
    di_14__u8 = 0x02;
    di_18__u8 = 0x30;
  }
  else /* must be sha512 *///if(hash_id__t == sha512)
  {
    di_1__u8 = 0x51;
    di_14__u8 = 0x03;
    di_18__u8 = 0x40;
  }
  /*else if(hash_id__t == sha512_224)
  {
    di_14__u8 = 0x05;
  }
  else if(hash_id__t == sha512_256)
  {
   di_1__u8 = 0x31; 
   di_14__u8 = 0x06;
   di_18__u8 = 0x20;
  }*/
  digest_info__p_u8[1] = di_1__u8;
  digest_info__p_u8[14] = di_14__u8;
  digest_info__p_u8[18] = di_18__u8;
}
