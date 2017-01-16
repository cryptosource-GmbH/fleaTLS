/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/ae.h"
#include "flea/array_util.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"

#ifdef FLEA_HAVE_AE
#define TEST_MAX_CT_LEN 900

static flea_err_t THR_flea_test_ae_init_dtor ()
{

  flea_ae_ctx_t ctx__t = flea_ae_ctx_t__INIT_VALUE;

  FLEA_THR_BEG_FUNC();

  FLEA_THR_FIN_SEC(
    flea_ae_ctx_t__dtor(&ctx__t);
    );
}

static flea_err_t THR_flea_test_ae_inner_convenience_funcs (flea_ae_id_t id__t, const flea_u8_t* key__pcu8, flea_dtl_t key_len__dtl, const flea_u8_t* nonce__pcu8, flea_dtl_t nonce_len__dtl, const flea_u8_t* pt__pcu8, flea_dtl_t pt_len__dtl, const flea_u8_t* exp_tag__pcu8, flea_dtl_t exp_tag_len__dtl, const flea_u8_t* exp_ct__pcu8, flea_dtl_t exp_ct_len__dtl, const flea_u8_t* assoc_data__pcu8, flea_dtl_t assoc_data_len__dtl, flea_al_u16_t tag_len__alu16 )
{
  FLEA_DECL_BUF(encr__bu8, flea_u8_t, TEST_MAX_CT_LEN);
  FLEA_DECL_BUF(decr__bu8, flea_u8_t, TEST_MAX_CT_LEN);
  FLEA_DECL_BUF(tag__bu8, flea_u8_t, FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH);
  FLEA_THR_BEG_FUNC();

  FLEA_ALLOC_BUF(encr__bu8, pt_len__dtl);
  FLEA_ALLOC_BUF(decr__bu8, pt_len__dtl);
  FLEA_ALLOC_BUF(tag__bu8, FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH);
  FLEA_CCALL(THR_flea_ae__encrypt(id__t, key__pcu8, key_len__dtl, nonce__pcu8, nonce_len__dtl, assoc_data__pcu8, assoc_data_len__dtl, pt__pcu8, encr__bu8, pt_len__dtl, tag__bu8, tag_len__alu16));

  if(memcmp(exp_ct__pcu8, encr__bu8, exp_ct_len__dtl))
  {
    FLEA_THROW("error with AE encrypted value", FLEA_ERR_FAILED_TEST);
  }
  if(memcmp(exp_tag__pcu8, tag__bu8, exp_tag_len__dtl))
  {
    FLEA_THROW("error with AE tag value", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CCALL(THR_flea_ae__decrypt(id__t, key__pcu8, key_len__dtl, nonce__pcu8, nonce_len__dtl, assoc_data__pcu8, assoc_data_len__dtl, encr__bu8, decr__bu8, pt_len__dtl, tag__bu8, tag_len__alu16));
  if(memcmp(pt__pcu8, decr__bu8, exp_ct_len__dtl))
  {
    FLEA_THROW("error with AE decrypted value", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(encr__bu8);
    FLEA_FREE_BUF_FINAL(decr__bu8);
    FLEA_FREE_BUF_FINAL(tag__bu8);
    );
}

static flea_err_t THR_flea_test_ae_inner_update__vary_update_lengths (flea_ae_id_t id__t, const flea_u8_t* key__pcu8, flea_dtl_t key_len__dtl, const flea_u8_t* nonce__pcu8, flea_dtl_t nonce_len__dtl, const flea_u8_t* pt__pcu8, flea_dtl_t pt_len__dtl, const flea_u8_t* exp_tag__pcu8, flea_dtl_t exp_tag_len__dtl, const flea_u8_t* exp_ct__pcu8, flea_dtl_t exp_ct_len__dtl, const flea_u8_t* assoc_data__pcu8, flea_dtl_t assoc_data_len__dtl, flea_al_u16_t tag_len__alu16 )
{
  flea_al_u8_t tag_len__alu8;
  flea_dtl_t decr_len__dtl;
  flea_dtl_t this_decr_len__dtl;
  flea_u8_t* decr_ptr__pu8;
  flea_ae_ctx_t ctx__t = flea_ae_ctx_t__INIT_VALUE;
  flea_ae_ctx_t decr_ctx__t = flea_ae_ctx_t__INIT_VALUE;
  flea_ae_ctx_t decr2_ctx__t = flea_ae_ctx_t__INIT_VALUE;

  FLEA_DECL_BUF(encr__bu8, flea_u8_t, TEST_MAX_CT_LEN);
  FLEA_DECL_BUF(decr__bu8, flea_u8_t, TEST_MAX_CT_LEN);
  FLEA_DECL_BUF(tag__bu8, flea_u8_t, FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH);
  FLEA_THR_BEG_FUNC();

  if((pt_len__dtl > TEST_MAX_CT_LEN) || (pt_len__dtl != exp_ct_len__dtl))
  {
    FLEA_THROW("error in AE test code", FLEA_ERR_INT_ERR);
  }
  if(pt_len__dtl < 33)
  {
    FLEA_THR_RETURN();
  }
  FLEA_ALLOC_BUF(encr__bu8, pt_len__dtl);
  FLEA_ALLOC_BUF(decr__bu8, pt_len__dtl);
  decr_len__dtl = pt_len__dtl;
  FLEA_CCALL(THR_flea_ae_ctx_t__ctor(&ctx__t, id__t, key__pcu8, key_len__dtl, nonce__pcu8, nonce_len__dtl, assoc_data__pcu8, assoc_data_len__dtl, tag_len__alu16));
  FLEA_CCALL(THR_flea_ae_ctx_t__ctor(&decr_ctx__t, id__t, key__pcu8, key_len__dtl, nonce__pcu8, nonce_len__dtl, assoc_data__pcu8, assoc_data_len__dtl, tag_len__alu16));
  FLEA_CCALL(THR_flea_ae_ctx_t__ctor(&decr2_ctx__t, id__t, key__pcu8, key_len__dtl, nonce__pcu8, nonce_len__dtl, assoc_data__pcu8, assoc_data_len__dtl, tag_len__alu16));

  tag_len__alu8 = ctx__t.tag_len__u8;
  FLEA_ALLOC_BUF(tag__bu8, tag_len__alu8);
  FLEA_CCALL(THR_flea_ae_ctx_t__update_encryption(&ctx__t, pt__pcu8, encr__bu8, 5));
  FLEA_CCALL(THR_flea_ae_ctx_t__update_encryption(&ctx__t, pt__pcu8 + 5, encr__bu8 + 5, 11));
  FLEA_CCALL(THR_flea_ae_ctx_t__update_encryption(&ctx__t, pt__pcu8 + 5 + 11, encr__bu8 + 5 + 11, 17));
  FLEA_CCALL(THR_flea_ae_ctx_t__update_encryption(&ctx__t, pt__pcu8 + 5 + 11 + 17, encr__bu8 + 5 + 11 + 17, 1));
  FLEA_CCALL(THR_flea_ae_ctx_t__update_encryption(&ctx__t, pt__pcu8 + 5 + 11 + 17 + 1, encr__bu8 + 5 + 11 + 17 + 1, pt_len__dtl - (5 + 11 + 17 + 1)));
  if(memcmp(exp_ct__pcu8, encr__bu8, exp_ct_len__dtl))
  {
    FLEA_THROW("error with AE encrypted value", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CCALL(THR_flea_ae_ctx_t__final_encryption(&ctx__t, tag__bu8, &tag_len__alu8));
  if(tag_len__alu8 != exp_tag_len__dtl)
  {
    FLEA_THROW("error with AE tag length", FLEA_ERR_FAILED_TEST);
  }
  if(memcmp(exp_tag__pcu8, tag__bu8, exp_tag_len__dtl))
  {
    FLEA_THROW("error with AE tag value", FLEA_ERR_FAILED_TEST);
  }

  this_decr_len__dtl = pt_len__dtl;
  decr_ptr__pu8 = decr__bu8;
  FLEA_CCALL(THR_flea_ae_ctx_t__update_decryption(&decr_ctx__t, encr__bu8, 1, decr_ptr__pu8, &this_decr_len__dtl));
  decr_ptr__pu8 += this_decr_len__dtl;
  decr_len__dtl -= this_decr_len__dtl;
  this_decr_len__dtl = decr_len__dtl;
  FLEA_CCALL(THR_flea_ae_ctx_t__update_decryption(&decr_ctx__t, encr__bu8 + 1, 16, decr_ptr__pu8, &this_decr_len__dtl));
  decr_ptr__pu8 += this_decr_len__dtl;
  decr_len__dtl -= this_decr_len__dtl;
  this_decr_len__dtl = decr_len__dtl;
  FLEA_CCALL(THR_flea_ae_ctx_t__update_decryption(&decr_ctx__t, encr__bu8 + 1 + 16, 14, decr_ptr__pu8, &this_decr_len__dtl));
  decr_ptr__pu8 += this_decr_len__dtl;
  decr_len__dtl -= this_decr_len__dtl;
  this_decr_len__dtl = decr_len__dtl;
  FLEA_CCALL(THR_flea_ae_ctx_t__update_decryption(&decr_ctx__t, encr__bu8 + 1 + 16 + 14, 1, decr_ptr__pu8, &this_decr_len__dtl));
  decr_ptr__pu8 += this_decr_len__dtl;
  decr_len__dtl -= this_decr_len__dtl;
  this_decr_len__dtl = decr_len__dtl;
  FLEA_CCALL(THR_flea_ae_ctx_t__update_decryption(&decr_ctx__t, encr__bu8 + 1 + 16 + 14 + 1, 1, decr_ptr__pu8, &this_decr_len__dtl));
  decr_ptr__pu8 += this_decr_len__dtl;
  decr_len__dtl -= this_decr_len__dtl;
  // process the remaining ciphertext
  this_decr_len__dtl = decr_len__dtl;
  FLEA_CCALL(THR_flea_ae_ctx_t__update_decryption(&decr_ctx__t, encr__bu8 + 1 + 16 + 14 + 1 + 1, pt_len__dtl - (1 + 16 + 14 + 1 + 1), decr_ptr__pu8, &this_decr_len__dtl));
  decr_ptr__pu8 += this_decr_len__dtl;
  decr_len__dtl -= this_decr_len__dtl;
  this_decr_len__dtl = decr_len__dtl;
  FLEA_CCALL(THR_flea_ae_ctx_t__update_decryption(&decr_ctx__t, tag__bu8, tag_len__alu8, decr_ptr__pu8, &this_decr_len__dtl ));
  if(decr_ptr__pu8 + this_decr_len__dtl != decr__bu8 + pt_len__dtl)
  {
    FLEA_THROW("error with length in AE decryption", FLEA_ERR_FAILED_TEST);
  }
  if(memcmp(decr__bu8, pt__pcu8, pt_len__dtl))
  {
    FLEA_THROW("error with AE decrypted value", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CCALL(THR_flea_ae_ctx_t__final_decryption(&decr_ctx__t));

  // now test with invalid tag
  decr_len__dtl = pt_len__dtl;
  FLEA_CCALL(THR_flea_ae_ctx_t__update_decryption(&decr2_ctx__t, encr__bu8, pt_len__dtl, decr__bu8, &decr_len__dtl));
  decr_ptr__pu8 = decr__bu8 + decr_len__dtl;
  decr_len__dtl = pt_len__dtl - decr_len__dtl;
  if(encr__bu8[0] & 1)
  {
    tag__bu8[tag_len__alu8 - 1] ^= 0x01;
  }
  else
  {
    tag__bu8[0] ^= 0x01;
  }
  FLEA_CCALL(THR_flea_ae_ctx_t__update_decryption(&decr2_ctx__t, tag__bu8, tag_len__alu8, decr_ptr__pu8, &decr_len__dtl ));
  if(FLEA_ERR_INV_MAC != THR_flea_ae_ctx_t__final_decryption(&decr2_ctx__t))
  {
    FLEA_THROW("manipulated MAC not detected", FLEA_ERR_FAILED_TEST);
  }

  FLEA_THR_FIN_SEC(
    flea_ae_ctx_t__dtor(&ctx__t);
    flea_ae_ctx_t__dtor(&decr_ctx__t);
    flea_ae_ctx_t__dtor(&decr2_ctx__t);
    FLEA_FREE_BUF_FINAL(encr__bu8);
    FLEA_FREE_BUF_FINAL(decr__bu8);
    FLEA_FREE_BUF_FINAL(tag__bu8);
    );

}

static flea_err_t THR_flea_test_ae_inner_update (flea_ae_id_t id__t, const flea_u8_t* key__pcu8, flea_dtl_t key_len__dtl, const flea_u8_t* nonce__pcu8, flea_dtl_t nonce_len__dtl, const flea_u8_t* pt__pcu8, flea_dtl_t pt_len__dtl, const flea_u8_t* exp_tag__pcu8, flea_dtl_t exp_tag_len__dtl, const flea_u8_t* exp_ct__pcu8, flea_dtl_t exp_ct_len__dtl, const flea_u8_t* assoc_data__pcu8, flea_dtl_t assoc_data_len__dtl, flea_al_u16_t tag_len__alu16 )
{
  flea_al_u8_t tag_len__alu8;
  flea_dtl_t decr_len__dtl;
  flea_u8_t* decr_ptr__pu8;
  flea_ae_ctx_t ctx__t = flea_ae_ctx_t__INIT_VALUE;
  flea_ae_ctx_t decr_ctx__t = flea_ae_ctx_t__INIT_VALUE;
  flea_ae_ctx_t decr2_ctx__t = flea_ae_ctx_t__INIT_VALUE;

  FLEA_DECL_BUF(encr__bu8, flea_u8_t, TEST_MAX_CT_LEN);
  FLEA_DECL_BUF(decr__bu8, flea_u8_t, TEST_MAX_CT_LEN);
  FLEA_DECL_BUF(tag__bu8, flea_u8_t, FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH);
  FLEA_THR_BEG_FUNC();

  if((pt_len__dtl > TEST_MAX_CT_LEN) || (pt_len__dtl != exp_ct_len__dtl))
  {
    FLEA_THROW("error in AE test code", FLEA_ERR_INT_ERR);
  }

  FLEA_ALLOC_BUF(encr__bu8, pt_len__dtl);
  FLEA_ALLOC_BUF(decr__bu8, pt_len__dtl);
  decr_len__dtl = pt_len__dtl;
  FLEA_CCALL(THR_flea_ae_ctx_t__ctor(&ctx__t, id__t, key__pcu8, key_len__dtl, nonce__pcu8, nonce_len__dtl, assoc_data__pcu8, assoc_data_len__dtl, tag_len__alu16));
  FLEA_CCALL(THR_flea_ae_ctx_t__ctor(&decr_ctx__t, id__t, key__pcu8, key_len__dtl, nonce__pcu8, nonce_len__dtl, assoc_data__pcu8, assoc_data_len__dtl, tag_len__alu16));
  FLEA_CCALL(THR_flea_ae_ctx_t__ctor(&decr2_ctx__t, id__t, key__pcu8, key_len__dtl, nonce__pcu8, nonce_len__dtl, assoc_data__pcu8, assoc_data_len__dtl, tag_len__alu16));

  tag_len__alu8 = ctx__t.tag_len__u8;
  FLEA_ALLOC_BUF(tag__bu8, tag_len__alu8);
  FLEA_CCALL(THR_flea_ae_ctx_t__update_encryption(&ctx__t, pt__pcu8, encr__bu8, pt_len__dtl));
  if(memcmp(exp_ct__pcu8, encr__bu8, exp_ct_len__dtl))
  {
    FLEA_THROW("error with AE encrypted value", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CCALL(THR_flea_ae_ctx_t__final_encryption(&ctx__t, tag__bu8, &tag_len__alu8));
  if(tag_len__alu8 != exp_tag_len__dtl)
  {
    FLEA_THROW("error with AE tag length", FLEA_ERR_FAILED_TEST);
  }
  if(memcmp(exp_tag__pcu8, tag__bu8, exp_tag_len__dtl))
  {
    FLEA_THROW("error with AE tag value", FLEA_ERR_FAILED_TEST);
  }

  FLEA_CCALL(THR_flea_ae_ctx_t__update_decryption(&decr_ctx__t, encr__bu8, pt_len__dtl, decr__bu8, &decr_len__dtl));
  decr_ptr__pu8 = decr__bu8 + decr_len__dtl;
  decr_len__dtl = pt_len__dtl - decr_len__dtl;
  FLEA_CCALL(THR_flea_ae_ctx_t__update_decryption(&decr_ctx__t, tag__bu8, tag_len__alu8, decr_ptr__pu8, &decr_len__dtl ));
  if(decr_ptr__pu8 + decr_len__dtl != decr__bu8 + pt_len__dtl)
  {
    FLEA_THROW("error with length in AE decryption", FLEA_ERR_FAILED_TEST);
  }
  if(memcmp(decr__bu8, pt__pcu8, pt_len__dtl))
  {
    FLEA_THROW("error with AE decrypted value", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CCALL(THR_flea_ae_ctx_t__final_decryption(&decr_ctx__t));

  // now test with invalid tag
  decr_len__dtl = pt_len__dtl;
  FLEA_CCALL(THR_flea_ae_ctx_t__update_decryption(&decr2_ctx__t, encr__bu8, pt_len__dtl, decr__bu8, &decr_len__dtl));
  decr_ptr__pu8 = decr__bu8 + decr_len__dtl;
  decr_len__dtl = pt_len__dtl - decr_len__dtl;
  if((pt_len__dtl != 0) && (encr__bu8[0] & 1))
  {
    tag__bu8[tag_len__alu8 - 1] ^= 0x01;
  }
  else
  {
    tag__bu8[0] ^= 0x01;
  }
  FLEA_CCALL(THR_flea_ae_ctx_t__update_decryption(&decr2_ctx__t, tag__bu8, tag_len__alu8, decr_ptr__pu8, &decr_len__dtl ));
  if(FLEA_ERR_INV_MAC != THR_flea_ae_ctx_t__final_decryption(&decr2_ctx__t))
  {
    FLEA_THROW("manipulated MAC not detected", FLEA_ERR_FAILED_TEST);
  }

  FLEA_THR_FIN_SEC(
    flea_ae_ctx_t__dtor(&ctx__t);
    flea_ae_ctx_t__dtor(&decr_ctx__t);
    flea_ae_ctx_t__dtor(&decr2_ctx__t);
    FLEA_FREE_BUF_FINAL(encr__bu8);
    FLEA_FREE_BUF_FINAL(decr__bu8);
    FLEA_FREE_BUF_FINAL(tag__bu8);
    );

}
static flea_err_t THR_flea_test_ae_inner (flea_ae_id_t id__t, const flea_u8_t* key__pcu8, flea_dtl_t key_len__dtl, const flea_u8_t* nonce__pcu8, flea_dtl_t nonce_len__dtl, const flea_u8_t* pt__pcu8, flea_dtl_t pt_len__dtl, const flea_u8_t* exp_tag__pcu8, flea_dtl_t exp_tag_len__dtl, const flea_u8_t* exp_ct__pcu8, flea_dtl_t exp_ct_len__dtl, const flea_u8_t* assoc_data__pcu8, flea_dtl_t assoc_data_len__dtl, flea_al_u16_t tag_len__alu16 )
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_test_ae_inner_update(id__t, key__pcu8, key_len__dtl, nonce__pcu8, nonce_len__dtl, pt__pcu8, pt_len__dtl, exp_tag__pcu8, exp_tag_len__dtl, exp_ct__pcu8, exp_ct_len__dtl, assoc_data__pcu8, assoc_data_len__dtl, tag_len__alu16));
  FLEA_CCALL(THR_flea_test_ae_inner_update__vary_update_lengths(id__t, key__pcu8, key_len__dtl, nonce__pcu8, nonce_len__dtl, pt__pcu8, pt_len__dtl, exp_tag__pcu8, exp_tag_len__dtl, exp_ct__pcu8, exp_ct_len__dtl, assoc_data__pcu8, assoc_data_len__dtl, tag_len__alu16));
  FLEA_CCALL(THR_flea_test_ae_inner_convenience_funcs(id__t, key__pcu8, key_len__dtl, nonce__pcu8, nonce_len__dtl, pt__pcu8, pt_len__dtl, exp_tag__pcu8, exp_tag_len__dtl, exp_ct__pcu8, exp_ct_len__dtl, assoc_data__pcu8, assoc_data_len__dtl, tag_len__alu16));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_test_ae ()
{

  const flea_u8_t flea_eax_aes128_key_1[] = { 0xC6, 0x1A, 0x08, 0x51, 0xAB, 0x4E, 0x51, 0x5D, 0x11, 0x52, 0x5B, 0x92, 0xE2, 0xB9, 0xD8, 0x50 };
  const flea_u8_t flea_eax_aes128_nonce_1[] = { 0xC8, 0x25, 0xFC, 0x7C, 0x4D, 0x53, 0x9D, 0xC7, 0x48, 0x87, 0xCE, 0xCC, 0x70, 0x88, 0x4F, 0x37 };
  const flea_u8_t flea_eax_aes128_exp_tag_1 [] = { 0x32, 0xE5, 0x5C, 0xE0, 0xC3, 0xFA, 0xEA, 0x48, 0x16, 0x4B, 0x12, 0x2C, 0x1B, 0xE2, 0x2D, 0x85 };

  //====================================

  const flea_u8_t flea_eax_aes128_key_2[] = { 0xF9, 0x56, 0xB8, 0x79, 0xEC, 0x7F, 0x80, 0x7F, 0x1F, 0xCB, 0x48, 0x2B, 0x53, 0x62, 0x36, 0x71 };
  const flea_u8_t flea_eax_aes128_nonce_2[] = { 0xE6, 0x4F, 0x90, 0xB4, 0x61, 0x9D, 0x93, 0x13, 0x7E, 0x62, 0x37, 0x92, 0x9E, 0xAB, 0xF2, 0x97 };
  const flea_u8_t flea_eax_aes128_pt_2[] = { 0x60 };
  const flea_u8_t flea_eax_aes128_exp_ct_2[] = { 0x71 };
  const flea_u8_t flea_eax_aes128_exp_tag_2 [] = { 0x0D, 0xAB, 0xD2, 0x4D, 0x40, 0x0F, 0x3B, 0x6B, 0x28, 0x4E, 0xA4, 0x7F, 0x81, 0xEB, 0xBD, 0x26 };

  //====================================

  const flea_u8_t flea_eax_aes128_key_4[] = { 0x25, 0x1A, 0xD4, 0x94, 0xD6, 0x4D, 0xAB, 0x08, 0xB6, 0x6A, 0x96, 0xCB, 0x8C, 0x78, 0x76, 0xA6  };
  const flea_u8_t flea_eax_aes128_nonce_4[] = { 0xF8, 0x7A, 0x82, 0x5C, 0x39, 0x32, 0x69, 0x49, 0xEB, 0x19, 0xEE, 0x5B, 0xD3, 0x0C, 0xCB, 0xF9 };
  const flea_u8_t flea_eax_aes128_pt_4[] = {
    0xE4, 0xBF, 0x7D, 0x59, 0x42, 0x28, 0xD3, 0xCB, 0x4D, 0x7E, 0x9E, 0xC6, 0x39, 0x7D, 0xB3, 0x32, 0x5B, 0x61, 0xD7, 0xC1, 0x43, 0x7D, 0x06, 0x34, 0xC6, 0x2F, 0xC3, 0x3D, 0x9B, 0x93, 0x2B, 0x7F, 0x52, 0xA8, 0xD8, 0x94, 0xD0, 0xAB, 0x60, 0x1E, 0x29, 0xFE, 0xE4, 0x63, 0x7B, 0x97, 0x95, 0xD7, 0xF9, 0x6D, 0x98, 0x3C, 0xEA, 0x9E, 0x70, 0xB0, 0xCD, 0x33, 0xEE, 0x68, 0xC6, 0x19, 0xE7, 0x18, 0xC1, 0xC0, 0xAD, 0x91, 0x6B, 0x0D, 0xAF, 0x95, 0x0B, 0x93, 0xF8, 0x87, 0x2B, 0x8D, 0x5E, 0x24, 0xFA, 0xF6, 0x60, 0xE4, 0x94, 0xD0, 0x95, 0x61, 0x04, 0x83, 0xCA, 0xCA, 0x9C, 0xB1, 0xE3, 0x5D, 0x71, 0x90, 0xEE, 0xDD, 0x9D, 0x9E, 0x72, 0xA8, 0x31, 0x6A, 0x2F, 0x5C, 0xF7, 0x8D, 0x80, 0xF2, 0x83, 0xE0, 0xD6, 0x17, 0xB1, 0x6B, 0x79, 0xB5, 0xEE, 0x43, 0x7F, 0x8A, 0xF4, 0x62, 0xE7, 0x66, 0xF2, 0xD6, 0x43, 0x8F, 0x74, 0xB5, 0x38, 0xA5, 0x1F, 0x67, 0x02, 0x16, 0xF5, 0x82, 0x08, 0x78, 0x63, 0xDF, 0x90, 0x14, 0x4A, 0x09, 0xC9, 0x39, 0x4C, 0x48, 0xC3, 0x40, 0xAB, 0xAB, 0xA6, 0x9D, 0x81, 0xE9, 0x2D, 0xF5, 0x9E, 0x65, 0x9A, 0xBD, 0xCC, 0x9C, 0xD4, 0xC1, 0x1F, 0xDC, 0x3A, 0x82, 0xBB, 0xCA, 0x96, 0x06, 0xD3, 0x5F, 0x3F, 0x1F, 0xA7, 0x02, 0x5F, 0x52, 0xAD, 0x06, 0xF0, 0x2E, 0xEF, 0x1D, 0x23, 0x8E, 0x82, 0xBE, 0x4B, 0x4E, 0x5A, 0x1F, 0x10, 0x79, 0xFC, 0x4A, 0xFB, 0xB7, 0x14, 0x91, 0xBD, 0xE7, 0xF0, 0xFC, 0x06, 0x98, 0xFF, 0x65, 0xEA, 0xAC, 0x6B, 0xDA, 0xDB, 0x5B, 0xF7, 0xFE, 0xE9, 0x79, 0xBC, 0x34, 0xC8, 0x17, 0x54, 0xD8, 0x90, 0x50, 0x22, 0x8C, 0x07, 0x36, 0x1D, 0xC5, 0x1D, 0x0E, 0xC1, 0x23, 0xA6, 0xC0, 0x88, 0x90, 0x6D, 0xF4, 0x6B, 0x48, 0x4F, 0x62, 0x46, 0x38, 0xDC, 0x03, 0x6C, 0xA4, 0x1A, 0xC0, 0x7C, 0xAA, 0x10, 0x9E, 0x36, 0x18, 0xD4, 0x54, 0xDD, 0xF1, 0x62, 0x9E, 0x14, 0x08, 0x5F, 0x9C, 0x98, 0xCC, 0x90, 0x03, 0x14, 0xDF, 0x66, 0x5A, 0x17, 0x42, 0x5D, 0x84, 0xE6, 0x77, 0x44, 0x62, 0x22, 0x55, 0x00, 0x58, 0x6D, 0xD4, 0xAC, 0x4A, 0xC5, 0x0E, 0xE8, 0xD9, 0x16, 0x47, 0x75, 0xAF, 0x13, 0x06, 0xB2, 0x27, 0xE5, 0x18, 0x82, 0xFD, 0x5A, 0xDF, 0x81, 0x40, 0x57, 0xC5, 0xA2, 0x79, 0x1A, 0xA2, 0xD1, 0x87, 0x76, 0x7E, 0xD1, 0x3B, 0x8C, 0xBA, 0x14, 0xA3, 0x01, 0x8A, 0x52, 0x15, 0x90, 0x04, 0x3C, 0x75, 0x1D, 0xBE, 0x72, 0x77, 0x9E, 0xF3, 0xB8, 0xF5, 0xB9, 0x5A, 0x6E, 0xD3, 0xFD, 0x3F, 0x5B, 0x73, 0xBD, 0x2C, 0xAF, 0x4A, 0xE6, 0xC3, 0xED, 0xE8, 0x4D, 0x3F, 0xFD, 0xDD, 0x43, 0x39, 0x53, 0x60, 0xF8, 0xC5, 0xD8, 0x96, 0xB9, 0x90, 0x8B, 0x72, 0xEA, 0xF9, 0x45, 0xE7, 0x38, 0xA0, 0x5B, 0xF6, 0xCD, 0x0A, 0x40, 0xB3, 0xCD, 0x2D, 0x9B, 0x1B, 0x6C, 0x98, 0xF8, 0xAF, 0xD2, 0x4B, 0x10, 0xCA, 0x11, 0xE8, 0x60, 0xCA, 0x78, 0xEB, 0x3C, 0x62, 0xE4, 0x81, 0x4A, 0x1C, 0x22, 0xA5, 0x12, 0xEF, 0xAF, 0x52, 0xA2, 0x7C, 0x7F, 0x3E, 0x97, 0xEB, 0xD6, 0x90, 0x9B, 0xA8, 0xDB, 0xAB, 0x72, 0xEC, 0x93, 0xD2, 0xB6, 0x0B, 0xBD, 0xF2, 0x6D, 0xA1, 0x74, 0xB7, 0xBE, 0x96, 0x5C, 0xD0, 0x85, 0x0B, 0x23, 0x27, 0x88, 0xA2, 0x65, 0x1F, 0x8E, 0x3C, 0xAF, 0x29, 0xE4, 0x8B, 0xD4, 0x57, 0x77, 0x67, 0x29, 0x2E, 0x72, 0xE7, 0x20, 0xDF, 0x88, 0x94, 0x97, 0x46, 0x2A, 0xF3, 0x17, 0xAF, 0xFF, 0x3A, 0xD7, 0x87, 0xDC, 0x3C, 0xA6, 0x6A, 0x78, 0x56, 0x93, 0x5D, 0xE1, 0x67, 0xB4, 0x58, 0xCE, 0xDD, 0x86, 0x40, 0xC4, 0xA7,
    0x20, 0x4D, 0x3B, 0xB7, 0x93, 0x66, 0xAA, 0xAA, 0x15, 0xA9, 0xE4, 0xEC, 0x30, 0xC1, 0x29, 0xD7, 0x2B, 0xA1, 0x2D, 0xBF, 0xFE, 0x0E, 0x26, 0xB2, 0x66, 0xF5, 0x90, 0xED, 0x35, 0x54, 0x94, 0x55, 0xA1, 0xCF, 0x0C, 0x35, 0x35, 0xB7, 0xDF, 0x4B, 0x60, 0xC4, 0x37, 0x91, 0x85, 0x60, 0x68, 0xB0, 0x02, 0x95, 0x6F, 0x00, 0xA3, 0x96, 0xB3, 0x09, 0x8B, 0x43, 0xF6, 0xC0, 0x97, 0x8A, 0x16, 0x39, 0x5A, 0x22, 0x6E, 0x8F, 0xD9, 0x4D, 0xDA, 0x3A, 0x11, 0x12, 0xCB, 0x96, 0x72, 0x33, 0x47, 0x74, 0xC8, 0xB6, 0x75, 0x6B, 0x4C, 0x28, 0x74, 0xD7, 0x6B, 0x6B, 0x98, 0x02, 0xF5, 0xAE, 0x3B, 0x4F, 0xD0, 0xA9, 0xDF, 0xAA, 0xF7, 0xB9, 0xE4, 0x08, 0xCB, 0xAF, 0x9F, 0x3E, 0xE2, 0xE6, 0xB2, 0xAA, 0x9C, 0x27, 0x15, 0xE9, 0x4F, 0x89, 0xC0, 0xBA, 0xF4, 0x58, 0xBD, 0xEA, 0x06, 0xF8, 0x39, 0xD7, 0xA2, 0x18, 0x81, 0x99, 0xD2, 0x65, 0xA1, 0x9D, 0x14, 0x40, 0xDB, 0xF6, 0x26, 0x8E, 0xA0, 0xC3, 0xB5, 0xB5, 0xAC, 0x05, 0x3E, 0x6C, 0xBF, 0x33, 0xC5, 0x7C, 0x1D, 0xCB, 0x75, 0x56, 0xA2, 0x17, 0x6F, 0x23, 0xB0, 0x41, 0x88, 0x51, 0xDE, 0x9C, 0x92, 0xBA, 0x92, 0xB8, 0x48, 0x32, 0x7B, 0xFD, 0xE7, 0x27, 0x02, 0x26, 0x94, 0xC2, 0x59, 0x59, 0x3E, 0x76, 0x24, 0xB3, 0xCC, 0xC7, 0xCA, 0x3B, 0xEA, 0x7A, 0x7C, 0x73, 0xCC, 0x5B, 0x0F, 0x5E, 0x15, 0xA2, 0x16, 0x5D, 0xD4, 0x92, 0x5A, 0xBC, 0xB9, 0x5D, 0xE2, 0x4D, 0x1F, 0x3B, 0xA6, 0x5D, 0xB1, 0xCB, 0x11, 0x7D, 0x92, 0xDB, 0xB9, 0x7C, 0x56, 0x35, 0xEF, 0x22, 0x90, 0xFF, 0x80, 0xA5, 0xA1, 0x96, 0x02, 0x75, 0x28, 0x5D, 0x31, 0xE2, 0xBA, 0x13, 0x2F, 0xD9, 0x4E, 0xD6, 0x36, 0xFF, 0xA1, 0x47, 0x7D, 0x33, 0x23, 0x36, 0xAF, 0x79, 0x6B, 0x9F, 0x9B, 0xFC, 0x9E, 0x1B, 0xA1, 0x3F, 0xB1, 0xA4, 0xB4, 0xDA, 0x01, 0xE6, 0xBC, 0xBB, 0xF9, 0xEB, 0x94, 0x48, 0xC1, 0xCA, 0x47, 0x62, 0x12, 0xC4, 0x95, 0x35, 0xFA, 0x45, 0xAE, 0x66, 0xE4, 0x49, 0x62, 0x82, 0x64, 0x03, 0xC1, 0x15, 0xA7, 0x75, 0xEF, 0xA8, 0x5B, 0xAB, 0x63, 0x55, 0x97, 0xF7, 0x9D, 0x58, 0xC2, 0xE4, 0xBB, 0xD4, 0xA9, 0x50, 0x09, 0xA3, 0x95, 0xB7, 0x09, 0x79, 0x00, 0x6B, 0xFB, 0x64, 0x6F, 0xBC, 0x79, 0x16, 0x32, 0x69, 0xBF, 0x8D, 0x14, 0x22, 0xE2, 0xAB, 0x1A, 0x7F, 0x04, 0xDC, 0x64, 0xBF, 0xB0, 0x0D, 0x0F, 0xB9, 0xB0, 0xA5, 0x70, 0xBA, 0x1E, 0x70
  };

  const flea_u8_t flea_eax_aes128_exp_ct_4[] = {
    0xC4, 0x37, 0x72, 0x3C, 0x80, 0xE3, 0xB3, 0x2A, 0xEE, 0xBD, 0x6D, 0xDE, 0x08, 0xD6, 0x14, 0x31, 0x2C, 0xD3, 0x17, 0x6E, 0x8B, 0xFA, 0x86, 0x50, 0xEA, 0xF3, 0xA3, 0x4D, 0xAE, 0x3B, 0x72, 0x76, 0x9F, 0x82, 0x3B, 0xC4, 0x8F, 0x88, 0xF4, 0x2A, 0xFC, 0xBB, 0xBD, 0xDA, 0x05, 0x34, 0xE8, 0xD2, 0xC9, 0xBA, 0xB6, 0x5A, 0x83, 0x93, 0x96, 0x68, 0xC9, 0x82, 0xA1, 0xCB, 0xC1, 0xB8, 0x26, 0xB2, 0x59, 0xD8, 0x3F, 0xD6, 0x50, 0x53, 0x81, 0xBA, 0x99, 0xB1, 0xC8, 0x50, 0xD5, 0xEF, 0xB5, 0xD0, 0xDB, 0xB0, 0x77, 0xF4, 0xAB, 0x02, 0x12, 0x46, 0x36, 0x62, 0x92, 0x97, 0x1B, 0xE1, 0x21, 0xC2, 0x65, 0xBC, 0xAB, 0x72, 0x2A, 0x6A, 0xB5, 0xB7, 0xCB, 0x7D, 0x55, 0xC9, 0x1F, 0x9F, 0xD5, 0xB3, 0xBD, 0x59, 0xA8, 0x43, 0x62, 0x50, 0xF1, 0x7D, 0x11, 0x0B, 0x5B, 0x25, 0x88, 0xF2, 0xDA, 0xCC, 0x98, 0xEE, 0x60, 0x88, 0x44, 0x36, 0x81, 0x05, 0x70, 0xA6, 0x1A, 0xF2, 0xD7, 0xA4, 0x24, 0xD4, 0xD5, 0x97, 0x00, 0x4D, 0x17, 0x5B, 0x65, 0x0F, 0x9E, 0xDE, 0x8D, 0x25, 0x44, 0x97, 0x49, 0x09, 0x05, 0xE5, 0xAF, 0xFD, 0x31, 0xDB, 0xC4, 0xFA, 0xE7, 0xEE, 0xF1, 0x80, 0xB0, 0x7B, 0x7D, 0x9D, 0x25, 0x79, 0xC1, 0xA1, 0x40, 0xF6, 0x3F, 0x31, 0xB0, 0xA2, 0x84, 0x70, 0x43, 0xFE, 0x6F, 0x98, 0x55, 0x6A, 0x3F, 0x90, 0xDE, 0x4C, 0x28, 0xF8, 0x58, 0x58, 0x1F, 0x69, 0x9E, 0xD3, 0xB6, 0xE3, 0xE5, 0x54, 0xDD, 0x0F, 0xE9, 0x19, 0x54, 0xFC, 0x06, 0x7B, 0xAB, 0xC6, 0xAC, 0x62, 0xE3, 0x14, 0x57, 0xB2, 0x99, 0xB9, 0xCF, 0x5E, 0x06, 0x1A, 0x9B, 0x6E, 0xD6, 0x28, 0xDF, 0xBD, 0xC1, 0x64, 0xAF, 0xB6, 0x56, 0x08, 0x47, 0x38, 0x9E, 0xE0, 0x25, 0x7A, 0x7C, 0xDE, 0x81, 0x12, 0x92, 0xBC, 0x76, 0x1E, 0x4D, 0x66, 0xD2, 0xCD, 0xED, 0xD2, 0xC6, 0xDE, 0x03, 0x33, 0xCF, 0x8E, 0xD6, 0x68, 0x21, 0x85, 0xAD, 0x5B, 0x6B, 0x1B, 0x05, 0x52, 0x63, 0x38, 0xC6, 0xEF, 0x72, 0xD0, 0x2A, 0x03, 0x46, 0xC4, 0x52, 0x7C, 0xCB, 0x3B, 0x1E, 0x34, 0x84, 0xB8, 0x3F, 0xC7, 0xAF, 0xC7, 0xBF, 0xA6, 0x9B, 0x11, 0x19, 0x80, 0xFD, 0xC5, 0x3C, 0x70, 0xBE, 0x72, 0xF3, 0xBA, 0x7F, 0x8B, 0x51, 0xA3, 0x63, 0xCD, 0x59, 0x0A, 0x98, 0x8A, 0xEE, 0xCA, 0x67, 0x26, 0x5C, 0x9B, 0xB8, 0x13, 0x14, 0x2F, 0x34, 0xD0, 0xB2, 0xFD, 0x20, 0xB0, 0x6F, 0x39, 0xC4, 0xDE, 0x7A, 0x00, 0xD7, 0x63, 0xE2, 0xB2, 0x01, 0xD9, 0x0A, 0x8F, 0xFC, 0xD1, 0x99, 0xED, 0xE6, 0x0E, 0xFF, 0xFC, 0x0C, 0xAB, 0xB6, 0x48, 0xC1, 0xD7, 0xF1, 0x53, 0x23, 0xF0, 0xE9, 0xBC, 0x13, 0xEA, 0xBD, 0x1E, 0xBE, 0x99, 0xBC, 0xBF, 0x97, 0x0D, 0x0A, 0xF2, 0x50, 0x18, 0x26, 0xE3, 0x7D, 0x22, 0x2E, 0xF4, 0xD9, 0xAF, 0xAB, 0x22, 0xEE, 0x99, 0x97, 0x2F, 0x2A, 0x97, 0xC8, 0x41, 0x75, 0xAA, 0xA4, 0x9E, 0xD2, 0xCE, 0xAF, 0x34, 0x02, 0x13, 0xE2, 0x9C, 0x7A, 0x88, 0xAF, 0x38, 0xF2, 0xCA, 0xD4, 0x2C, 0x2A, 0xF4, 0x99, 0x37, 0x26, 0x2F, 0x32, 0x81, 0xB8, 0x06, 0xE3, 0x43, 0xAF, 0x3E, 0xD0, 0xC7, 0x53, 0x57, 0x25, 0xA5, 0xAD, 0x0C, 0xAC, 0xBE, 0xDF, 0x51, 0x9F, 0x69, 0xCF, 0x82, 0x09, 0x80, 0x16, 0x9F, 0xD6, 0xDB, 0x67, 0xA1, 0x65, 0xF3, 0x88, 0x32, 0x16, 0xE2, 0x27, 0xB0, 0x7E, 0x3F, 0xAC, 0xB1, 0xE2, 0x79, 0x54, 0xFD, 0x1D, 0x08, 0xA2, 0xEC, 0x64, 0x72, 0xB0, 0xB1, 0xF7, 0xB0, 0xD6, 0xAF, 0xA2, 0xC6, 0x16, 0xF6, 0x20, 0x7E, 0x7A, 0x2C, 0x44, 0x44, 0xC6, 0xF9, 0x52, 0x26, 0x8B, 0xF7, 0x3E, 0xDB,
    0xEB, 0x46, 0x57, 0xAF, 0x47, 0x2D, 0x08, 0xBA, 0xEA, 0xFB, 0x23, 0x7F, 0x11, 0x8E, 0xED, 0x6C, 0xAC, 0xD8, 0x0E, 0x24, 0xAB, 0xEA, 0xED, 0x97, 0xD1, 0x63, 0x43, 0x67, 0x00, 0x07, 0x78, 0xC0, 0xE0, 0x95, 0x99, 0x47, 0x98, 0x00, 0x6D, 0x87, 0x49, 0x99, 0xE5, 0x42, 0xF5, 0xF4, 0x79, 0xE0, 0x8A, 0xD4, 0x81, 0xD2, 0x11, 0xA7, 0xA4, 0xD5, 0x1D, 0x58, 0xCF, 0xDC, 0x37, 0x44, 0x14, 0xF6, 0x81, 0x0A, 0x5A, 0xE0, 0x85, 0x73, 0xA3, 0x4D, 0x91, 0x4B, 0xE3, 0x17, 0x6C, 0xE7, 0xC3, 0x69, 0x9D, 0x83, 0xA0, 0x6F, 0xB9, 0xD8, 0x58, 0x5A, 0x03, 0x85, 0x4C, 0xC3, 0x8B, 0x8C, 0xFD, 0xF5, 0xCD, 0xD7, 0xC8, 0x88, 0x79, 0x0A, 0x04, 0xD2, 0xE7, 0xF2, 0xD2, 0x20, 0x99, 0xA9, 0x12, 0x0C, 0xE0, 0xC3, 0x73, 0x90, 0xB9, 0xAD, 0x91, 0x8A, 0xD0, 0xB4, 0x1C, 0x42, 0x39, 0xD2, 0xBB, 0xBA, 0xB8, 0x2B, 0x98, 0xE5, 0x99, 0x20, 0xB1, 0x73, 0xBC, 0xCD, 0xE0, 0xD4, 0x8F, 0xF8, 0x60, 0xF9, 0x12, 0x16, 0xC4, 0xA7, 0xE6, 0x8E, 0x05, 0xDA, 0xF7, 0xF5, 0x3E, 0xB7, 0x64, 0x11, 0x71, 0xD1, 0x83, 0xC9, 0x76, 0xC6, 0xB9, 0xCF, 0x1F, 0x57, 0xB2, 0xE4, 0x8F, 0x88, 0xBD, 0x5E, 0x8F, 0x55, 0x58, 0x93, 0x42, 0x45, 0xCB, 0xFB, 0xEE, 0x36, 0x5A, 0x2D, 0x45, 0x7B, 0x2E, 0xA5, 0xE6, 0xCD, 0x0F, 0x39, 0xAA, 0xA1, 0x54, 0x69, 0x2E, 0xB6, 0x04, 0xB2, 0xA3, 0x66, 0xB5, 0x3C, 0x58, 0x93, 0xC0, 0x45, 0x68, 0xBA, 0x98, 0xB4, 0xA0, 0xAF, 0xA8, 0xB6, 0xDB, 0x80, 0xC6, 0xD6, 0x6E, 0x9C, 0x93, 0xDF, 0xFB, 0x1B, 0xE5, 0x84, 0xED, 0x1C, 0xC1, 0x11, 0xD3, 0x15, 0x82, 0x3F, 0x25, 0xD6, 0xBF, 0xF9, 0x36, 0x7E, 0xA5, 0x84, 0xA3, 0xA0, 0xFC, 0x62, 0x78, 0x8D, 0x7D, 0x38, 0x5D, 0x08, 0x14, 0xE9, 0x84, 0xE6, 0xEE, 0x55, 0x6F, 0x83, 0xD0, 0x15, 0x84, 0xC8, 0xDE, 0x06, 0x56, 0xDC, 0x2A, 0x89, 0xA0, 0x8B, 0xBD, 0x26, 0x8F, 0x06, 0x44, 0xC6, 0x3B, 0x80, 0xA5, 0xBE, 0x57, 0xDE, 0xF7, 0x15, 0x66, 0xB6, 0x77, 0x59, 0x65, 0x57, 0xD4, 0xC2, 0x18, 0xDE, 0xC8, 0xA7, 0xD2, 0x61, 0x1F, 0xE6, 0xFA, 0x07, 0x63, 0x3C, 0x55, 0x8F, 0xF3, 0x72, 0x30, 0x8F, 0x5D, 0x68, 0x0C, 0x0F, 0x98, 0x58, 0x36, 0x2C, 0x2B, 0x2B, 0x8C, 0x29, 0x89, 0xF1, 0x9F, 0xD8, 0x41, 0x1C, 0x10, 0xB6, 0xE3, 0x7A, 0x64, 0x7A, 0x07, 0xD0, 0xB1, 0xD5, 0xE6, 0x81, 0xE2, 0x59, 0x02, 0xC3, 0x62, 0x31
  };
  const flea_u8_t flea_eax_aes128_exp_tag_4 [] = { 0xE9, 0xE5, 0xE8, 0x12, 0xB6, 0x23, 0xD9, 0xE7, 0x2C, 0x23, 0x51, 0x8F, 0x08, 0x2E, 0xA4, 0x8C };

  //====================================
  // from https://fossies.org/linux/Botan/doc/examples/eax.vec
  const flea_u8_t flea_eax_aes128_key_5[] = { 0x0B, 0x70, 0x00, 0x3E, 0x77, 0x14, 0x6B, 0x90, 0x3F, 0x06, 0xEF, 0x29, 0x4F, 0xEC, 0xD5, 0x17 };
  const flea_u8_t flea_eax_aes128_nonce_5[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F  };
  const flea_u8_t flea_eax_aes128_assoc_5[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F  };
  const flea_u8_t flea_eax_aes128_pt_5[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F  };
  const flea_u8_t flea_eax_aes128_exp_ct_5[] = { 0xC4, 0xBA, 0xD0, 0xE0, 0x35, 0x6F, 0xFD, 0x36, 0x91, 0x10, 0xC0, 0x48, 0xD4, 0x5D, 0x81, 0xBE };
  const flea_u8_t flea_eax_aes128_exp_tag_5 [] = { 0xDE, 0x7C, 0x2B, 0x1D, 0x83, 0xBE, 0x2C, 0xC8, 0xEA, 0x40, 0x2A, 0xBE, 0x10, 0x38, 0xBB, 0x79  };

  //====================================
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_test_ae_inner(flea_eax_aes128, flea_eax_aes128_key_1, sizeof(flea_eax_aes128_key_1), flea_eax_aes128_nonce_1, sizeof(flea_eax_aes128_nonce_1), NULL, 0, flea_eax_aes128_exp_tag_1, sizeof(flea_eax_aes128_exp_tag_1), NULL, 0, NULL, 0, 16));
  FLEA_CCALL(THR_flea_test_ae_inner(flea_eax_aes128, flea_eax_aes128_key_2, sizeof(flea_eax_aes128_key_2), flea_eax_aes128_nonce_2, sizeof(flea_eax_aes128_nonce_2), flea_eax_aes128_pt_2, sizeof(flea_eax_aes128_pt_2), flea_eax_aes128_exp_tag_2, sizeof(flea_eax_aes128_exp_tag_2), flea_eax_aes128_exp_ct_2, sizeof(flea_eax_aes128_exp_ct_2), NULL, 0, 16));
  FLEA_CCALL(THR_flea_test_ae_inner(flea_eax_aes128, flea_eax_aes128_key_4, sizeof(flea_eax_aes128_key_4), flea_eax_aes128_nonce_4, sizeof(flea_eax_aes128_nonce_4), flea_eax_aes128_pt_4, sizeof(flea_eax_aes128_pt_4), flea_eax_aes128_exp_tag_4, sizeof(flea_eax_aes128_exp_tag_4), flea_eax_aes128_exp_ct_4, sizeof(flea_eax_aes128_exp_ct_4), NULL, 0, 16));
  FLEA_CCALL(THR_flea_test_ae_inner(flea_eax_aes128, flea_eax_aes128_key_5, sizeof(flea_eax_aes128_key_5), flea_eax_aes128_nonce_5, sizeof(flea_eax_aes128_nonce_5), flea_eax_aes128_pt_5, sizeof(flea_eax_aes128_pt_5), flea_eax_aes128_exp_tag_5, sizeof(flea_eax_aes128_exp_tag_5), flea_eax_aes128_exp_ct_5, sizeof(flea_eax_aes128_exp_ct_5), flea_eax_aes128_assoc_5, sizeof(flea_eax_aes128_assoc_5), 16));

  FLEA_CCALL(THR_flea_test_ae_init_dtor());

  FLEA_THR_FIN_SEC_empty();
}
#endif // #ifdef FLEA_HAVE_AE
