/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#if 0
#include "internal/common/build_config.h"
#include "flea/types.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "internal/common/tls_ciph_state.h"
#include "flea/error_handling.h"

// performs no length check on key lengths
flea_err_t THR_flea_tls_cipher_state_t__ctor_cbc_hmac(flea_tls_cipher_state_t * state__pt, flea_block_cipher_id_t block_cipher_id, const flea_u8_t * cipher_key__pcu8, flea_al_u8_t cipher_key_len__alu8, flea_mac_id_t hmac_id, const flea_u8_t* mac_key__pcu8, flea_al_u8_t mac_key_len__alu8)
{
 // TODO: add to interface for MAC: reset
 //   for HMAC:
 //     - internal ctor which takes a hash ctx as arg, which already contains the
 //     state after feeding the initial key
 //     - that hash context is stored in tls_cipher_state_t

  // TODO: ENABBLE RESET FUNCTIONS FOR BOTH OBJECTS
 flea_tls_cbc_hmac_ctx_t *ctx__pt = &state__pt->cipher_specific__u.cbc_hmac__t;
FLEA_THR_BEG_FUNC();
#ifdef FLEA_USE_HEAP_BUF
 FLEA_ALLOC_MEM_ARR(ctx__pt->cipher_plain_key__bu8, cipher_key_len__alu8 + mac_key_len__alu8);
 ctx__pt->mac_key__bu8 = ctx__pt->cipher_plain_key__bu8 + cipher_key_len__alu8;
#endif
 ctx__pt->mac_key_len__u8 = mac_key_len__alu8;
 ctx__pt->cipher_plain_key_len__u8 = cipher_key_len__alu8;
memcpy(ctx__pt->cipher_plain_key__bu8, cipher_key__pcu8, cipher_key_len__alu8);
memcpy(ctx__pt->mac_key__bu8, mac_key__pcu8, mac_key_len__alu8);

/*
 FLEA_CCALL(THR_flea_mac_ctx_t__ctor(&state__pt->cipher_specific__u.cbc_hmac__t.hmac_ctx__t, hmac_id, mac_key__pcu8, mac_key_len__alu16));
 FLEA_CCALL(THR_flea_cbc_mode_ctx_t__ctor(&state__pt->cipher_specific__u.cbc_hmac__t.encr_ctx__t, block_cipher_id, cipher_key__pcu8, cipher_key_len__alu16, NULL, 0, flea_encrypt));
 FLEA_CCALL(THR_flea_cbc_mode_ctx_t__ctor(&state__pt->cipher_specific__u.cbc_hmac__t.encr_ctx__t, block_cipher_id, cipher_key__pcu8, cipher_key_len__alu16, NULL, 0, flea_decrypt));
 */
FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_()
{

 FLEA_CCALL(THR_flea_mac_ctx_t__ctor(&state__pt->cipher_specific__u.cbc_hmac__t.hmac_ctx__t, hmac_id, mac_key__pcu8, mac_key_len__alu16));
 FLEA_CCALL(THR_flea_cbc_mode_ctx_t__ctor(&state__pt->cipher_specific__u.cbc_hmac__t.encr_ctx__t, block_cipher_id, cipher_key__pcu8, cipher_key_len__alu16, NULL, 0, flea_encrypt));
FLEA_THR_FIN_SEC_empty();
}
#endif
