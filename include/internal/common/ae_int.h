/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_ae_int__H_
#define _flea_ae_int__H_

#include "internal/common/hash/ghash.h"

typedef struct
{
  flea_ctr_mode_ctx_t ctr_ctx__t;
  flea_mac_ctx_t      cmac_ctx__t;
#ifdef FLEA_USE_HEAP_BUF
  flea_u8_t*          nonce__bu8;
  flea_u8_t*          header_omac__bu8;
#else
  flea_u8_t           nonce__bu8 [FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH];
  flea_u8_t           header_omac__bu8[FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH];
#endif
} flea_ae_eax_specific_t;

typedef struct
{
  flea_ghash_ctx_t    ghash_ctx__t;
  flea_ctr_mode_ctx_t ctr_ctx__t;
} flea_ae_gcm_specific_t;

/* fwd declaration */
// struct flea_ae_config_entry_t;

typedef struct flea_ae_config_entry_struct flea_ae_config_entry_t;

#endif /* h-guard */
