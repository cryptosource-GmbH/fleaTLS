/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_ae_int__H_
#define _flea_ae_int__H_

#include "internal/common/default.h"
#include "internal/common/hash/ghash.h"

#ifdef FLEA_HAVE_EAX

typedef struct
{
  flea_ctr_mode_ctx_t ctr_ctx__t;
  flea_mac_ctx_t      cmac_ctx__t;
# ifdef FLEA_HEAP_MODE
  flea_u8_t*          nonce__bu8;
  flea_u8_t*          header_omac__bu8;
# else
  flea_u8_t           nonce__bu8 [FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH];
  flea_u8_t           header_omac__bu8[FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH];
# endif // ifdef FLEA_HEAP_MODE
} flea_ae_eax_specific_t;
#endif // ifdef FLEA_HAVE_EAX

#ifdef FLEA_HAVE_GCM

typedef struct
{
  flea_ghash_ctx_t    ghash_ctx__t;
  flea_ctr_mode_ctx_t ctr_ctx__t;
} flea_ae_gcm_specific_t;
#endif // ifdef FLEA_HAVE_GCM

/* fwd declaration */
struct flea_ae_config_entry_struct;

typedef struct flea_ae_config_entry_struct flea_ae_config_entry_t;

#endif /* h-guard */
