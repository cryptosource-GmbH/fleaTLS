/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_hash_int__H_
#define _flea_hash_int__H_

#include "flea/hash_fwd.h"
#include "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* internal function pointer types */
typedef flea_err_t (*THR_flea_hash_compression_f)(flea_hash_ctx_t* ctx, const flea_u8_t* input);
typedef void (*flea_hash_init_f)(flea_hash_ctx_t* ctx);
typedef void (*flea_hash_encode_hash_state_f)(const flea_hash_ctx_t* ctx, flea_u8_t* output, flea_al_u8_t output_len);

struct struct_flea_hash_config_entry_t;
typedef struct struct_flea_hash_config_entry_t flea_hash_config_entry_t;

#ifdef __cplusplus
}
#endif


#endif /* h-guard */
