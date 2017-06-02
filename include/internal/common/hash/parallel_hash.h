/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_parallel_hash__H_
#define _flea_parallel_hash__H_

#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/types.h"
#include "flea/hash.h"

#ifdef FLEA_HAVE_TLS // TODO: maybe create extra option?

# ifdef __cplusplus
extern "C" {
# endif

# define FLEA_TLS_MAX_PARALLEL_HASHES 5 // TODO: -> build_cfg

typedef struct
{
# ifdef FLEA_USE_HEAP_BUF
  flea_hash_ctx_t* hash_ctx__pt;
# else
  flea_hash_ctx_t  hash_ctx__pt[FLEA_TLS_MAX_PARALLEL_HASHES];
# endif
  flea_u8_t        num_hash_ctx__u8;
} flea_tls_parallel_hash_ctx_t;

flea_err_t THR_flea_tls_parallel_hash_ctx__ctor(
  flea_tls_parallel_hash_ctx_t* p_hash_ctx,
  flea_hash_id_t*               hash_ids__pt,
  flea_u8_t                     hashes_ids_len__u8
);

flea_err_t THR_flea_tls_parallel_hash_ctx__copy(
  flea_hash_ctx_t*                    hash_ctx_new__pt,
  const flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt,
  flea_hash_id_t                      hash_id__t
);

flea_err_t THR_flea_tls_parallel_hash_ctx__update(
  flea_tls_parallel_hash_ctx_t* p_hash_ctx,
  const flea_u8_t*              bytes__u8,
  flea_dtl_t                    bytes_len__dtl
);


flea_err_t THR_flea_tls_parallel_hash_ctx__final(
  flea_tls_parallel_hash_ctx_t* p_hash_ctx,
  flea_hash_id_t                hash_id__t,
  flea_bool_t                   copy,
  flea_u8_t*                    output__u8
);

flea_err_t THR_flea_tls_parallel_hash_ctx__dtor(flea_tls_parallel_hash_ctx_t* p_hash_ctx);


# ifdef __cplusplus
}
# endif

#endif // ifdef FLEA_HAVE_TLS

#endif /* h-guard */
