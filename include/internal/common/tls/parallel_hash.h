/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_parallel_hash__H_
# define _flea_parallel_hash__H_

# include "internal/common/default.h"
# include "flea/error_handling.h"
# include "flea/alloc.h"
# include "flea/types.h"
# include "flea/hash.h"

# ifdef FLEA_HAVE_TLS

#  ifdef __cplusplus
extern "C" {
#  endif


typedef struct
{
#  ifdef FLEA_HEAP_MODE
  flea_hash_ctx_t* hash_ctx__pt;
#  else
  flea_hash_ctx_t  hash_ctx__pt[FLEA_STKMD_TLS_MAX_PARALLEL_HASHES];
#  endif
  flea_u8_t        num_hash_ctx__u8;
  flea_bool_t      update_only_one__t; // switch to update only the update_only_hash_id__t hash
  flea_hash_id_e   update_only_hash_id__t;
} flea_tls_prl_hash_ctx_t;


#  define flea_tls_prl_hash_ctx_t__INIT(__p) FLEA_MEMSET(__p, 0, sizeof(*(__p)))


flea_err_e THR_flea_tls_prl_hash_ctx_t__ctor(
  flea_tls_prl_hash_ctx_t* p_hash_ctx,
  const flea_hash_id_e*    hash_ids__pt,
  flea_al_u8_t             hashes_ids_len__alu8
);

flea_err_e THR_flea_tls_prl_hash_ctx_t__create_hash_ctx_as_copy(
  flea_hash_ctx_t*               hash_ctx_new__pt,
  const flea_tls_prl_hash_ctx_t* p_hash_ctx__pt,
  flea_hash_id_e                 hash_id__t
);

flea_err_e THR_flea_tls_prl_hash_ctx_t__update(
  flea_tls_prl_hash_ctx_t* p_hash_ctx,
  const flea_u8_t*         bytes__u8,
  flea_dtl_t               bytes_len__dtl
);


flea_err_e THR_flea_tls_prl_hash_ctx_t__final(
  flea_tls_prl_hash_ctx_t* p_hash_ctx,
  flea_hash_id_e           hash_id__t,
  flea_bool_t              copy,
  flea_u8_t*               output__u8
);

void flea_tls_prl_hash_ctx_t__dtor(flea_tls_prl_hash_ctx_t* p_hash_ctx);

void flea_tls_prl_hash_ctx_t__stop_update_for_all_but_one(
  flea_tls_prl_hash_ctx_t* p_hash_ctx,
  flea_hash_id_e           hash_id__t
);

// get pointer to hash_ctx with corresponding hash_id
flea_err_e THR_flea_tls_prl_hash_ctx_t__select_hash_ctx(
  flea_tls_prl_hash_ctx_t* p_hash_ctx__pt,
  flea_hash_ctx_t**        hash_ctx__ppt,
  flea_hash_id_e           hash_id__t
);

#  ifdef __cplusplus
}
#  endif

# endif // ifdef FLEA_HAVE_TLS

#endif /* h-guard */
