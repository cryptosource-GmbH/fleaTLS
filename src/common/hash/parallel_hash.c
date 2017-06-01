/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/hash/parallel_hash.h"
#include "flea/array_util.h"

#ifdef FLEA_HAVE_TLS

flea_err_t THR_flea_tls_parallel_hash_ctx__ctor(
  flea_tls_parallel_hash_ctx_t* p_hash_ctx,
  flea_hash_id_t*               hash_ids__pt,
  flea_u8_t                     hash_ids_len__u8
)
{
  FLEA_THR_BEG_FUNC();

# ifdef FLEA_USE_HEAP_BUF
  FLEA_ALLOC_MEM_ARR(p_hash_ctx->hash_ctx__pt, hash_ids_len__u8);
# endif

  // TODO123: check if hash_ids_len > MAX_HASHES

  p_hash_ctx->num_hash_ctx__u8 = hash_ids_len__u8;

  for(flea_u8_t i = 0; i < hash_ids_len__u8; i++)
  {
    flea_hash_ctx_t__INIT(&p_hash_ctx->hash_ctx__pt[i]);
    FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&p_hash_ctx->hash_ctx__pt[i], hash_ids__pt[i]));
  }

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls_parallel_hash_ctx__update(
  flea_tls_parallel_hash_ctx_t* p_hash_ctx,
  const flea_u8_t*              bytes__u8,
  flea_dtl_t                    bytes_len__dtl
)
{
  FLEA_THR_BEG_FUNC();

  for(flea_u8_t i = 0; i < p_hash_ctx->num_hash_ctx__u8; i++)
  {
    FLEA_CCALL(THR_flea_hash_ctx_t__update(&p_hash_ctx->hash_ctx__pt[i], bytes__u8, bytes_len__dtl));
  }

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls_parallel_hash_ctx__final(
  flea_tls_parallel_hash_ctx_t* p_hash_ctx,
  flea_hash_id_t                hash_id__t,
  flea_bool_t                   copy,
  flea_u8_t*                    output__u8
)
{
  flea_hash_ctx_t* hash_ctx__pt;

  if(copy == FLEA_TRUE)
  {
    FLEA_DECL_OBJ(hash_ctx_t, flea_hash_ctx_t);
    hash_ctx__pt = &hash_ctx_t;
  }

  FLEA_THR_BEG_FUNC();

  for(flea_u8_t i = 0; i < p_hash_ctx->num_hash_ctx__u8; i++)
  {
    if(hash_id__t == flea_hash_ctx_t__get_hash_id(&p_hash_ctx->hash_ctx__pt[i]))
    {
      hash_ctx__pt = &p_hash_ctx->hash_ctx__pt[i];
      break;
    }
  }
  if(hash_ctx__pt)
  {
    FLEA_CCALL(THR_flea_hash_ctx_t__final(hash_ctx__pt, output__u8));
  }
  else
  {
    FLEA_THROW("hash id not matching", FLEA_ERR_INV_ARG);
  }

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls_parallel_hash_ctx__dtor(flea_tls_parallel_hash_ctx_t* p_hash_ctx)
{
  FLEA_THR_BEG_FUNC();

  for(flea_u8_t i = 0; i < p_hash_ctx->num_hash_ctx__u8; i++)
  {
    flea_hash_ctx_t__dtor(&p_hash_ctx->hash_ctx__pt[i]);
  }

# ifdef FLEA_USE_HEAP_BUF
  FLEA_FREE_MEM(p_hash_ctx->hash_ctx__pt);
# endif
  FLEA_THR_FIN_SEC_empty();
}

#endif /* ifdef FLEA_HAVE_TLS */
