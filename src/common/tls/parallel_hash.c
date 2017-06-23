/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/tls/parallel_hash.h"
// #include "flea/array_util.h"


#ifdef FLEA_HAVE_TLS

// TODO (FS): hash_ids__pt const machen
flea_err_t THR_flea_tls_parallel_hash_ctx_t__ctor(
  flea_tls_parallel_hash_ctx_t* p_hash_ctx,
  flea_hash_id_t*               hash_ids__pt,
  flea_u8_t                     hash_ids_len__u8
)
{
  FLEA_THR_BEG_FUNC();

# ifdef FLEA_USE_HEAP_BUF
  FLEA_ALLOC_MEM_ARR(p_hash_ctx->hash_ctx__pt, hash_ids_len__u8);
# endif

  if(hash_ids_len__u8 > FLEA_TLS_MAX_PARALLEL_HASHES)
  {
    FLEA_THROW("too many hash algorithms for this configuration", FLEA_ERR_INV_ARG);
  }

  for(flea_u8_t i = 0; i < hash_ids_len__u8; i++)
  {
    flea_hash_ctx_t__INIT(&p_hash_ctx->hash_ctx__pt[i]);
    p_hash_ctx->num_hash_ctx__u8++;
    FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&p_hash_ctx->hash_ctx__pt[i], hash_ids__pt[i]));
  }

  p_hash_ctx->update_only_one__t = FLEA_FALSE;
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls_parallel_hash_ctx_t__create_hash_ctx_as_copy(
  flea_hash_ctx_t*                    hash_ctx_new__pt,
  const flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt,
  flea_hash_id_t                      hash_id__t
)
{
  FLEA_THR_BEG_FUNC();
  for(flea_u8_t i = 0; i < p_hash_ctx__pt->num_hash_ctx__u8; i++)
  {
    if(hash_id__t == flea_hash_ctx_t__get_hash_id(&p_hash_ctx__pt->hash_ctx__pt[i]))
    {
      FLEA_CCALL(THR_flea_hash_ctx_t__ctor_copy(hash_ctx_new__pt, &p_hash_ctx__pt->hash_ctx__pt[i]));
      FLEA_THR_RETURN();
    }
  }
  FLEA_THROW("hash id not found", FLEA_ERR_INV_ARG);
  FLEA_THR_FIN_SEC_empty();
}

void flea_tls_parallel_hash_ctx_t__stop_update_for_all_but_one(
  flea_tls_parallel_hash_ctx_t* p_hash_ctx,
  flea_hash_id_t                hash_id__t
)
{
  p_hash_ctx->update_only_one__t     = FLEA_TRUE;
  p_hash_ctx->update_only_hash_id__t = hash_id__t;
}

flea_err_t THR_flea_tls_parallel_hash_ctx_t__update(
  flea_tls_parallel_hash_ctx_t* p_hash_ctx,
  const flea_u8_t*              bytes__u8,
  flea_dtl_t                    bytes_len__dtl
)
{
  FLEA_THR_BEG_FUNC();

  for(flea_u8_t i = 0; i < p_hash_ctx->num_hash_ctx__u8; i++)
  {
    if(p_hash_ctx->update_only_one__t == FLEA_FALSE ||
      p_hash_ctx->update_only_hash_id__t == flea_hash_ctx_t__get_hash_id(&p_hash_ctx->hash_ctx__pt[i]))
    {
      FLEA_CCALL(THR_flea_hash_ctx_t__update(&p_hash_ctx->hash_ctx__pt[i], bytes__u8, bytes_len__dtl));
    }
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls_parallel_hash_ctx_t__final(
  flea_tls_parallel_hash_ctx_t* p_hash_ctx,
  flea_hash_id_t                hash_id__t,
  flea_bool_t                   copy,
  flea_u8_t*                    output__u8
)
{
  flea_hash_ctx_t* hash_ctx__pt = NULL;

  FLEA_DECL_OBJ(hash_ctx_cpy_t, flea_hash_ctx_t);

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
    if(copy == FLEA_TRUE)
    {
      FLEA_CCALL(THR_flea_hash_ctx_t__ctor_copy(&hash_ctx_cpy_t, hash_ctx__pt));
      hash_ctx__pt = &hash_ctx_cpy_t;
    }
    FLEA_CCALL(THR_flea_hash_ctx_t__final(hash_ctx__pt, output__u8));
  }
  else
  {
    FLEA_THROW("hash id not matching", FLEA_ERR_INV_ARG);
  }

  FLEA_THR_FIN_SEC(
    flea_hash_ctx_t__dtor(&hash_ctx_cpy_t);
  );
} /* THR_flea_tls_parallel_hash_ctx__final */

void flea_tls_parallel_hash_ctx_t__dtor(flea_tls_parallel_hash_ctx_t* p_hash_ctx)
{
  for(flea_u8_t i = 0; i < p_hash_ctx->num_hash_ctx__u8; i++)
  {
    flea_hash_ctx_t__dtor(&p_hash_ctx->hash_ctx__pt[i]);
  }
  // TODO (FS): da der Pointer nicht initialisert wird, darfst Du das free nur
  // konditional machen. Meine Empfehlung ist es, auch den Pointer zu
  // initialisieren, sonst wird es kompliziert.
# ifdef FLEA_USE_HEAP_BUF
  FLEA_FREE_MEM_CHK_SET_NULL(p_hash_ctx->hash_ctx__pt);
# endif
}

flea_err_t THR_flea_tls_parallel_hash_ctx_t__select_hash_ctx(
  flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt,
  flea_hash_ctx_t**             hash_ctx__ppt,
  flea_hash_id_t                hash_id__t
)
{
  FLEA_THR_BEG_FUNC();
  *hash_ctx__ppt = 0;
  for(flea_u8_t i = 0; i < p_hash_ctx__pt->num_hash_ctx__u8; i++)
  {
    if(hash_id__t == flea_hash_ctx_t__get_hash_id(&p_hash_ctx__pt->hash_ctx__pt[i]))
    {
      *hash_ctx__ppt = &p_hash_ctx__pt->hash_ctx__pt[i];
      break;
    }
  }
  if(!(*hash_ctx__ppt))
  {
    FLEA_THROW("hash id not matching", FLEA_ERR_INV_ARG);
  }
  FLEA_THR_FIN_SEC_empty();
}

#endif /* ifdef FLEA_HAVE_TLS */
