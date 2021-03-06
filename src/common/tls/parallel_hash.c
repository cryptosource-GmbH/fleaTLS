/* fleaTLS cryptographic library
Copyright (C) 2015-2019 cryptosource GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

#include "internal/common/default.h"
#include "internal/common/tls/parallel_hash.h"
#include "flea/array_util.h"


#ifdef FLEA_HAVE_TLS

flea_err_e THR_flea_tls_prl_hash_ctx_t__ctor(
  flea_tls_prl_hash_ctx_t* p_hash_ctx,
  const flea_hash_id_e*    hash_ids__pt,
  flea_al_u8_t             hash_ids_len__alu8
)
{
  FLEA_THR_BEG_FUNC();

# ifdef FLEA_HEAP_MODE
  FLEA_ALLOC_MEM_ARR(p_hash_ctx->hash_ctx__pt, hash_ids_len__alu8);
  FLEA_SET_ARR(p_hash_ctx->hash_ctx__pt, 0, hash_ids_len__alu8);
# else
  if(hash_ids_len__alu8 > FLEA_STKMD_TLS_MAX_PARALLEL_HASHES)
  {
    FLEA_THROW("too many hash algorithms for this configuration", FLEA_ERR_INV_ARG);
  }
# endif /* ifdef FLEA_HEAP_MODE */

  p_hash_ctx->num_hash_ctx__u8 = 0;

  for(flea_u8_t i = 0; i < hash_ids_len__alu8; i++)
  {
    flea_hash_ctx_t__INIT(&p_hash_ctx->hash_ctx__pt[i]);
    p_hash_ctx->num_hash_ctx__u8++;
    FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&p_hash_ctx->hash_ctx__pt[i], hash_ids__pt[i]));
  }

  p_hash_ctx->update_only_one__t = FLEA_FALSE;
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_tls_prl_hash_ctx_t__create_hash_ctx_as_copy(
  flea_hash_ctx_t*               hash_ctx_new__pt,
  const flea_tls_prl_hash_ctx_t* p_hash_ctx__pt,
  flea_hash_id_e                 hash_id__t
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

void flea_tls_prl_hash_ctx_t__stop_update_for_all_but_one(
  flea_tls_prl_hash_ctx_t* p_hash_ctx,
  flea_hash_id_e           hash_id__t,
  flea_bool_t              do_prune__b
)
{
  p_hash_ctx->update_only_one__t     = FLEA_TRUE;
  p_hash_ctx->update_only_hash_id__t = hash_id__t;

# if defined FLEA_HEAP_MODE && defined FLEA_HAVE_TLS_CLIENT
  if(do_prune__b)
  {
    flea_al_u8_t i;
    flea_hash_ctx_t* tmp_ptr;
    flea_bool_t found__b = FLEA_FALSE;
    FLEA_ALLOC_MEM_NOCHK(tmp_ptr, sizeof(flea_hash_ctx_t));
    for(i = 0; i < p_hash_ctx->num_hash_ctx__u8; i++)
    {
      if(hash_id__t != flea_hash_ctx_t__get_hash_id(&p_hash_ctx->hash_ctx__pt[i]))
      {
        flea_hash_ctx_t__dtor(&p_hash_ctx->hash_ctx__pt[i]);
      }
      else if(tmp_ptr)
      {
        memcpy(tmp_ptr, &p_hash_ctx->hash_ctx__pt[i], sizeof(flea_hash_ctx_t));
        found__b = FLEA_TRUE;
      }
    }
    if(found__b && tmp_ptr)
    {
      FLEA_FREE_MEM(p_hash_ctx->hash_ctx__pt);
      p_hash_ctx->hash_ctx__pt     = tmp_ptr;
      p_hash_ctx->num_hash_ctx__u8 = 1;
    }
  }
# endif /* if defined FLEA_HEAP_MODE && defined FLEA_HAVE_TLS_CLIENT */
}

flea_err_e THR_flea_tls_prl_hash_ctx_t__update(
  flea_tls_prl_hash_ctx_t* p_hash_ctx,
  const flea_u8_t*         bytes__u8,
  flea_dtl_t               bytes_len__dtl
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

flea_err_e THR_flea_tls_prl_hash_ctx_t__final(
  flea_tls_prl_hash_ctx_t* p_hash_ctx,
  flea_hash_id_e           hash_id__t,
  flea_bool_t              copy,
  flea_u8_t*               output__u8
)
{
  flea_hash_ctx_t* hash_ctx__pt = NULL;

  flea_hash_ctx_t hash_ctx_cpy_t;

  FLEA_THR_BEG_FUNC();
  flea_hash_ctx_t__INIT(&hash_ctx_cpy_t);

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

void flea_tls_prl_hash_ctx_t__dtor(flea_tls_prl_hash_ctx_t* p_hash_ctx)
{
  for(flea_u8_t i = 0; i < p_hash_ctx->num_hash_ctx__u8; i++)
  {
    flea_hash_ctx_t__dtor(&p_hash_ctx->hash_ctx__pt[i]);
  }
# ifdef FLEA_HEAP_MODE
  FLEA_FREE_MEM_CHK_NULL(p_hash_ctx->hash_ctx__pt);
# endif
  flea_tls_prl_hash_ctx_t__INIT(p_hash_ctx);
}

flea_err_e THR_flea_tls_prl_hash_ctx_t__select_hash_ctx(
  flea_tls_prl_hash_ctx_t* p_hash_ctx__pt,
  flea_hash_ctx_t**        hash_ctx__ppt,
  flea_hash_id_e           hash_id__t
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
