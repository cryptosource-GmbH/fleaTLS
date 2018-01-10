#include "internal/common/default.h"
#include "flea/cert_store.h"
#include "flea/util.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/alloc.h"

#ifdef FLEA_HAVE_ASYM_SIG

flea_bool_t flea_cert_store_t__is_cert_trusted(
  const flea_cert_store_t* cert_store__pt,
  flea_al_u16_t            pos__alu16
)
{
  if((pos__alu16 >= cert_store__pt->nb_set_certs__u16) ||
    (!cert_store__pt->enc_cert_refs__bcu8[pos__alu16].trusted_flag))
  {
    return FLEA_FALSE;
  }
  return FLEA_TRUE;
}

static flea_err_e THR_flea_cert_store_t__add_cert(
  flea_cert_store_t* cert_store__pt,
  const flea_u8_t*   der_enc_cert__pcu8,
  flea_al_u16_t      der_enc_cert_len__alu16,
  flea_bool_t        trusted__b
)
{
  FLEA_THR_BEG_FUNC();
  /* this type only supports trusted certs */
# ifdef FLEA_HEAP_MODE

  FLEA_CCALL(
    THR_flea_alloc__ensure_buffer_capacity(
      (void**) &cert_store__pt->enc_cert_refs__bcu8,
      &cert_store__pt->nb_alloc_certs__dtl,
      cert_store__pt->nb_set_certs__u16,
      1,
      FLEA_CERT_STORE_PREALLOC,
      FLEA_MAX_CERT_COLLECTION_SIZE,
      sizeof(cert_store__pt->enc_cert_refs__bcu8[0])
    )
  );
# else /* ifdef FLEA_HEAP_MODE */
  if(cert_store__pt->nb_set_certs__u16 + 1 > FLEA_MAX_CERT_COLLECTION_SIZE)
  {
    FLEA_THROW("cert store buffer capacity exhausted", FLEA_ERR_BUFF_TOO_SMALL);
  }

# endif /* ifdef FLEA_HEAP_MODE */
  cert_store__pt->enc_cert_refs__bcu8[cert_store__pt->nb_set_certs__u16].data_ref__rcu8.data__pcu8 = der_enc_cert__pcu8;
  cert_store__pt->enc_cert_refs__bcu8[cert_store__pt->nb_set_certs__u16].data_ref__rcu8.len__dtl   =
    der_enc_cert_len__alu16;
  cert_store__pt->enc_cert_refs__bcu8[cert_store__pt->nb_set_certs__u16].trusted_flag = trusted__b;
  cert_store__pt->nb_set_certs__u16++;

  FLEA_THR_FIN_SEC_empty();
}

const flea_u8_t* flea_cert_store_t__get_ptr_to_trusted_enc_cert(
  flea_cert_store_t* cert_store__pt,
  flea_al_u16_t      pos__alu16
)
{
  if(flea_cert_store_t__is_cert_trusted(cert_store__pt, pos__alu16))
  {
    return flea_cert_store_t__GET_PTR_TO_ENC_CERT_RCU8(cert_store__pt, pos__alu16)->data__pcu8;
  }
  return NULL;
}

flea_err_e THR_flea_cert_store_t__ctor(flea_cert_store_t* cert_store__pt)
{
  FLEA_THR_BEG_FUNC();
# ifdef FLEA_HEAP_MODE
  FLEA_ALLOC_MEM_ARR(cert_store__pt->enc_cert_refs__bcu8, FLEA_CERT_STORE_PREALLOC);
  cert_store__pt->nb_alloc_certs__dtl = FLEA_CERT_STORE_PREALLOC;
# else
  cert_store__pt->nb_alloc_certs__dtl = FLEA_MAX_CERT_COLLECTION_SIZE;
# endif
  cert_store__pt->nb_set_certs__u16 = 0;
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_cert_store_t__add_trusted_cert(
  flea_cert_store_t* cert_store__pt,
  const flea_u8_t*   der_enc_cert__pcu8,
  flea_al_u16_t      der_enc_cert_len__alu16
)
{
  return THR_flea_cert_store_t__add_cert(cert_store__pt, der_enc_cert__pcu8, der_enc_cert_len__alu16, FLEA_TRUE);
}

flea_err_e THR_flea_cert_store_t__add_untrusted_cert(
  flea_cert_store_t* cert_store__pt,
  const flea_u8_t*   der_enc_cert__pcu8,
  flea_al_u16_t      der_enc_cert_len__alu16
)
{
  return THR_flea_cert_store_t__add_cert(cert_store__pt, der_enc_cert__pcu8, der_enc_cert_len__alu16, FLEA_FALSE);
}

flea_err_e THR_flea_cert_store_t__add_trusted_to_path_validator(
  const flea_cert_store_t*    cert_store__pct,
  flea_cert_path_validator_t* cpv__pt
)
{
  flea_al_u16_t i;

  FLEA_THR_BEG_FUNC();

  for(i = 0; i < cert_store__pct->nb_set_certs__u16; i++)
  {
    if(cert_store__pct->enc_cert_refs__bcu8[i].trusted_flag)
    {
      FLEA_CCALL(
        THR_flea_cert_path_validator_t__add_trust_anchor_cert(
          cpv__pt,
          cert_store__pct->enc_cert_refs__bcu8[i].data_ref__rcu8.data__pcu8,
          cert_store__pct->enc_cert_refs__bcu8[i].data_ref__rcu8.len__dtl
        )
      );
    }
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_cert_store_t__is_tbs_hash_trusted(
  const flea_cert_store_t* cert_store__pct,
  flea_hash_id_e           tbs_cert_hash_id__e,
  const flea_u8_t*         tbs_cert_hash_to_check__pcu8,
  flea_al_u8_t             tbs_cert_hash_to_check_len__alu8,
  flea_bool_t*             result_is_trusted__pb,
  flea_al_u16_t*           trusted_cert_idx__palu16
)
{
  flea_al_u16_t i;
  flea_al_u16_t nb_certs__alu16 = cert_store__pct->nb_set_certs__u16;

  FLEA_DECL_flea_byte_vec_t__CONSTR_HEAP_ALLOCATABLE_OR_STACK(local_hash__t, FLEA_MAX_HASH_OUT_LEN);
  FLEA_THR_BEG_FUNC();
  *result_is_trusted__pb = FLEA_FALSE;
  for(i = 0; i < nb_certs__alu16; i++)
  {
    if(flea_cert_store_t__is_cert_trusted(cert_store__pct, i))
    {
      flea_ref_cu8_t tbs_ref__rcu8;
      FLEA_CCALL(
        THR_flea_x509_cert__get_ref_to_tbs(
          cert_store__pct->enc_cert_refs__bcu8[i].data_ref__rcu8.data__pcu8,
          cert_store__pct->enc_cert_refs__bcu8[i].data_ref__rcu8.len__dtl,
          &tbs_ref__rcu8
        )
      );
      FLEA_CCALL(
        THR_flea_compute_hash_byte_vec(
          tbs_cert_hash_id__e,
          tbs_ref__rcu8.data__pcu8,
          tbs_ref__rcu8.len__dtl,
          &local_hash__t
        )
      );
      if(!flea_memcmp_wsize(
          local_hash__t.data__pu8,
          local_hash__t.len__dtl,
          tbs_cert_hash_to_check__pcu8,
          tbs_cert_hash_to_check_len__alu8
        ))
      {
        *result_is_trusted__pb    = FLEA_TRUE;
        *trusted_cert_idx__palu16 = i;
        break;
      }
    }
  }

  FLEA_THR_FIN_SEC(
    flea_byte_vec_t__dtor(&local_hash__t);
  );
} /* THR_flea_cert_store_t__is_tbs_hash_trusted */

flea_err_e THR_flea_cert_store_t__is_cert_trusted(
  const flea_cert_store_t* cert_store__pct,
  const flea_u8_t*         cert_to_check__pcu8,
  flea_al_u16_t            cert_to_check_len__alu16,
  flea_bool_t*             result_is_trusted__pb
)
{
  flea_al_u16_t nb_certs__alu16 = cert_store__pct->nb_set_certs__u16;
  flea_al_u16_t i;

  FLEA_THR_BEG_FUNC();
  *result_is_trusted__pb = FLEA_FALSE;
  for(i = 0; i < nb_certs__alu16; i++)
  {
    if(!flea_memcmp_wsize(
        cert_store__pct->enc_cert_refs__bcu8[i].data_ref__rcu8.data__pcu8,
        cert_store__pct->enc_cert_refs__bcu8[i].data_ref__rcu8.len__dtl,
        cert_to_check__pcu8,
        cert_to_check_len__alu16
      ))
    {
      *result_is_trusted__pb = flea_cert_store_t__is_cert_trusted(cert_store__pct, i);
      break;
    }
  }
  FLEA_THR_FIN_SEC_empty();
}

void flea_cert_store_t__dtor(flea_cert_store_t* cert_store__pt)
{
# ifdef FLEA_HEAP_MODE
  FLEA_FREE_MEM_CHK_SET_NULL(cert_store__pt->enc_cert_refs__bcu8);
# endif
}

#endif /* #ifdef FLEA_HAVE_ASYM_SIG */
