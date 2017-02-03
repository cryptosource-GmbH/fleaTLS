#include "internal/common/default.h"
#include "flea/cert_store.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/alloc.h"

#ifdef FLEA_HAVE_ASYM_SIG

flea_err_t THR_flea_cert_store_t__ctor(flea_cert_store_t *cert_store__pt)
{
  FLEA_THR_BEG_FUNC();
# ifdef FLEA_USE_HEAP_BUF
  FLEA_ALLOC_MEM_ARR(cert_store__pt->enc_cert_refs__bcu8, FLEA_CERT_STORE_PREALLOC);
  cert_store__pt->nb_alloc_certs__dtl = FLEA_CERT_STORE_PREALLOC;
# else
  cert_store__pt->nb_alloc_certs__dtl = FLEA_MAX_CERT_COLLECTION_SIZE;
# endif
  cert_store__pt->nb_set_certs__u16 = 0;
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_cert_store_t__add_trusted_cert(flea_cert_store_t *cert_store__pt, const flea_u8_t *der_enc_cert__pcu8, flea_al_u16_t der_enc_cert_len__alu16)
{
  FLEA_THR_BEG_FUNC();
  /* this type only supports trusted certs */
# ifdef FLEA_USE_HEAP_BUF
  FLEA_CCALL(THR_flea_alloc__ensure_buffer_capacity((void **) &cert_store__pt->enc_cert_refs__bcu8, &cert_store__pt->nb_alloc_certs__dtl, cert_store__pt->nb_set_certs__u16, 1, FLEA_CERT_STORE_PREALLOC, FLEA_MAX_CERT_COLLECTION_SIZE, sizeof(cert_store__pt->enc_cert_refs__bcu8[0])));
# else
  if(cert_store__pt->nb_set_certs__u16 + 1 > FLEA_MAX_CERT_COLLECTION_SIZE)
  {
    FLEA_THROW("cert store buffer capacity exhausted", FLEA_ERR_BUFF_TOO_SMALL);
  }

# endif
  cert_store__pt->enc_cert_refs__bcu8[cert_store__pt->nb_set_certs__u16].data__pcu8 = der_enc_cert__pcu8;
  cert_store__pt->enc_cert_refs__bcu8[cert_store__pt->nb_set_certs__u16].len__dtl   = der_enc_cert_len__alu16;
  cert_store__pt->nb_set_certs__u16++;

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_cert_store_t__add_trusted_to_path_validator(const flea_cert_store_t *cert_store__pct, flea_cert_path_validator_t *cpv__pt)
{
  flea_al_u16_t i;

  FLEA_THR_BEG_FUNC();

  for(i = 0; i < cert_store__pct->nb_set_certs__u16; i++)
  {
    FLEA_CCALL(THR_flea_cert_path_validator_t__add_trust_anchor_cert(cpv__pt, cert_store__pct->enc_cert_refs__bcu8[i].data__pcu8, cert_store__pct->enc_cert_refs__bcu8[i].len__dtl));
  }
  FLEA_THR_FIN_SEC_empty();
}

void flea_cert_store_t__dtor(flea_cert_store_t *cert_store__pt)
{
# ifdef FLEA_USE_HEAP_BUF
  FLEA_FREE_MEM_CHK_SET_NULL(cert_store__pt->enc_cert_refs__bcu8);
# endif
}

#endif /* #ifdef FLEA_HAVE_ASYM_SIG */
