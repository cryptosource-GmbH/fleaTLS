
#ifndef _flea_cert_store__H_
#define _flea_cert_store__H_

#include "flea/x509.h"
#include "flea/cert_path.h"

#ifdef FLEA_HAVE_ASYM_ALGS

#ifdef __cplusplus
extern "C" {
#endif


  typedef struct 
  {
#ifdef FLEA_USE_HEAP_BUF
    flea_ref_cu8_t * enc_cert_refs__bcu8;
#else
    flea_ref_cu8_t enc_cert_refs__bcu8[FLEA_MAX_CERT_COLLECTION_SIZE];
#endif
    flea_dtl_t nb_alloc_certs__dtl;
    flea_u16_t nb_set_certs__u16;
  } flea_cert_store_t;

#ifdef FLEA_USE_HEAP_BUF
#define flea_cert_store_t__INIT_VALUE { .enc_cert_refs__bcu8 = 0 }
#else 
#define flea_cert_store_t__INIT_VALUE { .enc_cert_refs__bcu8[0] = { 0, 0 } }
#endif 

void flea_cert_store_t__dtor(flea_cert_store_t *cert_store__pt);

flea_err_t THR_flea_cert_store_t__ctor(flea_cert_store_t *cert_store__pt);

flea_err_t THR_flea_cert_store_t__add_trusted_cert(flea_cert_store_t *cert_store__pt, const flea_u8_t *der_enc_cert__pcu8, flea_al_u16_t der_enc_cert_len__alu16);

/**
 * Add the trusted certs in a cert store to a path validator object as trust
 * anchors to be used in path validation.
 */
flea_err_t THR_flea_cert_store_t__add_trusted_to_path_validator(const flea_cert_store_t * cert_store__pct, flea_cert_path_validator_t * cpv__pt );

#ifdef __cplusplus
}
#endif

#endif /* #ifdef FLEA_HAVE_ASYM_ALGS */

#endif /* h-guard */
