/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_cert_chain__H_
#define _flea_cert_chain__H_

#include "flea/x509.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FLEA_MAX_CERT_COLLECTION_SIZE 20
/*
typedef struct 
{
 flea_x509_cert_ref_t* current__pt; 
 flea_x509_cert_ref_t* issuer__pt;
 flea_x509_cert_ref_t* issued__pt;
  
} flea_cert_chain_element_t;
*/

// TODO: CERT COLLECTION AS EXTRA TYPE WHICH IS CONSTRUCTED BY THE USER
// HE NEVER NEEDS TO SEE CERT CHAIN
// TODO: SUPPORT ADDING OF DER CERTS AND HAVE A CACHE FOR CERT_REFS. START
// WITHOUT A CACHE AND SIMPLY HAVE CHAIN AS DER REFS
typedef struct
{
  // TODO: cert_collection of type encapsulating cert_ref, having trusted__b,
  // valid/invalid issuer_sigs
   
  flea_x509_cert_ref_t cert_collection__pt[FLEA_MAX_CERT_COLLECTION_SIZE];
  flea_u16_t cert_collection_size__u16;
  flea_u16_t allocated_chain_len__u16;
  flea_u16_t chain_pos__u16; // offset to final element, = length - 1
#ifdef FLEA_USE_HEAP_BUF
  flea_u16_t * chain__bu16;
#else
  flea_u16_t chain__bu16[FLEA_MAX_CERT_CHAIN_DEPTH]; // including target and TA
#endif
  
} flea_cert_chain_t;

#define flea_cert_chain_t__INIT_VALUE  { .cert_collection_size__u16 = 0 }

// TODO: make ctor and dtor
#define flea_cert_chain_element_t__INIT_VALUE = {.current__pt = NULL, .issuer__pt = NULL, .issued__pt = NULL }

void flea_cert_chain_t__dtor(flea_cert_chain_t *chain__pt);
//void flea_cert_chain_element_t__dtor(flea_cert_chain_element_t *element__pt);

flea_err_t THR_flea_cert_chain_t__ctor(flea_cert_chain_t *chain__pt, flea_x509_cert_ref_t *target_cert__pt);

flea_err_t THR_flea_cert_chain_t__add_cert_without_trust_status(flea_cert_chain_t* chain__pt, const flea_x509_cert_ref_t * cert_ref__pt);

flea_err_t THR_flea_cert_chain_t__add_trust_anchor_cert(flea_cert_chain_t* chain__pt, const flea_x509_cert_ref_t * cert_ref__pt);

flea_err_t THR_flea_cert_chain__build_and_verify_cert_chain( flea_cert_chain_t *cert_chain__pt, const flea_gmt_time_t *time__pt);
#ifdef __cplusplus
}
#endif
#endif /* h-guard */
