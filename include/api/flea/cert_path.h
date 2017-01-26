/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_cert_path_validator__H_
#define _flea_cert_path_validator__H_

#include "internal/common/default.h"
#include "flea/x509.h"
#include "flea/pubkey.h"
#include "flea/hostn_ver.h"

#ifdef FLEA_HAVE_ASYM_ALGS

#ifdef __cplusplus
extern "C" {
#endif


typedef struct
{
#ifdef FLEA_USE_HEAP_BUF
  flea_ref_cu8_t *crl_collection__brcu8;
  flea_x509_cert_ref_t *cert_collection__bt;
  flea_u16_t *chain__bu16;
#else
  flea_ref_cu8_t crl_collection__brcu8[FLEA_MAX_CERT_COLLECTION_NB_CRLS]; 
  flea_x509_cert_ref_t cert_collection__bt[FLEA_MAX_CERT_COLLECTION_SIZE];
  flea_u16_t chain__bu16[FLEA_MAX_CERT_CHAIN_DEPTH]; // including target and TA
#endif
  flea_u16_t crl_collection_allocated__u16;
  flea_u16_t cert_collection_allocated__u16;
  flea_u16_t nb_crls__u16;
  flea_u16_t cert_collection_size__u16;
  flea_u16_t chain_pos__u16; // offset to final element, = length - 1
  flea_bool_t perform_revocation_checking__b;
  
  volatile flea_bool_t abort_cert_path_finding__vb;
#ifdef FLEA_USE_HEAP_BUF
#else
#endif
  
} flea_cert_path_validator_t;

#define flea_cert_path_validator_t__INIT_VALUE  { .cert_collection_size__u16 = 0 }

void flea_cert_path_validator_t__dtor(flea_cert_path_validator_t *chain__pt);

/**
 *
 */
flea_err_t THR_flea_cert_path_validator_t__ctor_cert(flea_cert_path_validator_t *chain__pt, const flea_u8_t *target_cert__pcu8, flea_al_u16_t target_cert_len__alu16);

flea_err_t THR_flea_cert_path_validator_t__ctor_cert_ref(flea_cert_path_validator_t *chain__pt, flea_x509_cert_ref_t *target_cert__pt);

void flea_cert_path_validator_t__disable_revocation_checking(flea_cert_path_validator_t *cert_chain__pt);

flea_err_t THR_flea_cert_path_validator_t__add_crl(flea_cert_path_validator_t* chain__pt, const flea_ref_cu8_t *crl_der__cprcu8);

flea_err_t THR_flea_cert_path_validator_t__add_cert_without_trust_status(flea_cert_path_validator_t *chain__pt, const flea_u8_t *cert__pcu8, flea_al_u16_t cert_len__alu16);

flea_err_t THR_flea_cert_path_validator_t__add_cert_ref_without_trust_status(flea_cert_path_validator_t* chain__pt, const flea_x509_cert_ref_t * cert_ref__pt);

/**
 * Add a trust anchor to object. It is possible to add the target cert itself again if it is trusted. This is
 * the proper way to handle directly trusted EE certificates.
 */
flea_err_t THR_flea_cert_path_validator_t__add_trust_anchor_cert(flea_cert_path_validator_t *chain__pt, const flea_u8_t *cert__pcu8, flea_al_u16_t cert_len__alu16);

flea_err_t THR_flea_cert_path_validator_t__add_trust_anchor_cert_ref(flea_cert_path_validator_t* chain__pt, const flea_x509_cert_ref_t * cert_ref__pt);

/**
 * This function tries to build a certificate path from the set target certificate
 * to one of the set trust anchors. Afterwards, it performs certificate path
 * validation including revocation checking for all certificates in the path except for the
 * trust anchor. This function does not check the key usage of the client
 * certificate, which must be performed seperatly.
 * @param time_mbn__pt the current time in timezon GMT. May be null, then the
 * function determines the current time itself.
 */
flea_err_t THR_flea_cert_path_validator__build_and_verify_cert_chain( flea_cert_path_validator_t *cert_chain__pt, const flea_gmt_time_t *time_mbn__pt);

/**
 * 
 * @param time_mbn__pt the current time in timezon GMT. May be null, then the
 * function determines the current time itself.
 */
flea_err_t THR_flea_cert_path_validator__build_and_verify_cert_chain_and_create_pub_key( flea_cert_path_validator_t *cert_chain__pt, const flea_gmt_time_t *time_mbn__pt, flea_public_key_t *key_to_construct_mbn__pt);


flea_err_t THR_flea_cert_path_validator__build_and_verify_cert_chain_and_hostid_and_create_pub_key( flea_cert_path_validator_t *cert_chain__pt, const flea_gmt_time_t *time_mbn__pt, const flea_ref_cu8_t *host_id__pcrcu8, flea_host_id_type_e host_id_type, flea_public_key_t *key_to_construct_mbn__pt);

/**
 * This function is intended to be called from another thread while the
 * certification path building and validation using the same flea_cert_path_validator_t object as
 * in this function is going on. If the function is called, the path search will
 * stop after the processing of the current path candidate has finished. This
 * allows to implement a timeout for the operation.
 *
 * @param cert_chain__pt pointer to the object which is used for the
 * certification path construction which shall be aborted.
 */
void flea_cert_path_validator_t__abort_cert_path_building(flea_cert_path_validator_t *chain__pt);

#ifdef __cplusplus
}
#endif

#endif /* #ifdef FLEA_HAVE_ASYM_ALGS */

#endif /* h-guard */

