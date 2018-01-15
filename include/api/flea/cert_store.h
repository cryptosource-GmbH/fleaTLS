#ifndef _flea_cert_store__H_
#define _flea_cert_store__H_

#include "flea/x509.h"
#include "flea/cert_path.h"
#include "internal/common/cert_path_int.h"

#ifdef FLEA_HAVE_ASYM_ALGS

# ifdef __cplusplus
extern "C" {
# endif


/**
 * Cert store type. Supports the storage of trusted certs and untrusted certs
 * for the use in a cert path validation.
 */
typedef struct
{
# ifdef FLEA_HEAP_MODE
  flea_enc_cert_ref_t* enc_cert_refs__bcu8;
# else
  flea_enc_cert_ref_t  enc_cert_refs__bcu8[FLEA_MAX_CERT_COLLECTION_SIZE];
  flea_u8_t            trust_flags__bcu8[FLEA_MAX_CERT_COLLECTION_SIZE];
# endif // ifdef FLEA_HEAP_MODE
  flea_dtl_t           nb_alloc_certs__dtl;
  flea_u16_t           nb_set_certs__u16;
} flea_cert_store_t;

# ifdef FLEA_HEAP_MODE
#  define flea_cert_store_t__INIT_VALUE {.enc_cert_refs__bcu8 = NULL}
#  define flea_cert_store_t__INIT(__p) do {(__p)->enc_cert_refs__bcu8 = NULL;} while(0)
# else
#  define flea_cert_store_t__INIT_VALUE {.enc_cert_refs__bcu8[0] = {{0, 0}, 0}}
#  define flea_cert_store_t__INIT(__p)
# endif // ifdef FLEA_HEAP_MODE

# define flea_cert_store_t__GET_PTR_TO_ENC_CERT_RCU8(__p, __i) (&(__p)->enc_cert_refs__bcu8[__i].data_ref__rcu8)
# define flea_cert_store_t__GET_NB_CERTS(__p)                  ((__p)->nb_set_certs__u16)

/**
 * Destroy a cert store.
 *
 * @param cert_store pointer to the cert store object to destruct.
 */
void flea_cert_store_t__dtor(flea_cert_store_t* cert_store);

/**
 * Construct an empty cert store object.
 *
 * @param cert_store pointer to the cert store object to construct.
 *
 */
flea_err_e THR_flea_cert_store_t__ctor(flea_cert_store_t* cert_store);

/**
 * Add a trusted certificate to the cert store. The encoded certificate must
 * remain in the same memory location during the lifetime of the cert store
 * object, since it only stores a reference to the encoded certificate.
 *
 * @param cert_store pointer to the cert store object to which to add the
 * certificate.
 * @param der_enc_cert DER encoded certificate to add
 * @param der_enc_cert_len length of der_enc_cert
 */
flea_err_e THR_flea_cert_store_t__add_trusted_cert(
  flea_cert_store_t* cert_store,
  const flea_u8_t*   der_enc_cert,
  flea_al_u16_t      der_enc_cert_len
);


/**
 * Add an untrusted certificate to the cert store. The encoded certificate must
 * remain in the same memory location during the lifetime of the cert store
 * object, since it only stores a reference to the encoded certificate.
 *
 * @param cert_store pointer to the cert store object to which to add the
 * certificate.
 * @param der_enc_cert DER encoded certificate to add
 * @param der_enc_cert_len length of der_enc_cert
 */
flea_err_e THR_flea_cert_store_t__add_untrusted_cert(
  flea_cert_store_t* cert_store,
  const flea_u8_t*   der_enc_cert,
  flea_al_u16_t      der_enc_cert_len
);

/**
 * Determine whether the certificate at a given index within the store is
 * trusted.
 *
 * @param cert_store the certificate store object
 * @param pos the index of the certificate in question
 *
 * @return FLEA_TRUE if the certificate at the given position is
 * trusted, FLEA_FALSE otherwise
 */
flea_bool_t flea_cert_store_t__is_cert_trusted(
  const flea_cert_store_t* cert_store,
  flea_al_u16_t            pos
);

/**
 * Get a pointer to a trusted cert.
 *
 * @param cert_store the certificate store object
 * @param pos the index of the cert in to get a pointer to
 *
 * @return the pointer to the indexed certificate if it is within
 * the range of available certifiates and the certificate is trusted; otherwise
 * NULL is returned.
 */
const flea_u8_t* flea_cert_store_t__get_ptr_to_trusted_enc_cert(
  flea_cert_store_t* cert_store,
  flea_al_u16_t      pos
);

/**
 * Find out whether a certain certificate with a given hash value of its to-be-signed data is contained in a cert store as a trusted certificate.
 *
 * @param[in] cert_store the cert store object to use
 * @param[in] tbs_cert_hash_id ID of the hash algorithm to use
 * @param[in] tbs_cert_hash_to_check the hash of the TBS of the certificate to check for
 * @param[in] tbs_cert_hash_to_check_len the length of tbs_cert_hash_to_check
 * @param[out] result_is_trusted receives the result: set to FLEA_TRUE if the sought
 * certificate is trusted, set to FLEA_FALSE otherwise
 * @param[out] trusted_cert_idx if result_is_trusted is set to FLEA_TRUE, then the pointer target receives the index of the certificate with the
 * sought TBS hash within this certificate store object, otherwise the value is
 * not updated.
 *
 * @return an error code
 */
flea_err_e THR_flea_cert_store_t__is_tbs_hash_trusted(
  const flea_cert_store_t* cert_store,
  flea_hash_id_e           tbs_cert_hash_id,
  const flea_u8_t*         tbs_cert_hash_to_check,
  flea_al_u8_t             tbs_cert_hash_to_check_len,
  flea_bool_t*             result_is_trusted,
  flea_al_u16_t*           trusted_cert_idx
);

/**
 * Add the trusted certs in a cert store to a path validator object as trust
 * anchors to be used in path validation. The encoded certificate added to the cert
 * store must remain in memory also for the life time of the cert path validator
 * object, since it stores only references to them.
 *
 * @param cert_store the cert store the trusted certificates of which are to be
 * added
 * @param cpv the path validator object in which the trusted certificates shall
 * be set
 *
 * @return an error code
 */
flea_err_e THR_flea_cert_store_t__add_trusted_to_path_validator(
  const flea_cert_store_t*    cert_store,
  flea_cert_path_validator_t* cpv
);

# ifdef __cplusplus
}
# endif

#endif /* #ifdef FLEA_HAVE_ASYM_ALGS */

#endif /* h-guard */
