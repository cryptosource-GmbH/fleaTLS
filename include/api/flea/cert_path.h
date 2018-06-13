/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_cert_path_validator__H_
# define _flea_cert_path_validator__H_

# include "internal/common/default.h"
# include "flea/x509.h"
# include "flea/pubkey.h"
# include "flea/hostn_ver.h"
# include "internal/common/cert_info_int.h"
# include "internal/common/crl_int.h"
# include "internal/common/crl_int.h"

# ifdef FLEA_HAVE_ASYM_ALGS

#  ifdef __cplusplus
extern "C" {
#  endif

typedef enum
{
  /** check revocation information for all certificates in the path */
  flea_rev_chk_all,

  /** do not check revocation at all */
  flea_rev_chk_none,

  /** check revocation information only for the end entity certificate, i.e.
   * target certificate */
  flea_rev_chk_only_ee
} flea_rev_chk_mode_e;


/**
 * Certificate path validator type. After having been configured with trusted
 * and untrusted certificates as well as CRLs, it can be used for certificate
 * path validation.
 */
typedef struct
{
#  ifdef FLEA_HEAP_MODE
  flea_ref_cu8_t*              crl_collection__brcu8;
  flea_x509_cert_info_t*       cert_collection__bt;
  flea_u16_t*                  chain__bu16;
#  else
  flea_ref_cu8_t               crl_collection__brcu8[FLEA_MAX_CERT_COLLECTION_NB_CRLS];
  flea_x509_cert_info_t        cert_collection__bt[FLEA_MAX_CERT_COLLECTION_SIZE];
  flea_u16_t                   chain__bu16[FLEA_MAX_CERT_CHAIN_DEPTH]; // including target and TA
#  endif // ifdef FLEA_HEAP_MODE
  flea_u16_t                   crl_collection_allocated__u16;
  flea_u16_t                   cert_collection_allocated__u16;
  flea_u16_t                   nb_crls__u16;
  flea_u16_t                   cert_collection_size__u16;
  flea_u16_t                   chain_pos__u16; // offset to final element, = length - 1
  flea_rev_chk_mode_e          rev_chk_mode__e;

  volatile flea_bool_t         abort_cert_path_finding__vb;
  flea_x509_validation_flags_e cert_ver_flags__e;
} flea_cpv_t;


#  define flea_cpv_t__INIT(cpv) FLEA_MEMSET(cpv, 0, sizeof(*(cpv)))

void flea_cpv_t__dtor(flea_cpv_t* cpv);

/**
 * Create a path validator object.
 *
 * @param cpv the path validator object to create
 * @param target_cert the DER encoded certificate which shall be validated
 * @param target_cert_len the length of target_cert
 * @param rev_chk_mode the mode of revocation checking (based on CRLs) to use
 * @param cert_ver_flags combination of flags to control the certificate path
 * validation
 */
flea_err_e THR_flea_cpv_t__ctor_cert(
  flea_cpv_t*                  cpv,
  const flea_u8_t*             target_cert,
  flea_al_u16_t                target_cert_len,
  flea_rev_chk_mode_e          rev_chk_mode,
  flea_x509_validation_flags_e cert_ver_flags
);


/**
 * Add a CRL to a cert path validator. The encoded CRL must stay in the same
 * memory location for the lifetime of the cert path validator, since it only
 * stores a reference to that CRL.
 *
 * @param cpv the cert path validator object
 * @param crl_der pointer to the DER encoded CRL
 * @param crl_der_len length of crl_der
 */
flea_err_e THR_flea_cpv_t__add_crl(
  flea_cpv_t*      cpv,
  const flea_u8_t* crl_der,
  flea_dtl_t       crl_der_len
);

/**
 * Add an untrusted certificate to a cert path validator. The encoded certificate must stay in the same
 * memory location for the lifetime of the cert path validator, since it only
 * stores a reference to that certificate.
 *
 * @param cpv the cert path validator object
 * @param cert pointer to the DER encoded certificate
 * @param cert_len length of cert
 */
flea_err_e THR_flea_cpv_t__add_cert_without_trust_status(
  flea_cpv_t*      cpv,
  const flea_u8_t* cert,
  flea_al_u16_t    cert_len
);

/**
 * Add a trust anchor to object. It is possible to add the target cert itself again if it is trusted. This is
 * the proper way to handle directly trusted EE certificates. The encoded certificate must stay in the same
 * memory location for the lifetime of the cert path validator, since it only
 * stores a reference to that certificate.
 *
 * @param cpv the cert path validator object
 * @param cert pointer to the DER encoded certificate
 * @param cert_len length of cert
 */
flea_err_e THR_flea_cpv_t__add_trust_anchor_cert(
  flea_cpv_t*      cpv,
  const flea_u8_t* cert,
  flea_al_u16_t    cert_len
);


/**
 * This function tries to build a certificate path from the set target certificate
 * to one of the set trust anchors. Afterwards, it performs certificate path
 * validation including revocation checking for all certificates in the path except for the
 * trust anchor. This function does not check the key usage of the client
 * certificate for any specific purpose, which must be performed seperatly. In
 * case of a successful path validation the function returns without an error.
 *
 * Note: The minimum key strength as specified in the flea_x509_validation_flags_e as specified in the object's ctor call will only be enforced for all issuing certificates in the chain, but not for the public key in the target certificate itself. To enforce also the minimum key strength for the target certificate's public key, use the function THR_flea_cpv_t__validate_and_create_pub_key() instead.
 *
 * @param cpv the cert path validator object
 * @param time_mbn the current time in timezone GMT. May be null, then the
 * function determines the current time itself.
 */
flea_err_e THR_flea_cpv_t__validate(
  flea_cpv_t*            cpv,
  const flea_gmt_time_t* time_mbn
);

/**
 * The same operation as THR_flea_cpv_t__validate(), but additionally constructs the public key of the the target certificate.
 *
 * Note: The minimum key strength as specified in the flea_x509_validation_flags_e as specified in the object's ctor call will be enforced for all certificates in the chain, including the target certificate's public key.
 *
 * @param cpv the cert path validator object
 * @param time_mbn the current time in timezone GMT. May be null, then the
 * function determines the current time itself.
 * @param key_to_construct_mbn pointer to the public key object to construct
 */
flea_err_e THR_flea_cpv_t__validate_and_create_pub_key(
  flea_cpv_t*            cpv,
  const flea_gmt_time_t* time_mbn,
  flea_pubkey_t*         key_to_construct_mbn
);

/**
 * The same as THR_flea_cpv_t__validate_and_create_pub_key(), but additionally verifies the host ID.
 *
 * @param cpv the cert path validator object
 * @param time_mbn the current time in timezone GMT. May be null, then the
 * function determines the current time itself.
 * @param host_id byte string of the host identifier (not null terminated)
 * @param host_id_type of host ID to be used
 * @param key_to_construct_mbn pointer to the public key object to construct
 *
 */
flea_err_e THR_flea_cpv_t__validate_and_hostid_and_create_pub_key(
  flea_cpv_t*            cpv,
  const flea_gmt_time_t* time_mbn,
  const flea_byte_vec_t* host_id,
  flea_host_id_type_e    host_id_type,
  flea_pubkey_t*         key_to_construct_mbn
);

/**
 * This function is intended to be called from another thread while the
 * certification path building and validation using the same flea_cpv_t object as
 * in this function is going on. If the function is called, the path search will
 * stop after the processing of the current path candidate has finished. This
 * allows to implement a timeout for the operation.
 *
 * @param cpv pointer to the object which is used for the
 * certification path construction which shall be aborted.
 */
void flea_cpv_t__abort_cert_path_building(flea_cpv_t* cpv);

#  ifdef __cplusplus
}
#  endif

# endif /* #ifdef FLEA_HAVE_ASYM_ALGS */

#endif /* h-guard */
