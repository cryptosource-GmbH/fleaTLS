/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_x509__H_
#define _flea_x509__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "internal/common/ber_dec.h"
#include "flea/asn1_date.h"

#ifdef __cplusplus
extern "C" {
#endif
// TODO: MAKE INTERNAL:
//
#define FLEA_X509_MAX_SERIALNUMBER_LEN 20
#define ID_UNSUPP_EXT_OID              0

/** id-ce **/
#define ID_CE_INDIC                (0x0100)
#define ID_CE_OID_AKI              (ID_CE_INDIC | 35)
#define ID_CE_OID_POLICIES         (ID_CE_INDIC | 32)
#define ID_CE_OID_KEY_USAGE        (ID_CE_INDIC | 15)
#define ID_CE_OID_SUBJ_KEY_ID      (ID_CE_INDIC | 14)
#define ID_CE_OID_SUBJ_ALT_NAME    (ID_CE_INDIC | 17)
#define ID_CE_OID_ISS_ALT_NAME     (ID_CE_INDIC | 18)
#define ID_CE_OID_BASIC_CONSTR     (ID_CE_INDIC | 19)
#define ID_CE_OID_NAME_CONSTR      (ID_CE_INDIC | 30)
#define ID_CE_OID_POLICY_CONSTR    (ID_CE_INDIC | 36)
#define ID_CE_OID_EXT_KEY_USAGE    (ID_CE_INDIC | 37)
#define ID_CE_OID_CRL_DISTR_POINT  (ID_CE_INDIC | 31)
#define ID_CE_OID_INHIB_ANY_POLICY (ID_CE_INDIC | 54)
#define ID_CE_OID_FRESHEST_CRL     (ID_CE_INDIC | 46)

/** id-pe**/
#define ID_PE_INDIC            (0x0200)
#define ID_PE_OID_AUTH_INF_ACC (ID_PE_INDIC | 1)
#define ID_PE_OID_SUBJ_INF_ACC (ID_PE_INDIC | 11)

extern const flea_u8_t id_pe__cau8 [7];

/**
 * Type to control the checking for specific key usages in key usage extensions (i.e. key usage or
 * extended key usage).
 *
 * flea_key_usage_explicit means the respective extension is present and the specified key usages are supported
 * flea_key_usage_implicit means the respective extension is not present and
 *                         thus the key usage is not restricted.
 */
typedef enum { flea_key_usage_explicit, flea_key_usage_implicit } flea_key_usage_exlicitness_e;

/**
 * An identifier for either the key usage or extended key usage extension in a
 * certificate.
 */
// typedef enum { flea_key_usage_extension, flea_extended_key_usage_extension } flea_key_usage_ext_type_e;

typedef enum
{
  flea_ku_none_set           = 0,
  flea_ku_digital_signature  = (1 << 15),
  flea_ku_content_commitment = (1 << 14), /*  aka  nonrepudiation  */
  flea_ku_key_encipherment   = (1 << 13),
  flea_ku_data_encipherment  = (1 << 12),
  flea_ku_key_agreement      = (1 << 11),
  flea_ku_key_cert_sign      = (1 << 10),
  flea_ku_crl_sign           = (1 << 9),
  flea_ku_encipher_only      = (1 << 8),
  flea_ku_decipher_only      = (1 << 7)
} flea_key_usage_e;

#define FLEA_ASN1_EKU_BITP_any_ext_ku       0
#define FLEA_ASN1_EKU_BITP_server_auth      1
#define FLEA_ASN1_EKU_BITP_client_auth      2
#define FLEA_ASN1_EKU_BITP_code_signing     3
#define FLEA_ASN1_EKU_BITP_email_protection 4
#define FLEA_ASN1_EKU_BITP_time_stamping    8
#define FLEA_ASN1_EKU_BITP_ocsp_signing     9

typedef enum
{
  flea_eku_none_set         = 0,
  flea_eku_any_ext_ku       = (1 << FLEA_ASN1_EKU_BITP_any_ext_ku),
  flea_eku_server_auth      = (1 << FLEA_ASN1_EKU_BITP_server_auth),
  flea_eku_client_auth      = (1 << FLEA_ASN1_EKU_BITP_client_auth),
  flea_eku_code_signing     = (1 << FLEA_ASN1_EKU_BITP_code_signing),
  flea_eku_email_protection = (1 << FLEA_ASN1_EKU_BITP_email_protection),
  flea_eku_time_stamping    = (1 << FLEA_ASN1_EKU_BITP_time_stamping),
  flea_eku_ocsp_signing     = (1 << FLEA_ASN1_EKU_BITP_ocsp_signing)
} flea_ext_key_usage_e;

typedef enum
{
  flea_dn_cmpnt_cn,
  flea_dn_cmpnt_country,
  flea_dn_cmpnt_org,
  flea_dn_cmpnt_org_unit,
#ifdef FLEA_HAVE_X509_DN_DETAILS
  flea_dn_cmpnt_dn_qual,
  flea_dn_cmpnt_locality_name,
  flea_dn_cmpnt_state_or_province,
  flea_dn_cmpnt_serial_number,
  flea_dn_cmpnt_domain_cmpnt_attrib
#endif
} flea_dn_cmpnt_e;

typedef struct
{
  const flea_u8_t*      data__pcu8;
  flea_dtl_t            len__dtl;
  flea_asn1_time_type_t time_type__t;
} flea_x509_date_ref_t;

typedef struct
{
  flea_byte_vec_t oid_ref__t;
  flea_byte_vec_t params_ref_as_tlv__t;
} flea_x509_algid_ref_t;

#define flea_x509_algid_ref_t__CONSTR_EMPTY_ALLOCATABLE {.oid_ref__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE, .params_ref_as_tlv__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE}

typedef struct
{
  flea_x509_algid_ref_t algid__t;
  flea_byte_vec_t       public_key_as_tlv__t;
} flea_x509_public_key_info_t;

// TODO: BACK TO REF_CU8
typedef struct
{
  flea_byte_vec_t raw_dn_complete__t;
  flea_byte_vec_t common_name__t;
  flea_byte_vec_t country__t;
  flea_byte_vec_t org__t;
  flea_byte_vec_t org_unit__t;
#ifdef FLEA_HAVE_X509_DN_DETAILS
  flea_byte_vec_t dn_qual__t;
  flea_byte_vec_t state_or_province_name__t;
  flea_byte_vec_t locality_name__t;
  flea_byte_vec_t serial_number__t;
  flea_byte_vec_t domain_component_attribute__t;
#endif
} flea_x509_dn_ref_t;

#ifdef FLEA_HAVE_X509_DN_DETAILS
# define flea_x509_dn_ref_t__CONSTR_EMPTY_ALLOCATABLE \
  { \
    .raw_dn_complete__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE, \
    .country__t         = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE, \
    .org__t      = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE, \
    .org_unit__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE, \
    .dn_qual__t  = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE, \
    .state_or_province_name__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE, \
    .locality_name__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE, \
    .common_name__t   = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE, \
    .serial_number__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE, \
    .domain_component_attribute__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE \
  }
#else // ifdef FLEA_HAVE_X509_DN_DETAILS
# define flea_x509_dn_ref_t__CONSTR_EMPTY_ALLOCATABLE \
  { \
    .raw_dn_complete__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE, \
    .common_name__t     = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE, \
    .country__t         = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE, \
    .org__t      = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE, \
    .org_unit__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_ALLOCATABLE, \
  }
#endif // ifdef FLEA_HAVE_X509_DN_DETAILS

typedef struct
{
  flea_u8_t       is_present__u8;
  flea_byte_vec_t key_id__t;
} flea_x509_auth_key_id_t;

typedef struct
{
  flea_u8_t   is_present__u8;
  flea_bool_t is_ca__b;
  flea_bool_t has_path_len__b;
  flea_u16_t  path_len__u16;
} flea_basic_constraints_t;

typedef struct
{
  flea_u8_t  is_present__u8;
  flea_u16_t purposes__u16;
} flea_key_usage_t;

typedef struct
{
  flea_u8_t       is_present__u8;
  flea_byte_vec_t raw_ref__t;
} flea_x509_raw_ext_t;

typedef struct
{
  flea_u8_t       is_present__u8;
  flea_byte_vec_t san_raw__t;
} flea_x509_subj_alt_names_t;

typedef struct
{
  flea_key_usage_t           key_usage__t;
  flea_key_usage_t           ext_key_usage__t;
  flea_x509_subj_alt_names_t san__t;
  flea_basic_constraints_t   basic_constraints__t;
  flea_x509_raw_ext_t        crl_distr_point__t;
#ifdef FLEA_X509_CERT_REF_WITH_DETAILS
  flea_x509_auth_key_id_t    auth_key_id__t;
  flea_byte_vec_t            subj_key_id__t;
  flea_x509_raw_ext_t        auth_inf_acc__t;
  flea_x509_raw_ext_t        freshest_crl__t;
#endif
} flea_x509_ext_ref_t;

typedef struct
{
  /**
   *  the interpreted version number (not the encoded integer)
   */
  flea_u8_t                   version__u8;

  flea_byte_vec_t             serial_number__t;
  flea_x509_algid_ref_t       tbs_sig_algid__t;

  flea_x509_dn_ref_t          issuer__t;


  flea_gmt_time_t             not_before__t;
  flea_gmt_time_t             not_after__t;
  flea_x509_dn_ref_t          subject__t;

  flea_x509_public_key_info_t subject_public_key_info__t;

#ifdef FLEA_X509_CERT_REF_WITH_DETAILS
  flea_byte_vec_t             issuer_unique_id_as_bitstr__t;

  flea_byte_vec_t             subject_unique_id_as_bitstr__t;
#endif
  flea_x509_ext_ref_t         extensions__t;

  flea_byte_vec_t             cert_signature_as_bit_string__t;
} flea_x509_cert_ref_t;


#define flea_x509_cert_ref_t__INIT_VALUE {.version__u8 = 0}
#define flea_x509_cert_ref_t__INIT(__p) memset((__p), 0, sizeof(*(__p)))

#define flea_x509_cert_ref_t__dtor(__p)

/**
 * Check if a path length limit is defined in the certificate's basic
 * constraints extension.
 *
 * @param cert_ref pointer to a flea_x509_cert_ref_t object.
 *
 * @return FLEA_TRUE if the certificate has a path length limit, FLEA_FALSE
 * otherwise.
 */
#define flea_x509_cert_ref_t__HAS_PATH_LEN_LIMIT(cert_ref__pt) (((cert_ref__pt)->extensions__t.basic_constraints__t.is_present__u8 && (cert_ref__pt)->extensions__t.basic_constraints__t.has_path_len__b) ? FLEA_TRUE : FLEA_FALSE)

/**
 * Get the path length limit as specified by the basic constraints extension.
 * May only be called if flea_x509_cert_ref_t__HAS_PATH_LEN_LIMIT returns
 * FLEA_TRUE.
 *
 * @return the path length limit of the certificate.
 */
#define flea_x509_cert_ref_t__GET_PATH_LEN_LIMIT(cert_ref__pt) ((cert_ref__pt)->extensions__t.basic_constraints__t.path_len__u16)

/**
 * Check whether the certificate is a valid CA certificate according to its
 * basic constraints extension.
 *
 * @return FLEA_TRUE if the certificate is a CA certificate, FLEA_FALSE
 * otherwise.
 */
#define flea_x509_cert_ref_t__IS_CA(cert_ref__pt) (((cert_ref__pt)->extensions__t.basic_constraints__t.is_present__u8 && (cert_ref__pt)->extensions__t.basic_constraints__t.is_ca__b) ? FLEA_TRUE : FLEA_FALSE)

/**
 * Determine whether the certificate features an issuer unique id.
 *
 * @return FLEA_TRUE if the certificate has an issuer unique id, FLEA_FALSE
 * otherwise.
 */
#define flea_x509_cert_ref_t__HAS_ISSUER_UNIQUE_ID(cert_ref__pt) (FLEA_DER_REF_IS_ABSENT(&(cert_ref__pt)->issuer_unique_id_as_bitstr__t) ? FLEA_FALSE : FLEA_TRUE)


/**
 * Get the issuer unique id as bit string.
 * May only be called if flea_x509_cert_ref_t__HAS_ISSUER_UNIQUE_ID return
 * FLEA_TRUE.
 *
 * @param cert_ref_pt pointer to the flea_x509_cert_ref_t object
 * @param result_ref a pointer to a flea_ref_cu8_t which receives the result
 *
 */
#ifdef FLEA_X509_CERT_REF_WITH_DETAILS
# define flea_x509_cert_ref_t__GET_REF_TO_ISSUER_UNIQUE_ID_AS_BIT_STRING(cert_ref__pt, result_ref) \
  do {if(FLEA_DER_REF_IS_ABSENT(&(cert_ref__pt)->issuer_unique_id_as_bitstr__t))  { \
        (result_ref)->data__pcu8 = NULL; \
        (result_ref)->len__dtl   = 0; \
      } else { \
        (result_ref)->data__pcu8 = (cert_ref__pt)->issuer_unique_id_as_bitstr__t.data__pu8; \
        (result_ref)->len__dtl   = (cert_ref__pt)->issuer_unique_id_as_bitstr__t.len__dtl; \
      } \
  } while(0)
#endif

/**
 * Get the version of the certificate.
 *
 * @param cert_ref_pt pointer to the flea_x509_cert_ref_t object
 *
 * @return the version of the certificate
 */
#define flea_x509_cert_ref_t__GET_CERT_VERSION(cert_ref__pt) ((cert_ref__pt)->version__u8)

/**
 * Get the serial number of the certificate.
 *
 * @param cert_ref_pt pointer to the flea_x509_cert_ref_t object
 * @param result__prcu8 a pointer to a flea_ref_u8_t which receives the result
 *
 */
#define flea_x509_cert_ref_t__GET_SERIAL_NUMBER(cert_ref__pt, result_ref__prcu8) \
  do { \
    (result_ref__prcu8)->data__pcu8 = (cert_ref__pt)->serial_number__t.data__pu8; \
    (result_ref__prcu8)->len__dtl   = (cert_ref__pt)->serial_number__t.len__dtl; \
  } while(0)

/**
 * Get the signature algorithm OID of the certificate.
 *
 * @param cert_ref_pt pointer to the flea_x509_cert_ref_t object
 * @param result__prcu8 a pointer to a flea_ref_u8_t which receives the result
 *
 */
#define flea_x509_cert_ref_t__GET_SIGALG_OID(cert_ref__pt, result_ref__prcu8) \
  do { \
    (result_ref__prcu8)->data__pcu8 = (cert_ref__pt)->tbs_sig_algid__t.oid_ref__t.data__pu8; \
    (result_ref__prcu8)->len__dtl   = (cert_ref__pt)->tbs_sig_algid__t.oid_ref__t.len__dtl; \
  } while(0)


/**
 * Create a flea_x509_cert_ref_t certifcate reference object, the purpose of which is to enable access to the certificate's elements. Such an object refers to the elements
 * of the DER encoded certificate which has been used to construct it, thus the
 * encoded certificate must remain in the same memory location for the whole
 * lifetime of the the flea_x509_cert_ref_t.
 *
 * @param cert_ref the certificate reference object to construct
 * @param der_encoded_cert pointer to the encoded certificate to parse
 * @param der_encoded_cert_len the length of der_encoded_cert
 */
flea_err_t THR_flea_x509_cert_ref_t__ctor(
  flea_x509_cert_ref_t* cert_ref,
  const flea_u8_t*      der_encoded_cert,
  flea_al_u16_t         der_encoded_cert_len
);

/**
 * Get a reference to a subject DN component of a certificate.
 *
 * @param cert_ref__pt the certificate reference object to get the data from
 * @param cmpnt identififier of the DN component to get
 * @param result pointer to the object to store the result
 */
flea_err_t THR_flea_x509_cert_ref_t__get_subject_dn_component(
  flea_x509_cert_ref_t const* cert_ref,
  flea_dn_cmpnt_e             cmpnt,
  flea_ref_cu8_t*             result
);


/**
 * Get a reference to an issuer DN component of a certificate.
 *
 * @param cert_ref__pt the certificate reference object to get the data from
 * @param cmpnt identififier of the DN component to get
 * @param result pointer to the object to store the result
 */
flea_err_t THR_flea_x509_cert_ref_t__get_issuer_dn_component(
  flea_x509_cert_ref_t const* cert_ref,
  flea_dn_cmpnt_e             cmpnt,
  flea_ref_cu8_t*             result
);

/**
 * Test for allowed key usages in the certificate.
 *
 * @param cert_ref the certificate reference object to check for the key usages.
 * @param required_usages the required key usages to check for as a combination
 * of values from flea_key_usage_e.
 * @param explicitness here, flea_key_usage_explicit means that the key usage
 * extension must be explicitly contained in the certificate for any key usage
 * to be considered supported; whereas in the case of flea_key_usage_implicit
 * a non-existing key usage extension means that all key usages are considered
 * to be supported.
 *
 * @return FLEA_TRUE if all the required key usages are supported, FLEA_FALSE
 * otherwise.
 */
flea_bool_t flea_x509_cert_ref_t__has_key_usages(
  flea_x509_cert_ref_t const*  cert_ref,
  flea_key_usage_e             required_usages,
  flea_key_usage_exlicitness_e explicitness
);

/**
 * Test for allowed extended key usages in the certificate.
 *
 * @param cert_ref the certificate reference object to check for the key usages.
 * @param required_usages the required key usages to check for as a combination
 * of values from flea_ext_key_usage_e.
 * @param explicitness here, flea_key_usage_explicit means that the extended key usage
 * extension must be explicitly contained in the certificate for any extended key usage
 * to be considered supported; whereas in the case of flea_key_usage_implicit
 * a non-existing extended key usage extension means that all key usages are considered
 * to be supported.
 *
 * @return FLEA_TRUE if all the required key usages are supported, FLEA_FALSE
 * otherwise.
 */
flea_bool_t flea_x509_cert_ref_t__has_extended_key_usages(
  flea_x509_cert_ref_t const*  cert_ref__pt,
  flea_ext_key_usage_e         required_usages,
  flea_key_usage_exlicitness_e explicitness
);


/**
 * Find out whether a certificate is self issued.
 *
 * @param cert_ref the certificate reference object
 *
 * @return FLEA_TRUE if the certificate is self issued, FLEA_FALSE otherwise.
 */
flea_bool_t flea_x509_is_cert_self_issued(const flea_x509_cert_ref_t* cert_ref);

/**
 * Get a reference to the to-be-signed part of a DER encoded certificate.
 *
 * @param der_encoded_cert pointer to the encoded certificate
 * @param der_encoded_cert_len length of the encoded certificate
 * @param ref_to_tbs receives the the result
 */
flea_err_t THR_flea_x509_cert__get_ref_to_tbs(
  const flea_u8_t* der_encoded_cert,
  flea_al_u16_t    der_encoded_cert_len,
  flea_ref_cu8_t*  ref_to_tbs
);


flea_err_t THR_flea_x509_cert__get_ref_to_tbs_byte_vec(
  const flea_u8_t* der_encoded_cert__pu8,
  flea_al_u16_t    der_encoded_cert_len__alu16,
  flea_byte_vec_t* ref_to_tbs__pt
);


#ifdef __cplusplus
}
#endif

#endif /* h-guard */
