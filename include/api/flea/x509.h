/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_x509__H_
#define _flea_x509__H_

#include "flea/types.h"
#include "flea/ber_dec.h"

/**
 * Type to control the checking for specific key usages in key usage extensions (i.e. key usage or
 * extended key usage).
 *
 * flea_key_usage_explicit means the respective extension is present and the specified key usages are supported
 * flea_key_usage_implicit means the respective extension is not present and
 *                         thus the key usage is not restricted.
 */
typedef enum {flea_key_usage_explicit, flea_key_usage_implicit } flea_key_usage_exlicitness_e;

/**
 * An identifier for either the key usage or extended key usage extension in a
 * certificate.
 */
typedef enum {flea_key_usage_extension, flea_extended_key_usage_extension } flea_key_usage_ext_e;

typedef enum {
flea_ku_none_set           = 0,
flea_ku_digital_signature  = (1  <<  15), 
flea_ku_content_commitment = (1  <<  14),     /*  aka  nonrepudiation  */
flea_ku_key_encipherment   = (1  <<  13),
flea_ku_data_encipherment  = (1  <<  12),
flea_ku_key_agreement      = (1  <<  11),
flea_ku_key_cert_sign      = (1  <<  10),
flea_ku_crl_sign           = (1  <<  9),
flea_ku_encipher_only      = (1  <<  8),
flea_ku_decipher_only      = (1  <<  7)
} flea_key_usage_e;

#define FLEA_ASN1_EKU_BITP_any_ext_ku        0
#define FLEA_ASN1_EKU_BITP_server_auth       1
#define FLEA_ASN1_EKU_BITP_client_auth       2
#define FLEA_ASN1_EKU_BITP_code_signing      3
#define FLEA_ASN1_EKU_BITP_email_protection  4
#define FLEA_ASN1_EKU_BITP_time_stamping     8
#define FLEA_ASN1_EKU_BITP_ocsp_signing      9

typedef enum {

 flea_eku_none_set         = 0,
 flea_eku_any_ext_ku       = (1 << FLEA_ASN1_EKU_BITP_any_ext_ku),
 flea_eku_server_auth      = (1 << FLEA_ASN1_EKU_BITP_server_auth),
 flea_eku_client_auth      = (1 << FLEA_ASN1_EKU_BITP_client_auth),
 flea_eku_code_signing     = (1 << FLEA_ASN1_EKU_BITP_code_signing),
 flea_eku_email_protection = (1 << FLEA_ASN1_EKU_BITP_email_protection),
 flea_eku_time_stamping    = (1 << FLEA_ASN1_EKU_BITP_time_stamping),
 flea_eku_ocsp_signing     = (1 << FLEA_ASN1_EKU_BITP_ocsp_signing)
} flea_ext_key_usage_e;

typedef flea_der_ref_t flea_x509_ref_t; 


typedef struct
{
  const flea_u8_t *data__pcu8;
  flea_dtl_t len__dtl;
  flea_asn1_time_type_t time_type__t;
} flea_x509_date_ref_t;

typedef struct
{
  flea_u16_t year;
  flea_u8_t month;
  flea_u8_t day;
  flea_u8_t hours;
  flea_u8_t minutes;
  flea_u8_t seconds;
} flea_gmt_time_t;


typedef struct
{
 flea_der_ref_t oid_ref__t;
 flea_der_ref_t params_ref_as_tlv__t;
} flea_x509_algid_ref_t;

typedef struct
{
  flea_x509_algid_ref_t algid__t;
  flea_x509_ref_t public_key_as_tlv__t;
} flea_x509_public_key_info_t;

typedef struct
{
  flea_x509_ref_t raw_dn_complete__t;
  flea_x509_ref_t country__t;
  flea_x509_ref_t org__t;
  flea_x509_ref_t org_unit__t;
  flea_x509_ref_t dn_qual__t;
  flea_x509_ref_t state_or_province_name__t;
  flea_x509_ref_t locality_name__t;
  flea_x509_ref_t common_name__t;
  flea_x509_ref_t serial_number__t;
  flea_x509_ref_t domain_component_attribute__t;
} flea_x509_dn_ref_t;

typedef struct
{
  flea_u8_t is_present__u8;
  flea_der_ref_t key_id__t;
} flea_x509_auth_key_id_t;

typedef struct
{
  flea_u8_t is_present__u8;
  flea_bool_t is_ca__b;
  flea_bool_t has_path_len__b;
  flea_u16_t path_len__u16;
} flea_basic_constraints_t;


typedef struct
{
  flea_u8_t is_present__u8;
  flea_u16_t purposes__u16;
} flea_key_usage_t;

typedef struct
{
  flea_u8_t is_present__u8;
  flea_der_ref_t raw_ref__t;
} flea_x509_raw_ext_t;


typedef struct 
{
  flea_u8_t is_present__u8;
  flea_ref_cu8_t san_raw__t;
} flea_x509_subj_alt_names_t;

typedef struct
{
  flea_x509_auth_key_id_t auth_key_id__t;
  flea_der_ref_t subj_key_id__t;
  flea_key_usage_t key_usage__t;
  flea_key_usage_t ext_key_usage__t;
  flea_x509_subj_alt_names_t san__t;
  flea_basic_constraints_t basic_constraints__t;
  flea_x509_raw_ext_t crl_distr_point__t;
  flea_x509_raw_ext_t auth_inf_acc__t;
  flea_x509_raw_ext_t freshest_crl__t;
} flea_x509_ext_ref_t;

typedef struct
{

  flea_der_ref_t tbs_ref__t;
  /**
   *  the interpreted version number (not the encoded integer)
   */
  flea_u8_t version__u8; 

  flea_x509_ref_t serial_number__t;
  flea_x509_algid_ref_t tbs_sig_algid__t;

  flea_x509_dn_ref_t issuer__t;


  flea_gmt_time_t not_before__t;
  flea_gmt_time_t not_after__t;
  flea_x509_dn_ref_t subject__t;

  flea_x509_public_key_info_t subject_public_key_info__t;

  flea_x509_ref_t issuer_unique_id_as_bitstr__t;

  flea_x509_ref_t subject_unique_id_as_bitstr__t;

  flea_x509_ext_ref_t extensions__t;

  flea_der_ref_t cert_signature_as_bit_string__t;

  flea_bool_t is_trusted__b;

} flea_x509_cert_ref_t;


#define flea_x509_cert_ref_t__INIT_VALUE { .version__u8 = 0 }

#define flea_x509_cert_ref_t__dtor(__p) 

flea_err_t THR_flea_x509_cert_ref_t__ctor(flea_x509_cert_ref_t *cert_ref__pt, const flea_u8_t* der_encoded_cert__pu8, flea_x509_len_t der_encoded_cert_len__x5l);


flea_bool_t flea_x509_has_key_usages(const flea_x509_cert_ref_t *cert_ref__pt, flea_key_usage_ext_e ku_type, flea_key_usage_e required_usages__u16, flea_key_usage_exlicitness_e explicitness);

flea_err_t THR_flea_x509__parse_algid_ref(flea_x509_algid_ref_t *algid_ref__pt, flea_ber_dec_t *dec__pt);

flea_err_t THR_flea_x509__parse_dn(flea_x509_dn_ref_t *dn_ref__pt, flea_ber_dec_t *dec__pt);

flea_err_t THR_flea_x509__process_alg_ids(flea_x509_algid_ref_t* tbs_ref__pt, const flea_x509_algid_ref_t* outer_ref__pt);
#endif /* h-guard */
