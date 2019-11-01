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


#ifndef _flea_x509_const_int__H_
#define _flea_x509_const_int__H_

#include "flea/byte_vec.h"
#include "flea/asn1_date.h"

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
#define ID_PE_INDIC                         (0x0200)
#define ID_PE_OID_AUTH_INF_ACC              (ID_PE_INDIC | 1)
#define ID_PE_OID_SUBJ_INF_ACC              (ID_PE_INDIC | 11)

#define FLEA_ASN1_EKU_BITP_any_ext_ku       0
#define FLEA_ASN1_EKU_BITP_server_auth      1
#define FLEA_ASN1_EKU_BITP_client_auth      2
#define FLEA_ASN1_EKU_BITP_code_signing     3
#define FLEA_ASN1_EKU_BITP_email_protection 4
#define FLEA_ASN1_EKU_BITP_time_stamping    8
#define FLEA_ASN1_EKU_BITP_ocsp_signing     9


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
#endif // ifdef FLEA_HAVE_X509_DN_DETAILS
} flea_x509_dn_ref_t;

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
#endif // ifdef FLEA_X509_CERT_REF_WITH_DETAILS
} flea_x509_ext_ref_t;

extern const flea_u8_t id_pe__cau8 [7];


#endif /* h-guard */
