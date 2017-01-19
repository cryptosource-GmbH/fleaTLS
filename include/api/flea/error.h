/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef __flea_error_H_
#define __flea_error_H_

#ifdef __cplusplus
extern "C" {
#endif


typedef enum
{
  FLEA_ERR_FINE                                       = 0x0000,
  FLEA_ERR_INT_ERR                                    = 0x0001,
  FLEA_ERR_INV_STATE                                  = 0x0002,
  FLEA_ERR_FAILED_TEST                                = 0x0003,
  FLEA_ERR_INTEGRITY_FAILURE                          = 0x0004,

  FLEA_ERR_INV_ARG                                    = 0x0006,
  FLEA_ERR_INV_ALGORITHM                              = 0x0008,
  FLEA_ERR_INV_MAC                                    = 0x0009,
  FLEA_ERR_POINT_NOT_ON_CURVE                         = 0x000A,
  FLEA_ERR_INV_ECC_DP                                 = 0x000B,
  FLEA_ERR_INV_KEY_SIZE                               = 0x000C,
  FLEA_ERR_INV_KEY_COMP_SIZE                          = 0x000D,
  FLEA_ERR_INV_KEY_TYPE															  = 0x000E,
  FLEA_ERR_UNSUPP_KEY_SIZE                            = 0x000F,
  FLEA_ERR_ZERO_POINT_AFF_TRF                         = 0x0020,

  /** 
   * invalid reverence to a builtin domain parameter set, for example via an invalid or
   * unsupported OID of a "named curve" in an X.509 certificate.
   */
  FLEA_ERR_ECC_INV_BUILTIN_DP_ID                      = 0x0021,

  /**
   * The cryptographic verification of the signature failed
   */
  FLEA_ERR_INV_SIGNATURE                              = 0x0022,
  
  /**
   * The invalid ciphertext detected during decryption. 
   */
  FLEA_ERR_INV_CIPHERTEXT                             = 0x0023,


 /**
  * The user provided hostname for the verification of the server
  * identity, e.g. in TLS, is of an invalid form.
  */ 
  FLEA_ERR_X509_INVALID_USER_HOSTN                    = 0x0040,
  
  /**
   * The user provided ID (DNS name, URI or IP address) of the TLS server 
   * could not be matched in the server certificate.
   */
  FLEA_ERR_X509_TLS_SERVER_ID_NO_MATCH                = 0x0041,

  /**
   * The key usage or extended key usage extension in the certificate of the peer (server or client to which the
   * connection is attempted) is not valid for the selected cipher suite.
   */
  FLEA_ERR_TLS_PEER_CERT_INVALID_KEY_USAGE            = 0x0043,

  /**
   * A fixed sized buffer is too small or a reallocation in heap mode failed 
   * because the configured maximal buffer size was exhausted.
   */
  FLEA_ERR_BUFF_TOO_SMALL                             = 0x00A0,
  FLEA_ERR_DECODING_FAILURE                           = 0x00A1,
  FLEA_ERR_ASN1_DER_DEC_ERR                           = 0x00A3,
  FLEA_ERR_ASN1_DER_UNEXP_TAG                         = 0x00A4,
  FLEA_ERR_ASN1_DER_EXCSS_LEN                         = 0x00A5,
  FLEA_ERR_ASN1_DER_EXCSS_NST                         = 0x00A6,
  FLEA_ERR_ASN1_DEC_TRGT_BUF_TOO_SMALL                = 0x00A7,
  FLEA_ERR_ASN1_DER_CALL_SEQ_ERR                      = 0x00A8,
  FLEA_ERR_ASN1_DER_CST_LEN_LIMIT_EXCEEDED            = 0x00A9,
  FLEA_ERR_FAILED_STREAM_READ                         = 0x00AD,
  FLEA_ERR_FAILED_STREAM_WRITE                        = 0x00AE,
  FLEA_ERR_PRNG_NVM_WRITE_ERROR                       = 0x00B1,
  FLEA_ERR_RNG_NOT_SEEDED                             = 0x00B2,
  FLEA_ERR_X509_VERSION_ERROR                         = 0x00C0,
  FLEA_ERR_X509_DN_ERROR                              = 0x00C1,
  FLEA_ERR_X509_ERR_UNSUP_CRIT_EXT                    = 0x00C2,
  FLEA_ERR_X509_KU_DEC_ERR                            = 0x00C3,
  FLEA_ERR_X509_SAN_DEC_ERR                           = 0x00C4,
  FLEA_ERR_X509_NEG_INT                               = 0x00C5,
  FLEA_ERR_X509_BC_EXCSS_PATH_LEN                     = 0x00C6,
  FLEA_ERR_X509_ERR_UNSUP_CRIT_NAME_CONSTRAINTS_EXT   = 0x00C7,
  FLEA_ERR_X509_ERR_UNSUP_CRIT_POLICY_CONSTRAINTS_EXT = 0x00C8,
  FLEA_ERR_X509_EKU_VAL_ERR                           = 0x00C9,
  FLEA_ERR_X509_SIG_ALG_ERR                           = 0x00CA,
  FLEA_ERR_X509_UNSUPP_PRIMITIVE                      = 0x00CB,
  FLEA_ERR_X509_BIT_STR_ERR                           = 0x00CC,

  
  /**
   * The hash function indicated by the encoding in an OID is not recognized.
   * This error is to be distinguished from INV_ALGORITHM, can indicate
   * that the support for an algorithm is not configured in flea
   */
  FLEA_ERR_X509_UNRECOG_HASH_FUNCTION                 = 0x00CD,

  /**
   * For a supported primitive the specified variant in an OID is not supported
   * or known.
   */
  FLEA_ERR_X509_UNSUPP_ALGO_VARIANT                   = 0x00CE,

  /**
   * Error with the decoded public ECC parameters.
   */
  FLEA_ERR_X509_INV_ECC_KEY_PARAMS                    = 0x00CF,
  FLEA_ERR_X509_INV_ECC_FIELD_TYPE                    = 0x00D0,
  FLEA_ERR_X509_IMPLICT_ECC_KEY_PARAMS                = 0x00D1,

  /**
   * Error with the ECC point format, e.g. invalid length or unknown/unsupported
   * encoding.
   */
  FLEA_ERR_X509_INV_ECC_POINT_ENCODING                = 0x00D2,

  /**
   * An encoded ECC cofactor has size larger than FLEA_ECC_MAX_COFACTOR_BIT_SIZE 
   */
  FLEA_ERR_X509_EXCSS_COFACTOR_SIZE                   = 0x00D3,

  /**
   * An unsupported critical CRL extension was encountered.
   */
  FLEA_ERR_X509_UNSUPP_CRIT_CRL_EXT                   = 0x00D4,
  /**
   * A Delta CRL, which is not supported by flea, was encountered.
   */
  FLEA_ERR_X509_UNSUPP_DELTA_CRL                      = 0x00D5,
  /**
   * An indirect CRL, which is not supported by flea, was encountered.
   */
  FLEA_ERR_X509_UNSUPP_INDIR_CRL                      = 0x00D6,

  /**
   * In the Issuing Distribution Point CRL Extension, onlySomeReasons was
   * specified and did not include all reasons. This is not supported by flea.
   */
  FLEA_ERR_X509_CRL_INCOMPL_REASONS                   = 0x00D7,

  /**
   * At least one of the issuer DNs of the CRL and the checked certificate does not match the 
   * subject DN of the issuer of both.
   */
  FLEA_ERR_X509_CRL_NAMES_DONT_MATCH                  = 0x00D8,
  
  FLEA_ERR_X509_CRL_NEXT_UPDATE_PASSED                = 0x00D9,
  FLEA_ERR_X509_CRL_ISSUER_WO_CRL_SIGN                = 0x00DA,

  /**
   * The CRL is issued for the wrong type of certificate according to the
   * Issuing Distribution Point CRL Extension.
   */
  FLEA_ERR_X509_UNSUITABLE_CRL                        = 0x00DB,
  FLEA_ERR_X509_CERT_REV_STAT_UNDET                   = 0x00DC,
  FLEA_ERR_X509_CERT_REVOKED                          = 0x00DD,

  /** 
   * There is a mismatch between the CRL Distribution Points extension in 
   * the certificate and the Issuing Distribution Point extension (IDP) in the 
   * CRL. Possible errors are:
   *  - a certificate doesn't have the CDP, 
   *  but the CRL has an IDP which contains a DP name
   */
  FLEA_ERR_X509_CRL_CDP_IDP_MISMATCH                  = 0x00DE,

	FLEA_ERR_CERT_PATH_NO_TRUSTED_CERTS									= 0x00E0,
	FLEA_ERR_CERT_PATH_NOT_FOUND 												= 0x00E1,
  FLEA_ERR_CERT_NOT_YET_VALID                         = 0x00E2,
  FLEA_ERR_CERT_NO_MORE_VALID                         = 0x00E3,
  FLEA_ERR_CERT_PATH_LEN_CONSTR_EXCEEDED              = 0x00E4,
  FLEA_ERR_CERT_INTERMED_IS_NOT_CA_CERT               = 0x00E5,

  /**
   * The routine for the construction of a valid certification path
   * was cancelled from another thread.
   */
  FLEA_ERR_X509_USER_CANCELLED                        = 0X00E6,


  FLEA_ERR_OUT_OF_MEM                                 = 0x00FF,

} flea_err_t;

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
