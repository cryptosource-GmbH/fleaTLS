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

#ifndef __flea_error_H_
# define __flea_error_H_

# ifdef __cplusplus
extern "C" {
# endif


typedef enum
{
  /**
   * Successful execution.
   */
  FLEA_ERR_FINE                                         = 0x00,

  /**
   * An unexpected internal error occurred.
   */
  FLEA_ERR_INT_ERR                                      = 0x01,

  /**
   * An invalid state occurred.
   */
  FLEA_ERR_INV_STATE                                    = 0x02,

  /**
   * A unit test failed.
   */
  FLEA_ERR_FAILED_TEST                                  = 0x03,

  /**
   * The integrity of a ciphertext was found to be violated during decryption.
   */
  FLEA_ERR_INTEGRITY_FAILURE                            = 0x04,

  /**
   * An integer overflow occurred.
   */
  FLEA_ERR_INT_OVERFLOW                                 = 0x05,

  /**
   * An invalid argument was provided to a function.
   */
  FLEA_ERR_INV_ARG                                      = 0x06,

  /**
   * An invalid / unsupported cryptographic algorithm was requested.
   */
  FLEA_ERR_INV_ALGORITHM                                = 0x08,

  /**
   * An invalid MAC tag was encountered.
   */
  FLEA_ERR_INV_MAC                                      = 0x09,

  /**
   * An elliptic curve point was found not to lie on the corresponding curve.
   */
  FLEA_ERR_POINT_NOT_ON_CURVE                           = 0x0A,

  /**
   * An elliptic curve domain parameter set is invalid.
   */
  FLEA_ERR_INV_ECC_DP                                   = 0x0B,

  /**
   * The requested cryptographic key size is invalid or unsupported.
   */
  FLEA_ERR_INV_KEY_SIZE                                 = 0x0C,

  /**
   * The size of a component of a cryptographic key is invalid.
   */
  FLEA_ERR_INV_KEY_COMP_SIZE                            = 0x0D,

  /**
   * An invalid cryptographic key type was specified for an operation.
   */
  FLEA_ERR_INV_KEY_TYPE                                 = 0x0E,

  /**
   * The public key size does not meet the required security level.
   */
  FLEA_ERR_PUBKEY_SEC_LEV_NOT_MET                       = 0x0F,

  /**
   * Attempt to transform the elliptic curve point O (zero) to affine
   * coordinates. Indicates invalid input data to an elliptic curve algorithm.
   */
  FLEA_ERR_ZERO_POINT_AFF_TRF                           = 0x20,

  /**
   * invalid reverence to a builtin domain parameter set, for example via an invalid or
   * unsupported OID of a "named curve" in an X.509 certificate.
   */
  FLEA_ERR_ECC_INV_BUILTIN_DP_ID                        = 0x21,

  /**
   * The cryptographic verification of the signature failed
   */
  FLEA_ERR_INV_SIGNATURE                                = 0x22,

  /**
   * The invalid ciphertext detected during decryption.
   */
  FLEA_ERR_INV_CIPHERTEXT                               = 0x23,

  /**
   * The user provided hostname for the verification of the server
   * identity, e.g. in TLS, is of an invalid form.
   */
  FLEA_ERR_X509_INVALID_USER_HOSTN                      = 0x40,

  /**
   * The user provided ID (DNS name, URI or IP address) of the TLS server
   * could not be matched in the server certificate.
   */
  FLEA_ERR_X509_TLS_SERVER_ID_NO_MATCH                  = 0x41,

  /**
   * The key usage or extended key usage extension in the certificate of the peer (server or client to which the
   * connection is attempted) is not valid for the selected cipher suite.
   */
  FLEA_ERR_TLS_PEER_CERT_INVALID_KEY_USAGE              = 0x43,

  /**
   * The operation cannot be carried out because the TLS session was closed.
   */
  FLEA_ERR_TLS_SESSION_CLOSED                           = 0x44,

  /**
   * A fatal TLS alert was received and the connection terminated.
   */
  FLEA_ERR_TLS_REC_FATAL_ALERT                          = 0x45,

  /**
   * An unexpected TLS message was received during a TLS handshake.
   */
  FLEA_ERR_TLS_UNEXP_MSG_IN_HANDSH                      = 0x46,

  /**
   * A bad record MAC was encountered when processing received TLS records.
   */
  FLEA_ERR_TLS_ENCOUNTERED_BAD_RECORD_MAC               = 0x47,

  /**
   * The validation of the peer's certificate failed.
   */
  FLEA_ERR_TLS_CERT_VER_FAILED                          = 0x48,

  /**
   * The TLS session was closed and the sending of alert has failed.
   */
  FLEA_ERR_TLS_SESSION_CLOSED_WHEN_TRYING_TO_SEND_ALERT = 0x49,

  /**
   * During the handshake, no cipher suite could be negotiated with the peer.
   */
  FLEA_ERR_TLS_COULD_NOT_AGREE_ON_CIPHERSUITE           = 0x4A,

  /**
   * During the handshake, no compression method could be negotiated with the peer.
   */
  FLEA_ERR_TLS_COULD_NOT_AGREE_ON_CMPR_METH             = 0x4B,

  /**
   * Indication of internal exceptional control flow.
   */
  FLEA_EXC_TLS_HS_MSG_DURING_APP_DATA                   = 0x4C,

  /**
   * Invalid contents of a TLS record header.
   */
  FLEA_ERR_TLS_INV_REC_HDR                              = 0x4E,

  /**
   * A received record does not fit into the available buffer.
   */
  FLEA_ERR_TLS_EXCSS_REC_LEN                            = 0x4F,

  /**
   * An invalid TLS record was received.
   */
  FLEA_ERR_TLS_INV_REC                                  = 0x51,

  /**
   * The fleaTLS client received an invalid algorithm choice in the server hello.
   */
  FLEA_ERR_TLS_INV_ALGO_IN_SERVER_HELLO                 = 0x52,

  /**
   * The peer only offered an unsupported TLS version.
   */
  FLEA_ERR_TLS_UNSUPP_PROT_VERSION                      = 0x53,

  /**
   * An error occurred while decoding a received TLS record.
   */
  FLEA_ERR_TLS_PROT_DECODE_ERR                          = 0x54,

  /**
   * An invalid TLS cipher suite was requested.
   */
  FLEA_ERR_TLS_INV_CIPH_SUITE                           = 0x55,


  /**
   * Received a no-renegotiation alert during a renegotiation. This error is
   * only handled internally and not observed on the API.
   */
  FLEA_ERR_TLS_REC_NORENEG_AL_DURING_RENEG = 0x56,


  /**
   * Thrown if renegotiation is requested through the API but due to the
   * connection's configuration, renegotiation is not allowed.
   */
  FLEA_ERR_TLS_RENEG_NOT_ALLOWED           = 0x57,

  /**
   * The parameters sent by the peer during the TLS handshake led to a handshake
   * failure.
   */
  FLEA_ERR_TLS_HANDSHK_FAILURE             = 0x58,

  /**
   * The TLS connection was ended due to receiving a close-notify alert.
   */
  FLEA_ERR_TLS_REC_CLOSE_NOTIFY            = 0x59,

  /**
   * thrown if we couldn't agree on a received SignatureAlgorithms field
   */
  FLEA_ERR_TLS_NO_SIG_ALG_MATCH            = 0x60,

  /**
   * thrown if the server does not recognize the client's psk_identity.
   */
  FLEA_ERR_TLS_UNKNOWN_PSK_IDENTITY        = 0x61,

  /**
   * thrown if a parameter in a handshake message is out of range / inconsistent
   * with other fields
   */
  FLEA_ERR_TLS_ILLEGAL_PARAMETER           = 0x62,

  /*
   * thrown if we explicitely want to trigger a RECORD_OVERFLOW alert.
   */
  FLEA_ERR_TLS_RECORD_OVERFLOW             = 0x63,

  /**
   * The PKCS#8 key type provided in the algorithm identifier is not supported.
   */
  FLEA_ERR_PKCS8_INVALID_KEY_OID           = 0x70,

  /**
   * An optional element in a PKCS#8 structure (optional in the ASN.1 specification) is missing which is necessary for the requested operation, e.g. for the creation of a public key.
   */
  FLEA_ERR_PKCS8_MISSING_OPT_ELEMENT       = 0x71,

  /**
   * A requested operation on a flea_rw_stream_t object is not supported by that
   * object.
   */
  FLEA_ERR_STREAM_FUNC_NOT_SUPPORTED       = 0x90,

  /**
   * A read stream has reached end-of-file.
   */
  FLEA_ERR_STREAM_EOF                      = 0x91,

  /**
   * During a stream read operation in timeout mode (flea_read_timeout), a
   * timeout occurred.
   */
  FLEA_ERR_TIMEOUT_ON_STREAM_READ          = 0x92,

  /**
   * An internal buffer is too small for the requested operation.
   */
  FLEA_ERR_BUFF_TOO_SMALL                  = 0xA0,

  /**
   * A general ASN.1 decoding error occurred.
   */
  FLEA_ERR_ASN1_DER_DEC_ERR                = 0xA3,

  /**
   * An unexpected tag was encountered during ASN.1 decoding.
   */
  FLEA_ERR_ASN1_DER_UNEXP_TAG              = 0xA4,

  /**
   * An excessive length was encountered during ASN.1 decoding.
   */
  FLEA_ERR_ASN1_DER_EXCSS_LEN              = 0xA5,

  /**
   * An excessive nesting was encountered during ASN.1 decoding.
   */
  FLEA_ERR_ASN1_DER_EXCSS_NST              = 0xA6,

  /**
   * The provided target buffer is too small during an ASN.1 decoding request.
   */
  FLEA_ERR_ASN1_DEC_TRGT_BUF_TOO_SMALL     = 0xA7,

  /**
   * The program's call sequence for ASN.1 decoding is invalid, for instance due
   * to closing more constructed types than previously opened.
   */
  FLEA_ERR_ASN1_DER_CALL_SEQ_ERR           = 0xA8,

  /**
   * An length limit was exceeded during ASN.1 decoding.
   */
  FLEA_ERR_ASN1_DER_CST_LEN_LIMIT_EXCEEDED = 0xA9,

  /**
   * Unspecified error while trying to read from a stream.
   */
  FLEA_ERR_FAILED_STREAM_READ              = 0xAD,

  /**
   * Unspecified error while trying to write to a stream.
   */
  FLEA_ERR_FAILED_STREAM_WRITE             = 0xAE,

  /**
   * An error occurred when opening a connection. This value is not thrown by
   * fleaTLS itself, but may be used by flea_rw_stream_t implementations to indicate
   * errors.
   */
  FLEA_ERR_FAILED_TO_OPEN_CONNECTION       = 0xAF,


  /**
   * An invalid version in an X.509 related object was encountered.
   */
  FLEA_ERR_X509_VERSION_ERROR      = 0xC0,

  /**
   * An error occurred while processing an X.509 distinguished name.
   */
  FLEA_ERR_X509_DN_ERROR           = 0xC1,

  /**
   * An unsupported critical extension was encountered.
   */
  FLEA_ERR_X509_ERR_UNSUP_CRIT_EXT = 0xC2,

  /**
   * An error occurred while decoding the Subject Alternative Name Extension of a
   * X.509 certificate.
   */
  FLEA_ERR_X509_SAN_DEC_ERR        = 0xC4,

  /**
   * A negative integer was unexpectedly encountered in an X.509 object.
   */
  FLEA_ERR_X509_NEG_INT            = 0xC5,


  /**
   * An unsupported Name Constraints Extension marked as critical was found in a
   * certificate.
   */
  FLEA_ERR_X509_ERR_UNSUP_CRIT_NAME_CONSTRAINTS_EXT   = 0xC7,

  /**
   * An unsupported Policy Constraints Extension marked as critical was found in a
   * certificate.
   */
  FLEA_ERR_X509_ERR_UNSUP_CRIT_POLICY_CONSTRAINTS_EXT = 0xC8,

  /**
   * An invalid value in the Extended Key Usage Extension was encountered.
   */
  FLEA_ERR_X509_EKU_VAL_ERR                           = 0xC9,

  /**
   * An invalid/inconsistent value of the signature algorithm in an X.509 object
   * was encountered.
   */
  FLEA_ERR_X509_SIG_ALG_ERR                           = 0xCA,

  /**
   * An unsupported algorithm specification was encountered in an X.509 object.
   */
  FLEA_ERR_X509_UNSUPP_ALGO                           = 0xCB,

  /**
   * An error occurred while decoding an ASN.1 bit string.
   */
  FLEA_ERR_X509_BIT_STR_ERR                           = 0xCC,

  /**
   * The hash function indicated by the encoding in an OID is not recognized.
   * This error is to be distinguished from INV_ALGORITHM, can indicate
   * that the support for an algorithm is not configured in flea
   */
  FLEA_ERR_X509_UNRECOG_HASH_FUNCTION                 = 0xCD,

  /**
   * For a supported primitive the specified variant in an OID is not supported
   * or known.
   */
  FLEA_ERR_X509_UNSUPP_ALGO_VARIANT                   = 0xCE,

  /**
   * Error with the decoded public ECC parameters. Is also used to
   * indicate missing parameters.
   */
  FLEA_ERR_X509_INV_ECC_KEY_PARAMS                    = 0xCF,

  /**
   * An invalid/unsupported ECC field type was encountered in an X.509 object.
   */
  FLEA_ERR_X509_INV_ECC_FIELD_TYPE                    = 0xD0,

  /**
   * An X.509 object did not provide explicit or named elliptic curve
   * parameters.
   */
  FLEA_ERR_X509_IMPLICT_ECC_KEY_PARAMS                = 0xD1,

  /**
   * Error with the ECC point format, e.g. invalid length or unknown/unsupported
   * encoding.
   */
  FLEA_ERR_X509_INV_ECC_POINT_ENCODING                = 0xD2,

  /**
   * An encoded ECC cofactor has size larger than FLEA_ECC_MAX_COFACTOR_BIT_SIZE
   */
  FLEA_ERR_X509_EXCSS_COFACTOR_SIZE                   = 0xD3,

  /**
   * An unsupported critical CRL extension was encountered.
   */
  FLEA_ERR_X509_UNSUPP_CRIT_CRL_EXT                   = 0xD4,

  /**
   * A Delta CRL, which is not supported by flea, was encountered.
   */
  FLEA_ERR_X509_UNSUPP_DELTA_CRL                      = 0xD5,

  /**
   * An indirect CRL, which is not supported by flea, was encountered.
   */
  FLEA_ERR_X509_UNSUPP_INDIR_CRL                      = 0xD6,

  /**
   * In the Issuing Distribution Point CRL Extension, onlySomeReasons was
   * specified and did not include all reasons. This is not supported by flea.
   */
  FLEA_ERR_X509_CRL_INCOMPL_REASONS                   = 0xD7,

  /**
   * At least one of the issuer DNs of the CRL and the checked certificate does not match the
   * subject DN of the issuer of both.
   */
  FLEA_ERR_X509_CRL_NAMES_DONT_MATCH                  = 0xD8,

  /**
   * The next update field of a CRL is exceeded.
   */
  FLEA_ERR_X509_CRL_NEXT_UPDATE_PASSED                = 0xD9,

  /**
   * A CRL issuer certificate does not fulfil the requirements for the Key
   * Usage Extension.
   */
  FLEA_ERR_X509_CRL_ISSUER_WO_CRL_SIGN                = 0xDA,

  /**
   * The CRL is issued for the wrong type of certificate according to the
   * Issuing Distribution Point CRL Extension.
   */
  FLEA_ERR_X509_UNSUITABLE_CRL                        = 0xDB,

  /**
   * The revocation status of a certificate could not be determined.
   */
  FLEA_ERR_X509_CERT_REV_STAT_UNDET                   = 0xDC,

  /**
   * An operation failed due to the X.509 certificate being revoked.
   */
  FLEA_ERR_X509_CERT_REVOKED                          = 0xDD,

  /**
   * There is a mismatch between the CRL Distribution Points extension in
   * the certificate and the Issuing Distribution Point extension (IDP) in the
   * CRL. Possible errors are:
   *  - a certificate doesn't have the CDP,
   *  but the CRL has an IDP which contains a DP name
   */
  FLEA_ERR_X509_CRL_CDP_IDP_MISMATCH                  = 0xDE,


  /**
   *  Certificate path validation failed because no trusted root certificate was
   *  found / contained in the path.
   */
  FLEA_ERR_CERT_PATH_NO_TRUSTED_CERTS    = 0xE0,

  /**
   * The certificate's cert path could not be found.
   */
  FLEA_ERR_CERT_PATH_NOT_FOUND           = 0xE1,

  /**
   * An operation failed due to the X.509 certificate being expired.
   */
  FLEA_ERR_X509_CERT_EXPIRED             = 0xE2,

  /**
   * An operation failed due to the X.509 certificate being not yet valid.
   */
  FLEA_ERR_X509_CERT_NOT_YET_VALID       = 0xE3,

  /**
   * The maximal allowed certification path length was exceeded during the
   * validation of an X.509 certificate.
   */
  FLEA_ERR_CERT_PATH_LEN_CONSTR_EXCEEDED = 0xE4,

  /**
   * An intermediate CA certificate is not qualified as a CA certificate.
   */
  FLEA_ERR_CERT_INTERMED_IS_NOT_CA_CERT  = 0xE5,

  /**
   * The routine for the construction of a valid certification path
   * was cancelled from another thread.
   */
  FLEA_ERR_X509_USER_CANCELLED           = 0xE6,

  /**
   * A function to determine the current time was not supplied to THR_flea_lib__init().
   */
  FLEA_ERR_NOW_FUNC_IS_NULL              = 0xE7,

  /**
   * The initialization of a mutex failed.
   */
  FLEA_ERR_MUTEX_INIT                    = 0xF1,

  /**
   * Locking or unlocking of a mutex failed.
   */
  FLEA_ERR_MUTEX_LOCK                    = 0xF2,

  /**
   * A memory allocation request could not be satisfied.
   */
  FLEA_ERR_OUT_OF_MEM                    = 0xFFFF,
} flea_err_e;

# ifdef __cplusplus
}
# endif

#endif /* h-guard */
