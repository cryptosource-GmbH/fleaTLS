/*! \page pageX509 X.509 Certificate Handling
 *
\section secX509 X.509 Certificates

fleaTLS supports the parsing and validation of X.509 certificates and CRLs.

\subsection secX509Parse Parsing Certificates

For parsing certificates, the #flea_x509_cert_ref_t  type is used. This type holds references to the parsed certificate.
The functionality of this type is demonstrated by following extracts that have all been taken from the file <code>test/src/common/test_x509.c</code>

The first one shows the construction of such an object:

\snippet test_x509.c parse_cert_ctor

The encoded certificate that is input to #THR_flea_x509_cert_ref_t__ctor() must remain in memory for the whole lifetime of the #flea_x509_cert_ref_t object.

Afterwards, a number of macros and functions is available to access the certificates fields:

\snippet test_x509.c parse_cert_version
\snippet test_x509.c parse_cert_serial

The following example shows how to access the certificate's not before date:

\snippet test_x509.c parse_cert_time

The subject and issuer DN components can be retrieved individually:

\snippet test_x509.c parse_cert_issuer_comp

Information about the basic constraints extension can be extracted as follows:

\snippet test_x509.c parse_cert_is_ca
\snippet test_x509.c parse_cert_path_len

The key usages in the key usage and extended key usage extensions can be checked checked as follows:
\snippet test_x509.c parse_cert_ku
\snippet test_x509.c parse_cert_eku

\subsection secX509Valid Validating Certificates

fleaTLS supports the certification path validation according to RFC 5280, including the revocation checking using CRLs.

\subsubsection secX509TrustStore Certification Path Validation

The certification path validation refers to the operation of constructing a validating a certificate chain from the certificate in question, the so-called target certificate, up to a trusted certificate. Typically, trusted certificates are CA certificates, but fleaTLS does not enforce this. It is also possible to set end-entity certificates as trusted directly.

The following shows a minimal example of a certification path validation, taken from the file <code>test/src/common/test_cert_chain.c</code>. In this example, no revocation checking is carried out:
\snippet test_cert_chain.c cert_validation_1
In the call to #THR_flea_cert_path_validator_t__ctor_cert(), the certificate to validate (the target certificate) is provided.
With #THR_flea_cert_path_validator_t__add_trust_anchor_cert(), at least one certificate has to be added. The path validation is successful when a valid chain up to one of the trusted certificates can be built.

The function #THR_flea_cert_path_validator__build_and_verify_cert_chain(), carries out the actual verification. It performs an exhaustive path search using the certificates that have been added to the #flea_cert_path_validator_t object.

Untrusted certificates can be added using #THR_flea_cert_path_validator_t__add_cert_without_trust_status(). During the validation, these certificates are used as intermediate certificates to complete the chain from the target certificate to the trust anchor.

In order to enable revocation checking, during the construction of the #flea_cert_path_validator_t the appropriate #flea_rev_chk_mode_e has to be set and afterwards CRLs have to be added using the function #THR_flea_cert_path_validator_t__add_crl().

\subsubsection secX509PureSigVer Mere Checking of Signatures

In order to check whether a certificate carries a correct signature produced by another certificate's associated  private key, the function #THR_flea_x509_verify_cert_signature() can be used.

*/
