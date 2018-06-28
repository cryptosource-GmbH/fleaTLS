/*! \page pagePubkey Public Key Schemes
 *
*
\section secPubKey Public Key Schemes
*
As public-key schemes, fleaTLS supports RSA and elliptic-curve-based schemes through an API for generic public and private key objects, namely #flea_pubkey_t and #flea_privkey_t.

\subsection secEcDomPar EC Domain Parameters
*
fleaTLS supports general GF(p) EC domain parameters. The built-in parameters are referenced through the enumeration #flea_ec_dom_par_id_e.
*
Domain parameters are represented by objects of type #flea_ec_dom_par_ref_t. These objects only the reference the values of the domain parameters stored elsewhere in memory.
*
In order to set a flea_ec_dom_par_ref_t object to one of fleaTLS' built-in parameters held in <code>const</code> memory, the function #THR_flea_ec_dom_par_ref_t__set_by_builtin_id() can be used.
*
flea_pubkey_t and flea_privkey_t objects, however, internally store copies of the referenced domain parameters and thus do not rely on the originally referenced values to remain elsewhere in memory.

\subsection secPkKeyInstantion Public and Private Key Instantiation

Public and private key objects can be instantiated in a number of ways. These are explained in the following subsections.

\subsubsection secPkKeyPkcs8 Decoding of PKCS#8 Encoded Keys

Public and private key objects can be instantiated by decoding unencrypted PKCS#8 DER encoded RSA or EC keys. This is done using the functions #THR_flea_privkey_t__ctor_pkcs8() and #THR_flea_pubkey_t__ctor_pkcs8(). The Instantiation of an EC public-key object from a PKCS#8 structure will only work if the data structure contains the public key information, which is optional in the PKCS#8 structure. Furthermore, for EC keys the EC domain parameters, which are optional in the PKCS#8 format, must be present.

\subsubsection secPkKeyFromCert Instantiating a Public Key From an X.509 Certificate

The function #THR_flea_pubkey_t__ctor_cert() creates a public key object from a certificate reference object.

\subsection secPkKeyExpl Explicit Instantiation

RSA and EC public and private keys can be created providing the explicit key values using the functions

- #THR_flea_pubkey_t__ctor_rsa()
- #THR_flea_pubkey_t__ctor_ecc()
- #THR_flea_privkey_t__ctor_rsa_components()
- #THR_flea_privkey_t__ctor_ecc()

\subsection secPkKeyEncod Encoding of Keys

fleaTLS currently support only the encoding of public and private key objects in "plain" format by the use of the functions #THR_flea_public_key__t__get_encoded_plain and #THR_flea_privkey_t__get_encoded_plain. Refer to the documentation of these functions regarding the concrete format of the encoded keys.


\subsubsection secPkKeyEccGenKey EC Key Generation

EC keys can be generated using one of the functions #THR_flea_pubkey__by_dp_id_gen_ecc_key_pair() or #THR_flea_pubkey__generate_ecc_key_pair_by_dp().

\subsection secPkSign Public-Key Signature Schemes

fleaTLS supports as public-key signature algorithms RSA PKCS#1 v1.5 and ECDSA signatures. In the following it is explained how signatures can generated and verified.

\subsubsection secPkSignGen Signature Generation

Signatures can be generated using either of the functions #THR_flea_privkey_t__sign() or #THR_flea_privkey_t__sign_digest().

Another option is the use of a #flea_pk_signer_t object which supports iterative feeding of the message. This is achieve using the call sequence

- #THR_flea_pk_signer_t__ctor(): construct the #flea_pk_signer_t object, which can be used both for signature generation as well as signature verification
- #THR_flea_pk_signer_t__update(): feed the message iteratively in potentially multiple calls to this function
- #THR_flea_pk_signer_t__final_sign(): generate the signature

The format of an ECDSA signature is specified by the value of #flea_pk_scheme_id_e:
- #flea_ecdsa_emsa1_asn1  indicates the ASN.1/DER encoded format as
   * <code>
   * SEQUENCE {
   *  INTEGER r,
   *  INTEGER s
   *  }</code>
- #flea_ecdsa_emsa1_concat indicates the plain concatenation of r and s, each having the same length as the associated domain parameter's  base point order

\subsubsection secPkSignVer Signature Verification

Signatures can be verified using either of the functions #THR_flea_pubkey_t__vrfy_sgntr() or #THR_flea_pubkey_t__verify_digest().

Another option is the use of a #flea_pk_signer_t object which supports iterative feeding of the message. This is achieve using the call sequence

- #THR_flea_pk_signer_t__ctor(): construct the #flea_pk_signer_t object, which can be used both for signature generation as well as signature verification
- #THR_flea_pk_signer_t__update(): feed the message iteratively in potentially multiple calls to this function
- #THR_flea_pk_signer_t__final_verify(): verify the signature

\subsection secPkEncrAlgs Public Key Cryptosystems

fleaTLS offers RSA-OAEP and RSA-PKCS#1 v1.5 as encryption schemes. Note that also the supported ECDH scheme can be used as an encryption scheme.

\subsubsection secPkEncrAlgsEncr Encryption Operation

The encryption is performed using the function. #THR_flea_pubkey_t__encrypt_message() and providing either #flea_pkcs1_v1_5 or #flea_oaep as the scheme ID. The hash ID parameter of this function is only used in OAEP, and is not relevant for the PKCS#1 v1.5 scheme.

\subsubsection secPkEncrAlgsDecr Decryption Operation

The function #THR_flea_privkey_t__decrypt_message() is used to decrypt messages. Note that for PKCS#1 v1.5 decryption, rather the use of the function #THR_flea_privkey_t__decr_msg_secure() is recommended. PKCS#1 v1.5 is a legacy scheme with a security flaw affecting the decryption operation that in many application contexts need to be mitigated. The latter function achieves this by realizing state-of-the-art countermeasures such as constant time decryption.

\subsection secPkEcdh EC Diffie-Hellman

fleaTLS implements the EC Diffie-Hellman Key Agreement scheme (ECDH or, synonymously, ECKA).
The key agreement is performed using the function #THR_flea_pubkey__compute_ecka().
The function can be used to perform a raw ECDH operation as well as one using the ANSI X9.62 key derivation function (KDF).

*/
