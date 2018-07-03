/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "build_cfg_pltf.h"

#ifndef _flea_build_cfg_gen__H_
# define _flea_build_cfg_gen__H_


/**
 * \weakgroup build_cfg fleaTLS build configuration
 */
/**@{*/


/**
 * \defgroup dbg_cfg Debugging configuration
 */
/**@{*/

/**
 * When set, print test failures and summary with printf.
 */
# define FLEA_DO_PRINTF_TEST_OUTPUT


/**
 * When activated, this switch disables assertions in the code that are only
 * suitable during development.  Remove this define to enable these runtime
 * development assertions. Enabling the development assertions is not suitable
 * for production code.  When the development assertions are enabled, a
 * violation of such an assertion causes the program abortion and printing of an
 * error message.
 */
# define FLEA_NO_DEV_ASSERTIONS // FBFLAGS_CORE_ON_OFF


// # if 0

/**
 * When set, print messages from thrown exception with printf (for debugging purposes). This causes output during tests which purposely trigger exceptions.
 */
# define FLEA_DO_PRINTF_ERRS

// # endif  // if 0
/* end dgb_cfg */
/**@}*/

/**
 * \defgroup mem_cfg Memory configuration
 */
/**@{*/

/**
 * Activate this flag to let fleaTLS make heap allocation for buffers (referred to
 * as "heap mode"). In heap mode, fleaTLS' functions perform heap allocation for
 * tempary variables and \link apiObjLifeCycle class-like types\endlink, and use
 * stack memory only for small-sized buffers.
 *
 * Deactivate this flag to let fleaTLS only use stack buffers
 * (referred to as "stack mode"). In stack mode, fleaTLS does not perform any
 * heap allocations and instead only uses the stack memory. This means that fleaTLS' functions and objects reserve stack space according to the configured algorithms and maximal key size definitions made in the build configuration.
 */
# define FLEA_HEAP_MODE // FBFLAGS_CORE_ON_OFF
/* end mem_cfg */
/**@}*/


/**
 * \defgroup pltf_support Platform support
 */
/**@{*/

/**
 * When activated, fleaTLS offers file-based flea_rw_stream_t objects. If not
 * FILE implementation is offered by the plattform, this feature must be deactivated.
 */
# define FLEA_HAVE_STDLIB_FILESYSTEM

/* end pltf_support */
/**@}*/

/**
 * \defgroup algo_support_cfg Algorithm support configuration
 */
/**@{*/

/**
 * Control whether HMAC support is compiled
 */
# define FLEA_HAVE_HMAC // FBFLAGS_MACALGS_ON_OFF

/**
 * Control whether CMAC support is compiled
 */
# define FLEA_HAVE_CMAC

/**
 * Control whether EAX support is compiled. Requires CMAC as a prerequisite.
 */
# define FLEA_HAVE_EAX  // FBFLAGS_AEALGS_ON_OFF

/**
 * Control whether GCM support is compiled
 */
# define FLEA_HAVE_GCM

/**
 * Control whether MD5 support is compiled
 */
# define FLEA_HAVE_MD5               // FBFLAGS_MD5_ON_OFF

/**
 * Control whether SHA1 support is compiled
 */
# define FLEA_HAVE_SHA1              // FBFLAGS_SHA1_ON_OFF

/**
 * Control whether SHA224 and SHA256 support is compiled. This flag is mandatory
 * in the current version of fleaTLS.
 */
# define FLEA_HAVE_SHA224_256        // NOT CONFIGURABLE

/**
 * Control whether SHA384 and SHA512 support is compiled.
 */
# define FLEA_HAVE_SHA384_512        // FBFLAGS_HAVE_SHA512_ON_OFF

/**
 * Control whether support for the AES-based hash function based on the Davies-Meyer-construction is compiled.
 */
# define FLEA_HAVE_DAVIES_MEYER_HASH // FBFLAGS_DAVIES_MEYER_HASH_ON_OFF

/**
 * Control whether support for the DES cipher is compiled.
 */
# define FLEA_HAVE_DES               // FBFLAGS_HAVE_DES_ON_OFF

/**
 * Control whether support for the 2-key triple-DES cipher is compiled.
 */
# define FLEA_HAVE_TDES_2KEY         // FBFLAGS_HAVE_TDES_ON_OFF

/**
 * Control whether support for the 3-key triple-DES cipher is compiled.
 */
# define FLEA_HAVE_TDES_3KEY         // FBFLAGS_HAVE_TDES_ON_OFF

/**
 * Control whether support for the DESX cipher is compiled.
 */
# define FLEA_HAVE_DESX // FBFLAGS_HAVE_DESX_ON_OFF

/**
 * Configure whether support for AES is compiled. In the current version of
 * fleaTLS, this option cannot be disabled.
 */
# define FLEA_HAVE_AES  // NOT CONFIGURABLE

/**
 * Control whether support for RSA shall be compiled.
 */
# define FLEA_HAVE_RSA            // FBFLAGS_PKALGS_ON_OFF

/**
 * Control whether support for ECDSA shall be compiled.
 */
# define FLEA_HAVE_ECDSA          // FBFLAGS_PKALGS_ON_OFF

/**
 * Control whether support for ECKA (=ECDH) shall be compiled.
 */
# define FLEA_HAVE_ECKA           // FBFLAGS_PKALGS_ON_OFF

/* end algo_support_cfg */
/**@}*/

/**
 * \defgroup crypto_params Algorithm key and parameter sizes
 */
/**@{*/

/**
 * Maximum supported key bit size for RSA (size of the public modulus).
 */
# define FLEA_RSA_MAX_KEY_BIT_SIZE 4096      // FBFLAGS__INT_LIST 1024 1536 2048 4096

/**
 * Maximum supported key public exponent bit size for RSA.
 */
# define FLEA_RSA_MAX_PUB_EXP_BIT_LEN 32

/**
 * Maximum supported key bit size for ECC (size of the prime p of the curve).
 */
# define FLEA_ECC_MAX_MOD_BIT_SIZE 521      // FBFLAGS__INT_LIST 160 192 224 256 320 384 521

/**
 * Maximum supported cofactor bit size for ECC.
 */
# define FLEA_ECC_MAX_COFACTOR_BIT_SIZE 32
/**@}*/

/**
 * \defgroup perfomance_cfg Performance optimization options
 */
/**@{*/

/**
 * Control whether loop unrolling within MD5 shall be used.
 */
# define FLEA_USE_MD5_LOOP_UNROLL    // FBFLAGS_MD5_ON_OFF

/**
 * Control whether loop unrolling within SHA1 shall be used.
 */
# define FLEA_USE_SHA1_LOOP_UNROLL   // FBFLAGS_SHA1_ON_OFF

/**
 * Control whether loop unrolling within SHA256 (and SHA224) shall be used.
 */
# define FLEA_USE_SHA256_LOOP_UNROLL // FBFLAGS_SHA256_ON_OFF

/**
 * Control whether loop unrolling within SHA512 (and SHA384) shall be used.
 */
# define FLEA_USE_SHA512_LOOP_UNROLL // FBFLAGS_SHA512_ON_OFF


/**
 * If activated, then AES block decryption and ECB and CBC mode are enabled. Otherwise
 * only the AES block encryption is available, which is sufficient for both
 * directions in CTR and GCM mode.
 */
# define FLEA_HAVE_AES_BLOCK_DECR // FBFLAGS_AES_ON_OFF

/**
 * Control whether an AES implementation with smaller lookup tables shall be
 * compiled.
 */
# define FLEA_USE_SMALL_AES       // FBFLAGS_AES_ON_OFF

/**
 * Control the window size for the RSA exponentiation. Choose 5 for greatest speed and 1 for smallest RAM footprint.
 */
# define FLEA_CRT_RSA_WINDOW_SIZE 5 // FBFLAGS__INT_LIST 1 2 3 4 5

/**
 * Control the window size for the ECC exponentiation. Choose 4 or 5 for greatest speed and 1 for smallest RAM footprint.
 */
# define FLEA_ECC_SINGLE_MUL_MAX_WINDOW_SIZE 5 // FBFLAGS__INT_LIST 1 2 3 4 5

/* end perfomance_cfg */
/**@}*/

/**
 * \defgroup sccm_cfg Side-Channel Countermeasures
 */
/**@{*/

/**
 * Use the "square & multiply always" algorithm for (window-based) modular exponentiation
 * in RSA private operations as a countermeasure against timing attacks.
 */
# define FLEA_SCCM_USE_RSA_MUL_ALWAYS // FBFLAGS_MOD_EXP_SQMA_ON_OFF

/**
 * Use the "add & double always" algorithm for (window-based) point multiplication in
 * ECC private operations as a countermeasure against timing attacks.
 */
# define FLEA_SCCM_USE_ECC_ADD_ALWAYS // FBFLAGS_ECC_ADA_ON_OFF

/**
 * Side channel countermeasure which adds pseudo random delays within the public key
 * operations.
 */
# define FLEA_SCCM_USE_PUBKEY_INPUT_BASED_DELAY // FBFLAGS_SCM_ON_OFF

/**
 * Side channel countermeasure which adds random delays within the public key
 * operations.
 */
# define FLEA_SCCM_USE_PUBKEY_USE_RAND_DELAY // FBFLAGS_SCM_ON_OFF

/**
 * Perform pseudo operations or data access for cache warming to achieve timing
 * neutral behaviour on platforms with cache within timing attack
 * countermeasures. This feature should be disabled on platforms without cache.
 */
# define FLEA_SCCM_USE_CACHEWARMING_IN_TA_CM // FBFLAGS_SCM_ON_OFF

/**@}*/

/**
 * \defgroup space_reserv Configuration of reserved memory spaces
 */
/**@{*/

/**
 * Used to determine the reserved space in bytes for X.509 certificates in stack mode.
 */
# define FLEA_STKMD_X509_MAX_CERT_SIZE 2000

/**
 * The maximum number of certificates in a chain, including the target
 * certificate and the trust anchor.
 * Relevant both for heap and stack mode.
 */
# define FLEA_MAX_CERT_CHAIN_DEPTH 20 // FBFLAGS__INT_LIST 2 3 4 10 20

/**
 * Maximal number of certificates that can set in a any type of
 * object storing certificates. Hard limit in case of both stack and heap
 * mode. In heap mode it can be set to zero to disable any predefined limit.
 */
# define FLEA_MAX_CERT_COLLECTION_SIZE 20

/**
 * Maximal number of CRLs that can set in a any type of
 * object storing CRLs . Hard limit in case of both stack and heap
 * mode. In heap mode it can be set to zero to disable any predefined limit.
 */
# define FLEA_MAX_CERT_COLLECTION_NB_CRLS 20

/**
 * Number of certificates or CRLs for which memory is initially allocated in
 * heap mode in objects storing such data types. This value is also used as the
 * number of objects for which new memory is allocated when reallocation is
 * triggered.
 */
# define FLEA_CERT_AND_CRL_PREALLOC_OBJ_CNT 5 // FBFLAGS__INT_LIST 1 2 3 4 10 20

/**
 * The initial allocated size and step size for allocation growth for a
 * cert_store_t object. Relevant only in heap mode.
 */
# define FLEA_CERT_STORE_PREALLOC 5

/**
 * Maximum size for CRL Distribution point extension of processed X.509 certificate. Takes effect only in stack
 * mode.
 *
 */
# define FLEA_STKMD_X509_MAX_CRLDP_LEN 260

/**
 * This value defines the maximal accepted length of name components (e.g. in
 * the Subject Alternative Name X.509 certificate extension).
 * Must not exceed 0xFFFF.
 */
# define FLEA_X509_NAME_COMPONENT_MAX_BYTE_LEN 256

/**
 * If this switch is deactivated, then only the most common certificate
 * extensions are supported. Deactivate it to save RAM.
 */
# define FLEA_X509_CERT_REF_WITH_DETAILS

/**
 * If this is switch is deactivated, then only the most typical DN components
 * are supported in X.509 certificates. Deactivating it saves RAM and a little bit of code.
 */
# define FLEA_HAVE_X509_DN_DETAILS

/**
 * The space reserved for an entry in the subject alternative name extension. Relevant only in stack mode.
 */
# define FLEA_STKMD_X509_SAN_ELEMENT_MAX_LEN 50

/**
 * Maximal byte length of an issuerDN in an X.509 certificate. Takes effect only
 * in stack mode.
 */
# define FLEA_STKMD_X509_MAX_ISSUER_DN_RAW_BYTE_LEN 256

/* end space_reserv  */
/**@}*/


/**
 * \defgroup tls_cfg TLS configuration
 */
/**@{*/
# if defined FLEA_HAVE_TLS_CS_PSK || ((defined FLEA_HAVE_RSA || defined FLEA_HAVE_ECDSA) && (defined FLEA_HAVE_HMAC || \
  defined FLEA_HAVE_GCM))

/**
 * Control whether fleaTLS supports TLS.
 */
#  define FLEA_HAVE_TLS
# endif // if defined FLEA_HAVE_TLS_CS_PSK || ((defined FLEA_HAVE_RSA || defined FLEA_HAVE_ECDSA) && (defined FLEA_HAVE_HMAC || defined FLEA_HAVE_GCM))

# ifdef FLEA_HAVE_TLS

/**
 * Control whether TLS client will be compiled.
 */
#  define FLEA_HAVE_TLS_CLIENT

/**
 * Control whether TLS server will be compiled.
 */
#  define FLEA_HAVE_TLS_SERVER


/**
 * Control whether support for PSK cipher suites shall be compiled.
 */
#  define FLEA_HAVE_TLS_CS_PSK

/*
 * Maximal size of identity length that will be processed from the peer.
 */
#  define FLEA_TLS_PSK_MAX_IDENTITY_LEN 128     //   RFC: MUST support 128 and can be up to 2^16

/*
 * Maximal size of identity hint length that will be processed from the peer.
 */

#  define FLEA_TLS_PSK_MAX_IDENTITY_HINT_LEN 128

/*
 * Maximal size of pre-shared keys that will be handled.
 */
#  define FLEA_TLS_PSK_MAX_PSK_LEN 64           //   RFC: MUST support 64 and can be up to 2^16

#  if defined FLEA_HAVE_ECKA

/**
 * Control whether support for ECDHE cipher suites shall be compiled.
 */
#   define FLEA_HAVE_TLS_CS_ECDHE

/**
 * Control whether support for ECDH cipher suites shall be compiled. (Not yet
 * supported by fleaTLS.)
 */
#   define FLEA_HAVE_TLS_CS_ECDH
#  endif // if defined FLEA_HAVE_ECKA

#  if defined FLEA_HAVE_ECDSA

/**
 * Control whether support for ECDSA cipher suites shall be compiled. (Not yet
 * supported by fleaTLS.)
 */
#   define FLEA_HAVE_TLS_CS_ECDSA
#  endif

#  if defined FLEA_HAVE_RSA

/**
 * Control whether support for RSA cipher suites shall be compiled.
 */
#   define FLEA_HAVE_TLS_CS_RSA
#  endif

#  ifdef FLEA_HAVE_HMAC

/**
 * Control whether support for CBC-based cipher suites shall be compiled.
 */
#   define FLEA_HAVE_TLS_CS_CBC
#  endif

#  ifdef FLEA_HAVE_GCM

/**
 * Control whether support for GCM-based cipher suites shall be compiled.
 */
#   define FLEA_HAVE_TLS_CS_GCM
#  endif

# endif // ifdef FLEA_HAVE_TLS


/*
 * Flags to enable cipher suites
 */
# ifdef FLEA_HAVE_TLS_CS_RSA /* Ciphersuites that require RSA */
#  ifdef FLEA_HAVE_TLS_CS_CBC
#   ifdef FLEA_HAVE_SHA1

/**
 * Control whether the cipher suite is supported.
 */
#    define FLEA_HAVE_TLS_CS_RSA_WITH_AES_128_CBC_SHA

/**
 * Control whether the cipher suite is supported.
 */
#    define FLEA_HAVE_TLS_CS_RSA_WITH_AES_256_CBC_SHA
#   endif // ifdef FLEA_HAVE_SHA1

/**
 * Control whether the cipher suite is supported.
 */
#   define FLEA_HAVE_TLS_CS_RSA_WITH_AES_128_CBC_SHA256

/**
 * Control whether the cipher suite is supported.
 */
#   define FLEA_HAVE_TLS_CS_RSA_WITH_AES_256_CBC_SHA256
#  endif // ifdef FLEA_HAVE_TLS_CS_CBC
#  ifdef FLEA_HAVE_TLS_CS_GCM

/**
 * Control whether the cipher suite is supported.
 */
#   define FLEA_HAVE_TLS_CS_RSA_WITH_AES_128_GCM_SHA256
#   ifdef FLEA_HAVE_SHA384_512

/**
 * Control whether the cipher suite is supported.
 */
#    define FLEA_HAVE_TLS_CS_RSA_WITH_AES_256_GCM_SHA384
#   endif
#  endif // ifdef FLEA_HAVE_TLS_CS_GCM
#  ifdef FLEA_HAVE_TLS_CS_ECDHE
#   ifdef FLEA_HAVE_SHA1

/**
 * Control whether the cipher suite is supported.
 */
#    define FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA

/**
 * Control whether the cipher suite is supported.
 */
#    define FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA
#   endif // ifdef FLEA_HAVE_SHA1

/**
 * Control whether the cipher suite is supported.
 */
#   define FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
#   ifdef FLEA_HAVE_SHA384_512

/**
 * Control whether the cipher suite is supported.
 */
#    define FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
#   endif
#   ifdef FLEA_HAVE_TLS_CS_GCM

/**
 * Control whether the cipher suite is supported.
 */
#    define FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
#    ifdef FLEA_HAVE_SHA384_512

/**
 * Control whether the cipher suite is supported.
 */
#     define FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
#    endif
#   endif // ifdef FLEA_HAVE_TLS_CS_GCM
#  endif // ifdef FLEA_HAVE_TLS_CS_ECDHE
# endif // ifdef FLEA_HAVE_TLS_CS_RSA

# ifdef FLEA_HAVE_TLS_CS_ECDSA /* Ciphersuits that require ECDSA */
#  ifdef FLEA_HAVE_TLS_CS_ECDHE
#   ifdef FLEA_HAVE_TLS_CS_CBC
#    ifdef FLEA_HAVE_SHA1

/**
 * Conrol whether the cipher suite is supported
 */
#     define FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA

/**
 * Conrol whether the cipher suite is supported
 */
#     define FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
#    endif // ifdef FLEA_HAVE_SHA1

/**
 * Conrol whether the cipher suite is supported
 */
#    define FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
#    ifdef FLEA_HAVE_SHA384_512

/**
 * Conrol whether the cipher suite is supported
 */
#     define FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
#    endif
#   endif // ifdef FLEA_HAVE_TLS_CS_CBC
#   ifdef FLEA_HAVE_TLS_CS_GCM

/**
 * Conrol whether the cipher suite is supported
 */
#    define FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
#    ifdef FLEA_HAVE_SHA384_512

/**
 * Conrol whether the cipher suite is supported
 */
#     define FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
#    endif
#   endif // ifdef FLEA_HAVE_TLS_CS_GCM
#  endif // ifdef FLEA_HAVE_TLS_CS_ECDHE
# endif // ifdef FLEA_HAVE_TLS_CS_ECDSA

# ifdef FLEA_HAVE_TLS_CS_PSK /* Ciphersuites that use pre-shared keys */
#  ifdef FLEA_HAVE_TLS_CS_CBC
#   ifdef FLEA_HAVE_SHA1

/**
 * Control whether the cipher suite is supported
 */
#    define FLEA_HAVE_TLS_CS_PSK_WITH_AES_128_CBC_SHA

/**
 * Control whether the cipher suite is supported.
 */
#    define FLEA_HAVE_TLS_CS_PSK_WITH_AES_256_CBC_SHA
#   endif // ifdef FLEA_HAVE_SHA1

/**
 * Control whether the cipher suite is supported.
 */
#   define FLEA_HAVE_TLS_CS_PSK_WITH_AES_128_CBC_SHA256
#   ifdef FLEA_HAVE_SHA384_512

/**
 * Control whether the cipher suite is supported.
 */
#    define FLEA_HAVE_TLS_CS_PSK_WITH_AES_256_CBC_SHA384
#   endif
#  endif // ifdef FLEA_HAVE_TLS_CS_CBC

#  ifdef FLEA_HAVE_TLS_CS_GCM

/**
 * Control whether the cipher suite is supported.
 */
#   define FLEA_HAVE_TLS_CS_PSK_WITH_AES_128_GCM_SHA256
#   ifdef FLEA_HAVE_SHA384_512

/**
 * Control whether the cipher suite is supported.
 */
#    define FLEA_HAVE_TLS_CS_PSK_WITH_AES_256_GCM_SHA384
#   endif
#  endif // ifdef FLEA_HAVE_TLS_CS_GCM
# endif // ifdef FLEA_HAVE_TLS_CS_PSK

/**
 *  The maximum number of supported signature algorithm hash functions in case
 *  of FLEA_STACK_MODE. Internally, the implementation has to instantiate that
 *  many parallel hash-context objects, in order to be able to start the
 *  handshake without knowing the hash function actually agreed on.
 */
# define FLEA_STKMD_TLS_MAX_PARALLEL_HASHES 5

/**
 * Length of the session IDs that are used by the fleaTLS server.
 */
# define FLEA_TLS_SESSION_ID_LEN 16 // FBFLAGS__INT_LIST 1 2 16 31 32


/**
 * Maximal number of sessions held by the server session manager (flea_tls_session_mngr_t, session cache). May not be zero.
 */
# define FLEA_TLS_MAX_NB_MNGD_SESSIONS 4 // FBFLAGS__INT_LIST 1 2 10 31 257

/**
 * If enabled, the tls client or server context will feature a flea_x509_cert_ref_t of the peer's
 * EE certificate used during the handshake. Disable this feature to save
 * a considerable amount of RAM.
 */
# define FLEA_TLS_HAVE_PEER_EE_CERT_REF

/**
 * If enabled, the tls client or server context will feature a flea_x509_cert_ref_t of the root
 * certificate used to authenticate the peer's EE certificate used during the handshake. Disable this feature to save
 * a considerable amount of RAM.
 */
# define FLEA_TLS_HAVE_PEER_ROOT_CERT_REF

/**
 * This variable controls whether support for DTLS 1.2 is available.
 */
# define FLEA_HAVE_DTLS

/**
 * The maximal plaintext size of TLS record that can received. Based on this
 * value the buffer size for received records will be calculated.  The TLS
 * standard mandates a size of 2^14 = 16384. If a smaller size is chosen, an
 * attempt will be made to negotiate smaller records using the maximum fragment
 * length negotiation extension (RFC 6066). The record plaintext sizes supported
 * by this extension are 512, 1024, 2048, and 4096. One of these value may be
 * configured for this variable.  If negotiation fails, fleaTLS will abort the
 * handshake with a fatal alert.  The receive buffer will be at most 325 bytes
 * larger than FLEA_TLS_RECORD_MAX_RECEIVE_PLAINTEXT_SIZE, depending on compiled
 * cipher suites.
 */
# define FLEA_TLS_RECORD_MAX_RECEIVE_PLAINTEXT_SIZE 1024

/**
 * If enabled, the maximum fragment length negotiation extension (RFC 6066) can
 * be negotiated if FLEA_TLS_RECORD_MAX_RECEIVE_PLAINTEXT_SIZE is smaller than the 16834 bytes that
 * are mandated by the TLS 1.2 standard and at least 512 bytes large.
 *
 * For further details see the API documentation.
 */
# define FLEA_TLS_HAVE_MAX_FRAG_LEN_EXT

/**
 * TLS send plaintext size. This buffer used for sending data and determines the
 * maximal record size of records sent by fleaTLS. Should not be smaller than
 * 150 bytes. A small size reduces performance. May not be greater than 16384.
 */
# define FLEA_TLS_RECORD_MAX_SEND_PLAINTEXT_SIZE 300

/**
 * The size of the flight buffer used within DTLS to store outgoing handshake messages for
 * being able to resend them if required and to assemble incoming handshake message
 * fragments. This buffer is part of the tls-handshake-context object and will
 * thus only be allocated during a TLS handshake.
 */
# define FLEA_DTLS_FLIGHT_BUF_SIZE 7000

/**
 * Maximal size of public key parameters object in an X.509 certificate. Mainly
 * relevant for certificates featuring EC public keys. Relevant only in stack
 * mode.
 */
# define FLEA_STKMD_TLS_CERT_PATH_VLD_PUBKEY_PARAMS_BUF_SIZE 256

/**
 * Maximum size of the buffer that reads in the cipher suites offered by the client.
 * Has to be a multiple of 2 as every cipher suite takes up two bytes.
 * Relevant only in stack mode.
 */
# define FLEA_TLS_MAX_CIPH_SUITES_BUF_SIZE 40

/* end tls_cfg*/
/**@}*/

/**
 * \defgroup arch_opt Architectural optimizations
 */
/**@{*/

/**
 * Control the bit width of flea_dtl_t, the type for the lengths of data processed by fleaTLS in various functions. The effect is that
 * flea_dtl_t, the type that represents data lengths in various API function
 * signatures, is defined with a width of 32 bit if the flag is set and with a width of 16 bit if deactivated.
 * Deactivate this switch in order to generate smaller and faster code on 16
 * bit architectures. Deactivating it also reduces the RAM size of some types
 * considerable.
 */
# define FLEA_HAVE_DTL_32BIT // FBFLAGS_DTL_32_BIT_ON_OFF


/**
 * Enabling this flag causes the choice of code optimized for big endian platforms in some places.
 * In any case, the generated code remains valid independently of the platform's
 * endianess, but may be non-optimal with regard to size and/or speed.
 */
# define FLEA_HAVE_BE_ARCH_OPT // FBFLAGS_ARCH_OPT_ON_OFF

/* end arch_opt */
/**@}*/


/**
 * \defgroup mt_cfg Multithreading support
 *
 */
/**@{*/

/**
 * Control if fleaTLS supports concurrency for its global RNG and the TLS server. Remove the
 * definition in order to deactivate multithreading support in fleaTLS.
 */
# define FLEA_HAVE_MUTEX // FBFLAGS_CORE_ON_OFF

/**
 * Include the mutex header. Remove include directive in the build_config_gen.h file if no mutex support is required. The define is just a dummy for proper generation of this documentation.
 */
# define FLEA_MUTEX_HEADER_INCL
# ifdef FLEA_HAVE_MUTEX
#  include <pthread.h>
# endif

/**
 * Define the mutex type to be used. Disable this define if mutexes are
 * disabled.
 */
# define FLEA_MUTEX_TYPE pthread_mutex_t

/* end mt_cfg */
/**@}*/

/* include must remain at the very end: */
# include "internal/common/build_config_util.h"

/* end build_cfg */
/**@}*/

#endif /* h-guard */
