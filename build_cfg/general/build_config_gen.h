/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "build_cfg_pltf.h"

#ifndef _flea_build_cfg_gen__H_
# define _flea_build_cfg_gen__H_


/**
 * When set, print test failures and summary with printf.
 */
# define FLEA_DO_PRINTF_TEST_OUTPUT

/**
 * When set, print messages from thrown exception with printf (for debugging purposes). This causes output during tests which purposely trigger exceptions.
 */
// # define FLEA_DO_PRINTF_ERRS

/**
 * Activate this flag to let flea make heap allocation for buffers. Deactivate
 * this flag to let flea only use stack buffers. In the latter case, be sure to
 * correctly define the RSA and EC key sizes.
 */
# define FLEA_USE_HEAP_BUF // FBFLAGS_CORE_ON_OFF

/**
 * Activate this flag to make use of the buffer overwrite detection. Should not
 * be used in productive code due to performance and code size effects.
 */
// #define FLEA_USE_BUF_DBG_CANARIES // FBFLAGS_CORE_ON_OFF

/**
 * Algorithm support selection
 */
# define FLEA_HAVE_HMAC // FBFLAGS_MACALGS_ON_OFF
# define FLEA_HAVE_CMAC // FBFLAGS_MACALGS_ON_OFF
# define FLEA_HAVE_EAX  // FBLAGS_AEALGS_ON_OFF
# define FLEA_HAVE_GCM

# define FLEA_HAVE_MD5               // FBFLAGS_MD5_ON_OFF
# define FLEA_HAVE_SHA1              // FBFLAGS_SHA1_ON_OFF
# define FLEA_HAVE_SHA224_256        // NOT CONFIGURABLE
# define FLEA_HAVE_SHA384_512        // FBFLAGS_HAVE_SHA512_ON_OFF
# define FLEA_HAVE_DAVIES_MEYER_HASH // FBFLAGS_DAVIES_MEYER_HASH_ON_OFF

# define FLEA_HAVE_DES               // FBFLAGS_HAVE_DES_ON_OFF
# define FLEA_HAVE_TDES_2KEY         // FBFLAGS_HAVE_TDES_ON_OFF
# define FLEA_HAVE_TDES_3KEY         // FBFLAGS_HAVE_TDES_ON_OFF
# define FLEA_HAVE_DESX              // FBFLAGS_HAVE_DESX_ON_OFF
# define FLEA_HAVE_AES               // NOT CONFIGURABLE

/**
 * Configuration
 */
# define FLEA_USE_MD5_LOOP_UNROLL    // FBFLAGS_MD5_ON_OFF
# define FLEA_USE_SHA1_LOOP_UNROLL   // FBFLAGS_SHA1_ON_OFF
# define FLEA_USE_SHA256_LOOP_UNROLL // FBFLAGS_SHA256_ON_OFF
# define FLEA_USE_SHA512_LOOP_UNROLL // FBFLAGS_SHA512_ON_OFF


/**
 * If set, then AES block decryption and ECB and CBC mode are enabled. Otherwise
 * only the AES block encryption is available, which is sufficient for both
 * directions in CTR mode.
 */
# define FLEA_HAVE_AES_BLOCK_DECR // FBFLAGS_AES_ON_OFF
# define FLEA_USE_SMALL_AES       // FBFLAGS_AES_ON_OFF

# define FLEA_HAVE_RSA            // FBFLAGS_PKALGS_ON_OFF
# define FLEA_HAVE_ECDSA          // FBFLAGS_PKALGS_ON_OFF
# define FLEA_HAVE_ECKA           // FBFLAGS_PKALGS_ON_OFF

/**
 * Choose 5 for greatest speed and 1 for smallest RAM footprint.
 */
# define FLEA_CRT_RSA_WINDOW_SIZE 5 // FBFLAGS__INT_LIST 1 2 3 4 5

/**
 * A window size of up to 5 is beneficial for single point multiplications even
 * for 112 bit curves.
 */
# define FLEA_ECC_SINGLE_MUL_MAX_WINDOW_SIZE 5 // FBFLAGS__INT_LIST 1 2 3 4 5

# define FLEA_STKMD_X509_MAX_CERT_SIZE       2000

/**
 * The maximum number of certificates in a chain, including the targert
 * certificate and the trust anchor.
 * Relevant both for heap and stack mode.
 */
# define FLEA_MAX_CERT_CHAIN_DEPTH 20 // FBFLAGS__INT_LIST 2 3 4 10 20

/* Maximal number of certificates that can set in a any type of
 * object storing certificates. Hard limit in case of both stack and heap
 * mode. In heap mode it can be set to zero to disable any predefined limit.
 */
# define FLEA_MAX_CERT_COLLECTION_SIZE 20

/* Maximal number of CRLs that can set in a any type of
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
 * The maximal capacity (certificate count) of a cert_store_t object. Applies to
 * both the heap and the stack mode as the threshold. In heap mode, the
 * allocated memory may grow up to this threshold.
 */
# define FLEA_CERT_STORE_MAX_CAPACITY 20

/**
 * The initial allocated size and step size for allocation growth for a
 * cert_store_t object. Relevant only in heap mode.
 */
# define FLEA_CERT_STORE_PREALLOC 5

/**
 * Algorithm maximum supported key and parameter sizes.
 */
# define FLEA_RSA_MAX_KEY_BIT_SIZE      4096 // FBFLAGS__INT_LIST 1024 1536 2048 4096
# define FLEA_RSA_MAX_PUB_EXP_BIT_LEN   32
# define FLEA_ECC_MAX_MOD_BIT_SIZE      521 // FBFLAGS__INT_LIST 160 192 224 256 320 384 521
# define FLEA_ECC_MAX_COFACTOR_BIT_SIZE 32

/**
 * Type for the maximal length of data processed by flea in various functions. The effect is that
 * flea_dtl_t, the type that represents data lengths in various API function
 * signatures, is defined with a width of 32 bit if the flag is set and with a width of 16 bit if deactivated out.
 * Deactivate this switch in order to generate smaller and faster code on 16 and 8
 * bit architectures. Deactivating it also reduces the RAM size of some types
 * considerable.
 */
# define FLEA_HAVE_DTL_32BIT // FBFLAGS_DTL_32_BIT_ON_OFF


/**
 * Enabling this flag causes the choice of code optimized for big endian platforms in some places.
 * In any case, the generated code remains valid independently of the platform's
 * endianess, but may be non-optimal with regard to size and/or speed.
 */
// #define FLEA_HAVE_BE_ARCH_OPT // FBFLAGS_ARCH_OPT_ON_OFF

/**
 * Maximum for CRL Distribution point extension which only takes effect in stack
 * mode.
 *
 */
# define FLEA_X509_STCKMD_MAX_CRLDP_LEN 260

/**
 * This value defines the maximal accepted length of name components (e.g. in
 * the Subject Alternative Name X.509 certificate extension).
 * Must not exceed 0xFFFF.
 */
# define FLEA_X509_NAME_COMPONENT_MAX_BYTE_LEN 256

/**
 * If this switch is deactivated, then only the most common certificate
 * extensions are supported. Saves RAM.
 */
# define FLEA_X509_CERT_REF_WITH_DETAILS

/**
 * If this is switch is deactivated, then only the most typical DN components
 * are supported in X.509 certificates. Saves RAM and a little bit of code.
 */
# define FLEA_HAVE_X509_DN_DETAILS

/**
 * Relevant only in stack mode.
 */
# define FLEA_STKMD_SAN_ELEMENT_MAX_LEN 50

/**
 * Use the "square & multiply always" algorithm for (window-based) modular exponentiation
 * in RSA private operations as a countermeasure against timing attacks.
 */
# define FLEA_USE_RSA_MUL_ALWAYS // FBFLAGS_MOD_EXP_SQMA_ON_OFF

/**
 * Use the "add & double always" algorithm for (window-based) point multiplication in
 * ECC private operations as a countermeasure against timing attacks.
 */
# define FLEA_USE_ECC_ADD_ALWAYS // FBFLAGS_ECC_ADA_ON_OFF

# define FLEA_USE_PUBKEY_INPUT_BASED_DELAY

# define FLEA_USE_PUBKEY_USE_RAND_DELAY

# if defined FLEA_HAVE_RSA && defined FLEA_HAVE_HMAC
#  define FLEA_HAVE_TLS
# endif

# ifdef FLEA_HAVE_TLS
#  define FLEA_HAVE_TLS_CLIENT
#  define FLEA_HAVE_TLS_SERVER

#  if defined FLEA_HAVE_ECKA
#   define FLEA_HAVE_TLS_ECDHE
#   define FLEA_HAVE_TLS_ECDH
#  endif

#  if defined FLEA_HAVE_ECDSA
#   define FLEA_HAVE_TLS_ECDSA
#  endif

#  if defined FLEA_HAVE_RSA
#   define FLEA_HAVE_TLS_RSA
#  endif

#  ifdef FLEA_HAVE_HMAC
#   define FLEA_HAVE_TLS_CBC_CS
#  endif

#  ifdef FLEA_HAVE_GCM
#   define FLEA_HAVE_TLS_GCM_CS
#  endif

# endif // ifdef FLEA_HAVE_TLS


# if defined FLEA_HAVE_TLS_ECDSA || defined FLEA_HAVE_TLS_ECDH || defined FLEA_HAVE_TLS_ECDHE
#  define FLEA_HAVE_TLS_ECC
# endif

/*
 * Flags to enable cipher suites
 */
# ifdef FLEA_HAVE_TLS_RSA /* Ciphersuites that require RSA */
#  ifdef FLEA_HAVE_TLS_CBC_CS
#   define FLEA_HAVE_TLS_RSA_WITH_AES_128_CBC_SHA
#   define FLEA_HAVE_TLS_RSA_WITH_AES_128_CBC_SHA256
#   define FLEA_HAVE_TLS_RSA_WITH_AES_256_CBC_SHA
#   define FLEA_HAVE_TLS_RSA_WITH_AES_256_CBC_SHA256
#  endif // ifdef FLEA_HAVE_TLS_CBC_CS
#  ifdef FLEA_HAVE_TLS_GCM_CS
#   define FLEA_HAVE_TLS_RSA_WITH_AES_128_GCM_SHA256
#   ifdef FLEA_HAVE_SHA384_512
#    define FLEA_HAVE_TLS_RSA_WITH_AES_256_GCM_SHA384
#   endif
#  endif // ifdef FLEA_HAVE_TLS_GCM_CS
#  ifdef FLEA_HAVE_TLS_ECDHE
#   define FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
#   define FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
#   define FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
#   ifdef FLEA_HAVE_SHA384_512
#    define FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
#   endif
#   ifdef FLEA_HAVE_TLS_GCM_CS
#    define FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
#    ifdef FLEA_HAVE_SHA384_512
#     define FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
#    endif
#   endif // ifdef FLEA_HAVE_TLS_GCM_CS
#  endif // ifdef FLEA_HAVE_TLS_ECDHE
# endif // ifdef FLEA_HAVE_TLS_RSA

# define FLEA_X509_MAX_ISSUER_DN_RAW_BYTE_LEN 256

/**
 * Length of the session IDs that are used by the TLS server.
 */
# define FLEA_TLS_SESSION_ID_LEN 16 // FBFLAGS__INT_LIST 1 2 16 31 32

/**
 * Maximal number of sessions held be the server session manager (session cache).
 */
# define FLEA_TLS_MAX_NB_MNGD_SESSIONS 4 // FBFLAGS__INT_LIST 1 2 10 31 257

/**
 * If enabled, the tls client or server context will feature a flea_x509_cert_ref_t of the peer's
 * EE certificate used during the handshake.
 */
# define FLEA_TLS_HAVE_PEER_EE_CERT_REF

/**
 * If enabled, the tls client or server context will feature a flea_x509_cert_ref_t of the root
 * certificate used to authenticate the peer's EE certificate used during the handshake.
 */
# define FLEA_TLS_HAVE_PEER_ROOT_CERT_REF

/**
 * Size of the buffer used in the cipher filter used inside TLS. Must be at
 * least 32 bytes. Larger values increase performance.
 */
# define FLEA_TLS_CIPH_FILTER_BUF_LEN 65

/**
 *  18432 bytes is the size mandated by the TLS standard (here, the additional 5 is due to the TLS header length).
 *  Smaller sizes may only *  be set if the implementation is used in an application context for which
 *  it is known that only smaller records are sent.
 */
# define FLEA_TLS_TRNSF_BUF_SIZE (18432 + 5)

/**
 * Send buffer size. This buffer used for sending data. Should not be smaller than 150 bytes.
 */
# define FLEA_TLS_ALT_SEND_BUF_SIZE 15000


/**
 * Relevant only in stack mode. Maximal size of public key parameters object in
 * an X.509 certificate. Mainly relevant for certificates featuring EC public keys.
 *
 */
# define FLEA_STKMD_TLS_CERT_PATH_VLD_PUBKEY_PARAMS_BUF_SIZE 256

/**
 * Relevant in stack mode.
 * Maximum size of the buffer that reads in the cipher suites offered by the client.
 * Has to be a multiple of 2 as every cipher suite takes up two bytes.
 */
# define FLEA_TLS_MAX_CIPH_SUITES_BUF_SIZE 40


/**************** begin multithreading ******************/

/**
 * Control if fleaTLS supports concurrency for its global RNG and the TLS server. Remove the
 * definition in order to deactivate multithreading support in fleaTLS.
 */
# define FLEA_HAVE_MUTEX

/**
 * Include the mutex header. Remove this line if no mutex support is required.
 */
# include <pthread.h>

/**
 * Define the mutex type to be used.
 */
# define FLEA_MUTEX_TYPE pthread_mutex_t

/**************** end multithreading ******************/

/* include must remain at the very end: */
# include "internal/common/build_config_util.h"


#endif /* h-guard */
