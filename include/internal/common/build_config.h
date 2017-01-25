/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_build_config__H_
#define _flea_build_config__H_

/**
 * When set, print test failures and summary with printf.
 */
#define FLEA_DO_PRINTF_TEST_OUTPUT
/**
 * When set, print messages from thrown exception with printf (for debugging purposes). This causes output during tests which purposely trigger exceptions.
 */
//#define FLEA_DO_PRINTF_ERRS

/**
 * Activate this flag to let flea make heap allocation for buffers. Deactivate
 * this flag to let flea only use stack buffers. In the latter case, be sure to
 * correctly define the RSA and EC key sizes.
 */
#define FLEA_USE_HEAP_BUF  // FBFLAGS_CORE_ON_OFF

/**
 * Activate this flag to make use of the buffer overwrite detection. Should not
 * be used in productive code due to performance and code size effects.
 */
#define FLEA_USE_BUF_DBG_CANARIES // FBFLAGS_CORE_ON_OFF

#define FLEA_HAVE_HMAC              // FBFLAGS_MACALGS_ON_OFF
#define FLEA_HAVE_CMAC              // FBFLAGS_MACALGS_ON_OFF
#define FLEA_HAVE_EAX               // FBLAGS_AEALGS_ON_OFF

#define FLEA_HAVE_MD5               // FBFLAGS_MD5_ON_OFF
#define FLEA_HAVE_SHA1              // FBFLAGS_SHA1_ON_OFF
#define FLEA_HAVE_SHA224_256        // NOT CONFIGURABLE
#define FLEA_HAVE_SHA384_512        // FBFLAGS_HAVE_SHA512_ON_OFF
#define FLEA_HAVE_DAVIES_MEYER_HASH // FBFLAGS_DAVIES_MEYER_HASH_ON_OFF

/**
 * Configuration
 */
#define FLEA_USE_MD5_ROUND_MACRO    // FBFLAGS_MD5_ON_OFF
#define FLEA_USE_SHA1_ROUND_MACRO   // FBFLAGS_SHA1_ON_OFF
#define FLEA_USE_SHA256_ROUND_MACRO // FBFLAGS_SHA256_ON_OFF
#define FLEA_USE_SHA512_ROUND_MACRO // FBFLAGS_SHA512_ON_OFF

#define FLEA_HAVE_DES               // FBFLAGS_HAVE_DES_ON_OFF
#define FLEA_HAVE_TDES_2KEY         // FBFLAGS_HAVE_TDES_ON_OFF
#define FLEA_HAVE_TDES_3KEY         // FBFLAGS_HAVE_TDES_ON_OFF
#define FLEA_HAVE_DESX              // FBFLAGS_HAVE_DESX_ON_OFF
#define FLEA_HAVE_AES               // NOT CONFIGURABLE

/**
 * If set, then AES block decryption and ECB and CBC mode are enabled. Otherwise
 * only the AES block encryption is available, which is sufficient for both
 * directions in CTR mode.
 */
#define FLEA_HAVE_AES_BLOCK_DECR  // FBFLAGS_AES_ON_OFF
#define FLEA_USE_SMALL_AES        // FBFLAGS_AES_ON_OFF

#define FLEA_HAVE_RSA             // FBFLAGS_PKALGS_ON_OFF
#define FLEA_HAVE_ECDSA           // FBFLAGS_PKALGS_ON_OFF
#define FLEA_HAVE_ECKA            // FBFLAGS_PKALGS_ON_OFF

/**
 * Choose 5 for greatest speed and 1 for smallest RAM footprint.
 */
#define FLEA_CRT_RSA_WINDOW_SIZE 5            // FBFLAGS__INT_LIST 1 2 3 4 5
/**
 * A window size of up to 5 is beneficial for single point multiplications even
 * for 112 bit curves.
 */
#define FLEA_ECC_SINGLE_MUL_MAX_WINDOW_SIZE 5 // FBFLAGS__INT_LIST 1 2 3 4 5


/**
 * The maximum number of certificates in a chain, including the targert 
 * certificate and the trust anchor.
 * Relevant both for heap and stack mode.
 */
#define FLEA_MAX_CERT_CHAIN_DEPTH 20          // FBFLAGS__INT_LIST 2 3 4 10 20

/* Maximal number of certificates that can set in a any type of 
 * object storing certificates. Hard limit in case of both stack and heap
 * mode. In heap mode it can be set to zero to disable any predefined limit.
 */
#define FLEA_MAX_CERT_COLLECTION_SIZE 20

/* Maximal number of CRLs that can set in a any type of 
 * object storing CRLs . Hard limit in case of both stack and heap
 * mode. In heap mode it can be set to zero to disable any predefined limit.
 */
#define FLEA_MAX_CERT_COLLECTION_NB_CRLS 20

/**
 * Number of certificates or CRLs for which memory is initially allocated in
 * heap mode in objects storing such data types. This value is also used as the
 * number of objects for which new memory is allocated when reallocation is
 * triggered.
 */
#define FLEA_CERT_AND_CRL_PREALLOC_OBJ_CNT 5  // FBFLAGS__INT_LIST 1 2 3 4 10 20

/**
 * The maximal capacity (certificate count) of a cert_store_t object. Applies to
 * both the heap and the stack mode as the threshold. In heap mode, the
 * allocated memory may grow up to this threshold.
 */
#define FLEA_CERT_STORE_MAX_CAPACITY 20

/** 
 * The initial allocated size and step size for allocation growth for a
 * cert_store_t object. Relevant only in heap mode.
 */
#define FLEA_CERT_STORE_PREALLOC 5

#define FLEA_RSA_MAX_KEY_BIT_SIZE 4096        // FBFLAGS__INT_LIST 1024 1536 2048 4096
#define FLEA_RSA_MAX_PUB_EXP_BIT_LEN 32 
#define FLEA_ECC_MAX_MOD_BIT_SIZE 521         // FBFLAGS__INT_LIST 160 192 224 256 320 384 521
#define FLEA_ECC_MAX_COFACTOR_BIT_SIZE 32

/**
 * Can be either 16 or 32
 */
#define FLEA_WORD_BIT_SIZE 32 // FBFLAGS__INT_LIST 16 32

/**
 * Has to be set to the platforms natural pointer size,
 * i.e. to sizeof(void*).
 * Supported values are 8 (64-bit), 4 (32-bit), and 2 (16-bit).
 */
#define FLEA_PTR_BYTE_SIZE 8

/**
 * Type for the maximal length of data processed by flea in various functions. The effect is that
 * flea_dtl_t, the type that represents data lengths in various API function
 * signatures, is defined with a width of 32 bit if the flag is set and with a width of 16 bit if commented out.
 * Deactivate this flag in order to generate smaller and faster code on 16 and 8
 * bit architectures.
 */
#define FLEA_HAVE_DTL_32BIT // FBFLAGS_DTL_32_BIT_ON_OFF

/**
 * set this value if flea runs on a linux platform and the os' interface shall
 * be used for various purposes.
 */
#define FLEA_ON_LINUX_PLTF

/**
 * Enabling this flag causes the choice of code optimized for big endian platforms in some places.
 * In any case, the generated remains valid independently of the platform's
 * endianess, but may be non-optimal with regard to size and/or speed.
 */
#define FLEA_HAVE_BE_ARCH_OPT // FBFLAGS_ARCH_OPT_ON_OFF

/**
 * set this value to use the user-provided implementation of the function
 * used by flea to determine the current time.
 */
//#define FLEA_USE_USER_CURR_TIME

/**
 * This value defines the maximal accepted length of name components (e.g. in
 * the Subject Alternative Name X.509 certificate extension). In stack mode,
 * this determines allocated buffer sizes.
 * Must not exceed 0xFFFF.
 */
#define FLEA_X509_NAME_COMPONENT_MAX_BYTE_LEN 256

/**
 * Use the "square & multiply always" algorithm for (window-based) modular exponentiation 
 * in RSA private operations as a countermeasure against timing attacks.
 */
#define FLEA_USE_RSA_MUL_ALWAYS // FBFLAGS_MOD_EXP_SQMA_ON_OFF

/**
 * Use the "add & double always" algorithm for (window-based) point multiplication in 
 * ECC private operations * as a countermeasure against timing attacks.
 */
#define FLEA_USE_ECC_ADD_ALWAYS // FBFLAGS_ECC_ADA_ON_OFF

/* include must remain at the very end: */
#include "internal/common/build_config_util.h"


#endif /* h-guard */
