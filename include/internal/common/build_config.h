/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_build_config__H_
#define _flea_build_config__H_

/**
 * When set, print test failures and summary with printf.
 */
#define FLEA_DO_PRINTF_TEST_OUTPUT
/**
 * When set, print messages from thrown exception with printf (for debugging purposes). This causes output during tests which trigger exceptions.
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
#define FLEA_RSA_MAX_KEY_BIT_SIZE 4096        // FBFLAGS__INT_LIST 1024 1536 2048 4096
#define FLEA_RSA_MAX_PUB_EXP_BIT_LEN 32 
#define FLEA_ECC_MAX_MOD_BIT_SIZE 521         // FBFLAGS__INT_LIST 112 128 160 192 224 256 320 384 521
#define FLEA_ECC_MAX_COFACTOR_BIT_SIZE 32

/**
 * Can be either 16 or 32
 */
#define FLEA_WORD_BIT_SIZE 32 // FBFLAGS__INT_LIST 16 32

/**
 * Don't change this.
 */
#define FLEA_HAVE_DTL_32BIT // FBFLAGS_DTL_32_BIT_ON_OFF

/**
 * set this value if flea runs on a linux platform and the os' interface shall
 * be used for various purposes.
 */
#define FLEA_ON_LINUX_PLTF

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

/* include must remain at the very end: */
#include "internal/common/build_config_util.h"


#endif /* h-guard */
