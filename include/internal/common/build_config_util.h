/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_build_config_util__H_
#define _flea_build_config_util__H_

#if defined FLEA_HAVE_ECDSA
# define FLEA_DO_IF_HAVE_ECDSA(x) x
#else
# define FLEA_DO_IF_HAVE_ECDSA(x)
#endif

#if defined FLEA_HAVE_TLS_CS_ECDSA || defined FLEA_HAVE_TLS_CS_ECDH || defined FLEA_HAVE_TLS_CS_ECDHE
# define FLEA_HAVE_TLS_CS_ECC
#endif

#if defined FLEA_HAVE_TLS_CS_ECC
# define FLEA_DO_IF_HAVE_TLS_ECC(x) x
#else
# define FLEA_DO_IF_HAVE_TLS_ECC(x)
#endif

#ifdef FLEA_SCCM_USE_PUBKEY_INPUT_BASED_DELAY
# define FLEA_DO_IF_USE_PUBKEY_INPUT_BASED_DELAY(x) x
#else
# define FLEA_DO_IF_USE_PUBKEY_INPUT_BASED_DELAY(x)
#endif

#if defined FLEA_HAVE_ECDSA || defined FLEA_HAVE_ECKA
# define FLEA_HAVE_ECC
#endif

#if defined FLEA_HAVE_ECC
# define FLEA_DO_IF_HAVE_ECC(x) x
#else
# define FLEA_DO_IF_HAVE_ECC(x)
#endif


#ifdef FLEA_HAVE_RSA
# define FLEA_HAVE_PK_CS
#endif

#if defined FLEA_HAVE_RSA || defined FLEA_HAVE_ECDSA
# define FLEA_HAVE_ASYM_SIG
#endif

#if defined FLEA_HAVE_RSA || defined FLEA_HAVE_ECDSA || defined FLEA_HAVE_ECKA
# define FLEA_HAVE_ASYM_ALGS
#endif

#ifndef FLEA_HEAP_MODE
# define FLEA_STACK_MODE
#endif

#ifdef FLEA_HAVE_AES_BLOCK_DECR
# define FLEA_DO_IF_HAVE_AES_BLOCK_DECR(x) x
#else
# define FLEA_DO_IF_HAVE_AES_BLOCK_DECR(x)
#endif

#if FLEA_CRT_RSA_WINDOW_SIZE > 1
# define FLEA_DO_IF_RSA_CRT_WINDOW_SIZE_GREATER_ONE(x) do {x} while(0)
#else
# define FLEA_DO_IF_RSA_CRT_WINDOW_SIZE_GREATER_ONE(x)
#endif

// fixed 32 bit size difference between P and Q is supported
#define FLEA_RSA_CRT_PQ_BIT_DIFF                 32
#define FLEA_RSA_CRT_PQ_BYTE_DIFF                ((FLEA_RSA_CRT_PQ_BIT_DIFF + 7) / 8)
#define FLEA_RSA_CRT_KEY_COMPONENT_MAX_BYTE_SIZE ((FLEA_RSA_MAX_KEY_BYTE_SIZE + 1) / 2 + FLEA_RSA_CRT_PQ_BYTE_DIFF)
#define FLEA_RSA_MAX_KEY_BYTE_SIZE               ((FLEA_RSA_MAX_KEY_BIT_SIZE + 7) / 8)

#define FLEA_ECC_MAX_COFACTOR_BYTE_SIZE          ((FLEA_ECC_MAX_COFACTOR_BIT_SIZE + 7) / 8)

/************ Begin MAC and AE ************/

#ifdef FLEA_HAVE_EAX
# ifndef FLEA_HAVE_CMAC
#  error CMAC MUST BE CONFIGURED FOR EAX MODE
# endif
#endif

#if defined FLEA_HAVE_EAX || defined FLEA_HAVE_GCM
# define FLEA_HAVE_AE
#endif

#if defined FLEA_HAVE_HMAC || defined FLEA_HAVE_CMAC
# define FLEA_HAVE_MAC
#endif

/************ End MAC and AE ************/


/************ Begin Check Ciphersuite Configuration ************/

#ifdef FLEA_HAVE_TLS
# if !defined FLEA_HAVE_TLS_CS_GCM && !defined FLEA_HAVE_TLS_CS_CBC
#  error for TLS, either FLEA_HAVE_TLS_CS_GCM  or FLEA_HAVE_TLS_CS_CBC must be defined
# endif
#endif

/************ End Check Ciphersuite Configuration ************/


/************ Begin Calculate Maximum Key Block Size ************/

#if defined FLEA_HAVE_TLS_CS_CBC
# if defined FLEA_HAVE_SHA384_512
#  define FLEA_TLS_MAX_KEY_BLOCK_SIZE 2 * (32 + 48) // AES256 + SHA384 is possible
# else
#  define FLEA_TLS_MAX_KEY_BLOCK_SIZE 2 * (32 + 32) // AES256 + SHA256
# endif
#else // GCM only case
# define FLEA_TLS_MAX_KEY_BLOCK_SIZE 2 * (32 + FLEA_CONST_TLS_GCM_FIXED_IV_LEN) // AES256 + salt/implicit nonce
#endif // if defined FLEA_HAVE_TLS_CS_CBC

/************ End Calculate Maximum Key Block Size ************/

#endif /* h-guard */
