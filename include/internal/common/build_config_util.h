/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_build_config_util__H_
#define _flea_build_config_util__H_

#if defined FLEA_HAVE_ECDSA
# define FLEA_DO_IF_HAVE_ECDSA(x) x
#else
# define FLEA_DO_IF_HAVE_ECDSA(x)
#endif

#if defined FLEA_HAVE_ECDSA || defined FLEA_HAVE_ECKA
# define FLEA_HAVE_ECC
#endif

#ifdef FLEA_HAVE_RSA
# define FLEA_HAVE_PK_CS
#endif

#if defined FLEA_HAVE_RSA
# define FLEA_HAVE_TLS
#endif

#if defined FLEA_HAVE_RSA || defined FLEA_HAVE_ECDSA
# define FLEA_HAVE_ASYM_SIG
#endif

#if defined FLEA_HAVE_RSA || defined FLEA_HAVE_ECDSA || defined FLEA_HAVE_ECKA
# define FLEA_HAVE_ASYM_ALGS
#endif

#ifndef FLEA_USE_HEAP_BUF
# define FLEA_USE_STACK_BUF
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
# define FLEA_HAVE_AE
# define FLEA_HAVE_CMAC
#endif

#if defined FLEA_HAVE_HMAC || defined FLEA_HAVE_CMAC
# define FLEA_HAVE_MAC
#endif

/************ End MAC and AE ************/


/************ Begin Check Ciphersuite Configuration ************/
#ifndef FLEA_HAVE_TLS_RSA
# if defined FLEA_HAVE_TLS_RSA_WITH_AES_128_CBC_SHA || defined FLEA_HAVE_TLS_RSA_WITH_AES_128_CBC_SHA256 || \
  defined FLEA_HAVE_TLS_RSA_WITH_AES_256_CBC_SHA || defined FLEA_HAVE_TLS_RSA_WITH_AES_256_CBC_SHA256 || \
  defined FLEA_HAVE_TLS_RSA_WITH_AES_128_GCM_SHA256 || defined FLEA_HAVE_TLS_RSA_WITH_AES_256_GCM_SHA384 || \
  defined FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA || defined FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA || \
  defined FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 || defined FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 || \
  defined FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 || defined FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
#  error "RSA is not configured but RSA cipher suites are configured!"
# endif
#endif

#ifndef FLEA_HAVE_TLS_ECDHE
# if defined FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA || defined FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA || \
  defined FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 || defined FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 || \
  defined FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 || defined FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
#  error "ECDHE is not configured but ECDHE cipher suites are configured!"
# endif
#endif

#ifndef FLEA_HAVE_TLS_CBC_CS
# if defined FLEA_HAVE_TLS_RSA_WITH_AES_128_CBC_SHA || defined FLEA_HAVE_TLS_RSA_WITH_AES_128_CBC_SHA256 || \
  defined FLEA_HAVE_TLS_RSA_WITH_AES_256_CBC_SHA || defined FLEA_HAVE_TLS_RSA_WITH_AES_256_CBC_SHA256 || \
  defined FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA || defined FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA || \
  defined FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 || defined FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
#  error "CBC is not configured but CBC cipher suites are configured!"
# endif
#endif

#ifndef FLEA_HAVE_TLS_GCM_CS
# if defined FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 || \
  defined FLEA_HAVE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 || defined FLEA_HAVE_TLS_RSA_WITH_AES_256_GCM_SHA384 || \
  defined FLEA_HAVE_TLS_RSA_WITH_AES_128_GCM_SHA256
#  error "GCM is not configured but GCM cipher suites are configured!"
# endif
#endif

/************ End Check Ciphersuite Configuration ************/


#endif /* h-guard */
