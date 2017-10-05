#ifndef _flea_tls_int__H_
#define _flea_tls_int__H_

#ifdef __cplusplus
extern "C" {
#endif

#define FLEA_TLS_CERT_TYPE_RSA_SIGN       1
#define FLEA_TLS_CERT_TYPE_ECDSA_SIGN     64

#define FLEA_TLS_HELLO_RANDOM_SIZE        32
#define FLEA_CONST_TLS_MASTER_SECRET_SIZE 48

// maximum size that we will ever allocate to temporary store the cipher suites
#define FLEA_TLS_MAX_CIPH_SUITES_BUF_SIZE_HEAP 1024

#define FLEA_CONST_TLS_GCM_RECORD_IV_LEN       8
#define FLEA_CONST_TLS_GCM_FIXED_IV_LEN        4
#define FLEA_CONST_TLS_GCM_TAG_LEN             16

typedef enum { flea_tls_read, flea_tls_write } flea_tls_stream_dir_e;

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
