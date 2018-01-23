/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_tls_rec_prot_fwd__H_
#define _flea_tls_rec_prot_fwd__H_


#ifdef __cplusplus
extern "C" {
#endif

struct struct_flea_tls_rec_prot_t;

typedef struct struct_flea_tls_rec_prot_t flea_tls_rec_prot_t;

typedef enum
{
  FLEA_TLS_CLIENT,
  FLEA_TLS_SERVER
} flea_tls__connection_end_t;

typedef enum { flea_tls_read, flea_tls_write } flea_tls_stream_dir_e;

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
