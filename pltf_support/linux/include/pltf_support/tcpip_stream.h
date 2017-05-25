#ifndef _flea_test_linux_sock__H_
#define _flea_test_linux_sock__H_


#ifdef __cplusplus
extern "C" {
#endif

flea_err_t THR_flea_pltfif_tcpip__create_rw_stream_client(flea_rw_stream_t* stream__pt);
flea_err_t THR_flea_pltfif_tcpip__create_rw_stream_server(
  flea_rw_stream_t* stream__pt,
  flea_u16_t        port__u16
);


#ifdef __cplusplus
}
#endif

#endif /* h-guard */
