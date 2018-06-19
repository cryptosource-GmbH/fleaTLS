// ! [whole_file]


#include "flea/types.h"
#include "flea_test/tcpip_stream.h"
#include "flea_test/linux_util.h"
#include "flea/tls.h"
#include "flea/pkcs8.h"
#include "flea/array_util.h"
#include "flea/error.h"
#include "flea/tls_server.h"
#include "flea/lib.h"
#include "../certs/CERT_PATH_TLS_CLIENT_valid_ipaddr_in_SAN/root_cert.c"
#include "../certs/CERT_PATH_TLS_CLIENT_valid_ipaddr_in_SAN/ee_pkcs8_key_der.c"
#include "../certs/CERT_PATH_TLS_CLIENT_valid_ipaddr_in_SAN/ee_cert.c"
#include "../certs/CERT_PATH_TLS_CLIENT_valid_ipaddr_in_SAN/sub_ca_cert.c"

#include <stdio.h>
#include <fcntl.h> // linux specific
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main()
{
#if !defined FLEA_HAVE_TLS_SERVER || !defined FLEA_HAVE_SHA1 || !defined FLEA_HAVE_TLS_CS_CBC || \
  !(defined FLEA_HAVE_TLS_CS_RSA || defined FLEA_HAVE_TLS_CS_ECDHE)
  printf("not enough TLS features activated in build configuration\n");
  return 0;

#else  /* if !defined FLEA_HAVE_TLS_SERVER || !defined FLEA_HAVE_SHA1 || !defined FLEA_HAVE_TLS_CS_CBC || !(defined FLEA_HAVE_TLS_CS_RSA || defined FLEA_HAVE_TLS_CS_ECDHE) */
  /* implementation specific context object: */
  linux_socket_stream_ctx_t sock_stream_ctx;

  /* data base object for session resumption */
  flea_tls_session_mngr_t sess_man__t;

  const int one = 1;
  flea_privkey_t server_key__t;
  flea_u8_t buf[100];
  flea_err_e err = FLEA_ERR_FINE;
  flea_tls_sigalg_e sig_algs[2] = {
    flea_tls_sigalg_rsa_sha224,
    flea_tls_sigalg_rsa_sha256
  };
  flea_rw_stream_t rw_stream__t;
  flea_tls_srv_ctx_t tls_ctx;
  flea_u8_t rnd_seed__au8 [32] = {0};

  flea_ref_cu8_t cert_chain [3] =
  {{ee_cert__au8,   sizeof(ee_cert__au8)  }, {sub_ca__au8, sizeof(sub_ca__au8)},
   {root_cert__au8, sizeof(root_cert__au8)}};

  const flea_tls_cipher_suite_id_t cipher_suites[] = {
# ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_128_CBC_SHA
    flea_tls_rsa_with_aes_128_cbc_sha,
# endif
# ifdef FLEA_HAVE_TLS_CS_RSA_WITH_AES_256_CBC_SHA
    flea_tls_rsa_with_aes_256_cbc_sha,
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    flea_tls_ecdhe_rsa_with_aes_128_cbc_sha,
# endif
# ifdef FLEA_HAVE_TLS_CS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    flea_tls_ecdhe_ecdsa_with_aes_256_cbc_sha
# endif
  };
  const flea_ec_dom_par_id_e ec_curves[2] = {flea_brainpoolP256r1, flea_secp256r1};

  flea_dtl_t buf_len = sizeof(buf) - 1;

# ifdef FLEA_HAVE_MUTEX
  flea_mutex_func_set_t mutex_func_set__t = {
    .init   = flea_linux__pthread_mutex_init,
    .destr  = pthread_mutex_destroy,
    .lock   = pthread_mutex_lock,
    .unlock = pthread_mutex_unlock
  };

# endif // ifdef FLEA_HAVE_MUTEX

  /* Draw a random seed - note that in a real world application rather /dev/random should be used */
  int rand_device        = open("/dev/urandom", O_RDONLY);
  ssize_t read_rnd_bytes = read(rand_device, rnd_seed__au8, sizeof(rnd_seed__au8));
  if(read_rnd_bytes != sizeof(rnd_seed__au8))
  {
    printf("error reading /dev/urandom\n");
    exit(1);
  }
  close(rand_device);


  flea_rw_stream_t__INIT(&rw_stream__t);
  flea_privkey_t__INIT(&server_key__t);
  flea_tls_srv_ctx_t__INIT(&tls_ctx);
  flea_tls_session_mngr_t__INIT(&sess_man__t);


  struct sockaddr_in addr;
  int sock_fd, listen_fd = -1;    // client_fd = 0;
  listen_fd = socket(AF_INET, SOCK_STREAM, 0);

  if(listen_fd == -1)
  {
    printf("error opening linux socket\n");
    err = FLEA_ERR_INV_STATE;
    goto cleanup;
  }
  if(setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int)) < 0)
  {
    printf("setsockopt(SO_REUSEADDR) failed\n");
    err = FLEA_ERR_INV_STATE;
    goto cleanup;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_family      = AF_INET;
  addr.sin_port        = htons(4444);   /* port */

  if((bind(listen_fd, (struct sockaddr*) &addr, sizeof(addr))) < 0)
  {
    printf("Socket bind failed\n");
    err = FLEA_ERR_FAILED_TO_OPEN_CONNECTION;
    goto cleanup;
  }
  listen(listen_fd, 1);
  printf("server waiting for connection...\n");
  sock_fd = unix_tcpip_accept(listen_fd, 0);    /* no timeout */
  if(sock_fd == -1)
  {
    printf("error with accept:\n");
    printf("ERROR: %s\n", strerror(errno));
    exit(1);
  }
  if((err =
    THR_flea_pltfif_tcpip__create_rw_stream_server(
      &rw_stream__t,
      &sock_stream_ctx,
      sock_fd,
      0   /* no read_timeout */
    )
    ))
  {
    goto cleanup;
  }

  /* initialize the fleaTLS library with or without mutex support */
  if(THR_flea_lib__init(
      &THR_flea_linux__get_current_time,
      (const flea_u8_t*) &rnd_seed__au8,
      sizeof(rnd_seed__au8),
      NULL
# ifdef FLEA_HAVE_MUTEX
      ,
      &mutex_func_set__t
# endif
    ))
  {
    FLEA_PRINTF_1_SWITCHED("error with lib init, tests aborted\n");
    return 1;
  }

  if((err = THR_flea_tls_session_mngr_t__ctor(
      &sess_man__t,
      3600 /* stored session is valid for one hour */
    )
    ))
  {
    goto cleanup;
  }

  memset(buf, 0x31, sizeof(buf));

  /* create the server's private key from a PKCS#8 / DER encoded array */
  if((err = THR_flea_privkey_t__ctor_pkcs8(&server_key__t, ee_pkcs8__au8, sizeof(ee_pkcs8__au8))))
  {
    goto cleanup;
  }

  if((err = THR_flea_tls_srv_ctx_t__ctor(
      &tls_ctx,
      &rw_stream__t,
      NULL, /* no cert store needed */
      &cert_chain[0],
      FLEA_NB_ARRAY_ENTRIES(cert_chain),
      &server_key__t,
      NULL, /* no CRLs */
      0, /* no CRLs */
      cipher_suites,
      FLEA_NB_ARRAY_ENTRIES(cipher_suites),
      ec_curves,
      FLEA_NB_ARRAY_ENTRIES(ec_curves),
      sig_algs,
      FLEA_NB_ARRAY_ENTRIES(sig_algs),
      flea_tls_flag__rev_chk_mode__check_none | flea_tls_flag__sha1_cert_sigalg__allow,
      &sess_man__t
    )
    ))
  {
    goto cleanup;
  }
  printf("handshake successfully done\n");

  if((err = THR_flea_tls_srv_ctx_t__read_app_data(&tls_ctx, buf, &buf_len, flea_read_nonblocking)))
  {
    goto cleanup;
  }
  if(!buf_len)
  {
    buf_len = sizeof(buf) - 1;
    sleep(1);
    if((err = THR_flea_tls_srv_ctx_t__read_app_data(&tls_ctx, buf, &buf_len, flea_read_nonblocking)))
    {
      goto cleanup;
    }
  }
  if(buf_len)
  {
    buf[buf_len] = 0; /* null terminate the string */
    printf("received data of length %u: ", buf_len);
    printf("%s\n", (const char*) buf);
  }
  else
  {
    printf("did not receive any data\n");
  }

  if((err = THR_flea_tls_srv_ctx_t__send_app_data(&tls_ctx, buf, buf_len)))
  {
    goto cleanup;
  }

  /*
   * ensure that it is acutally written on the wire
   */
  if((err = THR_flea_tls_srv_ctx_t__flush_write_app_data(&tls_ctx)))
  {
    goto cleanup;
  }
cleanup:
  flea_tls_session_mngr_t__dtor(&sess_man__t);
  flea_privkey_t__dtor(&server_key__t);
  flea_tls_srv_ctx_t__dtor(&tls_ctx);
  flea_lib__deinit();
  printf("ending with error code = %04x\n", err);
  return err;

#endif /* if !defined FLEA_HAVE_TLS_SERVER || !defined FLEA_HAVE_SHA1 || !defined FLEA_HAVE_TLS_CS_CBC || !(defined FLEA_HAVE_TLS_CS_RSA || defined FLEA_HAVE_TLS_CS_ECDHE) */
} /* main */

// ! [whole_file]
