// ! [whole_file]


#include "flea/types.h"
#include "flea_test/tcpip_stream.h"
#include "flea_test/linux_util.h"
#include "flea/tls.h"
#include "flea/array_util.h"
#include "flea/error.h"
#include "flea/tls_client.h"
#include "flea/lib.h"
#include "../certs/CERT_PATH_TLS_CLIENT_valid_ipaddr_in_SAN/root_cert.c"

#include <stdio.h>
#include <fcntl.h> // linux specific
#include <unistd.h>

int main()
{
  /* implementation specific context object: */
  linux_socket_stream_ctx_t sock_stream_ctx;

  flea_u8_t buf[100];
  flea_err_e err = FLEA_ERR_FINE;
  flea_tls_sigalg_e sig_algs[2] = {
    flea_tls_sigalg_rsa_sha224,
    flea_tls_sigalg_rsa_sha256
  };
  flea_rw_stream_t rw_stream__t;
  flea_tls_clt_ctx_t tls_ctx;
  flea_cert_store_t trust_store__t;
  flea_u8_t rnd_seed__au8 [32] = {0};

  const flea_u8_t hostname_arr[] = {127, 0, 0, 1};
  flea_ref_cu8_t hostname        = {hostname_arr, 4};
  const char* hostname_str       = {"127.0.0.1"};
  const flea_tls_cipher_suite_id_t cipher_suites[4] = {flea_tls_rsa_with_aes_128_cbc_sha, flea_tls_rsa_with_aes_256_cbc_sha, flea_tls_ecdhe_rsa_with_aes_128_cbc_sha, flea_tls_ecdhe_ecdsa_with_aes_256_cbc_sha};
  const flea_ec_dom_par_id_e ec_curves[2] = {flea_brainpoolP256r1, flea_secp256r1};


  flea_rw_stream_t__INIT(&rw_stream__t);
  flea_tls_clt_ctx_t__INIT(&tls_ctx);
  flea_cert_store_t__INIT(&trust_store__t);

  flea_dtl_t buf_len = sizeof(buf) - 1;
  memset(buf, 0x31, sizeof(buf));

  /* Draw a random seed - note that in a real world application rather /dev/random should be used */
  int rand_device        = open("/dev/urandom", O_RDONLY);
  ssize_t read_rnd_bytes = read(rand_device, rnd_seed__au8, sizeof(rnd_seed__au8));
  if(read_rnd_bytes != sizeof(rnd_seed__au8))
  {
    printf("error reading /dev/urandom\n");
    exit(1);
  }
  close(rand_device);

  /* initialize the fleaTLS library with or without mutex support */
#ifdef FLEA_HAVE_MUTEX
  flea_mutex_func_set_t mutex_func_set__t = {
    .init   = flea_linux__pthread_mutex_init,
    .destr  = pthread_mutex_destroy,
    .lock   = pthread_mutex_lock,
    .unlock = pthread_mutex_unlock
  };

#endif // ifdef FLEA_HAVE_MUTEX
  if(THR_flea_lib__init(
      &THR_flea_linux__get_current_time,
      (const flea_u8_t*) &rnd_seed__au8,
      sizeof(rnd_seed__au8),
      NULL
#ifdef FLEA_HAVE_MUTEX
      ,
      &mutex_func_set__t
#endif
    ))
  {
    FLEA_PRINTF_1_SWITCHED("error with lib init, tests aborted\n");
    return 1;
  }

  if((err = THR_flea_cert_store_t__ctor(&trust_store__t)))
  {
    goto cleanup;
  }

  if((err = THR_flea_cert_store_t__add_trusted_cert(
      &trust_store__t,
      root_cert__au8,
      sizeof(root_cert__au8)
    )))
  {
    goto cleanup;
  }
  /* create the TCP/IP connection = construct the rw_stream_t object */
  if((err = THR_flea_pltfif_tcpip__create_rw_stream_client(
      &rw_stream__t,
      &sock_stream_ctx,
      4444,   /* port */
      0,   /* read timeout */
      hostname_str,
      FLEA_FALSE   /* use ip address, not DNS name */
    )))
  {
    goto cleanup;
  }

  if((err = THR_flea_tls_clt_ctx_t__ctor(
      &tls_ctx,
      &rw_stream__t,
      &trust_store__t,
      &hostname, /* hostname which will be verified, i.e. the ip address */
      flea_host_ipaddr,
      NULL,   /* has no own cert chain */
      0,   /* has no own cert chain */
      NULL,   /* has no own key */
      NULL,   /* has no CRLs */
      0,   /* has no CRLs */
      cipher_suites,
      FLEA_NB_ARRAY_ENTRIES(cipher_suites),
      ec_curves,
      FLEA_NB_ARRAY_ENTRIES(ec_curves),
      sig_algs,
      FLEA_NB_ARRAY_ENTRIES(sig_algs),
      flea_tls_flag__reneg_mode__allow_secure_reneg | flea_tls_flag__sha1_cert_sigalg__allow | flea_tls_flag__rev_chk_mode__check_none,
      NULL   /* session resumption is not supported */
    )))
  {
    goto cleanup;
  }
  printf("handshake successfully done\n");

  /*
   * send some application data
   */
  if((err = THR_flea_tls_clt_ctx_t__send_app_data(&tls_ctx, buf, 10)))
  {
    goto cleanup;
  }

  /*
   * ensure that it is acutally written on the wire
   */
  if((err = THR_flea_tls_clt_ctx_t__flush_write_app_data(&tls_ctx)))
  {
    goto cleanup;
  }
  buf_len = sizeof(buf) - 1;
  if((err = THR_flea_tls_clt_ctx_t__read_app_data(&tls_ctx, buf, &buf_len, flea_read_nonblocking)))
  {
    goto cleanup;
  }
  if(!buf_len)
  {
    buf_len = sizeof(buf) - 1;
    sleep(1);
    if((err = THR_flea_tls_clt_ctx_t__read_app_data(&tls_ctx, buf, &buf_len, flea_read_nonblocking)))
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
    printf("did not receive ping-back data\n");
  }
cleanup:

  flea_tls_clt_ctx_t__dtor(&tls_ctx);
  flea_rw_stream_t__dtor(&rw_stream__t);
  flea_cert_store_t__dtor(&trust_store__t);
  flea_lib__deinit();
  printf("ending with error code = %04x\n", err);
  return err;
} /* main */

// ! [whole_file]
