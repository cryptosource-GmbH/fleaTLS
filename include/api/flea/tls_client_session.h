#ifndef _flea_tls_client_session__H_
#define _flea_tls_client_session__H_

#ifdef __cplusplus
extern "C" {
#endif

#include "flea/types.h"
#include "flea/byte_vec.h"
#include "internal/common/tls/tls_session_int.h"

typedef struct
{
  flea_tls_session_data_t session__t;
  flea_u8_t               session_id__au8[FLEA_CONST_TLS_SESSION_ID_MAX_LEN];
  flea_u8_t               for_resumption__u8;
  flea_u8_t               session_id_len__u8;
} flea_tls_client_session_t;

#define flea_tls_client_session_t__INIT(__p)
#define flea_tls_client_session_t__ctor(__p) memset(__p, 0, sizeof(*(__p)))
#define flea_tls_client_session_t__INIT_VALUE = {.session__t = {.rd_sequence_number__au32[0] = 0}}

#define flea_tls_client_session_t__dtor(__p)


flea_err_t THR_flea_tls_client_session_t_deserialize(
  flea_tls_client_session_t* client_session__pt,
  const flea_u8_t*           enc__pcu8,
  flea_al_u8_t               enc_len__alu8
);

flea_err_t THR_flea_tls_client_session_t__serialize(
  const flea_tls_client_session_t* client_session__pt,
  flea_byte_vec_t*                 result__pt
);

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
