/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "flea/tls_client_session.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/bin_utils.h"
#include "internal/common/tls/tls_int.h"
#include "flea/tls_session_mngr.h"

void flea_tls_client_session_t__ctor(flea_tls_client_session_t* client_session__pt)
{
  memset(client_session__pt, 0, sizeof(*(client_session__pt)));
}

flea_bool_e flea_tls_client_session_t__has_valid_session(const flea_tls_client_session_t* client_session__pt)
{
  if((client_session__pt->session_id_len__u8 == 0) ||
    !flea_tls_session_data_t__is_valid_session(&client_session__pt->session__t))
  {
    return flea_false;
  }
  return flea_true;
}

flea_err_e THR_flea_tls_client_session_t__serialize(
  const flea_tls_client_session_t* client_session__pt,
  flea_byte_vec_t*                 result__pt
)
{
  flea_u8_t enc__au8[4];

  FLEA_THR_BEG_FUNC();
  flea_byte_vec_t__reset(result__pt);
  if(!flea_tls_client_session_t__has_valid_session(client_session__pt))
  {
    FLEA_THROW("session not valid", FLEA_ERR_INV_STATE);
  }
  FLEA_CCALL(THR_flea_byte_vec_t__append(result__pt, &client_session__pt->session_id_len__u8, 1));
  FLEA_CCALL(
    THR_flea_byte_vec_t__append(
      result__pt,
      client_session__pt->session_id__au8,
      client_session__pt->session_id_len__u8
    )
  );
  flea__encode_U16_BE(client_session__pt->session__t.cipher_suite_id__u16, enc__au8);
  FLEA_CCALL(THR_flea_byte_vec_t__append(result__pt, enc__au8, 2));

  FLEA_CCALL(
    THR_flea_byte_vec_t__append(
      result__pt,
      client_session__pt->session__t.master_secret__au8,
      FLEA_TLS_MASTER_SECRET_SIZE
    )
  );

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_client_session_t__serialize */

flea_err_e THR_flea_tls_client_session_t__deserialize(
  flea_tls_client_session_t* client_session__pt,
  const flea_u8_t*           enc__pcu8,
  flea_al_u16_t              enc_len__alu16
)
{
  const flea_u8_t* ptr__pu8;

  FLEA_THR_BEG_FUNC();
  if(!enc_len__alu16 || enc__pcu8[0] > FLEA_CONST_TLS_SESSION_ID_MAX_LEN)
  {
    FLEA_THROW("encoded client session data of invalid length", FLEA_ERR_INV_ARG);
  }
  if(enc_len__alu16 != 1 + enc__pcu8[0] + FLEA_TLS_MASTER_SECRET_SIZE + 2)
  {
    FLEA_THROW("encoded client session data of invalid format", FLEA_ERR_INV_ARG);
  }
  client_session__pt->session_id_len__u8 = enc__pcu8[0];
  memcpy(client_session__pt->session_id__au8, &enc__pcu8[1], enc__pcu8[0]);
  ptr__pu8 = &enc__pcu8[enc__pcu8[0] + 1];

  client_session__pt->session__t.cipher_suite_id__u16 = flea__decode_U16_BE(ptr__pu8);
  ptr__pu8 += 2;

  memcpy(client_session__pt->session__t.master_secret__au8, ptr__pu8, FLEA_TLS_MASTER_SECRET_SIZE);
  client_session__pt->session__t.is_valid_session__u8 = 1;
  FLEA_THR_FIN_SEC_empty();
}
