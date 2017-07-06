#include "flea/tls_client_session.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/bin_utils.h"
#include "internal/common/tls/tls_int.h"
#include "flea/tls_session_mngr.h"


flea_err_t THR_flea_tls_client_session_t__serialize(
  const flea_tls_client_session_t* client_session__pt,
  flea_byte_vec_t*                 result__pt
)
{
  flea_u8_t enc__au8[4];

  FLEA_THR_BEG_FUNC();
  flea_byte_vec_t__reset(result__pt);
  if((client_session__pt->session_id_len__u8 == 0) ||
    !flea_tls_session_data_t__is_valid_session(&client_session__pt->session__t))
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

  /*flea__encode_U32_BE(client_session__pt->session__t.rd_sequence_number__au32[0], enc__au8);
   * FLEA_CCALL(THR_flea_byte_vec_t__append(result__pt, enc__au8, 4));
   * flea__encode_U32_BE(client_session__pt->session__t.rd_sequence_number__au32[1], enc__au8);
   * FLEA_CCALL(THR_flea_byte_vec_t__append(result__pt, enc__au8, 4));
   * flea__encode_U32_BE(client_session__pt->session__t.wr_sequence_number__au32[0], enc__au8);
   * FLEA_CCALL(THR_flea_byte_vec_t__append(result__pt, enc__au8, 4));
   * flea__encode_U32_BE(client_session__pt->session__t.wr_sequence_number__au32[1], enc__au8);
   * FLEA_CCALL(THR_flea_byte_vec_t__append(result__pt, enc__au8, 4));*/
  FLEA_CCALL(
    THR_flea_byte_vec_t__append(
      result__pt,
      client_session__pt->session__t.master_secret__au8,
      FLEA_CONST_TLS_MASTER_SECRET_SIZE
    )
  );

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_client_session_t__serialize */

flea_err_t THR_flea_tls_client_session_t_deserialize(
  flea_tls_client_session_t* client_session__pt,
  const flea_u8_t*           enc__pcu8,
  flea_al_u8_t               enc_len__alu8
)
{
  const flea_u8_t* ptr__pu8;

  FLEA_THR_BEG_FUNC();
  if(!enc_len__alu8 || enc__pcu8[0] > FLEA_CONST_TLS_SESSION_ID_MAX_LEN)
  {
    FLEA_THROW("encoded client session data of invalid length", FLEA_ERR_INV_ARG);
  }
  if(enc_len__alu8 != 1 + enc__pcu8[0] + FLEA_CONST_TLS_MASTER_SECRET_SIZE + 2)
  {
    FLEA_THROW("encoded client session data of invalid format", FLEA_ERR_INV_ARG);
  }
  client_session__pt->session_id_len__u8 = enc__pcu8[0];
  memcpy(client_session__pt->session_id__au8, &enc__pcu8[1], enc__pcu8[0]);
  ptr__pu8 = &enc__pcu8[enc__pcu8[0] + 1];

  client_session__pt->session__t.cipher_suite_id__u16 = flea__decode_U16_BE(ptr__pu8);
  ptr__pu8 += 2;

  /*client_session__pt->session__t.rd_sequence_number__au32[0] = flea__decode_U32_BE(ptr__pu8);
   * ptr__pu8 += 4;
   * client_session__pt->session__t.rd_sequence_number__au32[1] = flea__decode_U32_BE(ptr__pu8);
   * ptr__pu8 += 4;
   * client_session__pt->session__t.wr_sequence_number__au32[0] = flea__decode_U32_BE(ptr__pu8);
   * ptr__pu8 += 4;
   * client_session__pt->session__t.wr_sequence_number__au32[1] = flea__decode_U32_BE(ptr__pu8);
   * ptr__pu8 += 4;*/
  memcpy(client_session__pt->session__t.master_secret__au8, ptr__pu8, FLEA_CONST_TLS_MASTER_SECRET_SIZE);
  client_session__pt->session__t.is_valid_session__u8 = 1;
  FLEA_THR_FIN_SEC_empty();
}
