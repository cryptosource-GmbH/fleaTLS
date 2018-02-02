/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "internal/common/tls/tls_common_ecc.h"
#include "flea/bin_utils.h"
#include "flea/array_util.h"

#ifdef FLEA_HAVE_TLS_CS_ECC

typedef struct
{
  flea_u8_t flea_dp_id__u8;
  flea_u8_t curve_bytes__u8;
} curve_bytes_dp_id_map_entry_t;

static curve_bytes_dp_id_map_entry_t curve_bytes_flea_id_map[] = {
  {(flea_u8_t) flea_secp160r1,       16},
  {(flea_u8_t) flea_secp160r2,       17},
  {(flea_u8_t) flea_secp192r1,       19},
  {(flea_u8_t) flea_secp224r1,       21},
  {(flea_u8_t) flea_secp256r1,       23},
  {(flea_u8_t) flea_secp384r1,       24},
  {(flea_u8_t) flea_secp521r1,       25},
  {(flea_u8_t) flea_brainpoolP256r1, 26},
  {(flea_u8_t) flea_brainpoolP384r1, 27},
  {(flea_u8_t) flea_brainpoolP512r1, 28}
};

flea_err_e THR_flea_tls__map_curve_bytes_to_flea_curve(
  const flea_u8_t       bytes[2],
  flea_ec_dom_par_id_e* ec_dom_par_id__pe
)
{
  flea_al_u8_t i;

  FLEA_THR_BEG_FUNC();
  if(bytes[0] == 0)
  {
    for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(curve_bytes_flea_id_map); i++)
    {
      if(bytes[1] == curve_bytes_flea_id_map[i].curve_bytes__u8)
      {
        *ec_dom_par_id__pe = (flea_ec_dom_par_id_e) curve_bytes_flea_id_map[i].flea_dp_id__u8;
        FLEA_THR_RETURN();
      }
    }
  }

  FLEA_THROW("Unsupported curve", FLEA_ERR_TLS_HANDSHK_FAILURE);

  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_tls_ctx_t__parse_supported_curves_ext(
  flea_tls_ctx_t*   tls_ctx__pt,
  flea_rw_stream_t* rd_strm__pt,
  flea_al_u16_t     ext_len__alu16
)
{
  flea_u32_t len__u32;
  flea_al_u16_t curve_pos__alu16;

  FLEA_THR_BEG_FUNC();
  if(!ext_len__alu16)
  {
    FLEA_THR_RETURN();
  }

  FLEA_CCALL(
    THR_flea_rw_stream_t__read_int_be(
      rd_strm__pt,
      &len__u32,
      2
    )
  );
  if((len__u32 % 2) || (len__u32 > ext_len__alu16 - 2))
  {
    FLEA_THROW("invalid point supported curves extension", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }

  /*
   * find a choice.
   * client: choose from server's set
   * server: choose from client's set
   */
  curve_pos__alu16 = 0xFFFF;
  while(len__u32)
  {
    flea_ec_dom_par_id_e dp_id;
    flea_u8_t curve_bytes__au8 [2];
    flea_al_u16_t i;
    len__u32 -= 2;
    FLEA_CCALL(
      THR_flea_rw_stream_t__read_full(
        rd_strm__pt,
        curve_bytes__au8,
        sizeof(curve_bytes__au8)
      )
    );
    if(THR_flea_tls__map_curve_bytes_to_flea_curve(curve_bytes__au8, &dp_id))
    {
      continue;
    }
    for(i = 0; i < tls_ctx__pt->nb_allowed_curves__u16; i++)
    {
      /*
       * for ECDSA we simply choose the curve that is present in the certificate.
       * this ensures that the client supports the curve present in the
       * certificate or we abort the HS due to not being able to negotiate a
       * ciphersuite
       */
      if(tls_ctx__pt->private_key__pt && tls_ctx__pt->private_key__pt->key_type__t == flea_ecc_key)
      {
        if(tls_ctx__pt->private_key__pt->privkey_with_params__u.ec_priv_key_val__t.dp_id__e !=
          tls_ctx__pt->allowed_ecc_curves__pe[i])
        {
          continue;
        }
      }
      if(tls_ctx__pt->allowed_ecc_curves__pe[i] == dp_id)
      {
        if(i < curve_pos__alu16)
        {
          /* update if it has higher priority */
          curve_pos__alu16 = i;
          tls_ctx__pt->chosen_ecc_dp_internal_id__u8 = dp_id;
        }
        break;
      }
    }
  }
  if(curve_pos__alu16 == 0xFFFF)
  {
    tls_ctx__pt->extension_ctrl__u8 |= FLEA_TLS_EXT_CTRL_MASK__UNMATCHING;
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__parse_supported_curves_ext */

flea_err_e THR_flea_tls_ctx_t__parse_point_formats_ext(
  flea_tls_ctx_t*   tls_ctx__pt,
  flea_rw_stream_t* rd_strm__pt,
  flea_al_u16_t     ext_len__alu16
)
{
  flea_u8_t len__u8;
  flea_bool_t found__b = FLEA_FALSE;

  FLEA_THR_BEG_FUNC();
  if(!ext_len__alu16)
  {
    FLEA_THR_RETURN();
  }

  FLEA_CCALL(
    THR_flea_rw_stream_t__read_byte(
      rd_strm__pt,
      &len__u8
    )
  );
  if(len__u8 > ext_len__alu16 - 1)
  {
    FLEA_THROW("invalid point formats extension", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }
  while(len__u8--)
  {
    flea_u8_t byte;
    FLEA_CCALL(
      THR_flea_rw_stream_t__read_byte(
        rd_strm__pt,
        &byte
      )
    );
    if(byte == 0) /* uncompressed */
    {
      found__b = FLEA_TRUE;
    }
  }
  if(!found__b)
  {
    tls_ctx__pt->extension_ctrl__u8 |= FLEA_TLS_EXT_CTRL_MASK__UNMATCHING;
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__parse_point_formats_ext */

flea_bool_t flea_tls__is_cipher_suite_ecdhe_suite(flea_tls_cipher_suite_id_t suite_id)
{
  if(flea_tls_get_cipher_suite_by_id(suite_id)->mask & FLEA_TLS_CS_KEX_MASK__ECDHE)
  {
    return FLEA_TRUE;
  }
  return FLEA_FALSE;
}

flea_bool_t flea_tls__is_cipher_suite_ecc_suite(flea_tls_cipher_suite_id_t suite_id)
{
  if((suite_id >> 8) == 0xC0)
  {
    return FLEA_TRUE;
  }
  return FLEA_FALSE;
}

flea_err_e THR_flea_tls_ctx_t__send_ecc_point_format_ext(
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt
)
{
  FLEA_THR_BEG_FUNC();
  const flea_u8_t ext__acu8[] = {
    0x00, 0x0b, 0x00, 0x02, 0x01, 0x00 /* point formats */
  };
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx__pt->rec_prot__t,
      p_hash_ctx__pt,
      ext__acu8,
      sizeof(ext__acu8)
    )
  );
  FLEA_THR_FIN_SEC_empty();
}

flea_err_e THR_flea_tls_ctx_t__send_ecc_supported_curves_ext(
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt
)
{
  FLEA_THR_BEG_FUNC();
  flea_u8_t ext__au8[] = {
    0x00, 0x0a
  };

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx__pt->rec_prot__t,
      p_hash_ctx__pt,
      ext__au8,
      sizeof(ext__au8)
    )
  );
  flea__encode_U16_BE(tls_ctx__pt->nb_allowed_curves__u16 * 2 + 2, ext__au8);
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx__pt->rec_prot__t,
      p_hash_ctx__pt,
      ext__au8,
      sizeof(ext__au8)
    )
  );
  flea__encode_U16_BE(tls_ctx__pt->nb_allowed_curves__u16 * 2, ext__au8);
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx__pt->rec_prot__t,
      p_hash_ctx__pt,
      ext__au8,
      sizeof(ext__au8)
    )
  );

  flea_al_u16_t i;
  for(i = 0; i < tls_ctx__pt->nb_allowed_curves__u16; i++)
  {
    FLEA_CCALL(
      THR_flea_tls__map_flea_curve_to_curve_bytes(
        (flea_ec_dom_par_id_e) tls_ctx__pt->
        allowed_ecc_curves__pe[i],
        ext__au8
      )
    );
    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_content(
        &tls_ctx__pt->rec_prot__t,
        p_hash_ctx__pt,
        ext__au8,
        sizeof(ext__au8)
      )
    );
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__send_ecc_supported_curves_ext */

flea_err_e THR_flea_tls__map_flea_curve_to_curve_bytes(
  const flea_ec_dom_par_id_e ec_dom_par_id__e,
  flea_u8_t                  bytes[2]
)
{
  flea_al_u8_t i;

  FLEA_THR_BEG_FUNC();
  bytes[0] = 0;
  for(i = 0; i < (flea_u8_t) flea_secp521r1; i++)
  {
    if(ec_dom_par_id__e == curve_bytes_flea_id_map[i].flea_dp_id__u8)
    {
      bytes[1] = curve_bytes_flea_id_map[i].curve_bytes__u8;
      FLEA_THR_RETURN();
    }
  }
  FLEA_THROW("Unsupported curve, this should not happen", FLEA_ERR_INT_ERR);
  FLEA_THR_FIN_SEC_empty();
}

#endif  /* ifdef FLEA_HAVE_TLS_CS_ECC */
