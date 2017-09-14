/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/bin_utils.h"
#include "flea/tls.h"
#include "flea/cbc_filter.h"
#include "flea/hash_stream.h"
#include "flea/tee.h"
#include "internal/common/tls/handsh_reader.h"
#include "internal/common/tls/tls_rec_prot_rdr.h"
#include "internal/common/tls/tls_common.h"
#include "internal/common/tls/tls_cert_path.h"
#include "internal/common/tls/tls_client_int.h"

#include "flea/pubkey.h"
#include "flea/asn1_date.h"
#include "api/flea/cert_path.h"
#include "internal/common/ber_dec.h"
#include "flea/rng.h"
#include "flea/block_cipher.h"
#include "flea/bin_utils.h"
#include "flea/cert_store.h"
#include "flea/byte_vec.h"
#include "internal/common/tls_ciph_suite.h"
#include "internal/common/tls/parallel_hash.h"
#include "flea/tls_session_mngr.h"
#include "internal/pltf_if/time.h"
#include "flea/ec_key_gen.h"
#include "flea/ecka.h"
#include "internal/common/tls_ciph_suite.h"

#ifdef FLEA_HAVE_TLS

typedef struct
{
  flea_u16_t error;
  flea_u8_t  alert;
} error_alert_pair_t;


static const error_alert_pair_t error_alert_map__act [] = {
  {FLEA_ERR_TLS_ENCOUNTERED_BAD_RECORD_MAC,     FLEA_TLS_ALERT_DESC_BAD_RECORD_MAC     },
  {FLEA_ERR_TLS_UNEXP_MSG_IN_HANDSH,            FLEA_TLS_ALERT_DESC_UNEXPECTED_MESSAGE },
  {FLEA_ERR_TLS_INV_ALGO_IN_SERVER_HELLO,       FLEA_TLS_ALERT_DESC_HANDSHAKE_FAILURE  },
  {FLEA_ERR_TLS_COULD_NOT_AGREE_ON_CIPHERSUITE, FLEA_TLS_ALERT_DESC_HANDSHAKE_FAILURE  },
  {FLEA_ERR_TLS_INV_REC_HDR,                    FLEA_TLS_ALERT_DESC_DECRYPT_ERROR      },
  {FLEA_ERR_CERT_PATH_NO_TRUSTED_CERTS,         FLEA_TLS_ALERT_DESC_UNKNOWN_CA         },
  {FLEA_ERR_X509_TLS_SERVER_ID_NO_MATCH,        FLEA_TLS_ALERT_DESC_CERTIFICATE_UNKNOWN},
  {FLEA_ERR_X509_VERSION_ERROR,                 FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_ASN1_DER_DEC_ERR,                   FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_ASN1_DER_UNEXP_TAG,                 FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_ASN1_DER_EXCSS_LEN,                 FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_ASN1_DER_EXCSS_NST,                 FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_ASN1_DEC_TRGT_BUF_TOO_SMALL,        FLEA_TLS_ALERT_DESC_INTERNAL_ERROR     },
  {FLEA_ERR_ASN1_DER_CALL_SEQ_ERR,              FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_ASN1_DER_CST_LEN_LIMIT_EXCEEDED,    FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_ERR_UNSUP_CRIT_EXT,            FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_KU_DEC_ERR,                    FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_SAN_DEC_ERR,                   FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_NEG_INT,                       FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_BC_EXCSS_PATH_LEN,             FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_EKU_VAL_ERR,                   FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_SIG_ALG_ERR,                   FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_UNSUPP_PRIMITIVE,              FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_BIT_STR_ERR,                   FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_UNRECOG_HASH_FUNCTION,         FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_UNSUPP_ALGO_VARIANT,           FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_INV_ECC_KEY_PARAMS,            FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_INV_ECC_FIELD_TYPE,            FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_IMPLICT_ECC_KEY_PARAMS,        FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_INV_ECC_POINT_ENCODING,        FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_EXCSS_COFACTOR_SIZE,           FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_INV_SIGNATURE,                      FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_CERT_PATH_LEN_CONSTR_EXCEEDED,      FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_CERT_INTERMED_IS_NOT_CA_CERT,       FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
  {FLEA_ERR_X509_CERT_NOT_YET_VALID,            FLEA_TLS_ALERT_DESC_CERTIFICATE_EXPIRED},
  {FLEA_ERR_X509_CERT_EXPIRED,                  FLEA_TLS_ALERT_DESC_CERTIFICATE_EXPIRED},
  {FLEA_ERR_TLS_UNSUPP_PROT_VERSION,            FLEA_TLS_ALERT_DESC_PROTOCOL_VERSION   },
  {FLEA_ERR_TLS_PROT_DECODE_ERR,                FLEA_TLS_ALERT_DESC_DECODE_ERROR       },
  {FLEA_ERR_TLS_REC_NORENEG_AL_DURING_RENEG,    FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY       },
  {FLEA_ERR_FAILED_STREAM_READ,                 FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY       },
  {FLEA_ERR_FAILED_STREAM_WRITE,                FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY       },
  {FLEA_ERR_TLS_SESSION_CLOSED,                 FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY       },
  {FLEA_ERR_TLS_REC_CLOSE_NOTIFY,               FLEA_TLS_ALERT_DESC_CLOSE_NOTIFY       },
  {FLEA_ERR_TLS_HANDSHK_FAILURE,                FLEA_TLS_ALERT_DESC_HANDSHAKE_FAILURE  },
  {FLEA_ERR_TLS_CERT_VER_FAILED,                FLEA_TLS_ALERT_DESC_BAD_CERTIFICATE    },
};
static flea_bool_t determine_alert_from_error(
  flea_err_t                     err__t,
  flea_tls__alert_description_t* alert_desc__pe,
  flea_bool_t                    is_reneg__b,
  flea_bool_t                    is_read_app_data__b
)
{
  flea_al_u8_t i;

  if((is_reneg__b && (err__t == FLEA_ERR_TLS_REC_NORENEG_AL_DURING_RENEG)) ||
    (is_read_app_data__b && (err__t == FLEA_ERR_TIMEOUT_ON_STREAM_READ))
  )
  {
    *alert_desc__pe = FLEA_TLS_ALERT_NO_ALERT;
    return FLEA_FALSE;
  }

  for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(error_alert_map__act); i++)
  {
    if(err__t == error_alert_map__act[i].error)
    {
      *alert_desc__pe = error_alert_map__act[i].alert;
      return FLEA_TRUE;
    }
  }
  *alert_desc__pe = FLEA_TLS_ALERT_DESC_INTERNAL_ERROR;
  return FLEA_TRUE;
}

flea_mac_id_t flea_tls__map_hmac_to_hash(flea_hash_id_t hash)
{
  flea_mac_id_t hmac;

  switch(hash)
  {
      case flea_sha1: hmac = flea_hmac_sha1;
        break;
      case flea_sha256: hmac = flea_hmac_sha256;
        break;
      case flea_sha384: hmac = flea_hmac_sha384;
        break;
      case flea_sha512: hmac = flea_hmac_sha512;
        break;
      default:
        break;
  }
  return hmac;
}

typedef struct
{
  flea_u8_t  type__u8;
  flea_u32_t len__u32;
} handshake_header;

static void flea_tls_ctx_t__set_sec_reneg_flags(
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_tls_renegotiation_spec_e reneg_spec__e
)
{
  if(reneg_spec__e == flea_tls_only_secure_reneg)
  {
    tls_ctx__pt->allow_reneg__u8       = FLEA_TRUE;
    tls_ctx__pt->allow_insec_reneg__u8 = FLEA_FALSE;
  }
  else if(reneg_spec__e == flea_tls_allow_insecure_reneg)
  {
    tls_ctx__pt->allow_reneg__u8       = FLEA_TRUE;
    tls_ctx__pt->allow_insec_reneg__u8 = FLEA_TRUE;
  }
  else
  {
    tls_ctx__pt->allow_reneg__u8       = FLEA_FALSE;
    tls_ctx__pt->allow_insec_reneg__u8 = FLEA_FALSE;
  }
}

static flea_err_t P_Hash(
  const flea_u8_t* secret,
  flea_u16_t       secret_length,
  const flea_u8_t* label__pcu8,
  flea_al_u8_t     label_len__alu8,
  const flea_u8_t* seed,
  flea_u16_t       seed_length,
  flea_u8_t*       data_out,
  flea_u16_t       res_length,
  flea_mac_id_t    mac_id__e
)
{
  const flea_u16_t mac_out_len__alu8 = flea_mac__get_output_length_by_id(mac_id__e);

  FLEA_DECL_BUF(a__bu8, flea_u8_t, 2 * FLEA_TLS_MAX_MAC_SIZE);
  flea_u8_t* A;
  flea_u8_t* B;
  flea_u8_t* tmp__pu8;
  flea_mac_ctx_t hmac__t = flea_mac_ctx_t__INIT_VALUE;

  // expand to length bytes
  flea_al_u8_t len__alu8 = mac_out_len__alu8;
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(a__bu8, 2 * FLEA_TLS_MAX_MAC_SIZE);
  A = a__bu8;
  B = a__bu8 + FLEA_TLS_MAX_MAC_SIZE;
  flea_mac_ctx_t__INIT(&hmac__t);
  FLEA_CCALL(THR_flea_mac_ctx_t__ctor(&hmac__t, mac_id__e, secret, secret_length));
  FLEA_CCALL(THR_flea_mac_ctx_t__update(&hmac__t, label__pcu8, label_len__alu8));
  FLEA_CCALL(THR_flea_mac_ctx_t__update(&hmac__t, seed, seed_length));
  FLEA_CCALL(THR_flea_mac_ctx_t__final_compute(&hmac__t, A, &len__alu8));
  flea_mac_ctx_t__dtor(&hmac__t);
  while(res_length)
  {
    flea_al_u8_t to_go__alu16 = FLEA_MIN(res_length, mac_out_len__alu8);
    res_length -= to_go__alu16;
    // A(i) = HMAC_hash(secret, A(i-1))
    flea_mac_ctx_t__INIT(&hmac__t);
    FLEA_CCALL(THR_flea_mac_ctx_t__ctor(&hmac__t, mac_id__e, secret, secret_length));
    FLEA_CCALL(THR_flea_mac_ctx_t__update(&hmac__t, A, mac_out_len__alu8));
    FLEA_CCALL(THR_flea_mac_ctx_t__update(&hmac__t, label__pcu8, label_len__alu8));
    FLEA_CCALL(THR_flea_mac_ctx_t__update(&hmac__t, seed, seed_length));
    len__alu8 = to_go__alu16;
    FLEA_CCALL(THR_flea_mac_ctx_t__final_compute(&hmac__t, data_out, &len__alu8));
    data_out += to_go__alu16;
    len__alu8 = mac_out_len__alu8;
    FLEA_CCALL(
      THR_flea_mac__compute_mac(
        mac_id__e,
        secret,
        secret_length,
        A,
        mac_out_len__alu8,
        B,
        &len__alu8
      )
    );
    tmp__pu8 = A;
    A        = B;
    B        = tmp__pu8;
    flea_mac_ctx_t__dtor(&hmac__t);
  }
  FLEA_THR_FIN_SEC(
    flea_mac_ctx_t__dtor(&hmac__t);
    FLEA_FREE_BUF_FINAL_SECRET_ARR(a__bu8, 2 * FLEA_TLS_MAX_MAC_SIZE);
  );
} /* P_Hash */

static flea_err_t flea_tls__prf(
  const flea_u8_t* secret,
  flea_u8_t        secret_length,
  PRFLabel         label,
  const flea_u8_t* seed,
  flea_u16_t       seed_length,
  flea_u16_t       result_length,
  flea_u8_t*       result,
  flea_mac_id_t    mac_id__e
)
{
  const flea_u8_t client_finished[] = {99, 108, 105, 101, 110, 116, 32, 102, 105, 110, 105, 115, 104, 101, 100};
  const flea_u8_t server_finished[] = {115, 101, 114, 118, 101, 114, 32, 102, 105, 110, 105, 115, 104, 101, 100};
  const flea_u8_t master_secret[]   = {109, 97, 115, 116, 101, 114, 32, 115, 101, 99, 114, 101, 116};
  const flea_u8_t key_expansion[]   = {107, 101, 121, 32, 101, 120, 112, 97, 110, 115, 105, 111, 110};

  const flea_u8_t* label__pcu8;
  flea_al_u8_t label_len__alu8;

  FLEA_THR_BEG_FUNC();

  switch(label)
  {
      case PRF_LABEL_CLIENT_FINISHED:
        label__pcu8     = client_finished;
        label_len__alu8 = sizeof(client_finished);
        break;
      case PRF_LABEL_MASTER_SECRET:
        label__pcu8     = master_secret;
        label_len__alu8 = sizeof(master_secret);
        break;
      case PRF_LABEL_KEY_EXPANSION:
        label__pcu8     = key_expansion,
        label_len__alu8 = sizeof(key_expansion);
        break;
      case PRF_LABEL_SERVER_FINISHED:
        label__pcu8     = server_finished;
        label_len__alu8 = sizeof(server_finished);
        break;
      default:
        FLEA_THROW("Invalid label!", FLEA_ERR_TLS_INVALID_STATE);
  }
  FLEA_CCALL(
    P_Hash(
      secret,
      secret_length,
      label__pcu8,
      label_len__alu8,
      seed,
      seed_length,
      result,
      result_length,
      mac_id__e
    )
  );
  FLEA_THR_FIN_SEC_empty();
} /* flea_tls__prf */

static flea_mac_id_t flea_tls__prf_mac_id_from_suite_id(flea_tls__cipher_suite_id_t cs_id__t)
{
  const flea_tls__cipher_suite_t* cs__pt = flea_tls_get_cipher_suite_by_id(cs_id__t);

  if(cs__pt->hash_algorithm == flea_sha384)
  {
    return flea_hmac_sha384;
  }
  else if(cs__pt->hash_algorithm == flea_sha512)
  {
    return flea_hmac_sha512;
  }
  return flea_hmac_sha256;
}

flea_err_t THR_flea_tls__generate_key_block(
  // const flea_tls_ctx_t* tls_ctx,
  flea_al_u16_t                          selected_cipher_suite__alu16,
  const flea_tls__security_parameters_t* security_parameters__pt,
  flea_u8_t*                             key_block,
  flea_al_u8_t                           key_block_len__alu8
)
{
  FLEA_THR_BEG_FUNC();
  // TODO: MUST BE ABSTRACT BUF:
  flea_u8_t seed[64];
  // TODO: REDUNDANT ARRAY ?( could swap values and swap them back in fin-sec,
  // but this increases the code size) // Better: hand through 2 seed parts down
  // to the prf, this should not effectively increase code size too much (save 2
  // memcpy and add one function call parameter)
  memcpy(
    seed,
    security_parameters__pt->client_and_server_random + FLEA_TLS_HELLO_RANDOM_SIZE,
    FLEA_TLS_HELLO_RANDOM_SIZE
  );
  memcpy(
    seed + FLEA_TLS_HELLO_RANDOM_SIZE,
    security_parameters__pt->client_and_server_random,
    FLEA_TLS_HELLO_RANDOM_SIZE
  );

  FLEA_CCALL(
    flea_tls__prf(
      security_parameters__pt->master_secret,
      48,
      PRF_LABEL_KEY_EXPANSION,
      seed,
      2 * FLEA_TLS_HELLO_RANDOM_SIZE,// sizeof(seed),
      key_block_len__alu8,
      key_block,
      flea_tls__prf_mac_id_from_suite_id(selected_cipher_suite__alu16)
    )
  );
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__generate_key_block */

static void flea_tls_ctx_t__invalidate_session(flea_tls_ctx_t* tls_ctx__pt)
{
  if(tls_ctx__pt->security_parameters.connection_end == FLEA_TLS_CLIENT && tls_ctx__pt->client_session_mbn__pt)
  {
    flea_tls_session_data_t__invalidate_session(&tls_ctx__pt->client_session_mbn__pt->session__t);
  }
  else if(tls_ctx__pt->server_active_sess_mbn__pt)
  {
    flea_tls_session_data_t__invalidate_session(&tls_ctx__pt->server_active_sess_mbn__pt->session__t);// .is_valid_session__u8 = 0;
  }
}

flea_err_t THR_flea_tls__handle_tls_error(
  flea_tls_ctx_t* tls_ctx__pt,
  flea_err_t      err__t,
  flea_bool_t     is_reneg__b,
  flea_bool_t     is_read_app_data__b
)
{
  FLEA_THR_BEG_FUNC();
  if(err__t)
  {
    flea_tls__alert_description_t alert_desc__e;
    /* determine alert and exception at the same time: */
    flea_bool_t do_send_alert__b = determine_alert_from_error(err__t, &alert_desc__e, is_reneg__b, is_read_app_data__b);
    if(do_send_alert__b)
    {
      if(err__t != FLEA_ERR_TLS_REC_CLOSE_NOTIFY)
      {
        flea_tls_ctx_t__invalidate_session(tls_ctx__pt);
      }
      FLEA_CCALL(THR_flea_tls_rec_prot_t__send_alert_and_throw(&tls_ctx__pt->rec_prot__t, alert_desc__e, err__t));
    }
  }
  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_flea_tls__create_finished_data(
  flea_u8_t*    messages_hash,
  flea_u8_t     messages_hash_len__u8,
  flea_u8_t     master_secret[48],
  PRFLabel      label,
  flea_u8_t*    data,
  flea_u8_t     data_len,
  flea_mac_id_t mac_id__e
)
{
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(flea_tls__prf(master_secret, 48, label, messages_hash, messages_hash_len__u8, data_len, data, mac_id__e));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls__read_finished(
  flea_tls_ctx_t*           tls_ctx,
  flea_tls_handsh_reader_t* hs_rdr__pt,
  flea_hash_ctx_t*          hash_ctx
)
{
  FLEA_DECL_BUF(messages_hash__bu8, flea_u8_t, __FLEA_COMPUTED_MAX_HASH_OUT_LEN + 2 * 12);
  const flea_al_u8_t finished_len__alu8 = FLEA_TLS_VERIFY_DATA_SIZE;
  flea_rw_stream_t* hs_rd_stream__pt;
  flea_hash_id_t hash_id__t;
  flea_u8_t hash_len__u8;
  FLEA_THR_BEG_FUNC();

  hash_id__t   = flea_tls_get_prf_hash_by_cipher_suite_id(tls_ctx->selected_cipher_suite__u16);
  hash_len__u8 = flea_hash__get_output_length_by_id(hash_id__t);

  FLEA_ALLOC_BUF(messages_hash__bu8, hash_len__u8 + 2 * 12);
  flea_u8_t* finished__pu8     = messages_hash__bu8 + hash_len__u8;
  flea_u8_t* rec_finished__pu8 = messages_hash__bu8 + hash_len__u8 + finished_len__alu8;

  /*
   * use a copy of hash_ctx for send_finished instead of finalizing the original
   */

  // we are working on a copy so we can finalize without copying
  FLEA_CCALL(THR_flea_hash_ctx_t__final(hash_ctx, messages_hash__bu8));

  PRFLabel label;
  if(tls_ctx->security_parameters.connection_end == FLEA_TLS_CLIENT)
  {
    label = PRF_LABEL_SERVER_FINISHED;
  }
  else
  {
    label = PRF_LABEL_CLIENT_FINISHED;
  }

  FLEA_CCALL(
    THR_flea_tls__create_finished_data(
      messages_hash__bu8,
      hash_len__u8,
      tls_ctx->security_parameters.master_secret,
      label,
      finished__pu8,
      finished_len__alu8,
      flea_tls__prf_mac_id_from_suite_id(tls_ctx->selected_cipher_suite__u16)
    )
  );
  hs_rd_stream__pt = flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt);
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_full(
      hs_rd_stream__pt,
      rec_finished__pu8,
      finished_len__alu8
    )
  );
  if(tls_ctx->sec_reneg_flag__u8)
  {
    if(tls_ctx->security_parameters.connection_end == FLEA_TLS_CLIENT && tls_ctx->sec_reneg_flag__u8)
    {
      memcpy(tls_ctx->peer_vfy_data__bu8, rec_finished__pu8, finished_len__alu8);
    }
    else
    {
      memcpy(tls_ctx->own_vfy_data__bu8, rec_finished__pu8, finished_len__alu8);
    }
  }
  if(flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt) != 0)
  {
    FLEA_THROW("trailing data in finished message", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }
  if(!flea_sec_mem_equal(rec_finished__pu8, finished__pu8, finished_len__alu8))
  {
    FLEA_THROW("Finished message not verifiable", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }


  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(messages_hash__bu8);
  );
} /* THR_flea_tls__read_finished */

flea_err_t THR_flea_tls__read_certificate(
  flea_tls_ctx_t*                    tls_ctx,
  flea_tls_handsh_reader_t*          hs_rdr__pt,
  flea_public_key_t*                 pubkey,
  flea_tls_cert_path_params_t const* cert_path_params__pct
)
{
  flea_u8_t dummy__au8_l3[3];

  FLEA_THR_BEG_FUNC();


  // we don't need the length
  // TODO: consider checking length consistency with handshake msg length
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_full(
      flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt),
      dummy__au8_l3,
      sizeof(dummy__au8_l3)
    )
  );
  FLEA_CCALL(
    THR_flea_tls__cert_path_validation(
      tls_ctx,
      hs_rdr__pt,
      tls_ctx->trust_store__pt,
      pubkey,
      cert_path_params__pct
    )
  );
  FLEA_THR_FIN_SEC_empty(
  );
} /* THR_flea_tls__read_certificate */

flea_err_t THR_flea_tls__send_certificate(
  flea_tls_ctx_t*               tls_ctx,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx,
  flea_ref_cu8_t*               cert_chain__pt,
  flea_u8_t                     cert_chain_len__u8
)
{
  flea_u32_t hdr_len__u32;
  flea_u32_t cert_list_len__u32;

  FLEA_THR_BEG_FUNC();

  // TODO: add option to exclude the root CA (RFC: MAY be ommited)
  // calculate length for the header
  hdr_len__u32 = 3; // 3 byte for length of certificate list
  for(flea_u8_t i = 0; i < cert_chain_len__u8; i++)
  {
    hdr_len__u32 += 3; // 3 byte for length encoding of each certificate
    hdr_len__u32 += cert_chain__pt[i].len__dtl;
  }

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_hdr(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      HANDSHAKE_TYPE_CERTIFICATE,
      hdr_len__u32
    )
  );

  cert_list_len__u32 = hdr_len__u32 - 3;
  FLEA_CCALL(THR_flea_tls__send_handshake_message_int_be(&tls_ctx->rec_prot__t, p_hash_ctx, cert_list_len__u32, 3));

  for(flea_u8_t i = 0; i < cert_chain_len__u8; i++)
  {
    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_int_be(
        &tls_ctx->rec_prot__t,
        p_hash_ctx,
        cert_chain__pt[i].len__dtl,
        3
      )
    );

    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_content(
        &tls_ctx->rec_prot__t,
        p_hash_ctx,
        cert_chain__pt[i].data__pcu8,
        cert_chain__pt[i].len__dtl
      )
    );
  }


  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_certificate */

flea_err_t THR_flea_tls__send_handshake_message_hdr(
  flea_tls_rec_prot_t*          rec_prot__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx_mbn__pt,
  HandshakeType                 type,
  flea_u32_t                    content_len__u32
)
{
  flea_u8_t enc_for_hash__au8[4];

  FLEA_THR_BEG_FUNC();

  enc_for_hash__au8[0] = type;

  enc_for_hash__au8[1] = content_len__u32 >> 16;
  enc_for_hash__au8[2] = content_len__u32 >> 8;
  enc_for_hash__au8[3] = content_len__u32;
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__write_data(
      rec_prot__pt,
      CONTENT_TYPE_HANDSHAKE,
      enc_for_hash__au8,
      sizeof(enc_for_hash__au8)
    )
  );
  if(p_hash_ctx_mbn__pt)
  {
    FLEA_CCALL(
      THR_flea_tls_parallel_hash_ctx_t__update(
        p_hash_ctx_mbn__pt,
        enc_for_hash__au8,
        sizeof(enc_for_hash__au8)
      )
    );
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_handshake_message_hdr */

flea_err_t THR_flea_tls__create_master_secret(
  const flea_u8_t*            client_and_server_hello_random,
  // const flea_u8_t * server_hello_random,

  /*Random                      client_hello_random,
   *  Random                      server_hello_random,*/
  // flea_u8_t* pre_master_secret,
  flea_byte_vec_t*            premaster_secret__pt,
  flea_u8_t*                  master_secret_res,
  flea_tls__cipher_suite_id_t ciph_id__e
)
{
  FLEA_DECL_BUF(random_seed__bu8, flea_u8_t, 64);
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(random_seed__bu8, 64);

  // TODO: REDUNDANT ARRAY
  memcpy(random_seed__bu8, client_and_server_hello_random, 64);

  // pre_master_secret is 48 bytes, master_secret is desired to be 48 bytes
  FLEA_CCALL(
    flea_tls__prf(
      // pre_master_secret,
      premaster_secret__pt->data__pu8,
      premaster_secret__pt->len__dtl,
      PRF_LABEL_MASTER_SECRET,
      random_seed__bu8,
      64,
      48,
      master_secret_res,
      flea_tls__prf_mac_id_from_suite_id(ciph_id__e)
    )
  );
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL_SECRET_ARR(random_seed__bu8, 64);
  );
} /* THR_flea_tls__create_master_secret */

/*flea_stream_read_mode_e flea_tls_ctx_t__get_read_mode(const flea_tls_ctx_t * tls_ctx__pt)
 * {
 * }*/

// TODO: configurable parameters
// TODO: ctor = handshake function
flea_err_t THR_flea_tls_ctx_t__construction_helper(
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_rw_stream_t*             rw_stream__pt,
  flea_tls_renegotiation_spec_e reneg_spec__e,
  flea_tls_flag_e               flags__e
)
{
  flea_al_u8_t sec_reneg_field_size__alu8 = 12;

  FLEA_THR_BEG_FUNC();
  flea_tls_ctx_t__set_sec_reneg_flags(tls_ctx__pt, reneg_spec__e);
  // tls_ctx__pt->security_parameters = calloc(1, sizeof(flea_tls__security_parameters_t));
  tls_ctx__pt->rw_stream__pt = rw_stream__pt;
  // tls_ctx__pt->client_has_sec_reneg__u8 = FLEA_FALSE;
  /* specify connection end */

  /* set TLS version */
  tls_ctx__pt->version.major = 0x03;
  tls_ctx__pt->version.minor = 0x03;
# ifdef FLEA_USE_HEAP_BUF

  /*if(tls_ctx__pt->security_parameters.connection_end == FLEA_TLS_SERVER)
   * {*/
  sec_reneg_field_size__alu8 = 24;
  // }
  FLEA_ALLOC_MEM(tls_ctx__pt->own_vfy_data__bu8, sec_reneg_field_size__alu8);
  /* not used in case of client: */
  tls_ctx__pt->peer_vfy_data__bu8 = tls_ctx__pt->own_vfy_data__bu8 + 12;
# endif
  tls_ctx__pt->sec_reneg_flag__u8 = FLEA_FALSE;
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__ctor(
      &tls_ctx__pt->rec_prot__t,
      tls_ctx__pt->version.major,
      tls_ctx__pt->version.minor,
      rw_stream__pt
    )
  );

  tls_ctx__pt->selected_cipher_suite__u16 = FLEA_TLS_NULL_WITH_NULL_NULL;


  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__construction_helper */

flea_err_t THR_flea_tls__send_handshake_message_content(
  flea_tls_rec_prot_t*          rec_prot__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx_mbn__pt,
  const flea_u8_t*              msg_bytes,
  flea_u32_t                    msg_bytes_len
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__write_data(
      rec_prot__pt,
      CONTENT_TYPE_HANDSHAKE,
      msg_bytes,
      msg_bytes_len
    )
  );
  if(p_hash_ctx_mbn__pt)
  {
    FLEA_CCALL(THR_flea_tls_parallel_hash_ctx_t__update(p_hash_ctx_mbn__pt, msg_bytes, msg_bytes_len));
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls__send_handshake_message_int_be(
  flea_tls_rec_prot_t*          rec_prot__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx_mbn__pt,
  flea_u32_t                    int__u32,
  flea_al_u8_t                  int_byte_width__alu8
)
{
  flea_u8_t enc__au8[4];

  FLEA_THR_BEG_FUNC();
  if(int_byte_width__alu8 > 4)
  {
    int_byte_width__alu8 = 4;
  }
  flea__encode_U32_BE(int__u32, enc__au8);
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      rec_prot__pt,
      p_hash_ctx_mbn__pt,
      enc__au8 + (4 - int_byte_width__alu8),
      int_byte_width__alu8
    )
  );

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls__send_handshake_message(
  flea_tls_rec_prot_t*          rec_prot__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx_mbn__pt,
  HandshakeType                 type,
  const flea_u8_t*              msg_bytes,
  flea_u32_t                    msg_bytes_len
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_hdr(
      rec_prot__pt,
      p_hash_ctx_mbn__pt,
      type,
      msg_bytes_len
    )
  );

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      rec_prot__pt,
      p_hash_ctx_mbn__pt,
      msg_bytes,
      msg_bytes_len
    )
  );
  FLEA_CCALL(THR_flea_tls_rec_prot_t__write_flush(rec_prot__pt));
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_handshake_message */

flea_err_t THR_flea_tls__send_change_cipher_spec(
  flea_tls_ctx_t* tls_ctx
)
{
  FLEA_THR_BEG_FUNC();

  flea_u8_t css_bytes[1] = {1};

  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__send_record(
      &tls_ctx->rec_prot__t,
      css_bytes,
      sizeof(css_bytes),
      CONTENT_TYPE_CHANGE_CIPHER_SPEC
    )
  );

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls__send_finished(
  flea_tls_ctx_t*               tls_ctx,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx

)
{
  FLEA_DECL_BUF(verify_data__bu8, flea_u8_t, FLEA_TLS_VERIFY_DATA_SIZE + FLEA_MAX_HASH_OUT_LEN);
  flea_u8_t* messages_hash__pu8;
  PRFLabel label;
  flea_hash_id_t hash_id__t;
  flea_u8_t hash_len__u8;
  FLEA_THR_BEG_FUNC();

  // compute hash over handshake messages so far
  hash_id__t   = flea_tls_get_prf_hash_by_cipher_suite_id(tls_ctx->selected_cipher_suite__u16);
  hash_len__u8 = flea_hash__get_output_length_by_id(hash_id__t);

  FLEA_ALLOC_BUF(verify_data__bu8, FLEA_TLS_VERIFY_DATA_SIZE + hash_len__u8);
  messages_hash__pu8 = verify_data__bu8 + FLEA_TLS_VERIFY_DATA_SIZE;

  FLEA_CCALL(THR_flea_tls_parallel_hash_ctx_t__final(p_hash_ctx, hash_id__t, FLEA_TRUE, messages_hash__pu8));

  // TODO: REMOVE LABEL ENUM, USE REF TO LABELS DIRECTLY
  if(tls_ctx->security_parameters.connection_end == FLEA_TLS_CLIENT)
  {
    label = PRF_LABEL_CLIENT_FINISHED;
  }
  else
  {
    label = PRF_LABEL_SERVER_FINISHED;
  }

  FLEA_CCALL(
    THR_flea_tls__create_finished_data(
      messages_hash__pu8,
      hash_len__u8,
      tls_ctx->security_parameters.master_secret,
      label,
      verify_data__bu8,
      FLEA_TLS_VERIFY_DATA_SIZE,
      flea_tls__prf_mac_id_from_suite_id(tls_ctx->selected_cipher_suite__u16)
    )
  );

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message(
      &tls_ctx->rec_prot__t,
      p_hash_ctx,
      HANDSHAKE_TYPE_FINISHED,
      verify_data__bu8,
      FLEA_TLS_VERIFY_DATA_SIZE
    )
  );

  if(tls_ctx->sec_reneg_flag__u8)
  {
    if(tls_ctx->security_parameters.connection_end == FLEA_TLS_CLIENT)
    {
      memcpy(tls_ctx->own_vfy_data__bu8, verify_data__bu8, FLEA_TLS_SEC_RENEG_FINISHED_SIZE);
    }
    else
    {
      memcpy(tls_ctx->peer_vfy_data__bu8, verify_data__bu8, FLEA_TLS_SEC_RENEG_FINISHED_SIZE);
    }
  }

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL_SECRET_ARR(verify_data__bu8, FLEA_TLS_VERIFY_DATA_SIZE);
  );
} /* THR_flea_tls__send_finished */

void flea_tls__handshake_state_ctor(flea_tls__handshake_state_t* state)
{
  state->expected_messages = 0;
  state->finished         = FLEA_FALSE;
  state->initialized      = FLEA_FALSE;
  state->send_client_cert = FLEA_FALSE;
  state->sent_first_round = FLEA_FALSE;
}

flea_err_t THR_flea_tls_ctx_t__flush_write_app_data(flea_tls_ctx_t* tls_ctx)
{
  return THR_flea_tls_rec_prot_t__write_flush(&tls_ctx->rec_prot__t);
}

static flea_err_t THR_flea_tls_ctx_t__send_app_data_inner(
  flea_tls_ctx_t*  tls_ctx,
  const flea_u8_t* data,
  flea_u8_t        data_len
)
{
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(
    THR_flea_tls_rec_prot_t__send_record(
      &tls_ctx->rec_prot__t,
      data,
      data_len,
      CONTENT_TYPE_APPLICATION_DATA
    )
  );

  FLEA_CCALL(THR_flea_tls_rec_prot_t__write_flush(&tls_ctx->rec_prot__t));

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls_ctx_t__send_app_data(
  flea_tls_ctx_t*  tls_ctx__pt,
  const flea_u8_t* data,
  flea_u8_t        data_len
)
{
  flea_err_t err__t;

  FLEA_THR_BEG_FUNC();
  err__t = THR_flea_tls_ctx_t__send_app_data_inner(tls_ctx__pt, data, data_len);

  FLEA_CCALL(THR_flea_tls__handle_tls_error(tls_ctx__pt, err__t, FLEA_FALSE, FLEA_FALSE));
  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_flea_tls_ctx_t__read_app_data_inner(
  flea_tls_ctx_t*         tls_ctx__pt,
  flea_u8_t*              data__pu8,
  flea_al_u16_t*          data_len__palu16,
  flea_stream_read_mode_e rd_mode__e
)
{
  flea_err_t err__t;

  FLEA_THR_BEG_FUNC();

  do
  {
    err__t = THR_flea_tls_rec_prot_t__read_data(
      &tls_ctx__pt->rec_prot__t,
      CONTENT_TYPE_APPLICATION_DATA,
      data__pu8,
      data_len__palu16,
      rd_mode__e
      );
    if(err__t == FLEA_EXC_TLS_HS_MSG_DURING_APP_DATA)
    {
      /* assume it's the appropriate ClientHello or HelloRequest in order to
       * initiate a new handshake. a wrong handshake message type will result in
       * an error during the invoked handshake processing. the new record which caused the exception is still
       * held as current record in rec_prot.
       */

      if(tls_ctx__pt->security_parameters.connection_end == FLEA_TLS_SERVER)
      {
        if(tls_ctx__pt->allow_reneg__u8)
        {
          FLEA_CCALL(THR_flea_tls__server_handshake(tls_ctx__pt));// , FLEA_TRUE));
        }
        else
        {
          flea_tls_rec_prot_t__discard_current_read_record(&tls_ctx__pt->rec_prot__t);
          FLEA_CCALL(
            THR_flea_tls_rec_prot_t__send_alert(
              &tls_ctx__pt->rec_prot__t,
              FLEA_TLS_ALERT_DESC_NO_RENEGOTIATION,
              FLEA_TLS_ALERT_LEVEL_WARNING
            )
          );
        }
      }
      else // client
      {
        if(tls_ctx__pt->allow_reneg__u8)
        {
          FLEA_CCALL(THR_flea_tls_ctx_t__client_handle_server_initiated_reneg(tls_ctx__pt));
        }
        else
        {
          flea_tls_rec_prot_t__discard_current_read_record(&tls_ctx__pt->rec_prot__t);
          FLEA_CCALL(
            THR_flea_tls_rec_prot_t__send_alert(
              &tls_ctx__pt->rec_prot__t,
              FLEA_TLS_ALERT_DESC_NO_RENEGOTIATION,
              FLEA_TLS_ALERT_LEVEL_WARNING
            )
          );
        }
      }
    }
    else if(err__t)
    {
      FLEA_THROW("rethrowing during read app data", err__t);
    }
  } while(err__t);

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__read_app_data_inner */

flea_err_t THR_flea_tls_ctx_t__read_app_data(
  flea_tls_ctx_t*         tls_ctx__pt,
  flea_u8_t*              data__pu8,
  flea_al_u16_t*          data_len__palu16,
  flea_stream_read_mode_e rd_mode__e
)
{
  flea_err_t err__t;

  FLEA_THR_BEG_FUNC();
  err__t = THR_flea_tls_ctx_t__read_app_data_inner(tls_ctx__pt, data__pu8, data_len__palu16, rd_mode__e);

  FLEA_CCALL(THR_flea_tls__handle_tls_error(tls_ctx__pt, err__t, FLEA_FALSE, FLEA_TRUE));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls_ctx_t__renegotiate(
  flea_tls_ctx_t*          tls_ctx__pt,
  const flea_cert_store_t* trust_store__pt,
  /* new session id? */
  flea_ref_cu8_t*          cert_chain__pt,
  flea_al_u8_t             cert_chain_len__alu8,
  const flea_ref_cu16_t*   allowed_cipher_suites__prcu16,
  flea_rev_chk_mode_e      rev_chk_mode__e,
  const flea_byte_vec_t*   crl_der__pt,
  flea_al_u16_t            nb_crls__alu16
)
{
  flea_err_t err__t;

  FLEA_THR_BEG_FUNC();

  if(!tls_ctx__pt->allow_reneg__u8)
  {
    FLEA_THROW("renegotiation not allowed in this tls connection", FLEA_ERR_TLS_RENEG_NOT_ALLOWED);
  }
  tls_ctx__pt->trust_store__pt = trust_store__pt; // TODO: doesn't seem to have to be part of the ctx
  tls_ctx__pt->rev_chk_cfg__t.rev_chk_mode__e = rev_chk_mode__e;
  tls_ctx__pt->rev_chk_cfg__t.nb_crls__u16    = nb_crls__alu16;
  tls_ctx__pt->rev_chk_cfg__t.crl_der__pt     = crl_der__pt;
  tls_ctx__pt->cert_chain__pt     = cert_chain__pt;
  tls_ctx__pt->cert_chain_len__u8 = cert_chain_len__alu8;
  tls_ctx__pt->allowed_cipher_suites__prcu16 = allowed_cipher_suites__prcu16;
  flea_tls_set_tls_random(tls_ctx__pt);

  flea_public_key_t__dtor(&tls_ctx__pt->peer_pubkey); // TODO: does this really need to be part of the ctx?
  // tls_ctx__pt->resumption = FLEA_FALSE;
  // TODO: discard pending read (/ flush pending write (done automatically))
  if(tls_ctx__pt->security_parameters.connection_end == FLEA_TLS_CLIENT)
  {
    err__t = THR_flea_tls__client_handshake(tls_ctx__pt, tls_ctx__pt->client_session_mbn__pt);
  }
  else
  {
    FLEA_CCALL(
      THR_flea_tls__send_handshake_message(
        &tls_ctx__pt->rec_prot__t,
        NULL,
        HANDSHAKE_TYPE_HELLO_REQUEST,
        NULL,
        0
      )
    );
    err__t = THR_flea_tls__server_handshake(tls_ctx__pt);// , FLEA_TRUE);
  }
  FLEA_CCALL(THR_flea_tls__handle_tls_error(tls_ctx__pt, err__t, FLEA_TRUE, FLEA_FALSE));

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__renegotiate */

void flea_tls_set_tls_random(flea_tls_ctx_t* ctx__pt)
{
# if 0
  flea_rng__randomize(ctx__pt->security_parameters.client_random.gmt_unix_time, 4); // TODO: check RFC for correct implementation - actual time?
  flea_rng__randomize(ctx__pt->security_parameters.client_random.random_bytes, 28);

  /* set server random */
  flea_rng__randomize(ctx__pt->security_parameters.server_random.gmt_unix_time, 4);
  flea_rng__randomize(ctx__pt->security_parameters.server_random.random_bytes, 28);
# endif
  flea_rng__randomize(ctx__pt->security_parameters.client_and_server_random, 2 * FLEA_TLS_HELLO_RANDOM_SIZE);
}

flea_bool_t flea_tls_ctx_t__do_send_sec_reneg_ext(flea_tls_ctx_t* tls_ctx__pt)
{
  if(tls_ctx__pt->security_parameters.connection_end == FLEA_TLS_SERVER)
  {
    if(tls_ctx__pt->sec_reneg_flag__u8 == FLEA_TRUE)
    {
      return FLEA_TRUE;
    }
    return FLEA_FALSE;
  }
  // TODO: NOT NEEDED, SHOULD NOT BE CALLED BY CLIENT AT ALL:
  else
  {
    return FLEA_TRUE;
  }
}

/*static flea_bool_t flea_tls_ctx_t__is_ecc_suite(flea_tls_ctx_t* tls_ctx__pt)
 * {
 * return FLEA_TRUE;
 * }*/

flea_al_u16_t flea_tls_ctx_t__compute_extensions_length(flea_tls_ctx_t* tls_ctx__pt)
{
  flea_al_u16_t len__alu16 = 0;

  if(flea_tls_ctx_t__do_send_sec_reneg_ext(tls_ctx__pt))
  {
    flea_al_u8_t reneg_conn_len__alu8 = 0;
    len__alu16 += 5; /* type:2 + data-len:2 + info-len:1 */
    if(tls_ctx__pt->security_parameters.connection_end == FLEA_TLS_CLIENT)
    {
      if(tls_ctx__pt->sec_reneg_flag__u8)
      {
        reneg_conn_len__alu8 += 12;
      }
    }
    else /* server */
    {
      if(tls_ctx__pt->sec_reneg_flag__u8 && flea_tls_rec_prot_t__have_done_initial_handshake(&tls_ctx__pt->rec_prot__t))
      {
        reneg_conn_len__alu8 += 24;
      }
    }
    len__alu16 += reneg_conn_len__alu8;
  }

  // signature algorithms extension
  if(tls_ctx__pt->security_parameters.connection_end == FLEA_TLS_CLIENT)
  {
    len__alu16 += 6 + tls_ctx__pt->allowed_sig_algs__rcu8.len__dtl;
  }

# ifdef FLEA_HAVE_ECC

  if(tls_ctx__pt->security_parameters.connection_end == FLEA_TLS_CLIENT)
  {
    if(tls_ctx__pt->extension_ctrl__u8 & FLEA_TLS_EXT_CTRL_MASK__SUPPORTED_CURVES)
    {
      len__alu16 += 6; /* supported curves extension */
      len__alu16 += tls_ctx__pt->allowed_ecc_curves__rcu8.len__dtl * 2;
    }
    if(tls_ctx__pt->extension_ctrl__u8 & FLEA_TLS_EXT_CTRL_MASK__POINT_FORMATS)
    {
      len__alu16 += 6; /*  point formats extension */
    }
  }
  /* server: */
  else if(flea_tls__is_cipher_suite_ecc_suite(tls_ctx__pt->selected_cipher_suite__u16))
  {
    if(tls_ctx__pt->extension_ctrl__u8 & FLEA_TLS_EXT_CTRL_MASK__POINT_FORMATS)
    {
      len__alu16 += 6; /*  point formats extension */
    }
  }
# endif /* ifdef FLEA_HAVE_ECC */
  return len__alu16;
} /* flea_tls_ctx_t__compute_extensions_length */

flea_err_t THR_flea_tls_ctx_t__send_extensions_length(
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx_mbn__pt
)
{
  flea_u8_t enc_len__au8[2] = {0, 0};
  flea_al_u16_t len__alu16  = 0;

  FLEA_THR_BEG_FUNC();
  len__alu16 = flea_tls_ctx_t__compute_extensions_length(tls_ctx__pt);

  if(len__alu16)
  {
    flea__encode_U16_BE(len__alu16, enc_len__au8);
    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_content(
        &tls_ctx__pt->rec_prot__t,
        p_hash_ctx_mbn__pt,
        enc_len__au8,
        sizeof(enc_len__au8)
      )
    );
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls_ctx_t__send_reneg_ext(
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt
)
{
  const flea_u8_t reneg_ext_type__cau8[] = {0xff, 0x01};
  flea_u8_t len__u8 = 0;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx__pt->rec_prot__t,
      p_hash_ctx__pt,
      reneg_ext_type__cau8,
      sizeof(reneg_ext_type__cau8)
    )
  );
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx__pt->rec_prot__t, p_hash_ctx__pt, &len__u8, 1));
  if(tls_ctx__pt->sec_reneg_flag__u8)
  {
    if(tls_ctx__pt->security_parameters.connection_end == FLEA_TLS_CLIENT)
    {
      len__u8 = 12;
    }
    else if(flea_tls_rec_prot_t__have_done_initial_handshake(&tls_ctx__pt->rec_prot__t))
    {
      len__u8 = 24;
    }
  }
  else // TODO: ELSE BLOCK NOT NEEDED
  {
    len__u8 = 0;
  }
  len__u8 += 1;
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx__pt->rec_prot__t, p_hash_ctx__pt, &len__u8, 1));
  len__u8 -= 1;
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx__pt->rec_prot__t, p_hash_ctx__pt, &len__u8, 1));
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx__pt->rec_prot__t,
      p_hash_ctx__pt,
      tls_ctx__pt->own_vfy_data__bu8,
      len__u8
    )
  );

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__send_reneg_ext */

# ifdef FLEA_HAVE_ECC

/*
 * flea_bool_t flea_tls_ctx_t__do_send_ecc_point_formats_ext(
 * flea_tls_ctx_t*               tls_ctx__pt
 * )
 * {
 * if(tls_ctx__pt->security_parameters.connection_end == FLEA_TLS_CLIENT)
 * {
 * return FLEA_TRUE;
 * }
 * }
 * flea_bool_t flea_tls_ctx_t__do_send_ecc_supported_curves_ext(
 * flea_tls_ctx_t*               tls_ctx__pt
 * )
 * {
 *
 * }
 */
flea_err_t THR_flea_tls_ctx_t__send_ecc_point_format_ext(
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

flea_err_t THR_flea_tls_ctx_t__send_ecc_supported_curves_ext(
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
  flea__encode_U16_BE(tls_ctx__pt->allowed_ecc_curves__rcu8.len__dtl * 2 + 2, ext__au8);
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx__pt->rec_prot__t,
      p_hash_ctx__pt,
      ext__au8,
      sizeof(ext__au8)
    )
  );
  flea__encode_U16_BE(tls_ctx__pt->allowed_ecc_curves__rcu8.len__dtl * 2, ext__au8);
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx__pt->rec_prot__t,
      p_hash_ctx__pt,
      ext__au8,
      sizeof(ext__au8)
    )
  );

  /*if(tls_ctx__pt->security_parameters.connection_end == FLEA_TLS_CLIENT)
   * {*/
  flea_al_u16_t i;
  for(i = 0; i < tls_ctx__pt->allowed_ecc_curves__rcu8.len__dtl; i++)
  {
    // flea_u8_t curve_bytes__au8[2];
    FLEA_CCALL(
      THR_flea_tls__map_flea_curve_to_curve_bytes(
        (flea_ec_dom_par_id_t) tls_ctx__pt->
        allowed_ecc_curves__rcu8.data__pcu8[i],
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

  /*}
   * else
   * {
   * flea_u8_t curve_bytes__au8[2];
   * FLEA_CCALL(
   *  THR_flea_tls__map_flea_curve_to_curve_bytes(
   *    (flea_ec_dom_par_id_t) tls_ctx__pt->
   *    chosen_ecc_dp_internal_id__u8,
   *    curve_bytes__au8
   *  )
   * );
   * FLEA_CCALL(
   *  THR_flea_tls__send_handshake_message_content(
   *    &tls_ctx__pt->rec_prot__t,
   *    p_hash_ctx__pt,
   *    curve_bytes__au8,
   *    sizeof(curve_bytes__au8)
   *  )
   * );
   * }*/
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__send_ecc_supported_curves_ext */

# endif /* ifdef FLEA_HAVE_ECC */

/*flea_err_t THR_flea_tls_ctx_t__send_extensions(
 * flea_tls_ctx_t*               tls_ctx__pt,
 * flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt
 * )
 * {
 * FLEA_THR_BEG_FUNC();
 * FLEA_THR_FIN_SEC_empty();
 * }
 */
static flea_err_t THR_flea_tls_ctx__parse_reneg_ext(
  flea_tls_ctx_t*   tls_ctx__pt,
  flea_rw_stream_t* rd_strm__pt,
  flea_al_u16_t     ext_len__alu16
)
{
  flea_u8_t len__u8;

  FLEA_DECL_BUF(cmp__bu8, flea_u8_t, 2 * FLEA_TLS_SEC_RENEG_FINISHED_SIZE);
  flea_al_u8_t exp_len__alu8 = FLEA_TLS_SEC_RENEG_FINISHED_SIZE;
  FLEA_THR_BEG_FUNC();
  if(!tls_ctx__pt->sec_reneg_flag__u8)
  {
    exp_len__alu8 = 0;
  }
  if(tls_ctx__pt->security_parameters.connection_end == FLEA_TLS_CLIENT)
  {
    exp_len__alu8 *= 2;
  }
  FLEA_ALLOC_BUF(cmp__bu8, exp_len__alu8);
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_byte(
      rd_strm__pt,
      &len__u8
    )
  );
  if(len__u8 + 1 != ext_len__alu16)
  {
    FLEA_THROW("inconsistent length for reneg info", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }
  if(len__u8 != exp_len__alu8)
  {
    FLEA_THROW("invalid renegotiation info size", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_full(
      rd_strm__pt,
      cmp__bu8,
      exp_len__alu8
    )
  );

  /*if( tls_ctx__pt->sec_reneg_flag__u8)
   * {*/
  if(!flea_sec_mem_equal(tls_ctx__pt->own_vfy_data__bu8, cmp__bu8, exp_len__alu8))
  {
    FLEA_THROW("invalid renegotiation info content", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }

  /*}
   * else
   * {
   * if(len__u8)
   * {
   *  FLEA_THROW("non-empty renegotiation info provided during first handshake", FLEA_ERR_TLS_INV_RENEG_INFO);
   * }
   *
   * }*/

  if(flea_tls_rec_prot_t__have_done_initial_handshake(&tls_ctx__pt->rec_prot__t) && !len__u8)
  {
    FLEA_THROW("empty renegotiation info provided during handshake after the first", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(cmp__bu8);
  );
} /* THR_flea_tls_ctx__parse_reneg_ext */

flea_u8_t flea_tls_map_tls_hash_to_flea_hash__t[6][2] = {
  {0x01, flea_md5   },
  {0x02, flea_sha1  },
  {0x03, flea_sha224},
  {0x04, flea_sha256},
  {0x05, flea_sha384},
  {0x06, flea_sha512}
};

flea_u8_t flea_tls_map_tls_sig_to_flea_sig__t[2][2] = {
  {0x01, flea_rsa_pkcs1_v1_5_sign},
  {0x03, flea_ecdsa_emsa1        }
};


flea_err_t THR_flea_tls__map_tls_sig_to_flea_sig(
  flea_u8_t            id__u8,
  flea_pk_scheme_id_t* pk_scheme_id__pt
)
{
  FLEA_THR_BEG_FUNC();

  for(flea_u8_t i = 0; i < sizeof(flea_tls_map_tls_sig_to_flea_sig__t); i++)
  {
    if(flea_tls_map_tls_sig_to_flea_sig__t[i][0] == id__u8)
    {
      *pk_scheme_id__pt = (flea_pk_scheme_id_t) flea_tls_map_tls_sig_to_flea_sig__t[i][1];
      FLEA_THR_RETURN();
    }
  }
  FLEA_THROW("unsupported signature algorithm", FLEA_ERR_TLS_HANDSHK_FAILURE);
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls__map_flea_sig_to_tls_sig(
  flea_pk_scheme_id_t pk_scheme_id__t,
  flea_u8_t*          id__pu8
)
{
  FLEA_THR_BEG_FUNC();
  for(flea_u8_t i = 0; i < sizeof(flea_tls_map_tls_sig_to_flea_sig__t); i++)
  {
    if(flea_tls_map_tls_sig_to_flea_sig__t[i][1] == pk_scheme_id__t)
    {
      *id__pu8 = flea_tls_map_tls_sig_to_flea_sig__t[i][0];
      FLEA_THR_RETURN();
    }
  }
  FLEA_THROW("signature algorithm has no mapping for tls", FLEA_ERR_INT_ERR);
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls__map_tls_hash_to_flea_hash(
  flea_u8_t       id__u8,
  flea_hash_id_t* hash_id__pt
)
{
  FLEA_THR_BEG_FUNC();
  for(flea_u8_t i = 0; i < sizeof(flea_tls_map_tls_hash_to_flea_hash__t); i++)
  {
    if(flea_tls_map_tls_hash_to_flea_hash__t[i][0] == id__u8)
    {
      *hash_id__pt = (flea_hash_id_t) flea_tls_map_tls_hash_to_flea_hash__t[i][1];
      FLEA_THR_RETURN();
    }
  }
  FLEA_THROW("unsupported hash algorithm", FLEA_ERR_TLS_HANDSHK_FAILURE);
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls__map_flea_hash_to_tls_hash(
  flea_hash_id_t hash_id__t,
  flea_u8_t*     id__pu8
)
{
  FLEA_THR_BEG_FUNC();
  for(flea_u8_t i = 0; i < sizeof(flea_tls_map_tls_hash_to_flea_hash__t); i++)
  {
    if(flea_tls_map_tls_hash_to_flea_hash__t[i][1] == hash_id__t)
    {
      *id__pu8 = flea_tls_map_tls_hash_to_flea_hash__t[i][0];
      FLEA_THR_RETURN();
    }
  }
  FLEA_THROW("hash algorithm has no mapping for tls", FLEA_ERR_INT_ERR);
  FLEA_THR_FIN_SEC_empty();
}

flea_pk_scheme_id_t flea_tls__get_sig_alg_from_key_type(
  flea_pk_key_type_t key_type__t
)
{
  if(key_type__t == flea_ecc_key)
  {
    return flea_ecdsa_emsa1;
  }
  else
  {
    return flea_rsa_pkcs1_v1_5_sign;
  }
}

flea_u8_t flea_tls__get_tls_cert_type_from_flea_key_type(flea_pk_key_type_t key_type__t)
{
  if(key_type__t == flea_rsa_key)
  {
    return 1;
  }
  return 2; // dss_sign / dsa
}

// TODO: intention is to check whether an offered sig/hash algorithm pair
// matches the certificate. Better to not only check the key but the entire
// certificate which might contain additional constraints
flea_err_t THR_flea_tls__check_sig_alg_compatibility_for_key_type(
  flea_pk_key_type_t  key_type__t,
  flea_pk_scheme_id_t pk_scheme_id__t
)
{
  FLEA_THR_BEG_FUNC();
  if((key_type__t == flea_ecc_key && pk_scheme_id__t != flea_ecdsa_emsa1) ||
    (key_type__t == flea_rsa_key && pk_scheme_id__t != flea_rsa_pkcs1_v1_5_sign))
  {
    FLEA_THROW("key type and signature algorithm do not match", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls_ctx_t__send_sig_alg_ext(
  flea_tls_ctx_t*               tls_ctx__pt,
  flea_tls_parallel_hash_ctx_t* p_hash_ctx__pt
)
{
  flea_u8_t ext__au8[] = {
    0x00, 0x0d
  };
  flea_u8_t curr_sig_alg_enc__au8[2];

  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx__pt->rec_prot__t,
      p_hash_ctx__pt,
      ext__au8,
      sizeof(ext__au8)
    )
  );

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_int_be(
      &tls_ctx__pt->rec_prot__t,
      p_hash_ctx__pt,
      tls_ctx__pt->allowed_sig_algs__rcu8.len__dtl + 2,
      2
    )
  );

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_int_be(
      &tls_ctx__pt->rec_prot__t,
      p_hash_ctx__pt,
      tls_ctx__pt->allowed_sig_algs__rcu8.len__dtl,
      2
    )
  );

  // send supported sig algs
  for(int i = 0; i < tls_ctx__pt->allowed_sig_algs__rcu8.len__dtl; i += 2)
  {
    FLEA_CCALL(
      THR_flea_tls__map_flea_hash_to_tls_hash(
        (flea_hash_id_t) tls_ctx__pt->allowed_sig_algs__rcu8.data__pcu8[i],
        &curr_sig_alg_enc__au8[0]
      )
    );
    FLEA_CCALL(
      THR_flea_tls__map_flea_sig_to_tls_sig(
        (flea_pk_scheme_id_t) tls_ctx__pt->allowed_sig_algs__rcu8.
        data__pcu8[i + 1],
        &curr_sig_alg_enc__au8[1]
      )
    );
    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_content(
        &tls_ctx__pt->rec_prot__t,
        p_hash_ctx__pt,
        curr_sig_alg_enc__au8,
        sizeof(curr_sig_alg_enc__au8)
      )
    );
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__send_sig_alg_ext */

flea_err_t THR_flea_tls_ctx_t__parse_sig_alg_ext(
  flea_tls_ctx_t*   tls_ctx__pt,
  flea_rw_stream_t* rd_strm__pt,
  flea_al_u16_t     ext_len__alu16
)
{
  flea_al_u16_t len__alu16;
  flea_al_u16_t hash_alg_pos__alu16;

  FLEA_THR_BEG_FUNC();
  if(!ext_len__alu16)
  {
    FLEA_THROW("No Signature and Hash algorithms offered by client", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }

  FLEA_CCALL(THR_flea_rw_stream_t__read_int_be(rd_strm__pt, &len__alu16, 2));
  if((len__alu16 % 2) || (len__alu16 > ext_len__alu16 - 2))
  {
    FLEA_THROW("invalid signature algorithms extension", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }

  // iterate over all algorithm pairs and pick the best matching
  // we can only pick the signature algorithm matching to our certificate
  hash_alg_pos__alu16 = 0xFFFF;
  while(len__alu16)
  {
    len__alu16 -= 2;
    flea_u8_t sig_alg_bytes__au8[2];
    flea_hash_id_t hash_id__t;
    flea_pk_scheme_id_t pk_scheme_id__t;
    flea_al_u16_t i;

    FLEA_CCALL(THR_flea_rw_stream_t__read_full(rd_strm__pt, sig_alg_bytes__au8, sizeof(sig_alg_bytes__au8)));

    // map sig and hash alg and also check that the sig alg matches our key
    if(THR_flea_tls__map_tls_hash_to_flea_hash(
        sig_alg_bytes__au8[0],
        &hash_id__t
      ) || THR_flea_tls__map_tls_sig_to_flea_sig(sig_alg_bytes__au8[1], &pk_scheme_id__t))
    {
      continue;
    }
    if(THR_flea_tls__check_sig_alg_compatibility_for_key_type(tls_ctx__pt->private_key__t.key_type__t, pk_scheme_id__t))
    {
      continue;
    }

    // if the sig/hash pair is suitable, use it if it's highest priority
    for(i = 0; i < tls_ctx__pt->allowed_sig_algs__rcu8.len__dtl; i += 2)
    {
      if(hash_id__t == (flea_hash_id_t) tls_ctx__pt->allowed_sig_algs__rcu8.data__pcu8[i])
      {
        if(i / 2 < hash_alg_pos__alu16)
        {
          /* update if it has higher priority */
          hash_alg_pos__alu16 = i / 2;
          tls_ctx__pt->chosen_hash_algorithm__t = hash_id__t;
        }
        break;
      }
    }
  }

  if(hash_alg_pos__alu16 != 0xFFFF)
  {
    tls_ctx__pt->can_use_ecdhe = FLEA_TRUE;
  }
  else
  {
    tls_ctx__pt->can_use_ecdhe = FLEA_FALSE;
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__parse_sig_alg_ext */

# ifdef FLEA_HAVE_ECC
flea_err_t THR_flea_tls_ctx_t__parse_supported_curves_ext(
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
    flea_ec_dom_par_id_t dp_id;
    // flea_u32_t curve_id__u32;
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
    for(i = 0; i < tls_ctx__pt->allowed_ecc_curves__rcu8.len__dtl; i++)
    {
      if(tls_ctx__pt->allowed_ecc_curves__rcu8.data__pcu8[i] == dp_id)
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

flea_err_t THR_flea_tls_ctx_t__parse_point_formats_ext(
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

flea_bool_t flea_tls__is_cipher_suite_ecdhe_suite(flea_u16_t suite_id)
{
  if(flea_tls_get_cipher_suite_by_id(suite_id)->mask & FLEA_TLS_CS_KEX_MASK__ECDHE)
  {
    return FLEA_TRUE;
  }
  return FLEA_FALSE;
}

flea_bool_t flea_tls__is_cipher_suite_ecc_suite(flea_u16_t suite_id)
{
  // TODO: MAKE GENERAL IMPLEMENTATION
  // if(suite_id == FLEA_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
  if((suite_id >> 8) == 0xC0)
  {
    return FLEA_TRUE;
  }
  return FLEA_FALSE;
}

# endif /* ifdef FLEA_HAVE_ECC */

/*static void flea_tls_ctx_t__reset_extension_state(flea_tls_ctx_t* tls_ctx__pt)
 * {
 * tls_ctx__pt->sec_reneg_flag__u8 = FLEA_FALSE;
 * }*/
flea_err_t THR_flea_tls_ctx_t__parse_hello_extensions(
  flea_tls_ctx_t*           tls_ctx__pt,
  flea_tls_handsh_reader_t* hs_rdr__pt,
  flea_bool_t*              found_sec_reneg__pb
) // flea_rw_stream_t* hs_read_strm__pt)
{
  flea_u32_t extensions_len__u32;
  flea_rw_stream_t* hs_rd_stream__pt;
  flea_bool_t receive_sig_algs_ext__b = FLEA_FALSE;
  flea_bool_t support_sha1__b         = FLEA_FALSE;
  flea_al_u8_t i;

  FLEA_THR_BEG_FUNC();

  /**
   * pre-selection which takes effect in case the peer doesn't send the
   * supported curves extension.
   */
  if(tls_ctx__pt->allowed_ecc_curves__rcu8.len__dtl)
  {
    tls_ctx__pt->chosen_ecc_dp_internal_id__u8 = tls_ctx__pt->allowed_ecc_curves__rcu8.data__pcu8[0];
  }
  else
  {
    tls_ctx__pt->extension_ctrl__u8 |= FLEA_TLS_EXT_CTRL_MASK__UNMATCHING;
  }

  if(flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt) == 0)
  {
    FLEA_THR_RETURN();
  }

  hs_rd_stream__pt = flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt);

  FLEA_CCALL(
    THR_flea_rw_stream_t__read_int_be(
      hs_rd_stream__pt,
      &extensions_len__u32,
      2
    )
  );
  while(extensions_len__u32)
  {
    flea_u32_t ext_type_be__u32;
    flea_u32_t ext_len__u32;
    FLEA_CCALL(
      THR_flea_rw_stream_t__read_int_be(
        hs_rd_stream__pt,
        &ext_type_be__u32,
        2
      )
    );
    FLEA_CCALL(
      THR_flea_rw_stream_t__read_int_be(
        hs_rd_stream__pt,
        &ext_len__u32,
        2
      )
    );
    extensions_len__u32 -= (((flea_u32_t) 4) + ext_len__u32);

    if(ext_type_be__u32 == FLEA_TLS_EXT_TYPE__RENEG_INFO)
    {
      FLEA_CCALL(THR_flea_tls_ctx__parse_reneg_ext(tls_ctx__pt, hs_rd_stream__pt, ext_len__u32));
      *found_sec_reneg__pb = FLEA_TRUE;
    }
    // skip over ext. if received from server (not allowed)
    else if(ext_type_be__u32 == FLEA_TLS_EXT_TYPE__SIGNATURE_ALGORITHMS &&
      tls_ctx__pt->security_parameters.connection_end == FLEA_TLS_SERVER)
    {
      FLEA_CCALL(THR_flea_tls_ctx_t__parse_sig_alg_ext(tls_ctx__pt, hs_rd_stream__pt, ext_len__u32));
      receive_sig_algs_ext__b = FLEA_TRUE;
    }
    else if(ext_type_be__u32 == FLEA_TLS_EXT_TYPE__POINT_FORMATS)
    {
      FLEA_CCALL(THR_flea_tls_ctx_t__parse_point_formats_ext(tls_ctx__pt, hs_rd_stream__pt, ext_len__u32));
      tls_ctx__pt->extension_ctrl__u8 |= FLEA_TLS_EXT_CTRL_MASK__POINT_FORMATS;
    }
    else if(ext_type_be__u32 == FLEA_TLS_EXT_TYPE__SUPPORTED_CURVES &&
      tls_ctx__pt->security_parameters.connection_end == FLEA_TLS_SERVER)
    {
      FLEA_CCALL(THR_flea_tls_ctx_t__parse_supported_curves_ext(tls_ctx__pt, hs_rd_stream__pt, ext_len__u32));
      tls_ctx__pt->extension_ctrl__u8 |= FLEA_TLS_EXT_CTRL_MASK__SUPPORTED_CURVES;
    }
    else
    {
      FLEA_CCALL(
        THR_flea_rw_stream_t__skip_read(
          hs_rd_stream__pt,
          ext_len__u32
        )
      );
    }
  }

  // no signature_algorithms ext. received from client
  if(receive_sig_algs_ext__b == FLEA_FALSE && tls_ctx__pt->security_parameters.connection_end == FLEA_TLS_SERVER)
  {
    // we need to set the default signature and hash algorithm because the
    // client does not support any other. This means sha1 + signature scheme
    // of the currently loaded certificate
    for(i = 0; i < tls_ctx__pt->allowed_sig_algs__rcu8.len__dtl; i += 2)
    {
      // only check for hash/sig pair which matches our key
      if(THR_flea_tls__check_sig_alg_compatibility_for_key_type(
          tls_ctx__pt->private_key__t.key_type__t,
          (flea_pk_scheme_id_t) tls_ctx__pt->allowed_sig_algs__rcu8.data__pcu8[i + 1]
        ))
      {
        continue;
      }
      if(tls_ctx__pt->allowed_sig_algs__rcu8.data__pcu8[i] == flea_sha1)
      {
        support_sha1__b = FLEA_TRUE;
        break;
      }
    }
    if(support_sha1__b == FLEA_FALSE)
    {
      tls_ctx__pt->can_use_ecdhe = FLEA_FALSE;
    }
    else
    {
      tls_ctx__pt->chosen_hash_algorithm__t = flea_sha1;
      tls_ctx__pt->can_use_ecdhe = FLEA_TRUE;
    }
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__client_parse_extensions */

# ifdef FLEA_HAVE_ECKA
flea_err_t THR_flea_tls__create_ecdhe_key(
  flea_private_key_t*  priv_key__pt,
  flea_public_key_t*   pub_key__pt,
  flea_ec_dom_par_id_t dom_par_id__t
)
{
  FLEA_DECL_BUF(pub_key__bu8, flea_u8_t, FLEA_PK_MAX_INTERNAL_FORMAT_PUBKEY_LEN);
  FLEA_DECL_BUF(priv_key__bu8, flea_u8_t, FLEA_ECC_MAX_ENCODED_POINT_LEN);
  flea_pub_key_param_u param__u;
  flea_al_u8_t priv_key_len__alu8;
  flea_byte_vec_t scalar_vec__t   = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE;
  flea_byte_vec_t pubpoint_vec__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE;
  flea_al_u8_t pub_key_len__alu8  = FLEA_ECC_MAX_ENCODED_POINT_LEN;


  FLEA_THR_BEG_FUNC();

  // set domain parameters
  FLEA_CCALL(THR_flea_ec_gfp_dom_par_ref_t__set_by_builtin_id(&param__u.ecc_dom_par__t, dom_par_id__t));

  priv_key_len__alu8 = FLEA_ECC_MAX_ORDER_BYTE_SIZE;
  FLEA_ALLOC_BUF(pub_key__bu8, pub_key_len__alu8);
  FLEA_ALLOC_BUF(priv_key__bu8, priv_key_len__alu8);
  FLEA_CCALL(
    THR_flea_generate_ecc_key(
      pub_key__bu8,
      &pub_key_len__alu8,
      priv_key__bu8,
      &priv_key_len__alu8,
      &param__u.ecc_dom_par__t
    )
  );

  flea_byte_vec_t__set_ref(&pubpoint_vec__t, pub_key__bu8, pub_key_len__alu8);
  flea_byte_vec_t__set_ref(&scalar_vec__t, priv_key__bu8, priv_key_len__alu8);

  // generate keys
  FLEA_CCALL(
    THR_flea_private_key_t__ctor_ecc(
      priv_key__pt,
      &scalar_vec__t,
      &param__u.ecc_dom_par__t
    )
  );
  FLEA_CCALL(
    THR_flea_public_key_t__ctor_ecc(
      pub_key__pt,
      &pubpoint_vec__t,
      &param__u.ecc_dom_par__t
    )
  );

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(pub_key__bu8);
    FLEA_FREE_BUF_FINAL(priv_key__bu8);
  );
} /* THR_flea_tls__create_ecdhe_key */

# endif /* ifdef FLEA_HAVE_ECKA */


# ifdef FLEA_HAVE_ECC

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

flea_err_t THR_flea_tls__map_flea_curve_to_curve_bytes(
  const flea_ec_dom_par_id_t ec_dom_par_id__e,
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

flea_err_t THR_flea_tls__map_curve_bytes_to_flea_curve(
  const flea_u8_t       bytes[2],
  flea_ec_dom_par_id_t* ec_dom_par_id__pe
)
{
  flea_al_u8_t i;

  FLEA_THR_BEG_FUNC();
  if(bytes[0] == 0)
  {
    for(i = 0; i < (flea_u8_t) flea_secp521r1; i++)
    {
      if(bytes[1] == curve_bytes_flea_id_map[i].curve_bytes__u8)
      {
        *ec_dom_par_id__pe = (flea_ec_dom_par_id_t) curve_bytes_flea_id_map[i].flea_dp_id__u8;
        FLEA_THR_RETURN();
      }
    }
  }

  FLEA_THROW("Unsupported curve", FLEA_ERR_TLS_HANDSHK_FAILURE);

  FLEA_THR_FIN_SEC_empty();
}

# endif /* ifdef FLEA_HAVE_ECKA */

# ifdef FLEA_HAVE_ECKA
flea_err_t THR_flea_tls__read_peer_ecdhe_key_and_compute_premaster_secret(
  flea_tls_ctx_t*     tls_ctx__pt,
  flea_rw_stream_t*   hs_rd_stream__pt,
  flea_byte_vec_t*    premaster_secret__pt,
  flea_private_key_t* priv_key__pt,
  flea_public_key_t*  peer_pubkey__pt
)
{
  flea_u8_t peer_enc_pubpoint_len__u8;

  FLEA_DECL_BUF(peer_enc_pubpoint__bu8, flea_u8_t, FLEA_ECC_MAX_ENCODED_POINT_LEN);
  flea_byte_vec_t peer_enc_pubpoint_vec__t = flea_byte_vec_t__CONSTR_ZERO_CAPACITY_NOT_ALLOCATABLE;
  flea_pub_key_param_u param__u;
  flea_al_u8_t result_len__alu8;

  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(
    THR_flea_rw_stream_t__read_byte(
      hs_rd_stream__pt,
      &peer_enc_pubpoint_len__u8
    )
  );
  // TODO: QUESTION (JR): correct? Or do we only set a limit for stack usage? (tls
  // only uses 1 byte length field so 255 is the maximum length supported in
  // tls)
  if(peer_enc_pubpoint_len__u8 > FLEA_ECC_MAX_ENCODED_POINT_LEN)
  {
    FLEA_THROW("peer pub point too large", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }
  FLEA_ALLOC_BUF(peer_enc_pubpoint__bu8, peer_enc_pubpoint_len__u8);
  FLEA_CCALL(
    THR_flea_rw_stream_t__read_full(
      hs_rd_stream__pt,
      peer_enc_pubpoint__bu8,
      peer_enc_pubpoint_len__u8
    )
  );

  flea_byte_vec_t__set_ref(&peer_enc_pubpoint_vec__t, peer_enc_pubpoint__bu8, peer_enc_pubpoint_len__u8);
  FLEA_CCALL(
    THR_flea_ec_gfp_dom_par_ref_t__set_by_builtin_id(
      &param__u.ecc_dom_par__t,
      tls_ctx__pt->chosen_ecc_dp_internal_id__u8
    )
  );

  FLEA_CCALL(
    THR_flea_public_key_t__ctor_ecc(
      peer_pubkey__pt,
      &peer_enc_pubpoint_vec__t,
      &param__u.ecc_dom_par__t
    )
  );

  if(peer_enc_pubpoint_len__u8 == 0)
  {
    FLEA_THROW("invalid public point length for ecka kdf-ansi-X9.63", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }

  result_len__alu8 = (peer_enc_pubpoint_len__u8 - 1) / 2;
#  ifdef FLEA_USE_STACK_BUF
  if(result_len__alu8 > FLEA_ECC_MAX_MOD_BYTE_SIZE)
  {
    FLEA_THROW("field size not supported", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }
#  endif
  FLEA_CCALL(THR_flea_byte_vec_t__resize(premaster_secret__pt, result_len__alu8));

  FLEA_CCALL(
    THR_flea_ecka__compute_raw(
      peer_enc_pubpoint__bu8,
      peer_enc_pubpoint_len__u8,
      priv_key__pt->privkey_with_params__u.ec_priv_key_val__t.scalar__rcu8.data__pu8,
      priv_key__pt->privkey_with_params__u.ec_priv_key_val__t.scalar__rcu8.len__dtl,
      premaster_secret__pt->data__pu8,
      &result_len__alu8,
      &param__u.ecc_dom_par__t
    )
  );

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(peer_enc_pubpoint__bu8);
  );
} /* THR_flea_tls__read_peer_ecdhe_key_and_compute_premaster_secret */

# endif /* ifdef FLEA_HAVE_ECKA */


void flea_tls_ctx_t__dtor(flea_tls_ctx_t* tls_ctx__pt)
{
  flea_tls_rec_prot_t__dtor(&tls_ctx__pt->rec_prot__t);
  flea_public_key_t__dtor(&tls_ctx__pt->peer_pubkey);
  flea_private_key_t__dtor(&tls_ctx__pt->private_key__t);
  flea_public_key_t__dtor(&tls_ctx__pt->ecdhe_pub_key__t);
  flea_private_key_t__dtor(&tls_ctx__pt->ecdhe_priv_key__t);
# if 0
  if(tls_ctx__pt->client_session_mbn__pt && tls_ctx__pt->client_session_mbn__pt->session_id_len__u8)
  {
    flea_tls_session_data_t__set_session_as_valid(&tls_ctx__pt->client_session_mbn__pt->session__t);
  }
# endif
# ifdef FLEA_USE_HEAP_BUF
  FLEA_FREE_MEM_CHK_NULL(tls_ctx__pt->own_vfy_data__bu8);
# endif
}

#endif /* ifdef FLEA_HAVE_TLS */
