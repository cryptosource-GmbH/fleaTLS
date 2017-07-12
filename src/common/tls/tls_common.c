/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


/*
 * TODO: compute hashes for all possible hmac algorithms during handshake (?)
 * TODO: read_next_handshake_message: handle the case that one record contains more than one handshake message
 * TODO: const for input values
 * TODO: proper error handling (-> distinct errors)
 * TODO: process alerts and send alerts
 * QUESTION: do we need the structs at all? Simply save the important parts in the tls_ctx (e.g. security_parameters)
 * TODO: Cipher Suites: use new struct and array of supported ciphersuites. (see "Implementing SSL/TLS" page 340f)f
 */


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
#include "flea/tls_session_mngr.h"
#include "internal/pltf_if/time.h"

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
};
static flea_bool_t determine_alert_from_error(
  flea_err_t                     err__t,
  flea_tls__alert_description_t* alert_desc__pe,
  flea_bool_t                    is_reneg__b
)
{
  flea_al_u8_t i;

  if(is_reneg__b && err__t == FLEA_ERR_TLS_REC_NORENEG_AL_DURING_RENEG)
  {
    *alert_desc__pe = FLEA_TLS_ALERT_NO_ALERT;
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

/**
 *    P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
 *                           HMAC_hash(secret, A(2) + seed) +
 *                           HMAC_hash(secret, A(3) + seed) + ...
 *
 * where + indicates concatenation.
 *
 * A() is defined as:
 *    A(0) = seed
 *    A(i) = HMAC_hash(secret, A(i-1))
 *
 *
 *    PRF(secret, label, seed) = P_<hash>(secret, label + seed)
 *
 *  P_Hash is Sha256 for all ciphers defined in RFC5246
 *
 *
 *  FinishedMessage:
 *  verify_data
 *           PRF(master_secret, finished_label, Hash(handshake_messages))
 *              [0..verify_data_length-1];
 */
// length: how long should the output be. 12 Octets = 96 Bits
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
        FLEA_THROW("Invalid label!", FLEA_ERR_TLS_GENERIC);
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

static flea_mac_id_t flea_tls__prf_mac_id_from_suite_id(flea_tls__cipher_suite_id_t ciph)
{
  // TODO: NEED TO COVER FURTHER GCM SUITES WITH ECDH,ECDSA
  if(ciph == FLEA_TLS_RSA_WITH_AES_256_GCM_SHA384)
  {
    return flea_hmac_sha384;
  }
  return flea_hmac_sha256;
}

/*
 * key_block = PRF(SecurityParameters.master_secret,
 *        "key expansion",
 *        SecurityParameters.server_random +
 *        SecurityParameters.client_random);
 */
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
      // tls_ctx->security_parameters.master_secret,
      security_parameters__pt->master_secret,
      48,
      PRF_LABEL_KEY_EXPANSION,
      seed,
      2 * FLEA_TLS_HELLO_RANDOM_SIZE,// sizeof(seed),
      key_block_len__alu8,
      key_block,
      // flea_tls__prf_mac_id_from_suite_id(tls_ctx->selected_cipher_suite__u16)
      flea_tls__prf_mac_id_from_suite_id(selected_cipher_suite__alu16)
    )
  );
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__generate_key_block */

void flea_tls_ctx_t__invalidate_session(flea_tls_ctx_t* tls_ctx__pt)
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
  flea_bool_t     is_reneg__b
)
{
  FLEA_THR_BEG_FUNC();
  if(err__t)
  {
    flea_tls__alert_description_t alert_desc__e;
    flea_bool_t do_send_alert__b = determine_alert_from_error(err__t, &alert_desc__e, is_reneg__b);
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
  flea_u8_t     master_secret[48],
  PRFLabel      label,
  flea_u8_t*    data,
  flea_u8_t     data_len,
  flea_mac_id_t mac_id__e
)
{
  FLEA_THR_BEG_FUNC();
  // TODO: hardcoded hash-len 32 always correct?
  FLEA_CCALL(flea_tls__prf(master_secret, 48, label, messages_hash, 32, data_len, data, mac_id__e));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls__read_finished(
  flea_tls_ctx_t*           tls_ctx,
  flea_tls_handsh_reader_t* hs_rdr__pt,
  flea_hash_ctx_t*          hash_ctx
)
{
  FLEA_DECL_BUF(messages_hash__bu8, flea_u8_t, __FLEA_COMPUTED_MAX_HASH_OUT_LEN + 2 * 12);
  // TODO: need to generalize 12byte ? (botan doesn't do it either) -  avoiding "magical number" would be better
  const flea_al_u8_t finished_len__alu8 = 12;
  flea_rw_stream_t* hs_rd_stream__pt;
  FLEA_DECL_OBJ(hash_ctx_copy, flea_hash_ctx_t);
  FLEA_THR_BEG_FUNC();

  FLEA_ALLOC_BUF(messages_hash__bu8, __FLEA_COMPUTED_MAX_HASH_OUT_LEN + 2 * 12);
  flea_u8_t* finished__pu8     = messages_hash__bu8 + __FLEA_COMPUTED_MAX_HASH_OUT_LEN;
  flea_u8_t* rec_finished__pu8 = messages_hash__bu8 + __FLEA_COMPUTED_MAX_HASH_OUT_LEN + finished_len__alu8;

  /*
   * use a copy of hash_ctx for send_finished instead of finalizing the original
   */
  // TODO: CHECK IF THE COPY IS NEEDED AT ALL:
  if(tls_ctx->security_parameters.connection_end == FLEA_TLS_SERVER)
  {
    FLEA_CCALL(THR_flea_hash_ctx_t__ctor_copy(&hash_ctx_copy, hash_ctx));
    // FLEA_CCALL(THR_flea_hash_ctx_t__final(&hash_ctx_copy, messages_hash__bu8));
    hash_ctx = &hash_ctx_copy;
  }
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
      tls_ctx->security_parameters.master_secret,
      label,
      finished__pu8,
      finished_len__alu8,
      flea_tls__prf_mac_id_from_suite_id(tls_ctx->selected_cipher_suite__u16)
    )
  );
  hs_rd_stream__pt = flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt);
  FLEA_CCALL(THR_flea_rw_stream_t__read_full(hs_rd_stream__pt, rec_finished__pu8, finished_len__alu8));
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
    FLEA_THROW("trailing data in finished message", FLEA_ERR_TLS_GENERIC);
  }
  if(!flea_sec_mem_equal(rec_finished__pu8, finished__pu8, finished_len__alu8))
  {
    FLEA_THROW("Finished message not verifiable", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }


  FLEA_THR_FIN_SEC(
    flea_hash_ctx_t__dtor(&hash_ctx_copy);
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


  // TODO: ADD ALSO CRLS

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
  flea_tls_ctx_t*  tls_ctx,
  flea_hash_ctx_t* hash_ctx,
  flea_ref_cu8_t*  cert_chain__pt,
  flea_u8_t        cert_chain_len__u8
)
{
  flea_u32_t hdr_len__u32;
  flea_u32_t cert_list_len__u32;
  flea_u8_t enc_len__au8[3];

  FLEA_THR_BEG_FUNC();

  // TODO: enable option to exclude the root CA (RFC: MAY be ommited)

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
      hash_ctx,
      HANDSHAKE_TYPE_CERTIFICATE,
      hdr_len__u32
    )
  );


  cert_list_len__u32 = hdr_len__u32 - 3;
  enc_len__au8[0]    = cert_list_len__u32 >> 16;
  enc_len__au8[1]    = cert_list_len__u32 >> 8;
  enc_len__au8[2]    = cert_list_len__u32;

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx->rec_prot__t,
      hash_ctx,
      enc_len__au8,
      3
    )
  );

  // TODO use stream function for encoding
  for(flea_u8_t i = 0; i < cert_chain_len__u8; i++)
  {
    enc_len__au8[0] = cert_chain__pt[i].len__dtl >> 16;
    enc_len__au8[1] = cert_chain__pt[i].len__dtl >> 8;
    enc_len__au8[2] = cert_chain__pt[i].len__dtl;

    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_content(
        &tls_ctx->rec_prot__t,
        hash_ctx,
        enc_len__au8,
        3
      )
    );
    FLEA_CCALL(
      THR_flea_tls__send_handshake_message_content(
        &tls_ctx->rec_prot__t,
        hash_ctx,
        cert_chain__pt[i].data__pcu8,
        cert_chain__pt[i].len__dtl
      )
    );
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls__send_certificate */

flea_err_t THR_flea_tls__send_handshake_message_hdr(
  flea_tls_rec_prot_t* rec_prot__pt,
  flea_hash_ctx_t*     hash_ctx_mbn__pt,
  HandshakeType        type,
  flea_u32_t           content_len__u32
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
  if(hash_ctx_mbn__pt)
  {
    FLEA_CCALL(THR_flea_hash_ctx_t__update(hash_ctx_mbn__pt, enc_for_hash__au8, sizeof(enc_for_hash__au8)));
  }
  FLEA_THR_FIN_SEC_empty();
}

/** master_secret = PRF(pre_master_secret, "master secret",
 *    ClientHello.random + ServerHello.random)
 *    [0..47];
 */
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
  // flea_u8_t random_seed[64];
  // memcpy(random_seed__bu8, client_hello_random.gmt_unix_time, 4);
  // memcpy(random_seed__bu8 + 4, client_hello_random.random_bytes, 28);
  // memcpy(random_seed__bu8, client_hello_random, 32);
  // memcpy(random_seed__bu8 + 32, server_hello_random.gmt_unix_time, 4);
  // memcpy(random_seed__bu8 + 36, server_hello_random.random_bytes, 28);
  // TODO: REDUNDANT ARRAY
  memcpy(random_seed__bu8, client_and_server_hello_random, 64);

  // pre_master_secret is 48 bytes, master_secret is desired to be 48 bytes
  // FLEA_CCALL(THR_flea_byte_vec_t__resize(premaster_secret__pt, 48));
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

// TODO: configurable parameters
// TODO: ctor = handshake function
flea_err_t THR_flea_tls_ctx_t__construction_helper(
  flea_tls_ctx_t*               ctx,
  flea_rw_stream_t*             rw_stream__pt,
  flea_tls_renegotiation_spec_e reneg_spec__e
)
{
  flea_al_u8_t sec_reneg_field_size__alu8 = 12;

  FLEA_THR_BEG_FUNC();
  flea_tls_ctx_t__set_sec_reneg_flags(ctx, reneg_spec__e);
  // ctx->security_parameters = calloc(1, sizeof(flea_tls__security_parameters_t));
  ctx->rw_stream__pt = rw_stream__pt;
  // ctx->client_has_sec_reneg__u8 = FLEA_FALSE;
  /* specify connection end */

  /* set TLS version */
  ctx->version.major = 0x03;
  ctx->version.minor = 0x03;
# ifdef FLEA_USE_HEAP_BUF

  /*if(ctx->security_parameters.connection_end == FLEA_TLS_SERVER)
   * {*/
  sec_reneg_field_size__alu8 = 24;
  // }
  FLEA_ALLOC_MEM(ctx->own_vfy_data__bu8, sec_reneg_field_size__alu8);
  /* not used in case of client: */
  ctx->peer_vfy_data__bu8 = ctx->own_vfy_data__bu8 + 12;
# endif
  ctx->sec_reneg_flag__u8 = FLEA_FALSE;
  FLEA_CCALL(THR_flea_tls_rec_prot_t__ctor(&ctx->rec_prot__t, ctx->version.major, ctx->version.minor, rw_stream__pt));

  ctx->selected_cipher_suite__u16 = FLEA_TLS_NULL_WITH_NULL_NULL;

  /* set SessionID */

  /*if(session_id_len > 32)
   * {
   * FLEA_THROW("session id too large", FLEA_ERR_TLS_GENERIC);
   * }*/
  // memcpy(&ctx->session_id, session_id, session_id_len);
  // ctx->session_id_len = session_id_len;

  /* set client_random */
  // TODO: do we need these parameters in the ctx? everything only needed during
  // handshake should be local to that function
  //

  // ctx->resumption = FLEA_FALSE;

# if 0
#  ifdef FLEA_USE_HEAP_BUF
  // nothing to do
  // ctx->premaster_secret = calloc(256, sizeof(flea_u8_t));
#  else
  ctx->premaster_secret =
    flea_byte_vec_t__CONSTR_EXISTING_BUF_EMPTY_ALLOCATABLE(ctx->premaster_secret__au8, sizeof(premaster_secret__au8));
#  endif
# endif

  FLEA_THR_FIN_SEC_empty();
} /* flea_tls_ctx_t__ctor */

flea_err_t THR_flea_tls__send_handshake_message_content(
  flea_tls_rec_prot_t* rec_prot__pt,
  flea_hash_ctx_t*     hash_ctx_mbn__pt,
  const flea_u8_t*     msg_bytes,
  flea_u32_t           msg_bytes_len
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
  if(hash_ctx_mbn__pt)
  {
    FLEA_CCALL(THR_flea_hash_ctx_t__update(hash_ctx_mbn__pt, msg_bytes, msg_bytes_len));
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls__send_handshake_message_int_be(
  flea_tls_rec_prot_t* rec_prot__pt,
  flea_hash_ctx_t*     hash_ctx_mbn__pt,
  flea_u32_t           int__u32,
  flea_al_u8_t         int_byte_width__alu8
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
      hash_ctx_mbn__pt,
      enc__au8 + (4 - int_byte_width__alu8),
      int_byte_width__alu8
    )
  );

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls__send_handshake_message(
  flea_tls_rec_prot_t* rec_prot__pt,
  flea_hash_ctx_t*     hash_ctx_mbn__pt,
  HandshakeType        type,
  const flea_u8_t*     msg_bytes,
  flea_u32_t           msg_bytes_len
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_tls__send_handshake_message_hdr(rec_prot__pt, hash_ctx_mbn__pt, type, msg_bytes_len));

  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(rec_prot__pt, hash_ctx_mbn__pt, msg_bytes, msg_bytes_len));
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
  flea_tls_ctx_t*  tls_ctx,
  flea_hash_ctx_t* hash_ctx
)
{
  FLEA_DECL_BUF(verify_data__bu8, flea_u8_t, 12 + 32);
  const flea_al_u8_t verify_data_len__alu8 = 12;
  flea_u8_t* messages_hash__pu8;
  PRFLabel label;

  FLEA_DECL_OBJ(hash_ctx_copy, flea_hash_ctx_t);
  FLEA_THR_BEG_FUNC();

  // compute hash over handshake messages so far
  FLEA_ALLOC_BUF(verify_data__bu8, verify_data_len__alu8 + 32);
  messages_hash__pu8 = verify_data__bu8 + verify_data_len__alu8;

  /*
   * use a copy of hash_ctx for send_finished instead of finalizing the original
   */
  FLEA_CCALL(THR_flea_hash_ctx_t__ctor_copy(&hash_ctx_copy, hash_ctx));
  FLEA_CCALL(THR_flea_hash_ctx_t__final(&hash_ctx_copy, messages_hash__pu8));

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
      tls_ctx->security_parameters.master_secret,
      label,
      verify_data__bu8,
      verify_data_len__alu8,
      flea_tls__prf_mac_id_from_suite_id(tls_ctx->selected_cipher_suite__u16)
    )
  );

  FLEA_CCALL(
    THR_flea_tls__send_handshake_message(
      &tls_ctx->rec_prot__t,
      hash_ctx,
      HANDSHAKE_TYPE_FINISHED,
      verify_data__bu8,
      12
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
    FLEA_FREE_BUF_FINAL_SECRET_ARR(verify_data__bu8, 12);
    flea_hash_ctx_t__dtor(&hash_ctx_copy);
  );
} /* THR_flea_tls__send_finished */

/**
 * Implementation note: Public-key-encrypted data is represented as an
 * opaque vector <0..2^16-1> (see Section 4.7).  Thus, the RSA-encrypted
 * PreMasterSecret in a ClientKeyExchange is preceded by two length
 * bytes.
 *
 * These bytes are redundant in the case of RSA because the
 * EncryptedPreMasterSecret is the only data in the ClientKeyExchange
 * and its length can therefore be unambiguously determined
 *
 * => send 2 length bytes
 */


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

  FLEA_CCALL(THR_flea_tls__handle_tls_error(tls_ctx__pt, err__t, FLEA_FALSE));
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

  FLEA_CCALL(THR_flea_tls__handle_tls_error(tls_ctx__pt, err__t, FLEA_FALSE));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls_ctx_t__renegotiate(
  flea_tls_ctx_t*          tls_ctx__pt,
  const flea_cert_store_t* trust_store__pt,
  /* new session id? */
  flea_ref_cu8_t*          cert_chain__pt,
  flea_al_u8_t             cert_chain_len__alu8,
  flea_ref_cu8_t*          private_key__pt,
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
  tls_ctx__pt->private_key__pt    = private_key__pt;
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
  FLEA_CCALL(THR_flea_tls__handle_tls_error(tls_ctx__pt, err__t, FLEA_TRUE));

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
  else
  {
    return FLEA_TRUE;
  }
}

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
  return len__alu16;
}

flea_err_t THR_flea_tls_ctx_t__send_extensions_length(
  flea_tls_ctx_t*  tls_ctx__pt,
  flea_hash_ctx_t* hash_ctx_mbn__pt
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
        hash_ctx_mbn__pt,
        enc_len__au8,
        sizeof(enc_len__au8)
      )
    );
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_tls_ctx_t__send_reneg_ext(
  flea_tls_ctx_t*  tls_ctx__pt,
  flea_hash_ctx_t* hash_ctx__pt
)
{
  const flea_u8_t reneg_ext_type__cau8[] = {0xff, 0x01};
  flea_u8_t len__u8 = 0;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx__pt->rec_prot__t,
      hash_ctx__pt,
      reneg_ext_type__cau8,
      sizeof(reneg_ext_type__cau8)
    )
  );
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx__pt->rec_prot__t, hash_ctx__pt, &len__u8, 1));
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
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx__pt->rec_prot__t, hash_ctx__pt, &len__u8, 1));
  len__u8 -= 1;
  FLEA_CCALL(THR_flea_tls__send_handshake_message_content(&tls_ctx__pt->rec_prot__t, hash_ctx__pt, &len__u8, 1));
  FLEA_CCALL(
    THR_flea_tls__send_handshake_message_content(
      &tls_ctx__pt->rec_prot__t,
      hash_ctx__pt,
      tls_ctx__pt->own_vfy_data__bu8,
      len__u8
    )
  );

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__send_reneg_ext */

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
  FLEA_CCALL(THR_flea_rw_stream_t__read_byte(rd_strm__pt, &len__u8));
  if(len__u8 + 1 != ext_len__alu16)
  {
    FLEA_THROW("inconsistent length for reneg info", FLEA_ERR_TLS_PROT_DECODE_ERR);
  }
  if(len__u8 != exp_len__alu8)
  {
    FLEA_THROW("invalid renegotiation info size", FLEA_ERR_TLS_HANDSHK_FAILURE);
  }
  FLEA_CCALL(THR_flea_rw_stream_t__read_full(rd_strm__pt, cmp__bu8, exp_len__alu8));

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

  FLEA_THR_BEG_FUNC();
  hs_rd_stream__pt = flea_tls_handsh_reader_t__get_read_stream(hs_rdr__pt);
  // flea_tls_ctx_t__reset_extension_state(tls_ctx__pt);

  /*if(!flea_tls_handsh_reader_t__get_msg_rem_len(hs_rdr__pt))
   * {
   * if(tls_ctx__pt->sec_reneg_flag__u8)
   * {
   * FLEA_THROW("peer behaves inconsistently regarding secure renegotiation", FLEA_ERR_TLS_INCONS_SEC_RENEG);
   * }
   * FLEA_THR_RETURN();
   * }*/
  FLEA_CCALL(THR_flea_rw_stream_t__read_int_be(hs_rd_stream__pt, &extensions_len__u32, 2));
  while(extensions_len__u32)
  {
    flea_u32_t ext_type_be__u32;
    flea_u32_t ext_len__u32;
    FLEA_CCALL(THR_flea_rw_stream_t__read_int_be(hs_rd_stream__pt, &ext_type_be__u32, 2));
    FLEA_CCALL(THR_flea_rw_stream_t__read_int_be(hs_rd_stream__pt, &ext_len__u32, 2));
    extensions_len__u32 -= (((flea_u32_t) 4) + ext_len__u32);
    if(ext_type_be__u32 == 0xff01)
    {
      FLEA_CCALL(THR_flea_tls_ctx__parse_reneg_ext(tls_ctx__pt, hs_rd_stream__pt, ext_len__u32));
      *found_sec_reneg__pb = FLEA_TRUE;
    }
    else
    {
      FLEA_CCALL(THR_flea_rw_stream_t__skip_read(hs_rd_stream__pt, ext_len__u32));
    }
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_tls_ctx_t__client_parse_extensions */

void flea_tls_ctx_t__dtor(flea_tls_ctx_t* tls_ctx__pt)
{
  flea_tls_rec_prot_t__dtor(&tls_ctx__pt->rec_prot__t);
  flea_public_key_t__dtor(&tls_ctx__pt->peer_pubkey);
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
