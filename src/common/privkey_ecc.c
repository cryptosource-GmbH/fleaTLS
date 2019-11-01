/* fleaTLS cryptographic library
Copyright (C) 2015-2019 cryptosource GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */


#include "internal/common/default.h"
#include "flea/privkey.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "internal/common/namespace_asn1.h"
#include "flea/x509.h"
#include "internal/common/x509_key_int.h"
#include "flea/ec_key.h"
#include "flea/ecdsa.h"
#include "internal/common/pubkey_int.h"
#include "flea/mem_read_stream.h"
#include "flea/ecc_named_curves.h"
#include "flea/ecka.h"

#ifdef FLEA_HAVE_ECKA

flea_err_e THR_flea_pubkey__compute_ecka(
  const flea_pubkey_t*  pubkey__pt,
  const flea_privkey_t* privkey__pt,
  flea_dtl_t            kdf_out_len__dtl,
  const flea_u8_t*      shared_info_mbn__pcu8,
  flea_al_u16_t         shared_info_mbn_len__alu16,
  flea_hash_id_e        hash_id__e,
  flea_byte_vec_t*      result__pt
)
{
  flea_ref_cu8_t ref__t;
  flea_al_u8_t result_len__alu8;

  FLEA_THR_BEG_FUNC();
  if(pubkey__pt->key_type__t != flea_ecc_key || privkey__pt->key_type__t != flea_ecc_key)
  {
    FLEA_THROW("invalid key type for ECKA", FLEA_ERR_INV_KEY_TYPE);
  }
  flea_pubkey_t__get_encoded_plain_ref(pubkey__pt, &ref__t);
  if(kdf_out_len__dtl == 0)
  {
    result_len__alu8 = (ref__t.len__dtl - 1) / 2;
    FLEA_CCALL(THR_flea_byte_vec_t__resize(result__pt, result_len__alu8));
    FLEA_CCALL(
      THR_flea_ecka__compute_raw(
        ref__t.data__pcu8,
        ref__t.len__dtl,
        privkey__pt->privkey_with_params__u.ec_priv_key_val__t.scalar__rcu8.data__pu8,
        privkey__pt->privkey_with_params__u.ec_priv_key_val__t.scalar__rcu8.len__dtl,
        result__pt->data__pu8,
        &result_len__alu8,
        &pubkey__pt->pubkey_with_params__u.ec_public_val__t.dp__t
      )
    );
  }
  else
  {
    FLEA_CCALL(THR_flea_byte_vec_t__resize(result__pt, kdf_out_len__dtl));
    FLEA_CCALL(
      THR_flea_ecka__compute_ecka_with_kdf_ansi_x9_63(
        hash_id__e,
        ref__t.data__pcu8,
        ref__t.len__dtl,
        privkey__pt->privkey_with_params__u.ec_priv_key_val__t.scalar__rcu8.data__pu8,
        privkey__pt->privkey_with_params__u.ec_priv_key_val__t.scalar__rcu8.len__dtl,
        shared_info_mbn__pcu8,
        shared_info_mbn_len__alu16,
        result__pt->data__pu8,
        kdf_out_len__dtl,
        &pubkey__pt->pubkey_with_params__u.ec_public_val__t.dp__t
      )
    );
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_pubkey__ecka */

#endif /* ifdef FLEA_HAVE_ECKA */
