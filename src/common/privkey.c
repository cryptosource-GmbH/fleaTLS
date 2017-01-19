/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "flea/privkey.h"
#include "flea/error.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/namespace_asn1.h"
#include "flea/x509.h"
#include "flea/ec_key.h"
#include "flea/util.h"
#include "flea/bin_utils.h"
#include "flea/pk_api.h"
#include "flea/ecc_named_curves.h"
#include <string.h>


#ifdef FLEA_HAVE_ECC
flea_err_t THR_flea_private_key_t__ctor_ecc(flea_private_key_t *key__pt, const flea_ref_cu8_t *scalar__cprcu8, const flea_ec_gfp_dom_par_ref_t *dp_ref__pt)
{
	flea_al_u16_t dp_concat_len__alu16;
	FLEA_THR_BEG_FUNC();	
	key__pt->key_type__t = flea_ecc_key;		
	key__pt->key_bit_size__u16 = flea__get_BE_int_bit_len(dp_ref__pt->n__ru8.data__pcu8, dp_ref__pt->n__ru8.len__dtl);
	if(key__pt->key_bit_size__u16 > FLEA_ECC_MAX_ORDER_BIT_SIZE)
	{
		FLEA_THROW("ECC order too large", FLEA_ERR_INV_ECC_DP );
	}
	if(flea__get_BE_int_bit_len(scalar__cprcu8->data__pcu8, scalar__cprcu8->len__dtl) > key__pt->key_bit_size__u16)
	{
		FLEA_THROW("ECC order too large", FLEA_ERR_INV_KEY_SIZE);
	}
#ifdef FLEA_USE_HEAP_BUF
	dp_concat_len__alu16 = flea_ec_gfp_dom_par_ref_t__get_concat_length(dp_ref__pt);
	FLEA_ALLOC_MEM(key__pt->privkey_with_params__u.ec_priv_key_val__t.dp_mem__bu8, dp_concat_len__alu16);
	FLEA_ALLOC_MEM(key__pt->privkey_with_params__u.ec_priv_key_val__t.priv_scalar__mem__bu8, scalar__cprcu8->len__dtl);
#else
	dp_concat_len__alu16 = sizeof( key__pt->privkey_with_params__u.ec_priv_key_val__t.dp_mem__bu8);
#endif
	flea_copy_rcu8_use_mem(&key__pt->privkey_with_params__u.ec_priv_key_val__t.scalar__rcu8, key__pt->privkey_with_params__u.ec_priv_key_val__t.priv_scalar__mem__bu8, scalar__cprcu8);

	FLEA_CCALL(THR_flea_ec_gfp_dom_par_ref_t__write_to_concat_array(&key__pt->privkey_with_params__u.ec_priv_key_val__t.dp__t, key__pt->privkey_with_params__u.ec_priv_key_val__t.dp_mem__bu8, dp_concat_len__alu16, dp_ref__pt));

	FLEA_THR_FIN_SEC_empty();	
}
#endif /* #ifdef FLEA_HAVE_ECC */
#ifdef FLEA_HAVE_RSA
flea_err_t THR_flea_private_key_t__ctor_rsa_internal_format(flea_private_key_t *key__pt, const flea_ref_cu8_t* priv_key_enc_internal_format__prcu8, flea_al_u16_t key_bit_size__alu16)
{
	FLEA_THR_BEG_FUNC();	
	
		const flea_u8_t * key_mem__pcu8 = priv_key_enc_internal_format__prcu8->data__pcu8;
		flea_al_u16_t key_len__alu16 = priv_key_enc_internal_format__prcu8->len__dtl;
		flea_al_u16_t half_mod_len__alu16 = key_len__alu16 / 5;
		if( key_len__alu16 % 5 || key_len__alu16 > FLEA_RSA_CRT_KEY_INTERNAL_FORMAT_MAX_BYTE_SIZE)
		{
			FLEA_THROW("invalid length of RSA key in internal format", FLEA_ERR_INV_KEY_COMP_SIZE);
		}

FLEA_CCALL(THR_flea_private_key_t__ctor_rsa_components(
		key__pt, 
		key_bit_size__alu16,
		key_mem__pcu8,
		half_mod_len__alu16,
		key_mem__pcu8 + half_mod_len__alu16,
		half_mod_len__alu16,
		key_mem__pcu8 + 2 * half_mod_len__alu16,
		half_mod_len__alu16,
		key_mem__pcu8 + 3 * half_mod_len__alu16,
		half_mod_len__alu16,
		key_mem__pcu8 + 4 * half_mod_len__alu16,
		half_mod_len__alu16
		));
	
FLEA_THR_FIN_SEC_empty();
}
#endif /* #ifdef FLEA_HAVE_RSA */

#ifdef FLEA_HAVE_RSA
flea_err_t THR_flea_private_key_t__ctor_rsa_components(
		flea_private_key_t *key__pt, 
		flea_al_u16_t key_bit_size__alu16,
		const flea_u8_t* p__pcu8,
		flea_al_u16_t p_len__alu16,
		const flea_u8_t* q__pcu8,
		flea_al_u16_t q_len__alu16,
		const flea_u8_t* d1__pcu8,
		flea_al_u16_t d1_len__alu16,
		const flea_u8_t* d2__pcu8,
		flea_al_u16_t d2_len__alu16,
		const flea_u8_t* c__pcu8,
		flea_al_u16_t c_len__alu16
		)
{

	FLEA_THR_BEG_FUNC();
	flea_al_u8_t i;
	flea_u8_t *priv_key_mem__pcu8;
	const flea_u8_t *  comp_ptrs__apcu8 [] = { p__pcu8, q__pcu8, d1__pcu8, d2__pcu8, c__pcu8 };
	const flea_al_u16_t comp_lens__aalu16 [] = { p_len__alu16, q_len__alu16, d1_len__alu16, d2_len__alu16, c_len__alu16 };

#ifdef FLEA_USE_HEAP_BUF
	flea_al_u16_t key_len__al_u16;
#endif
	key__pt->key_bit_size__u16 = key_bit_size__alu16;	
	key__pt->key_type__t = flea_rsa_key;

	if(p_len__alu16 > FLEA_RSA_CRT_KEY_COMPONENT_MAX_BYTE_SIZE
			|| q_len__alu16 > FLEA_RSA_CRT_KEY_COMPONENT_MAX_BYTE_SIZE
			|| d1_len__alu16 > FLEA_RSA_CRT_KEY_COMPONENT_MAX_BYTE_SIZE
			|| d2_len__alu16 > FLEA_RSA_CRT_KEY_COMPONENT_MAX_BYTE_SIZE
			|| c_len__alu16 > FLEA_RSA_CRT_KEY_COMPONENT_MAX_BYTE_SIZE
		)
	{
		FLEA_THROW("invalid RSA private key component size", FLEA_ERR_INV_KEY_COMP_SIZE);
	}
#ifdef FLEA_USE_HEAP_BUF
	key_len__al_u16 = p_len__alu16 + q_len__alu16 + d1_len__alu16 + d2_len__alu16 + c_len__alu16;
	FLEA_ALLOC_MEM(key__pt->privkey_with_params__u.rsa_priv_key_val__t.priv_key_mem__bu8, key_len__al_u16);

#endif

	priv_key_mem__pcu8  = key__pt->privkey_with_params__u.rsa_priv_key_val__t.priv_key_mem__bu8;
	for(i = 0; i < 5; i++)
	{
		const flea_u8_t *ptr__pcu8 = comp_ptrs__apcu8[i];
		flea_al_u16_t len__alu16 = comp_lens__aalu16[i];
		memcpy(priv_key_mem__pcu8, ptr__pcu8, len__alu16);
		key__pt->privkey_with_params__u.rsa_priv_key_val__t.pqd1d2c__rcu8[i].data__pcu8 = priv_key_mem__pcu8;
		key__pt->privkey_with_params__u.rsa_priv_key_val__t.pqd1d2c__rcu8[i].len__dtl =  len__alu16;
		priv_key_mem__pcu8 += len__alu16;
	}


	FLEA_THR_FIN_SEC_empty();
}

#endif /* #ifdef FLEA_HAVE_RSA */

void flea_private_key_t__dtor(flea_private_key_t *privkey__pt)
{
#ifdef FLEA_USE_HEAP_BUF
#ifdef FLEA_HAVE_RSA
	if(privkey__pt->key_type__t == flea_rsa_key)
	{
		FLEA_FREE_MEM_CHK_SET_NULL(privkey__pt->privkey_with_params__u.rsa_priv_key_val__t.priv_key_mem__bu8);
	}
#endif
#ifdef FLEA_HAVE_ECC
	if(privkey__pt->key_type__t == flea_ecc_key)
	{
		FLEA_FREE_MEM_CHK_SET_NULL(privkey__pt->privkey_with_params__u.ec_priv_key_val__t.dp_mem__bu8);
		FLEA_FREE_MEM_CHK_SET_NULL(privkey__pt->privkey_with_params__u.ec_priv_key_val__t.priv_scalar__mem__bu8);
	}
#endif 
#endif
}
