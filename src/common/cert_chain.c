/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#include "internal/common/default.h"
#include "flea/types.h"
#include "flea/alloc.h"
#include "flea/cert_verify.h"
#include "flea/array_util.h"
#include "flea/cert_chain.h"
#include "flea/asn1_date.h"
#include "flea/error_handling.h"
#include "flea/ber_dec.h"
#include "flea/x509.h"

#ifdef FLEA_HAVE_ASYM_SIG
#define END_OF_COLL 0xFFFF

/**
 * finds the next cert which is not already part of the the chain
 */
/*static flea_al_u16_t get_next_candidate(const flea_x509_cert_ref_t *cert_collection__pt, flea_al_u16_t cert_collection_size__alu16, flea_al_u16_t start_pos__alu16, flea_u16_t *used_chain__pu16, flea_al_u16_t used_chain_len)
{
  flea_al_u16_t i;
  for(i = start_pos__alu16; i < cert_collection_size__alu16; i++)
  {
    if
  }
}*/

static flea_al_u16_t find_cert(const flea_x509_cert_ref_t* cert_to_find__pt, const flea_x509_cert_ref_t *cert_collection__pt, flea_al_u16_t cert_collection_size__alu16, flea_al_u16_t start_pos__alu16) 
{
  flea_al_u16_t i;
  //flea_al_u16_t result = END_OF_COLL;
  for(i = start_pos__alu16; i < cert_collection_size__alu16; i++)
  {
    /* compare subject DN's */
    if(!flea_rcu8_cmp(&cert_to_find__pt->subject__t.raw_dn_complete__t, &cert_collection__pt[i].subject__t.raw_dn_complete__t))
    {
      /* compare tbs */
      // TODO: CACHE TBS HASHES AND COMPARE THESE ? => MAKE FUNCTION FOR CERT
      // COMPARE WHICH HANDLES ALL POSSIBILITIES*/ 
      if(!flea_rcu8_cmp(&cert_to_find__pt->tbs_ref__t, &cert_collection__pt[i].tbs_ref__t) )
      {
        if(FLEA_DER_REF_IS_ABSENT(&cert_collection__pt[i].cert_signature_as_bit_string__t) || 
            FLEA_DER_REF_IS_ABSENT(&cert_to_find__pt->cert_signature_as_bit_string__t) ||
            !flea_rcu8_cmp(&cert_to_find__pt->cert_signature_as_bit_string__t, &cert_collection__pt[i].cert_signature_as_bit_string__t))
        return i;        
      }
    }

  }
  return END_OF_COLL;
}

static flea_al_u16_t find_issuer(const flea_x509_cert_ref_t* cert_to_find_issuer_to__pt, const flea_x509_cert_ref_t *cert_collection__pt, flea_al_u16_t cert_collection_size__alu16, flea_al_u16_t start_pos__alu16, flea_u16_t *used_chain__pu16, flea_al_u16_t used_chain_len__alu16) 
{
//  search through collection for matching DN and AKIE
//
  flea_al_u16_t i;
  //flea_al_u16_t result = END_OF_COLL;
  for(i = start_pos__alu16; i < cert_collection_size__alu16; i++)
  {
    /* compare subject DN's */
    // TODO: document binary comparison of issuer/subject
    if(!flea_rcu8_cmp(&cert_to_find_issuer_to__pt->issuer__t.raw_dn_complete__t, &cert_collection__pt[i].subject__t.raw_dn_complete__t))
    {
      flea_bool_t already_used__b = FLEA_FALSE;
        // TODO: COMPARE AKI IF PRESENT
        //check if that candidate is not yet part of the chain 
        flea_al_u16_t j;
        for(j = 0; j < used_chain_len__alu16; j++)
        {
          if(used_chain__pu16[j] == i)
          {
            already_used__b = FLEA_TRUE; 
            break;
          } 
        }
        if(!already_used__b)
        {
          return i;
        }
      
    }
  }
  return END_OF_COLL;
}

static flea_bool_t is_cert_trusted(const flea_x509_cert_ref_t *cert_ref__pt)
{
  return cert_ref__pt->is_trusted__b;
}

void flea_cert_chain_t__dtor(flea_cert_chain_t *chain__pt)  
{
#ifdef FLEA_USE_HEAP_BUF
  FLEA_FREE_MEM_CHK_SET_NULL(chain__pt->chain__bu16);
#endif
  //*(element__pt) = flea_cert_chain_element_t__INIT_VALUE;
}

static flea_bool_t is_cert_self_issued(const flea_x509_cert_ref_t *cert__pt)
{
  if(FLEA_DER_REF_IS_ABSENT(&cert__pt->issuer__t.raw_dn_complete__t))
  {
    return FLEA_TRUE;
  }
  if(0 == flea_rcu8_cmp(&cert__pt->subject__t.raw_dn_complete__t, &cert__pt->issuer__t.raw_dn_complete__t))
  {
    return FLEA_TRUE;
  }
  return FLEA_FALSE;
}

static flea_err_t THR_validate_cert_path(flea_cert_chain_t *cert_chain__pt, const flea_gmt_time_t *compare_time__pt, flea_public_key_t *key_to_construct_mbn__pt)
{
  flea_s32_t i;
  flea_al_u16_t chain_len__alu16 =  cert_chain__pt->chain_pos__u16 + 1;
  flea_al_u16_t m_path__u16 = chain_len__alu16;
  flea_ref_cu8_t inherited_params__rcu8;
  FLEA_THR_BEG_FUNC();
  if(chain_len__alu16 == 0)
  {
    FLEA_THROW("attempted to verify an empty certificate path", FLEA_ERR_INV_ARG);
  }

  for(i = chain_len__alu16 - 1; i >= 0 ; i--)
  {
    flea_x509_cert_ref_t * current__pt = &cert_chain__pt->cert_collection__pt[cert_chain__pt->chain__bu16[i]];
    flea_bool_t is_current_ta;
    flea_bool_t is_current_target; 
    is_current_ta = ( i == (flea_s32_t)chain_len__alu16 - 1);
    is_current_target = ( i == 0 );
    //flea_al_u16_t path_len_constr__alu16;
    flea_basic_constraints_t *basic_constraints__pt;
    flea_key_usage_t *key_usage__pt;

    key_usage__pt = & current__pt->extensions__t.key_usage__t;
    basic_constraints__pt = &current__pt->extensions__t.basic_constraints__t;
    // verify validity date
    if(1 == flea_asn1_cmp_utc_time(&current__pt->not_before__t, compare_time__pt))
    {
      FLEA_THROW("certificate not yet valid", FLEA_ERR_CERT_NOT_YET_VALID); 
    }
    if(-1 == flea_asn1_cmp_utc_time(&current__pt->not_after__t, compare_time__pt))
    {
      FLEA_THROW("certificate not yet valid", FLEA_ERR_CERT_NOT_YET_VALID); 
    }
    // TODO: CHECK REVOCATION
    //if(!is_current_ta)
    if(!is_cert_self_issued(current__pt) && !is_current_target) 
    {
      if(m_path__u16 == 0)
      {
      // PKITS 4.6.15 triggers this condition when the self-issued cert is
      // processed
//#error BUG TO FIX
      FLEA_THROW("path len constraint exceeded", FLEA_ERR_CERT_PATH_LEN_CONSTR_EXCEEDED);
      }

      //if(!is_current_target) // && !is_current_ta ??
      {
        //printf("cert is not self issued\n");
        m_path__u16 -= 1;
      }
      /*else
      {
        //printf("cert is not self issued\n");
      }*/
    }

    //path_len_constr__alu16 = 
    if(basic_constraints__pt->is_present__u8)
    {
      if(basic_constraints__pt->has_path_len__b)
      {
        m_path__u16 = FLEA_MIN(basic_constraints__pt->path_len__u16, m_path__u16);
      }
      // TODO: PARAMETER INHERITANCE FROM PREVIOUS
      // HERE, ENSURE THAT SUBJECT PUBLIC KEY ALGO MATCHES TO THE PREVIOUS IN CHAIN
    }

    /** flea does not check the TA to be a CA **/
    if(!is_current_target && !is_current_ta) 
    {
      if(!basic_constraints__pt->is_present__u8)
      {
        FLEA_THROW("basic constraints missing", FLEA_ERR_CERT_INTERMED_IS_NOT_CA_CERT);
      }
      if(!basic_constraints__pt->is_ca__b)
      {
        FLEA_THROW("basic constraints does not indicate CA", FLEA_ERR_CERT_INTERMED_IS_NOT_CA_CERT);
      }
      if(key_usage__pt->is_present__u8 &&
          !(key_usage__pt->purposes__u16 & FLEA_ASN1_KEY_USAGE_MASK_key_cert_sign))
      {
        FLEA_THROW("key usage cert sign missing", FLEA_ERR_CERT_INTERMED_IS_NOT_CA_CERT);
      }
    }
  }
  // verify signature from target to TA
  // TODO: INVERT ORDER AND IMPLEMENT PARAMETER INHERITANCE
  inherited_params__rcu8.data__pcu8 = NULL;
  inherited_params__rcu8.len__dtl = 0;
  for(i = (flea_s32_t)(chain_len__alu16 - 2); i > 0; i--)
  //for(i = 0; i < (flea_s32_t)(chain_len__alu16 - 1); i++)
  {
    flea_ref_cu8_t returned_params__rcu8;
    //if(i != (flea_s32_t)(chain_len__alu16 -  1))
    {
      flea_ref_cu8_t *inherited_params_to_use__prcu8 = inherited_params__rcu8.len__dtl ? &inherited_params__rcu8 : NULL;
      // verify against subsequent certificate
      FLEA_CCALL(THR_flea_x509_verify_cert_ref_signature_inherited_params(&cert_chain__pt->cert_collection__pt[cert_chain__pt->chain__bu16[i]], &cert_chain__pt->cert_collection__pt[cert_chain__pt->chain__bu16[i+1]], &returned_params__rcu8, inherited_params_to_use__prcu8));
      if(returned_params__rcu8.len__dtl)
      {
        inherited_params__rcu8 = returned_params__rcu8;
      }
      //printf("validated signature OK\n");
    }
  }
  if(key_to_construct_mbn__pt)
  {
    flea_bool_t dummy;
      flea_ref_cu8_t *inherited_params_to_use__prcu8 = inherited_params__rcu8.len__dtl ? &inherited_params__rcu8 : NULL;
    FLEA_CCALL(THR_flea_public_key_t__ctor_cert_inherited_params(key_to_construct_mbn__pt, &cert_chain__pt->cert_collection__pt[cert_chain__pt->chain__bu16[0]], inherited_params_to_use__prcu8, &dummy));
  }

  FLEA_THR_FIN_SEC_empty();
}


flea_err_t THR_flea_cert_chain__build_and_verify_cert_chain( flea_cert_chain_t *cert_chain__pt, const flea_gmt_time_t *time__pt)
{
  return THR_flea_cert_chain__build_and_verify_cert_chain_and_create_pub_key(cert_chain__pt, time__pt, NULL);
}
flea_err_t THR_flea_cert_chain__build_and_verify_cert_chain_and_create_pub_key( flea_cert_chain_t *cert_chain__pt, const flea_gmt_time_t *time__pt, flea_public_key_t *key_to_construct_mbn__pt)
{
  flea_u16_t *chain_pos__pu16 = &cert_chain__pt->chain_pos__u16;
  flea_x509_cert_ref_t *cert_collection__pt = cert_chain__pt->cert_collection__pt;
  flea_x509_cert_ref_t *target_cert__pt = &cert_collection__pt[0];
  flea_al_u16_t target_pos = 0;
  flea_u16_t *chain__bu16 = cert_chain__pt->chain__bu16; 
  flea_al_u16_t cert_collection_size__alu16 = cert_chain__pt->cert_collection_size__u16;
  FLEA_THR_BEG_FUNC();
  *chain_pos__pu16 = 0;
  FLEA_SET_ARR(chain__bu16, 0, FLEA_MAX_CERT_CHAIN_DEPTH);
  if(cert_collection_size__alu16 == END_OF_COLL)
  {
    FLEA_THROW("exceeded maximal number of certificates in collection", FLEA_ERR_INV_ARG);
  }
  if(cert_collection_size__alu16 == 0)
  {
    FLEA_THROW("no certificate collection provided for path validation", FLEA_ERR_CERT_PATH_NO_TRUSTED_CERTS);
  }
  // TODO: IF TARGET CERT IS TRUSTED THEN NO NEED FOR A SIGNATURE
  if(FLEA_DER_REF_IS_ABSENT(&target_cert__pt->cert_signature_as_bit_string__t))
  {
    FLEA_THROW("target certificate carries no signature", FLEA_ERR_INV_ARG);
  }
  /* check if the target cert is directly trusted */
#if FLEA_MAX_CERT_CHAIN_DEPTH < 2
#error FLEA_MAX_CERT_CHAIN_DEPTH < 2
#endif
  // COVER THE TARGET CERT APPEARING AS TRUSTED IN THE COLL BY SEARCHING
  // THROUGH IT, AND SETTING CURRENT AS TRUSTED IF IT IS FOUND AS TRUSTED. AT THE START OF THE CONSTRUCTION LOOP THEN
  // IT IS CHECKED IF THE CURRENT IS TRUSTED 
  while(target_pos != END_OF_COLL)
  {
    target_pos = find_cert(target_cert__pt, &cert_collection__pt[1], cert_collection_size__alu16-1, target_pos); // find by TBS match and possibly signature match (if both signatures are available)

      if((target_pos != END_OF_COLL))
      {
        if(is_cert_trusted(&cert_collection__pt[target_pos] ))
        {
          //return validate_cert_path(); // still have to check for validity times, policy key usage etc.
          target_cert__pt->is_trusted__b = FLEA_TRUE; 
          break;
        }
        target_pos++;
      }
  }
  /* try to find a path */
  // TODO: SUPPLY VOLATILE STOP INDICATOR TO BE CHECKED AS LOOP CONDITION
  while(1)
  {
    flea_x509_cert_ref_t *subject;
    flea_al_u16_t issuer_pos;
    flea_bool_t failed_path = FLEA_FALSE; 
      subject = &cert_collection__pt[chain__bu16[*chain_pos__pu16]];

        /*{
          unsigned i;
          printf("\n\nchain when starting loop = ");
          for(i = 0; i <= *chain_pos__pu16; i++)
          {
            printf("%u ", chain__bu16[i]);
          }
          printf("\n");

        }*/
      if(is_cert_trusted(subject))
      {
        /*{
          unsigned i;
          printf("at TA, chain when calling validate path = ");
          for(i = 0; i <= *chain_pos__pu16; i++)
          {
            printf("%u ", chain__bu16[i]);
          }
          printf("\n");

        }*/
          flea_err_t validation_error = THR_validate_cert_path(cert_chain__pt, time__pt, key_to_construct_mbn__pt);
          if(validation_error == FLEA_ERR_FINE)
          {
            return FLEA_ERR_FINE;
          }
          failed_path = FLEA_TRUE; 

        if((*chain_pos__pu16) == 0)
        {
          // directly trusted cert not valid
          FLEA_THROW("no valid certificate path found", FLEA_ERR_CERT_PATH_NOT_FOUND); 
        }
        (*chain_pos__pu16)--; // look for next candidate above me

          // TODO: DIFFERENTIATE: 
          // MEMORY ALLOCATION ERROR => ?
          // DECODING ERROR => CANCEL A CERT FROM COLL
          // OTHER VERIFICATION ERROR => CONTINUE PATH CONSTRUCTION WITH NEXT
          // CERT
      } 
      // no trusted cert yet found. can only enlarge the chain if it has
      // capacitiy left.
    else if(*chain_pos__pu16 + 1 < FLEA_MAX_CERT_CHAIN_DEPTH ) 
    {
      flea_al_u16_t start_offs = chain__bu16[(*chain_pos__pu16) + 1];
    //printf("looking for issuer starting from position %u within collection\n", start_offs); 
    issuer_pos = find_issuer( subject /* cert to which to find an issuer */, cert_collection__pt, cert_collection_size__alu16, start_offs/* offset where to start the search */, &chain__bu16[0] /* already used certs in terms of their possitions*/, (*chain_pos__pu16)+1 /* number of used certs */);
    }
    else
    {
      //printf("no potential issuer found\n");
      issuer_pos = END_OF_COLL;
    }
    // TODO: IN THE ABOVE, THE OCCURENCE OF THE TARGET CERT IN THE COLLECTION
    // IS NOT COVERED (AS ISN'T THE MULTIPLE OCCURENCE OF ANY CERT)
    // => offer function which prunes the collection from duplicates (preserving
    // trusted-quality for resulting instance )
    if(!failed_path && issuer_pos == END_OF_COLL) // || )
    {
        //printf("no failed path, no issuer found, backing up\n");
        /*{
          unsigned i;
          //printf("chain before potential backup  = ");
          for(i = 0; i <= *chain_pos__pu16; i++)
          {
            printf("%u ", chain__bu16[i]);
          }
          printf("\n");

        }*/
      // back up
      while(((*chain_pos__pu16) + 1 >= FLEA_MAX_CERT_CHAIN_DEPTH) || (chain__bu16[(*chain_pos__pu16) + 1] >= cert_collection_size__alu16))
      {
        //printf("backing up: \n");
        failed_path = FLEA_FALSE;
        if((*chain_pos__pu16) == 0)
        {
          FLEA_THROW("no valid certificate path found", FLEA_ERR_CERT_PATH_NOT_FOUND); 
        }
        if(!(((*chain_pos__pu16) + 1) >= FLEA_MAX_CERT_CHAIN_DEPTH)) // causes valid test to fail
        {
          chain__bu16[(*chain_pos__pu16) + 1] = 0;
        }
        (*chain_pos__pu16)--; 
      }


        /*{
          unsigned i;
          printf("chain after potential backup  = ");
          for(i = 0; i <= *chain_pos__pu16; i++)
          {
            printf("%u ", chain__bu16[i]);
          }
          printf("\n");

        }*/
    }
    //else if(*chain_pos__pu16 + 1 < FLEA_MAX_CERT_CHAIN_DEPTH )
    else if(!failed_path && (issuer_pos != END_OF_COLL)) // new issuer found 
    {
      /* found a candidate */
        // add untrusted issuer to the chain.
        // capacity was already checked above
        //printf("placing issuer candidate into chain\n");
        (*chain_pos__pu16)++;
        chain__bu16[(*chain_pos__pu16)] = issuer_pos;
        continue; 
      
    }  

    // no issuer new issuer found (backed up or not, maybe stepped down from invalid trust anchor). try the next one at the
    // current level
    chain__bu16[(*chain_pos__pu16) + 1] += 1;
    //printf("incrementing issuer search position to %u\n", chain__bu16[(*chain_pos__pu16) + 1]);


  } 


  FLEA_THR_FIN_SEC(
      );

}

flea_err_t THR_flea_cert_chain_t__ctor(flea_cert_chain_t *chain__pt, flea_x509_cert_ref_t *target_cert__pt)
{
  FLEA_THR_BEG_FUNC();
#ifdef FLEA_USE_HEAP_BUF
  //FLEA_ALLOC_MEM(chain__pt->cert_collection__pt, FLEA_MAX_CERT_COLL...);
  FLEA_ALLOC_MEM_ARR(chain__pt->chain__bu16, FLEA_MAX_CERT_CHAIN_DEPTH);
#endif

  FLEA_CCALL(THR_flea_cert_chain_t__add_cert_without_trust_status(chain__pt, target_cert__pt));
  FLEA_THR_FIN_SEC_empty(); 
}

flea_err_t THR_flea_cert_chain_t__add_cert_without_trust_status(flea_cert_chain_t* chain__pt, const flea_x509_cert_ref_t * cert_ref__pt)
{
  FLEA_THR_BEG_FUNC();
  if(chain__pt->cert_collection_size__u16 == FLEA_MAX_CERT_COLLECTION_SIZE)
  {
    FLEA_THROW("cert collection full", FLEA_ERR_BUFF_TOO_SMALL);
  }
  chain__pt->cert_collection__pt[chain__pt->cert_collection_size__u16] = *cert_ref__pt;
  chain__pt->cert_collection_size__u16++;
  FLEA_THR_FIN_SEC_empty(); 
}


flea_err_t THR_flea_cert_chain_t__add_trust_anchor_cert(flea_cert_chain_t* chain__pt, const flea_x509_cert_ref_t * cert_ref__pt)
{
  FLEA_THR_BEG_FUNC();
  if(chain__pt->cert_collection_size__u16 == FLEA_MAX_CERT_COLLECTION_SIZE)
  {
    FLEA_THROW("cert collection full", FLEA_ERR_BUFF_TOO_SMALL);
  }
  chain__pt->cert_collection__pt[chain__pt->cert_collection_size__u16] = *cert_ref__pt;
  chain__pt->cert_collection__pt[chain__pt->cert_collection_size__u16].is_trusted__b = FLEA_TRUE;
  chain__pt->cert_collection_size__u16++;
  FLEA_THR_FIN_SEC_empty(); 
}

#endif /* #ifdef FLEA_HAVE_ASYM_SIG */
