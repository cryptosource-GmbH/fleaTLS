/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "internal/common/default.h"
#include "flea/error_handling.h"
#include "internal/common/ber_dec.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/namespace_asn1.h"
#include "flea/mem_read_stream.h"

#define FLEA_BER_DEC_LEVELS_PRE_ALLOC 5

#define FLEA_BER_DEC_CURR_REM_LEN(dec__pt) dec__pt->allo_open_cons__bdtl[dec__pt->level__alu8]


typedef enum { flea_accept_any_tag, flea_be_strict_about_tag } flea_tag_verify_mode_t;

typedef enum { extr_ref_to_tlv, extr_ref_to_v, extr_read_v } access_mode_t;


flea_err_t THR_flea_ber_dec_t__ctor(
  flea_ber_dec_t*   dec__pt,
  flea_rw_stream_t* read_stream__pt,
  flea_dtl_t        length_limit__dtl
)
{
  FLEA_THR_BEG_FUNC();
  dec__pt->level__alu8 = 0;
  dec__pt->source__pt  = read_stream__pt;
#ifdef FLEA_USE_HEAP_BUF
  FLEA_ALLOC_MEM_ARR(dec__pt->allo_open_cons__bdtl, FLEA_BER_DEC_LEVELS_PRE_ALLOC);
  dec__pt->alloc_levels__alu8 = FLEA_BER_DEC_LEVELS_PRE_ALLOC;
  FLEA_SET_ARR(dec__pt->allo_open_cons__bdtl, 0, FLEA_BER_DEC_LEVELS_PRE_ALLOC);
#else
  dec__pt->alloc_levels__alu8 = FLEA_NB_ARRAY_ENTRIES(dec__pt->allo_open_cons__bdtl);
#endif
  dec__pt->length_limit__dtl       = length_limit__dtl;
  dec__pt->stored_tag_nb_bytes__u8 = 0;
  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_flea_ber_dec_t__consume_current_length(
  flea_ber_dec_t* dec__pt,
  flea_dtl_t      length__dtl
)
{
  FLEA_THR_BEG_FUNC();

  if(dec__pt->level__alu8 && (dec__pt->allo_open_cons__bdtl[dec__pt->level__alu8] < length__dtl))
  {
    FLEA_THROW("inner length exceeding outer length", FLEA_ERR_ASN1_DER_DEC_ERR);
  }
  dec__pt->allo_open_cons__bdtl[dec__pt->level__alu8] -= length__dtl;
  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_flea_ber_dec_t__read_byte_and_consume_length(
  flea_ber_dec_t* dec__pt,
  flea_u8_t*      out_mem__pu8
)
{
  FLEA_THR_BEG_FUNC();
  // FLEA_CCALL(THR_flea_rw_stream_t__read_byte(dec__pt->source__pt, out_mem__pu8));
  FLEA_CCALL(THR_flea_rw_stream_t__read_byte(dec__pt->source__pt, out_mem__pu8));
  FLEA_CCALL(THR_flea_ber_dec_t__consume_current_length(dec__pt, 1));
  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_flea_ber_dec_t__verify_next_tag_opt(
  flea_ber_dec_t*        dec__pt,
  flea_asn1_tag_t        type__t,
  flea_al_u8_t           class_form__alu8,
  flea_bool_t*           optional_found__pb,
  flea_tag_verify_mode_t tag_verify_mode__t
)
{
  flea_u8_t next_byte;
  flea_al_u8_t count = 0;
  flea_al_u8_t found_class_form;
  flea_asn1_tag_t found_type;

  FLEA_THR_BEG_FUNC();
  if(!flea_ber_dec_t__has_current_more_data(dec__pt))
  {
    if(*optional_found__pb)
    {
      *optional_found__pb = FLEA_FALSE;
      FLEA_THR_RETURN();
    }
    else
    {
      FLEA_THROW("trying to decode with no more data left in level", FLEA_ERR_ASN1_DER_DEC_ERR);
    }
  }
  if(dec__pt->stored_tag_nb_bytes__u8)
  {
    found_class_form = dec__pt->stored_tag_class_form__u8;
    found_type       = dec__pt->stored_tag_type__t;
  }
  else
  {
    FLEA_CCALL(THR_flea_ber_dec_t__read_byte_and_consume_length(dec__pt, &next_byte));

    // check for short form tag
    if((next_byte & 0x1F) != 0x1F)
    {
      found_class_form = next_byte & 0xE0;
      found_type       = next_byte & 0x1F;
    }
    else
    {
      found_type = found_class_form = 0;
      while(next_byte & 0x80)
      {
        /* more tag octets to follow */
        if(++count == 4)
        {
          FLEA_THROW("long form tag of more than 32 bits", FLEA_ERR_ASN1_DER_DEC_ERR);
        }
        FLEA_CCALL(THR_flea_ber_dec_t__read_byte_and_consume_length(dec__pt, &next_byte));
        found_type = found_type << 8 | (next_byte & 0x7F);
      }
    }
  }
  if(tag_verify_mode__t == flea_be_strict_about_tag && (found_type != type__t || found_class_form != class_form__alu8))
  {
    if(!dec__pt->stored_tag_nb_bytes__u8)
    {
      dec__pt->stored_tag_nb_bytes__u8   = count + 1;
      dec__pt->stored_tag_type__t        = found_type;
      dec__pt->stored_tag_class_form__u8 = found_class_form;
    }
    if(!*optional_found__pb)
    {
      FLEA_THROW("unexpected ASN.1 tag", FLEA_ERR_ASN1_DER_DEC_ERR);
    }
    else
    {
      *optional_found__pb = FLEA_FALSE;
    }
  }
  else // found matching tag
  {
    dec__pt->stored_tag_nb_bytes__u8 = 0;
    *optional_found__pb = FLEA_TRUE;
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_ber_dec_t__verify_next_tag_opt */

static flea_err_t THR_flea_ber_dec_t__verify_next_tag(
  flea_ber_dec_t* dec__pt,
  flea_asn1_tag_t type__t,
  flea_al_u8_t    class_form__alu8
)
{
  flea_bool_t b = FLEA_FALSE;

  return THR_flea_ber_dec_t__verify_next_tag_opt(dec__pt, type__t, class_form__alu8, &b, flea_be_strict_about_tag);
}

#ifdef FLEA_USE_HEAP_BUF
static flea_err_t THR_flea_ber_dec_t__grow_levels(
  flea_ber_dec_t* dec__pt,
  flea_al_u8_t    new_size
)
{
  flea_dtl_t* tmp__pdtl;

  FLEA_THR_BEG_FUNC();

  FLEA_ALLOC_MEM_ARR(tmp__pdtl, new_size);
  FLEA_CP_ARR(tmp__pdtl, dec__pt->allo_open_cons__bdtl, dec__pt->level__alu8 + 1);

  FLEA_FREE_MEM(dec__pt->allo_open_cons__bdtl);
  dec__pt->allo_open_cons__bdtl = tmp__pdtl;
  /** don't free tmp__pu8, since there is no second thrower in the function **/
  FLEA_THR_FIN_SEC_empty();
}

#endif /* #ifdef FLEA_USE_HEAP_BUF */

static flea_err_t THR_flea_ber_dec_t__decode_length(
  flea_ber_dec_t* dec__pt,
  flea_dtl_t*     length__pdtl
)
{
  flea_u8_t first_byte;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_ber_dec_t__read_byte_and_consume_length(dec__pt, &first_byte));
  if(first_byte <= 127)
  {
    // short definite length
    *length__pdtl = first_byte;
  }
  else
  {
    // long definite length
    flea_al_u8_t i;
    flea_dtl_t length__dtl = 0;
    first_byte &= ~0x80;
    for(i = 0; i < first_byte; i++)
    {
      flea_u8_t next_byte;
      FLEA_CCALL(THR_flea_ber_dec_t__read_byte_and_consume_length(dec__pt, &next_byte));
      length__dtl = (length__dtl << 8) | next_byte;
      /* check if the MSB is already populated and there is one more to go */
      if((i != next_byte - 1) && (length__dtl & (((flea_dtl_t) 0xFF) << ((sizeof(length__dtl) - 1) * 8))))
      {
        FLEA_THROW("long definite length overflows flea_dtl_t", FLEA_ERR_ASN1_DER_EXCSS_LEN);
      }
    }
    *length__pdtl = length__dtl;
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_bool_t flea_ber_dec_t__has_current_more_data(flea_ber_dec_t* dec__pt)
{
  return dec__pt->level__alu8 ? FLEA_BER_DEC_CURR_REM_LEN(dec__pt) : FLEA_TRUE;
}

flea_err_t THR_flea_ber_dec_t__open_sequence(flea_ber_dec_t* dec__pt)
{
  return THR_flea_ber_dec_t__open_constructed(dec__pt, FLEA_ASN1_SEQUENCE, FLEA_ASN1_CONSTRUCTED);
}

flea_err_t THR_flea_ber_dec_t__open_set(flea_ber_dec_t* dec__pt)
{
  return THR_flea_ber_dec_t__open_constructed(dec__pt, FLEA_ASN1_SET, FLEA_ASN1_CONSTRUCTED);
}

static flea_err_t THR_flea_ber_dec_t__open_constructed_opt(
  flea_ber_dec_t* dec__pt,
  flea_asn1_tag_t type__t,
  flea_al_u8_t    class_form__alu8,
  flea_bool_t*    optional_found__pb
)
{
  flea_dtl_t length__dtl;

  FLEA_THR_BEG_FUNC();

  if(*optional_found__pb)
  {
    FLEA_CCALL(
      THR_flea_ber_dec_t__verify_next_tag_opt(
        dec__pt,
        type__t,
        class_form__alu8,
        optional_found__pb,
        flea_be_strict_about_tag
      )
    );
    if(!*optional_found__pb)
    {
      FLEA_THR_RETURN();
    }
  }
  else
  {
    FLEA_CCALL(THR_flea_ber_dec_t__verify_next_tag(dec__pt, type__t, class_form__alu8));
  }
  FLEA_CCALL(THR_flea_ber_dec_t__decode_length(dec__pt, &length__dtl));
  if(dec__pt->level__alu8 + 1 >= dec__pt->alloc_levels__alu8)
  {
#ifdef FLEA_USE_HEAP_BUF
    // printf("called grow levels\n");
    FLEA_CCALL(THR_flea_ber_dec_t__grow_levels(dec__pt, dec__pt->level__alu8 + 2 + FLEA_BER_DEC_LEVELS_PRE_ALLOC));
#else
    FLEA_THROW("nesting too deep", FLEA_ERR_ASN1_DER_EXCSS_NST);
#endif
  }

  /* substract expected length from current (in this respect outer)
   * length. The tag and length octets of the newly opened constructed have
   * already been substracted */
  FLEA_CCALL(THR_flea_ber_dec_t__consume_current_length(dec__pt, length__dtl));
  /* switch to new level */
  if(dec__pt->length_limit__dtl && length__dtl > dec__pt->length_limit__dtl)
  {
    FLEA_THROW("DER decoder length limit exceeded", FLEA_ERR_ASN1_DER_CST_LEN_LIMIT_EXCEEDED);
  }
  dec__pt->level__alu8++;
  dec__pt->allo_open_cons__bdtl[dec__pt->level__alu8] = length__dtl;
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_ber_dec_t__open_constructed_opt */

flea_err_t THR_flea_ber_dec_t__open_constructed_optional_cft(
  flea_ber_dec_t* dec__pt,
  flea_asn1_tag_t cft,
  flea_bool_t*    found__pb
)
{
  flea_bool_t optional_found__b = FLEA_TRUE;
  flea_asn1_tag_t type__t       = CFT_GET_T(cft);
  flea_al_u8_t class_form__alu8 = CFT_GET_CF(cft);

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_ber_dec_t__open_constructed_opt(dec__pt, type__t, class_form__alu8, &optional_found__b));
  *found__pb = optional_found__b;
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_ber_dec_t__open_constructed_optional(
  flea_ber_dec_t* dec__pt,
  flea_asn1_tag_t type__t,
  flea_al_u8_t    class_form__alu8,
  flea_bool_t*    found__pb
)
{
  flea_bool_t optional_found__b = FLEA_TRUE;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_ber_dec_t__open_constructed_opt(dec__pt, type__t, class_form__alu8, &optional_found__b));
  *found__pb = optional_found__b;
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_ber_dec_t__open_constructed(
  flea_ber_dec_t* dec__pt,
  flea_asn1_tag_t type__t,
  flea_al_u8_t    class_form__alu8
)
{
  flea_bool_t optional__b = FLEA_FALSE;

  return THR_flea_ber_dec_t__open_constructed_opt(dec__pt, type__t, class_form__alu8, &optional__b);
}

flea_err_t THR_flea_ber_dec_t__close_constructed_skip_remaining(flea_ber_dec_t* dec__pt)
{
  flea_dtl_t remaining__dtl;

  FLEA_THR_BEG_FUNC();

  if(!dec__pt->level__alu8)
  {
    FLEA_THROW("trying to close constructed at outmost level", FLEA_ERR_ASN1_DER_CALL_SEQ_ERR);
  }
  remaining__dtl = dec__pt->allo_open_cons__bdtl[dec__pt->level__alu8];
  if(remaining__dtl)
  {
    /* if a tag was cached, we loose it now */
    dec__pt->stored_tag_nb_bytes__u8 = 0;
    FLEA_CCALL(THR_flea_rw_stream_t__skip_read(dec__pt->source__pt, remaining__dtl));
  }
  dec__pt->level__alu8--;

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_ber_dec_t__close_constructed_at_end(flea_ber_dec_t* dec__pt)
{
  FLEA_THR_BEG_FUNC();
  if((dec__pt->stored_tag_nb_bytes__u8 != 0) || (dec__pt->allo_open_cons__bdtl[dec__pt->level__alu8] != 0))
  {
    FLEA_THROW("trying to close constructed which has remaining data", FLEA_ERR_ASN1_DER_DEC_ERR);
  }
  FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_skip_remaining(dec__pt));
  FLEA_THR_FIN_SEC_empty();
}

/**
 * return zero length in len__pdtl if there was a tag but it did not match
 */
static flea_err_t THR_flea_ber_dec_t__get_ref_to_raw_opt_cft(
  flea_ber_dec_t*   dec__pt,
  flea_asn1_tag_t   cft,
  flea_u8_t const** raw__ppu8,
  flea_dtl_t*       raw_len__pdtl,
  flea_bool_t*      optional__pb,
  access_mode_t     ref_extract_mode__t
)
{
  flea_asn1_tag_t type__t       = CFT_GET_T(cft);
  flea_al_u8_t class_form__alu8 = CFT_GET_CF(cft);
  const flea_u8_t* p__pu8;
  flea_dtl_t length__dtl;
  flea_bool_t optional_found__b = *optional__pb;
  flea_tag_verify_mode_t tag_verify_mode__t =
    (ref_extract_mode__t == extr_ref_to_tlv) ? flea_accept_any_tag : flea_be_strict_about_tag;

  FLEA_THR_BEG_FUNC();
  if(!flea_ber_dec_t__has_current_more_data(dec__pt))
  {
    if(!*optional__pb)
    {
      FLEA_THROW("current level has no more data", FLEA_ERR_ASN1_DER_DEC_ERR);
    }
    *optional__pb = FLEA_FALSE;
    FLEA_THR_RETURN();
  }
  if(ref_extract_mode__t == extr_ref_to_tlv)
  {
    // TODO: HACK FOR MEMORY-READ-STREAMS:
    // *raw__ppu8 = flea_rw_stream_t__get_memory_pointer_to_current(dec__pt->source__pt);
    // TODO: instead of providing ref, allocate space, cp the data, and return
    // that pointer. in case of data source memory however, give direct access.
    *raw__ppu8 =
      &((flea_mem_read_stream_help_t*) dec__pt->source__pt->custom_obj__pv)->data__pcu8[((flea_mem_read_stream_help_t*)
      dec__pt->source__pt->custom_obj__pv)->offs__dtl];
    if(!*raw__ppu8)
    {
      FLEA_THROW(
        "trying to get pointer reference to ber obj even though the underlying data source is not of type 'memory'",
        FLEA_ERR_INV_ARG
      );
    }
  }
  FLEA_CCALL(
    THR_flea_ber_dec_t__verify_next_tag_opt(
      dec__pt,
      type__t,
      class_form__alu8,
      &optional_found__b,
      tag_verify_mode__t
    )
  );
  if(*optional__pb && !optional_found__b)
  {
    *optional__pb = FLEA_FALSE;
    FLEA_THR_RETURN();
  }
  FLEA_CCALL(THR_flea_ber_dec_t__decode_length(dec__pt, &length__dtl));
  if(ref_extract_mode__t == extr_ref_to_v || ref_extract_mode__t == extr_ref_to_tlv)
  {
    // TODO: HACK FOR MEMORY-READ-STREAMS:
    // p__pu8 = flea_rw_stream_t__get_memory_pointer_to_current(dec__pt->source__pt);
    p__pu8 =
      &((flea_mem_read_stream_help_t*) dec__pt->source__pt->custom_obj__pv)->data__pcu8[((flea_mem_read_stream_help_t*)
      dec__pt->source__pt->custom_obj__pv)->offs__dtl];


    if(ref_extract_mode__t != extr_ref_to_tlv)
    {
      *raw__ppu8     = p__pu8;
      *raw_len__pdtl = length__dtl;
    }
    else // ref to whole tlv
    {
      *raw_len__pdtl = p__pu8 - *raw__ppu8 + length__dtl;
    }
  }
  FLEA_CCALL(THR_flea_ber_dec_t__consume_current_length(dec__pt, length__dtl));
  if(ref_extract_mode__t == extr_ref_to_v || ref_extract_mode__t == extr_ref_to_tlv)
  {
    FLEA_CCALL(THR_flea_rw_stream_t__skip_read(dec__pt->source__pt, length__dtl));
  }
  else // read_v
  {
    if(length__dtl > *raw_len__pdtl)
    {
      FLEA_THROW("target memory area for ASN.1 decoding output too small", FLEA_ERR_ASN1_DEC_TRGT_BUF_TOO_SMALL);
    }
    FLEA_CCALL(THR_flea_rw_stream_t__force_read(dec__pt->source__pt, (flea_u8_t*) *raw__ppu8, length__dtl));
    *raw_len__pdtl = length__dtl;
  }

  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_ber_dec_t__get_ref_to_raw_opt_cft */

flea_err_t THR_flea_ber_dec_t__get_ref_to_next_tlv_raw(
  flea_ber_dec_t* dec__pt,
  flea_ref_cu8_t* ref__pt
)
{
  flea_bool_t optional__b = FLEA_FALSE;

  return THR_flea_ber_dec_t__get_ref_to_raw_opt_cft(
    dec__pt,
    /*unspec cft */ 0,
    &ref__pt->data__pcu8,
    &ref__pt->len__dtl,
    &optional__b,
    extr_ref_to_tlv
  );
}

flea_err_t THR_flea_ber_dec_t__get_ref_to_next_tlv_raw_optional(
  flea_ber_dec_t* dec__pt,
  flea_ref_cu8_t* ref__pt
)
{
  flea_bool_t optional__b = FLEA_TRUE;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_ber_dec_t__get_ref_to_raw_opt_cft(
      dec__pt, /*unspec cft */
      0,
      &ref__pt->data__pcu8,
      &ref__pt->len__dtl,
      &optional__b,
      extr_ref_to_tlv
    )
  );
  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_flea_ber_dec_t__get_ref_to_raw(
  flea_ber_dec_t*   dec__pt,
  flea_asn1_tag_t   type__t,
  flea_al_u8_t      class_form__alu8,
  flea_u8_t const** raw__ppu8,
  flea_dtl_t*       len__pdtl
)
{
  flea_bool_t optional__b = FLEA_FALSE;

  return THR_flea_ber_dec_t__get_ref_to_raw_opt_cft(
    dec__pt,
    FLEA_ASN1_CFT_MAKE2(
      class_form__alu8,
      type__t
    ),
    raw__ppu8,
    len__pdtl,
    &optional__b,
    extr_ref_to_v
  );
}

flea_err_t THR_flea_ber_dec_t__get_ref_to_raw_cft(
  flea_ber_dec_t* dec__pt,
  flea_asn1_tag_t cft,
  flea_ref_cu8_t* ref__pt
)
{
  flea_bool_t optional__b = FLEA_FALSE;

  return THR_flea_ber_dec_t__get_ref_to_raw_opt_cft(
    dec__pt,
    cft,
    &ref__pt->data__pcu8,
    &ref__pt->len__dtl,
    &optional__b,
    extr_ref_to_v
  );
}

static flea_err_t THR_flea_ber_dec__ensure_pos_int_and_remove_leading_zeros(flea_ref_cu8_t* der_ref__pt)
{
  FLEA_THR_BEG_FUNC();
  if(der_ref__pt->data__pcu8[0] & 0x80)
  {
    FLEA_THROW("negative asn1 integer where positive was expected", FLEA_ERR_X509_NEG_INT);
  }
  while((der_ref__pt->len__dtl > 1) && (der_ref__pt->data__pcu8[0] == 0))
  {
    der_ref__pt->len__dtl--;
    der_ref__pt->data__pcu8++;
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_ber_dec_t__get_der_ref_to_positive_int_wo_lead_zeroes(
  flea_ber_dec_t* dec__pt,
  flea_ref_cu8_t* der_ref__pt
)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_ber_dec_t__get_der_ref_to_int(dec__pt, der_ref__pt));
  FLEA_CCALL(THR_flea_ber_dec__ensure_pos_int_and_remove_leading_zeros(der_ref__pt));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_ber_dec_t__get_der_ref_to_positive_int_wo_lead_zeroes_optional(
  flea_ber_dec_t* dec__pt,
  flea_ref_cu8_t* der_ref__pt
)
{
  flea_bool_t optional__b = FLEA_TRUE;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_ber_dec_t__get_ref_to_raw_opt_cft(
      dec__pt,
      FLEA_ASN1_CFT_MAKE2(UNIVERSAL_PRIMITIVE, FLEA_ASN1_INT),
      &der_ref__pt->data__pcu8,
      &der_ref__pt->len__dtl,
      &optional__b,
      extr_ref_to_v
    )
  );
  FLEA_CCALL(THR_flea_ber_dec__ensure_pos_int_and_remove_leading_zeros(der_ref__pt));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_ber_dec_t__get_der_ref_to_int(
  flea_ber_dec_t* dec__pt,
  flea_ref_cu8_t* der_ref__pt
)
{
  return THR_flea_ber_dec_t__get_ref_to_raw(
    dec__pt,
    FLEA_ASN1_INT,
    0,
    &der_ref__pt->data__pcu8,
    &der_ref__pt->len__dtl
  );
}

flea_err_t THR_flea_ber_dec_t__get_der_ref_to_oid(
  flea_ber_dec_t* dec__pt,
  flea_ref_cu8_t* ref__pt
)
{
  return THR_flea_ber_dec_t__get_ref_to_raw(dec__pt, FLEA_ASN1_OID, 0, &ref__pt->data__pcu8, &ref__pt->len__dtl);
}

flea_err_t THR_flea_ber_dec_t__get_ref_to_raw_optional(
  flea_ber_dec_t*   dec__pt,
  flea_asn1_tag_t   type__t,
  flea_al_u8_t      class_form__alu8,
  flea_u8_t const** raw__cppu8,
  flea_dtl_t*       len__pdtl,
  flea_bool_t*      found__pb
)
{
  flea_ref_cu8_t der_ref__t;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(
      dec__pt,
      FLEA_ASN1_CFT_MAKE2(class_form__alu8, type__t),
      &der_ref__t,
      found__pb
    )
  );

  *raw__cppu8 = der_ref__t.data__pcu8;
  *len__pdtl  = der_ref__t.len__dtl;
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(
  flea_ber_dec_t* dec__pt,
  flea_asn1_tag_t cft,
  flea_ref_cu8_t* der_ref__pt,
  flea_bool_t*    found__pb
)
{
  flea_bool_t optional_found__b = FLEA_TRUE;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_ber_dec_t__get_ref_to_raw_opt_cft(
      dec__pt,
      cft,
      &der_ref__pt->data__pcu8,
      &der_ref__pt->len__dtl,
      &optional_found__b,
      extr_ref_to_v
    )
  );
  *found__pb = optional_found__b;
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_ber_dec_t__get_ref_to_string(
  flea_ber_dec_t*       dec__pt,
  flea_asn1_str_type_t* str_type__pt,
  flea_u8_t const**     raw__cppu8,
  flea_dtl_t*           len__pdtl
)
{
  flea_bool_t optional_found__b = FLEA_TRUE;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_ber_dec_t__get_ref_to_raw_optional(
      dec__pt,
      FLEA_ASN1_PRINTABLE_STR,
      FLEA_ASN1_UNIVERSAL_PRIMITIVE,
      raw__cppu8,
      len__pdtl,
      &optional_found__b
    )
  );
  if(optional_found__b == FLEA_TRUE)
  {
    *str_type__pt = flea_asn1_printable_str;
    FLEA_THR_RETURN();
  }
  FLEA_CCALL(
    THR_flea_ber_dec_t__get_ref_to_raw(
      dec__pt,
      FLEA_ASN1_UTF8_STR,
      FLEA_ASN1_UNIVERSAL_PRIMITIVE,
      raw__cppu8,
      len__pdtl
    )
  );
  *str_type__pt = flea_asn1_utf8_str;


  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_ber_dec_t__get_ref_to_string */

flea_err_t THR_flea_ber_dec_t__get_ref_to_date_opt(
  flea_ber_dec_t*        dec__pt,
  flea_asn1_time_type_t* time_type__pt,
  flea_u8_t const**      raw__cppu8,
  flea_dtl_t*            len__pdtl,
  flea_bool_t*           optional_found__pb
)
{
  flea_bool_t optional_found__b = *optional_found__pb;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_ber_dec_t__get_ref_to_raw_optional(
      dec__pt,
      FLEA_ASN1_GENERALIZED_TIME,
      FLEA_ASN1_UNIVERSAL_PRIMITIVE,
      raw__cppu8,
      len__pdtl,
      &optional_found__b
    )
  );
  if(optional_found__b == FLEA_TRUE)
  {
    *time_type__pt      = flea_asn1_generalized_time;
    *optional_found__pb = FLEA_TRUE;
    FLEA_THR_RETURN();
  }
  optional_found__b = *optional_found__pb;
  FLEA_CCALL(
    THR_flea_ber_dec_t__get_ref_to_raw_optional(
      dec__pt,
      FLEA_ASN1_UTC_TIME,
      FLEA_ASN1_UNIVERSAL_PRIMITIVE,
      raw__cppu8,
      len__pdtl,
      &optional_found__b
    )
  );
  if(optional_found__b == FLEA_TRUE)
  {
    *time_type__pt      = flea_asn1_utc_time;
    *optional_found__pb = FLEA_TRUE;
    FLEA_THR_RETURN();
  }
  if(!*optional_found__pb)
  {
    FLEA_THROW("non-optional date not present", FLEA_ERR_ASN1_DER_DEC_ERR);
  }
  *optional_found__pb = FLEA_FALSE;
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_ber_dec_t__get_ref_to_date_opt */

flea_err_t THR_flea_ber_dec_t__read_value_raw(
  flea_ber_dec_t* dec__pt,
  flea_asn1_tag_t type__t,
  flea_al_u8_t    class_form__alu8,
  flea_u8_t*      out_mem__pu8,
  flea_dtl_t*     out_mem_len__pdtl
)
{
  return THR_flea_ber_dec_t__read_value_raw_cft(
    dec__pt,
    FLEA_ASN1_CFT_MAKE2(
      class_form__alu8,
      type__t
    ),
    out_mem__pu8,
    out_mem_len__pdtl
  );
}

flea_err_t THR_flea_ber_dec_t__read_value_raw_cft(
  flea_ber_dec_t* dec__pt,
  flea_asn1_tag_t cft,
  flea_u8_t*      out_mem__pu8,
  flea_dtl_t*     out_mem_len__pdtl
)
{
  flea_bool_t optional_found__b = FLEA_FALSE;

  return THR_flea_ber_dec_t__read_value_raw_cft_opt(dec__pt, cft, out_mem__pu8, out_mem_len__pdtl, &optional_found__b);
}

flea_err_t THR_flea_ber_dec_t__read_value_raw_cft_opt(
  flea_ber_dec_t* dec__pt,
  flea_asn1_tag_t cft,
  flea_u8_t*      out_mem__pu8,
  flea_dtl_t*     out_mem_len__pdtl,
  flea_bool_t*    optional_found__pb
)
{
  flea_u8_t* out_mem_local__pu8 = out_mem__pu8;

  return THR_flea_ber_dec_t__get_ref_to_raw_opt_cft(
    dec__pt,
    cft,
    (const flea_u8_t**) &out_mem_local__pu8,
    out_mem_len__pdtl,
    optional_found__pb,
    extr_read_v
  );
}

flea_err_t THR_flea_ber_dec_t__decode_boolean_default_false(
  flea_ber_dec_t* dec__pt,
  flea_bool_t*    result__p
)
{
  *result__p = FLEA_FALSE;
  return THR_flea_ber_dec_t__decode_boolean_default(dec__pt, result__p);
}

flea_err_t THR_flea_ber_dec_t__decode_boolean_default(
  flea_ber_dec_t* dec__pt,
  flea_bool_t*    result__p
)
{
  const flea_u8_t* data__pcu8;
  flea_dtl_t len__dtl = 1;
  flea_bool_t optional_found__b = FLEA_TRUE;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_ber_dec_t__get_ref_to_raw_opt_cft(
      dec__pt,
      FLEA_ASN1_BOOL,
      &data__pcu8,
      &len__dtl,
      &optional_found__b,
      extr_ref_to_v
    )
  );
  if(optional_found__b)
  {
    if(len__dtl != 1 || (data__pcu8[0] != 0 && data__pcu8[0] != 0xFF))
    {
      FLEA_THROW("error decoding boolean", FLEA_ERR_ASN1_DER_DEC_ERR);
    }
    *result__p = data__pcu8[0] ? FLEA_TRUE : FLEA_FALSE;
  }


  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_flea_ber_dec_t__get_ref_to_implicit_universal_optional_with_inner_toggled(
  flea_ber_dec_t* dec__pt,
  flea_al_u8_t    outer_tag__alu8,
  flea_asn1_tag_t encap_type__t,
  flea_ref_cu8_t* ref__pt,
  flea_bool_t     with_inner__b
)
{
  flea_bool_t is_present__b;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(
    THR_flea_ber_dec_t__open_constructed_optional(
      dec__pt,
      outer_tag__alu8,
      FLEA_ASN1_CONSTRUCTED | FLEA_ASN1_CONTEXT_SPECIFIC,
      &is_present__b
    )
  );
  if(is_present__b)
  {
    if(with_inner__b)
    {
      FLEA_CCALL(
        THR_flea_ber_dec_t__get_ref_to_raw(
          dec__pt,
          encap_type__t,
          FLEA_ASN1_UNIVERSAL_PRIMITIVE,
          &ref__pt->data__pcu8,
          &ref__pt->len__dtl
        )
      );
    }
    else
    {
      FLEA_CCALL(THR_flea_ber_dec_t__get_ref_to_next_tlv_raw(dec__pt, ref__pt));
    }
    FLEA_CCALL(THR_flea_ber_dec_t__close_constructed_at_end(dec__pt));
  }
  else
  {
    FLEA_DER_REF_SET_ABSENT(ref__pt);
  }
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_ber_dec_t__get_ref_to_implicit_universal_optional_with_inner_toggled */

flea_err_t THR_flea_ber_dec_t__get_ref_to_implicit_universal_optional_with_inner(
  flea_ber_dec_t* dec__pt,
  flea_al_u8_t    outer_tag__alu8,
  flea_asn1_tag_t encap_type__t,
  flea_ref_cu8_t* ref__pt
)
{
  return THR_flea_ber_dec_t__get_ref_to_implicit_universal_optional_with_inner_toggled(
    dec__pt,
    outer_tag__alu8,
    encap_type__t,
    ref__pt,
    FLEA_TRUE
  );
}

flea_err_t THR_flea_ber_dec_t__get_ref_to_implicit_universal_optional(
  flea_ber_dec_t* dec__pt,
  flea_al_u8_t    outer_tag__alu8,
  flea_asn1_tag_t encap_type__t,
  flea_ref_cu8_t* ref__pt
)
{
  return THR_flea_ber_dec_t__get_ref_to_implicit_universal_optional_with_inner_toggled(
    dec__pt,
    outer_tag__alu8,
    encap_type__t,
    ref__pt,
    FLEA_FALSE
  );
}

void flea_ber_dec_t__dtor(flea_ber_dec_t* dec__pt)
{
#ifdef FLEA_USE_HEAP_BUF
  FLEA_FREE_MEM_CHK_SET_NULL(dec__pt->allo_open_cons__bdtl);
#endif
}

static flea_err_t THR_flea_ber_dec_t__decode_short_bit_str_to_u32_opt(
  flea_ber_dec_t* dec__pt,
  flea_u32_t*     val__pu32,
  flea_al_u8_t*   nb_bits__palu8,
  flea_bool_t*    optional_found__pb
)
{
  flea_al_u8_t nb_bits__alu8;
  flea_u32_t val__u32 = 0;
  flea_u8_t enc__au8[5];
  flea_dtl_t enc_len__dtl       = sizeof(enc__au8);
  flea_bool_t optional_found__b = *optional_found__pb;
  flea_al_u8_t unused__alu8;
  flea_al_u8_t i;
  flea_asn1_tag_t cft = FLEA_ASN1_CFT_MAKE2(FLEA_ASN1_UNIVERSAL_PRIMITIVE, BIT_STRING);

  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_ber_dec_t__read_value_raw_cft_opt(dec__pt, cft, enc__au8, &enc_len__dtl, &optional_found__b));
  if(!optional_found__b)
  {
    *optional_found__pb = FLEA_FALSE;
    FLEA_THR_RETURN();
  }
  if(enc_len__dtl <= 1)
  {
    *nb_bits__palu8 = 0;
    FLEA_THR_RETURN();
  }
  // at least one content octet from here on
  unused__alu8 = enc__au8[0];
  if(unused__alu8 > 8)
  {
    unused__alu8 = 8;
  }
  for(i = 1; i < enc_len__dtl; i++)
  {
    val__u32 |= (enc__au8[i] << (i * 8));
  }
  nb_bits__alu8 = (enc_len__dtl - 1) * 8 - unused__alu8;

  *val__pu32      = val__u32;
  *nb_bits__palu8 = nb_bits__alu8;
  FLEA_THR_FIN_SEC_empty();
} /* THR_flea_ber_dec_t__decode_short_bit_str_to_u32_opt */

flea_err_t THR_flea_ber_dec_t__decode_short_bit_str_to_u32_optional(
  flea_ber_dec_t* dec__pt,
  flea_u32_t*     val__pu32,
  flea_al_u8_t*   nb_bits__palu8,
  flea_bool_t*    found__pb
)
{
  FLEA_THR_BEG_FUNC();
  flea_bool_t optional__b = FLEA_TRUE;
  FLEA_CCALL(THR_flea_ber_dec_t__decode_short_bit_str_to_u32_opt(dec__pt, val__pu32, nb_bits__palu8, &optional__b));
  *found__pb = optional__b;

  FLEA_THR_FIN_SEC_empty();
}

flea_al_u8_t flea_ber_dec_t__get_nb_bits_from_bit_string(const flea_ref_cu8_t* bit_string__pt)
{
  flea_al_u8_t unsused__alu8;

  if(bit_string__pt->len__dtl < 2)
  {
    return 0;
  }

  if(bit_string__pt->data__pcu8[0] > 8)
  {
    unsused__alu8 = 8;
  }
  else
  {
    unsused__alu8 = bit_string__pt->data__pcu8[0];
  }
  return bit_string__pt->len__dtl * 8 - unsused__alu8;
}

flea_err_t THR_flea_ber_dec__get_ref_to_bit_string_content_no_unused_bits(
  const flea_ref_cu8_t* raw_bit_str__pt,
  flea_ref_cu8_t*       content__pt
)
{
  FLEA_THR_BEG_FUNC();
  if(raw_bit_str__pt->len__dtl < 1)
  {
    FLEA_THROW("bit string of zero length", FLEA_ERR_ASN1_DER_DEC_ERR);
  }
  if(raw_bit_str__pt->data__pcu8[0])
  {
    FLEA_THROW("unused bits in bit string assumed to have none", FLEA_ERR_X509_BIT_STR_ERR);
  }
  content__pt->len__dtl   = raw_bit_str__pt->len__dtl - 1;
  content__pt->data__pcu8 = raw_bit_str__pt->data__pcu8 + 1;

  FLEA_THR_FIN_SEC_empty();
}

static flea_err_t THR_flea_ber_dec_t__decode_integer_u32_opt(
  flea_ber_dec_t* dec__pt,
  flea_asn1_tag_t cft,
  flea_u32_t*     result__pu32,
  flea_bool_t*    optional_found__pb
)
{
  flea_u8_t enc_int__au8 [4];
  flea_dtl_t enc_int_len__dtl = 4;
  flea_u32_t result__u32      = 0;
  flea_al_u8_t i;
  flea_bool_t optional__b = *optional_found__pb;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_ber_dec_t__read_value_raw_cft_opt(dec__pt, cft, enc_int__au8, &enc_int_len__dtl, &optional__b));
  if(*optional_found__pb && !optional__b)
  {
    *optional_found__pb = FLEA_FALSE;
    FLEA_THR_RETURN();
  }
  *optional_found__pb = optional__b;

  if(!enc_int_len__dtl)
  {
    FLEA_THROW("empty asn1 integer", FLEA_ERR_ASN1_DER_DEC_ERR);
  }
  if(enc_int__au8[0] & 0x80)
  {
    FLEA_THROW("negative asn1 integer where positive was expected", FLEA_ERR_X509_NEG_INT);
  }
  for(i = 0; i < enc_int_len__dtl; i++)
  {
    result__u32 <<= 8;
    result__u32  |= enc_int__au8[i];
  }
  *result__pu32 = result__u32;
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_ber_dec_t__decode_integer_u32_default(
  flea_ber_dec_t* dec__pt,
  flea_asn1_tag_t cft,
  flea_u32_t*     result__pu32,
  flea_u32_t      default__u32
)
{
  FLEA_THR_BEG_FUNC();
  flea_bool_t found__b;
  FLEA_CCALL(THR_flea_ber_dec_t__decode_integer_u32_optional(dec__pt, cft, result__pu32, &found__b));
  if(!found__b)
  {
    *result__pu32 = default__u32;
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_ber_dec_t__decode_integer_u32_optional(
  flea_ber_dec_t* dec__pt,
  flea_asn1_tag_t cft,
  flea_u32_t*     result__pu32,
  flea_bool_t*    found__pb
)
{
  *found__pb = FLEA_TRUE;
  return THR_flea_ber_dec_t__decode_integer_u32_opt(dec__pt, cft, result__pu32, found__pb);
}

flea_err_t THR_flea_ber_dec_t__decode_integer_u32(
  flea_ber_dec_t* dec__pt,
  flea_asn1_tag_t cft,
  flea_u32_t*     result__pu32
)
{
  flea_bool_t optional__b = FLEA_FALSE;

  return THR_flea_ber_dec_t__decode_integer_u32_opt(dec__pt, cft, result__pu32, &optional__b);
}

flea_bool_t flea_ber_dec__are_der_refs_equal(
  const flea_ref_cu8_t* a__pt,
  const flea_ref_cu8_t* b__pt
)
{
  if(a__pt->len__dtl != b__pt->len__dtl)
  {
    return FLEA_FALSE;
  }
  return (0 == memcmp(a__pt->data__pcu8, b__pt->data__pcu8, a__pt->len__dtl));
}

flea_bool_t flea_ber_dec__is_tlv_null(const flea_ref_cu8_t* ref__pt)
{
  if(ref__pt->len__dtl != 2)
  {
    return FLEA_FALSE;
  }
  if((ref__pt->data__pcu8[0] == 0x05) && (ref__pt->data__pcu8[1] == 0x00))
  {
    return FLEA_TRUE;
  }
  return FLEA_FALSE;
}
