/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_ber_dec__H_
#define _flea_ber_dec__H_

#include "internal/common/default.h"
#include "flea/ber_dec_fwd.h"
#include "flea/data_source.h"
#include "flea/util.h"

#define FLEA_BER_DEC_MAX_NESTING_LEVEL 15

#ifdef __cplusplus
extern "C" {
#endif

#define FLEA_ASN1_UNIVERSAL_PRIMITIVE 0x00
#define FLEA_ASN1_CONTEXT_SPECIFIC    0x80
#define FLEA_ASN1_UNIVERSAL           0x00
#define FLEA_ASN1_APPLICATION         0x40
#define FLEA_ASN1_CONSTRUCTED         0x20
#define FLEA_ASN1_SEQUENCE            0x10
#define FLEA_ASN1_SET                 0x11
#define FLEA_ASN1_BOOL                0x01
#define FLEA_ASN1_INT                 0x02
#define FLEA_ASN1_BIT_STRING          0x03
#define FLEA_ASN1_OCTET_STRING        0x04
#define FLEA_ASN1_OID                 0x06
#define FLEA_ASN1_UTF8_STR            0x0C
#define FLEA_ASN1_PRINTABLE_STR       0x13
#define FLEA_ASN1_GENERALIZED_TIME    24 
#define FLEA_ASN1_UTC_TIME            23

  /** 
   * class, form and type encoded in an u32
   */
#define FLEA_ASN1_CFT_MAKE3(class_, form_, type_) ((((flea_u32_t)class_) << 24) | (((flea_u32_t)form_) << 24) | (((flea_u32_t)type_) & ((flea_u32_t)~0xE0000000L)))
#define FLEA_ASN1_CFT_MAKE2(class_form_, type_) (((flea_u32_t)class_form_) << 24 | (((flea_u32_t)type_) & ((flea_u32_t)~0xE0000000L)))
#define FLEA_ASN1_CFT_GET_C(cft) (((cft) >> 24) & 0xC0)
#define FLEA_ASN1_CFT_GET_F(cft) (((cft) >> 24) & 0x20)
#define FLEA_ASN1_CFT_GET_CF(cft) (((cft) >> 24) & 0xE0)
#define FLEA_ASN1_CFT_GET_T(cft) ((cft) & ~0xE0000000L)

#define FLEA_ASN1_OID_FIRST_BYTE(a1, a2) (a1 * 40 + a2)
  typedef flea_u32_t flea_asn1_tag_t;

  typedef enum { flea_asn1_printable_str, flea_asn1_utf8_str } flea_asn1_str_type_t;

  typedef enum { flea_asn1_utc_time, flea_asn1_generalized_time } flea_asn1_time_type_t;

#define FLEA_DER_REF_SET_ABSENT(__p) (__p)->data__pcu8 = NULL; (__p)->len__dtl = 0
#define FLEA_DER_REF_IS_ABSENT(__p) ((__p)->data__pcu8 ==  0) 

 struct struct_flea_ber_dec_t
 {
   flea_data_source_t *source__pt;
   flea_al_u8_t level__alu8;  
   flea_al_u8_t alloc_levels__alu8;
#ifdef FLEA_USE_HEAP_BUF
  flea_dtl_t* allo_open_cons__bdtl;
#else
  flea_dtl_t allo_open_cons__bdtl[FLEA_BER_DEC_MAX_NESTING_LEVEL];
#endif
  flea_dtl_t length_limit__dtl;
  flea_asn1_tag_t stored_tag_type__t;
  flea_u8_t stored_tag_class_form__u8;
  flea_u8_t stored_tag_nb_bytes__u8;
 };

#ifdef FLEA_USE_HEAP_BUF
#define flea_ber_dec_t__INIT_VALUE { .allo_open_cons__bdtl = NULL }
#else
#define flea_ber_dec_t__INIT_VALUE { .allo_open_cons__bdtl = {0} }
#endif

/**
 * Create a DER decoder. Despite its name, this encoder currently only performs
 * DER decoding.
 * @param dec pointer to the decoder to create
 * @param source pointer to the data source to read the DER data from
 * @param length_limit limitation of the total length of DER data
 * structure. A value of zero means no limitation
 *
 * @return flea_error code
 *
 */
flea_err_t THR_flea_ber_dec_t__ctor(flea_ber_dec_t* dec, flea_data_source_t *source, flea_dtl_t length_limit);

/**
 * Destroy a decoder.
 * @param dec__pt the decoder to destroy
 */
void flea_ber_dec_t__dtor(flea_ber_dec_t *dec__pt);

/**
 *  Determine if the currently opened constructed has more data.
 * called in the outermost level (e.g. before opening the first constructed) it
 * will always return FLEA_TRUE.
 *
 * @param dec__pt [in] the decoder 
 *
 * @return FLEA_TRUE if the current constructed has more data to process, and
 * FLEA_FALSE otherwise.
 *
 */
flea_bool_t flea_ber_dec_t__has_current_more_data(flea_ber_dec_t *dec__pt);

/**
 * Open a constructed.
 */
flea_err_t THR_flea_ber_dec_t__open_constructed(flea_ber_dec_t *dec__pt, flea_asn1_tag_t type__t, flea_al_u8_t class_form__alu8);

/**
 * Open an optional constructed.
 *
 * @param dec__pt [in] the decoder 
 * @param type__t [in] the type part of the tag
 * @param class_form__alu8 the combined class and form part of the tag
 * (CONSTRUCTED has to be specified explicitly here)
 * @param found__pb [out] receives FLEA_TRUE if the constructed was found,
 * FLEA_FALSE otherwise
 *
 */
flea_err_t THR_flea_ber_dec_t__open_constructed_optional(flea_ber_dec_t *dec__pt, flea_asn1_tag_t type__t, flea_al_u8_t class_form__alu8, flea_bool_t * found__pb);

flea_err_t THR_flea_ber_dec_t__open_constructed_optional_cft(flea_ber_dec_t *dec__pt, flea_asn1_tag_t cft, flea_bool_t * found__pb);

/**
 * Open a sequence.
 */

flea_err_t THR_flea_ber_dec_t__open_sequence(flea_ber_dec_t *dec__pt);
/**
 * Open a set.
 */
flea_err_t THR_flea_ber_dec_t__open_set(flea_ber_dec_t *dec__pt);

/**
 * Close a constructed and verify that there is no more data left in it.
 */
flea_err_t THR_flea_ber_dec_t__close_constructed_at_end(flea_ber_dec_t *dec__pt);

/**
 * Close a constructed and discard any data potentially left in it.
 */
flea_err_t THR_flea_ber_dec_t__close_constructed_skip_remaining(flea_ber_dec_t *dec__pt);
 
/**
 * Read the raw value of the current TLV.
 *
 * @param out_mem__pu8 [out] the memory to receive the read value
 * @param out_mem_len__pdtl [in/out] the caller has to set the pointer target to the maximal length of out_mem__pu8,
 * upon return, it will receive the length of the data read into out_mem__pu8
 */
flea_err_t THR_flea_ber_dec_t__read_value_raw(flea_ber_dec_t *dec__pt, flea_asn1_tag_t type_t, flea_al_u8_t class_form__alu8, flea_u8_t *out_mem__pu8, flea_dtl_t *out_mem_len__pdtl);

/**
 * DEPRECATED
 * @param found_ptr [out] receives FLEA_TRUE if the specified tag was found and FLEA_FALSE otherwise
 * 
 */
flea_err_t THR_flea_ber_dec_t__get_ref_to_raw_optional(flea_ber_dec_t *dec__pt, flea_asn1_tag_t type__t, flea_al_u8_t class_form__alu8, flea_u8_t const** raw__cppu8, flea_dtl_t * len__pdtl, flea_bool_t *found_ptr);

/**
 * Get a reference to an optional value.
 *
 * @param dec__pt [in]
 * @param cft [in]
 * @param der_ref_t [out] object to receive the reference. if the object is not found
 * in the encoded data, then this value remains untouched.
 * @param found__pb [out] receives FLEA_TRUE if the object was found, FLEA_FALSE
 * otherwise
 *
 */
flea_err_t THR_flea_ber_dec_t__get_ref_to_raw_optional_cft(flea_ber_dec_t *dec__pt, flea_asn1_tag_t cft, flea_ref_cu8_t *der_ref__t, flea_bool_t *found__pb);

flea_err_t THR_flea_ber_dec_t__decode_integer_u32_optional(flea_ber_dec_t * dec__pt, flea_asn1_tag_t cft, flea_u32_t * result__pu32, flea_bool_t *found__pb);

flea_err_t THR_flea_ber_dec_t__decode_integer_u32_default(flea_ber_dec_t * dec__pt, flea_asn1_tag_t cft, flea_u32_t * result__pu32, flea_u32_t default__u32);

flea_err_t THR_flea_ber_dec_t__decode_integer_u32(flea_ber_dec_t * dec__pt, flea_asn1_tag_t cft, flea_u32_t * result__pu32);

flea_err_t THR_flea_ber_dec_t__get_der_ref_to_int(flea_ber_dec_t *dec__pt, flea_ref_cu8_t *der_ref__pt);

flea_err_t THR_flea_ber_dec_t__get_der_ref_to_positive_int_wo_lead_zeroes(flea_ber_dec_t *dec__pt, flea_ref_cu8_t *der_ref__pt);

flea_err_t THR_flea_ber_dec_t__get_der_ref_to_positive_int_wo_lead_zeroes_optional(flea_ber_dec_t *dec__pt, flea_ref_cu8_t *der_ref__pt);

flea_err_t THR_flea_ber_dec_t__get_der_ref_to_oid(flea_ber_dec_t *dec__pt, flea_ref_cu8_t *ref__pt);

/**
 * Decode a ASN.1 String. Supported types are printableString and UTF8String. 
 *
 * @param str_type_ptr  [out] receives the value of the decoded string type
 */
flea_err_t THR_flea_ber_dec_t__get_ref_to_string(flea_ber_dec_t *dec__pt, flea_asn1_str_type_t *str_type_ptr, flea_u8_t const** raw__cppu8, flea_dtl_t * len__pdtl);


flea_err_t THR_flea_ber_dec_t__get_ref_to_date(flea_ber_dec_t *dec__pt, flea_asn1_time_type_t *time_type__pt, flea_u8_t const** raw__cppu8, flea_dtl_t * len__pdtl);

flea_err_t THR_flea_ber_dec_t__get_ref_to_date_opt(flea_ber_dec_t *dec__pt, flea_asn1_time_type_t *time_type__pt, flea_u8_t const** raw__cppu8, flea_dtl_t * len__pdtl, flea_bool_t *optional_found__pb);

flea_err_t THR_flea_ber_dec_t__get_ref_to_implicit_universal_optional(flea_ber_dec_t *dec__pt, flea_al_u8_t outer_tag__alu8, flea_asn1_tag_t encap_type__t, flea_ref_cu8_t  *ref__pt);

flea_err_t THR_flea_ber_dec_t__get_ref_to_implicit_universal_optional_with_inner(flea_ber_dec_t *dec__pt, flea_al_u8_t outer_tag__alu8, flea_asn1_tag_t encap_type__t, flea_ref_cu8_t  *ref__pt);

flea_err_t THR_flea_ber_dec_t__get_ref_to_next_tlv_raw(flea_ber_dec_t *dec__pt, flea_ref_cu8_t *ref__pt);

flea_err_t THR_flea_ber_dec_t__get_ref_to_next_tlv_raw_optional(flea_ber_dec_t *dec__pt, flea_ref_cu8_t *ref__pt);

/**
 * This function allows to
 * initialize the result value to its default value prior to calling it.
 * @param dec__pt
 * @param result__pb receives the result if the boolean is encoded. Otherwise,
 * the value pointed to is left unchanged. 
 */
flea_err_t THR_flea_ber_dec_t__decode_boolean_default(flea_ber_dec_t *dec__pt, flea_bool_t* result__pb);

/**
 * Decode an optional boolean value which defaults to false.
 */
flea_err_t THR_flea_ber_dec_t__decode_boolean_default_false(flea_ber_dec_t *dec__pt, flea_bool_t* result__p);


flea_err_t THR_flea_ber_dec_t__read_value_raw_cft(flea_ber_dec_t *dec__pt, flea_asn1_tag_t cft, flea_u8_t *out_mem__pu8, flea_dtl_t *out_mem_len__pdtl);

flea_err_t THR_flea_ber_dec_t__read_value_raw_cft_opt(flea_ber_dec_t *dec__pt, flea_asn1_tag_t cft, flea_u8_t *out_mem__pu8, flea_dtl_t *out_mem_len__pdtl, flea_bool_t *optional_found__pb);

flea_err_t THR_flea_ber_dec_t__get_ref_to_raw_cft(flea_ber_dec_t *dec__pt, flea_asn1_tag_t cft, flea_ref_cu8_t *ref__pt);



flea_bool_t flea_ber_dec__are_der_refs_equal(const flea_ref_cu8_t *a__pt, const flea_ref_cu8_t *b__pt);

/**
 * Decode a bit string of no more than 32 bits into a u32 type. Decoding is
 * optional, and if the object is not found, then no changes are
 * made to the output values val__pu32 and nb_bits__palu8.
 *
 * @param val__pu32 [out] receives the decoded result. The LSBit/LSByte of the u32 is
 * the first bit/byte of the bits string.
 * @param nb_bits__palu8 [out] receives the number of encoded bits in the bit string
 * @param optional_found__pb [in/out] On input, the pointer target deterimes whether the
 * decoding is optional. On function return, it tells whether the object was found (FLEA_TRUE) or not (FLEA_FALSE). 
 *
 */
flea_err_t THR_flea_ber_dec_t__decode_short_bit_str_to_u32_optional(flea_ber_dec_t *dec__pt, flea_u32_t *val__pu32, flea_al_u8_t *nb_bits__palu8, flea_bool_t *optional_found__pb);

flea_al_u8_t flea_ber_dec_t__get_nb_bits_from_bit_string(const flea_ref_cu8_t * bit_string__pt);

/**
 * throws if there are unused bits
 */
flea_err_t THR_flea_ber_dec__get_ref_to_bit_string_content_no_unused_bits(const flea_ref_cu8_t *raw_bit_str__pt, flea_ref_cu8_t *content__pt);

flea_bool_t flea_ber_dec__is_tlv_null(flea_ref_cu8_t *ref__pt);

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
