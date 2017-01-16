/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */


#ifndef _flea_namespace_asn1__H_
#define _flea_namespace_asn1__H_

#include "flea/ber_dec.h"

#define CFT_MAKE3(class_, form_, type_) (FLEA_ASN1_CFT_MAKE3(class_, form_, type_) 
#define CFT_MAKE2(class_form_, type_) FLEA_ASN1_CFT_MAKE2(class_form_, type_) 
#define CFT_GET_C(cft) FLEA_ASN1_CFT_GET_C(cft) 
#define CFT_GET_F(cft) FLEA_ASN1_CFT_GET_F(cft) 
#define CFT_GET_CF(cft) FLEA_ASN1_CFT_GET_CF(cft) 
#define CFT_GET_T(cft) FLEA_ASN1_CFT_GET_T(cft) 

#define UNIVERSAL_PRIMITIVE FLEA_ASN1_UNIVERSAL_PRIMITIVE
#define CONTEXT_SPECIFIC   FLEA_ASN1_CONTEXT_SPECIFIC   
#define UNIVERSAL          FLEA_ASN1_UNIVERSAL          
#define APPLICATION        FLEA_ASN1_APPLICATION        
#define CONSTRUCTED        FLEA_ASN1_CONSTRUCTED        
#define SEQUENCE           FLEA_ASN1_SEQUENCE           
#define SET                FLEA_ASN1_SET                
#define BOOL               FLEA_ASN1_BOOL               
#define INT                FLEA_ASN1_INT                
#define BIT_STRING         FLEA_ASN1_BIT_STRING         
#define OCTET_STRING       FLEA_ASN1_OCTET_STRING       
#define OID                FLEA_ASN1_OID                
#define UTF8_STR           FLEA_ASN1_UTF8_STR           
#define PRINTABLE_STR      FLEA_ASN1_PRINTABLE_STR      
#define GENERALIZED_TIME   FLEA_ASN1_GENERALIZED_TIME   
#define UTC_TIME           FLEA_ASN1_UTC_TIME           


#endif /* h-guard */
