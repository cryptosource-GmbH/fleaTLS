/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#ifndef _flea_pk_def__H_
#define _flea_pk_def__H_


#define FLEA_PUBKEY_STRENGTH_MASK__256 3
#define FLEA_PUBKEY_STRENGTH_MASK__128 2
#define FLEA_PUBKEY_STRENGTH_MASK__112 1
#define FLEA_PUBKEY_STRENGTH_MASK__80  0
#define FLEA_PUBKEY_STRENGTH_MASK__0   4

#define FLEA_X509_FLAGS_SEC_LEVEL_OFFS 1

#define FLEA_PK_SEC_LEV_BIT_MASK_FROM_X509_FLAGS(flags) ((flags >> FLEA_X509_FLAGS_SEC_LEVEL_OFFS) & ((1 << 4) - 1))

#endif /* h-guard */
