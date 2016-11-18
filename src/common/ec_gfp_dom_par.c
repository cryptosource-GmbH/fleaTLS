/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "flea/ec_gfp_dom_par.h"
#include "flea/types.h"
#include "flea/array_util.h"
#include "flea/error_handling.h"
#include "internal/common/default.h"
#include <stdlib.h>

#ifdef FLEA_HAVE_ECC

typedef struct
{
  flea_u8_t dp_id;
  const flea_u8_t* dp_ptr;
  flea_u16_t dp_len__u16;
} dp_id_ptr_entry_t;

// TODO: PREDEF PARAMS INTO SEPERATE FILE
//        WITH ADDITIONAL BUILD CONFIG
const flea_u8_t flea_ec_gfp_brainpoolP160r1_domain_params [] =
{
  160 / 8,
//p:
  0xE9,		0x5E,		 0x4A,		0x5F,	 0x73, 0x70, 0x59, 0xDC, 0x60, 0xDF, 0xC7, 0xAD, 0x95, 0xB3, 0xD8, 0x13, 0x95, 0x15, 0x62, 0x0F,
//A:
  0x34,		0x0E,		 0x7B,		0xE2,	 0xA2, 0x80, 0xEB, 0x74, 0xE2, 0xBE, 0x61, 0xBA, 0xDA, 0x74, 0x5D, 0x97, 0xE8, 0xF7, 0xC3, 0x00,
//B:
  0x1E,		0x58,		 0x9A,		0x85,	 0x95, 0x42, 0x34, 0x12, 0x13, 0x4F, 0xAA, 0x2D, 0xBD, 0xEC, 0x95, 0xC8, 0xD8, 0x67, 0x5E, 0x58,
//x(P_0):
  0xBE,		0xD5,		 0xAF,		0x16,	 0xEA, 0x3F, 0x6A, 0x4F, 0x62, 0x93, 0x8C, 0x46, 0x31, 0xEB, 0x5A, 0xF7, 0xBD, 0xBC, 0xDB, 0xC3,
//y(P_0):
  0x16,		0x67,		 0xCB,		0x47,	 0x7A, 0x1A, 0x8E, 0xC3, 0x38, 0xF9, 0x47, 0x41, 0x66, 0x9C, 0x97, 0x63, 0x16, 0xDA, 0x63, 0x21,
//q:
  0x00,
  0xE9,		0x5E,		 0x4A,		0x5F,	 0x73, 0x70, 0x59, 0xDC, 0x60, 0xDF, 0x59, 0x91, 0xD4, 0x50, 0x29, 0x40, 0x9E, 0x60, 0xFC, 0x09,
//i:
  0x00,		0x01
};

const flea_u8_t flea_ec_gfp_brainpoolP192r1_domain_params []  =
{
  192 / 8,
//p:
  0xC3,		0x02,		 0xF4,		0x1D,	 0x93, 0x2A, 0x36, 0xCD, 0xA7, 0xA3, 0x46, 0x30, 0x93, 0xD1, 0x8D, 0xB7, 0x8F, 0xCE, 0x47, 0x6D, 0xE1, 0xA8, 0x62, 0x97,
//A:
  0x6A,		0x91,		 0x17,		0x40,	 0x76, 0xB1, 0xE0, 0xE1, 0x9C, 0x39, 0xC0, 0x31, 0xFE, 0x86, 0x85, 0xC1, 0xCA, 0xE0, 0x40, 0xE5, 0xC6, 0x9A, 0x28, 0xEF,
//B:
  0x46,		0x9A,		 0x28,		0xEF,	 0x7C, 0x28, 0xCC, 0xA3, 0xDC, 0x72, 0x1D, 0x04, 0x4F, 0x44, 0x96, 0xBC, 0xCA, 0x7E, 0xF4, 0x14, 0x6F, 0xBF, 0x25, 0xC9,
//x(P_0):
  0xC0,		0xA0,		 0x64,		0x7E,	 0xAA, 0xB6, 0xA4, 0x87, 0x53, 0xB0, 0x33, 0xC5, 0x6C, 0xB0, 0xF0, 0x90, 0x0A, 0x2F, 0x5C, 0x48, 0x53, 0x37, 0x5F, 0xD6,
//y(P_0):
  0x14,		0xB6,		 0x90,		0x86,	 0x6A, 0xBD, 0x5B, 0xB8, 0x8B, 0x5F, 0x48, 0x28, 0xC1, 0x49, 0x00, 0x02, 0xE6, 0x77, 0x3F, 0xA2, 0xFA, 0x29, 0x9B, 0x8F,
//q:
  0x00,
  0xC3,		0x02,		 0xF4,		0x1D,	 0x93, 0x2A, 0x36, 0xCD, 0xA7, 0xA3, 0x46, 0x2F, 0x9E, 0x9E, 0x91, 0x6B, 0x5B, 0xE8, 0xF1, 0x02, 0x9A, 0xC4, 0xAC, 0xC1,
  0x00,		0x01
};

const flea_u8_t flea_ec_gfp_brainpoolP224r1_domain_params [] =
{
  224 / 8,
//p:
  0xD7,		0xC1,		 0x34,		0xAA,	 0x26, 0x43, 0x66, 0x86, 0x2A, 0x18, 0x30, 0x25, 0x75, 0xD1, 0xD7, 0x87, 0xB0, 0x9F, 0x07, 0x57, 0x97, 0xDA, 0x89, 0xF5, 0x7E, 0xC8, 0xC0, 0xFF,
//A:
  0x68,		0xA5,		 0xE6,		0x2C,	 0xA9, 0xCE, 0x6C, 0x1C, 0x29, 0x98, 0x03, 0xA6, 0xC1, 0x53, 0x0B, 0x51, 0x4E, 0x18, 0x2A, 0xD8, 0xB0, 0x04, 0x2A, 0x59, 0xCA, 0xD2, 0x9F, 0x43,
//B:
  0x25,		0x80,		 0xF6,		0x3C,	 0xCF, 0xE4, 0x41, 0x38, 0x87, 0x07, 0x13, 0xB1, 0xA9, 0x23, 0x69, 0xE3, 0x3E, 0x21, 0x35, 0xD2, 0x66, 0xDB, 0xB3, 0x72, 0x38, 0x6C, 0x40, 0x0B,
//x(P_0):
  0x0D,		0x90,		 0x29,		0xAD,	 0x2C, 0x7E, 0x5C, 0xF4, 0x34, 0x08, 0x23, 0xB2, 0xA8, 0x7D, 0xC6, 0x8C, 0x9E, 0x4C, 0xE3, 0x17, 0x4C, 0x1E, 0x6E, 0xFD, 0xEE, 0x12, 0xC0, 0x7D,
//y(P_0):
  0x58,		0xAA,		 0x56,		0xF7,	 0x72, 0xC0, 0x72, 0x6F, 0x24, 0xC6, 0xB8, 0x9E, 0x4E, 0xCD, 0xAC, 0x24, 0x35, 0x4B, 0x9E, 0x99, 0xCA, 0xA3, 0xF6, 0xD3, 0x76, 0x14, 0x02, 0xCD,
//q:
  0x00,
  0xD7,		0xC1,		 0x34,		0xAA,	 0x26, 0x43, 0x66, 0x86, 0x2A, 0x18, 0x30, 0x25, 0x75, 0xD0, 0xFB, 0x98, 0xD1, 0x16, 0xBC, 0x4B, 0x6D, 0xDE, 0xBC, 0xA3, 0xA5, 0xA7, 0x93, 0x9F,
//h
  0x00,		0x01
};
const flea_u8_t flea_ec_gfp_brainpoolP256r1_domain_params [] =
{
  256 / 8,
//p:
  0xA9,		0xFB,		 0x57,		0xDB,	 0xA1, 0xEE, 0xA9, 0xBC, 0x3E, 0x66, 0x0A, 0x90, 0x9D, 0x83, 0x8D, 0x72, 0x6E, 0x3B, 0xF6, 0x23, 0xD5, 0x26, 0x20, 0x28, 0x20, 0x13, 0x48, 0x1D, 0x1F, 0x6E, 0x53, 0x77,
//A:
  0x7D,		0x5A,		 0x09,		0x75,	 0xFC, 0x2C, 0x30, 0x57, 0xEE, 0xF6, 0x75, 0x30, 0x41, 0x7A, 0xFF, 0xE7, 0xFB, 0x80, 0x55, 0xC1, 0x26, 0xDC, 0x5C, 0x6C, 0xE9, 0x4A, 0x4B, 0x44, 0xF3, 0x30, 0xB5, 0xD9,
//B:
  0x26,		0xDC,		 0x5C,		0x6C,	 0xE9, 0x4A, 0x4B, 0x44, 0xF3, 0x30, 0xB5, 0xD9, 0xBB, 0xD7, 0x7C, 0xBF, 0x95, 0x84, 0x16, 0x29, 0x5C, 0xF7, 0xE1, 0xCE, 0x6B, 0xCC, 0xDC, 0x18, 0xFF, 0x8C, 0x07, 0xB6,
//x(P_0):
  0x8B,		0xD2,		 0xAE,		0xB9,	 0xCB, 0x7E, 0x57, 0xCB, 0x2C, 0x4B, 0x48, 0x2F, 0xFC, 0x81, 0xB7, 0xAF, 0xB9, 0xDE, 0x27, 0xE1, 0xE3, 0xBD, 0x23, 0xC2, 0x3A, 0x44, 0x53, 0xBD, 0x9A, 0xCE, 0x32, 0x62,
//y(P_0):
  0x54,		0x7E,		 0xF8,		0x35,	 0xC3, 0xDA, 0xC4, 0xFD, 0x97, 0xF8, 0x46, 0x1A, 0x14, 0x61, 0x1D, 0xC9, 0xC2, 0x77, 0x45, 0x13, 0x2D, 0xED, 0x8E, 0x54, 0x5C, 0x1D, 0x54, 0xC7, 0x2F, 0x04, 0x69, 0x97,
//n:
  0x00,
  0xA9,		0xFB,		 0x57,		0xDB,	 0xA1, 0xEE, 0xA9, 0xBC, 0x3E, 0x66, 0x0A, 0x90, 0x9D, 0x83, 0x8D, 0x71, 0x8C, 0x39, 0x7A, 0xA3, 0xB5, 0x61, 0xA6, 0xF7, 0x90, 0x1E, 0x0E, 0x82, 0x97, 0x48, 0x56, 0xA7,
// h:
  0x00,		0x01
};
const flea_u8_t flea_ec_gfp_brainpoolP320r1_domain_params [] =
{
  320 / 8,
//p:
  0xD3,		0x5E,		 0x47,		0x20,	 0x36, 0xBC, 0x4F, 0xB7, 0xE1, 0x3C, 0x78, 0x5E, 0xD2, 0x01, 0xE0, 0x65, 0xF9, 0x8F, 0xCF, 0xA6, 0xF6, 0xF4, 0x0D, 0xEF, 0x4F, 0x92, 0xB9, 0xEC, 0x78, 0x93, 0xEC, 0x28, 0xFC, 0xD4, 0x12, 0xB1, 0xF1, 0xB3, 0x2E, 0x27,
//A:
  0x3E,		0xE3,		 0x0B,		0x56,	 0x8F, 0xBA, 0xB0, 0xF8, 0x83, 0xCC, 0xEB, 0xD4, 0x6D, 0x3F, 0x3B, 0xB8, 0xA2, 0xA7, 0x35, 0x13, 0xF5, 0xEB, 0x79, 0xDA, 0x66, 0x19, 0x0E, 0xB0, 0x85, 0xFF, 0xA9, 0xF4, 0x92, 0xF3, 0x75, 0xA9, 0x7D, 0x86, 0x0E, 0xB4,
//B:
  0x52,		0x08,		 0x83,		0x94,	 0x9D, 0xFD, 0xBC, 0x42, 0xD3, 0xAD, 0x19, 0x86, 0x40, 0x68, 0x8A, 0x6F, 0xE1, 0x3F, 0x41, 0x34, 0x95, 0x54, 0xB4, 0x9A, 0xCC, 0x31, 0xDC, 0xCD, 0x88, 0x45, 0x39, 0x81, 0x6F, 0x5E, 0xB4, 0xAC, 0x8F, 0xB1, 0xF1, 0xA6,
//x(P_0):
  0x43,		0xBD,		 0x7E,		0x9A,	 0xFB, 0x53, 0xD8, 0xB8, 0x52, 0x89, 0xBC, 0xC4, 0x8E, 0xE5, 0xBF, 0xE6, 0xF2, 0x01, 0x37, 0xD1, 0x0A, 0x08, 0x7E, 0xB6, 0xE7, 0x87, 0x1E, 0x2A, 0x10, 0xA5, 0x99, 0xC7, 0x10, 0xAF, 0x8D, 0x0D, 0x39, 0xE2, 0x06, 0x11,
//y(P_0):
  0x14,		0xFD,		 0xD0,		0x55,	 0x45, 0xEC, 0x1C, 0xC8, 0xAB, 0x40, 0x93, 0x24, 0x7F, 0x77, 0x27, 0x5E, 0x07, 0x43, 0xFF, 0xED, 0x11, 0x71, 0x82, 0xEA, 0xA9, 0xC7, 0x78, 0x77, 0xAA, 0xAC, 0x6A, 0xC7, 0xD3, 0x52, 0x45, 0xD1, 0x69, 0x2E, 0x8E, 0xE1,
//q:
  0x00,
  0xD3,		0x5E,		 0x47,		0x20,	 0x36, 0xBC, 0x4F, 0xB7, 0xE1, 0x3C, 0x78, 0x5E, 0xD2, 0x01, 0xE0, 0x65, 0xF9, 0x8F, 0xCF, 0xA5, 0xB6, 0x8F, 0x12, 0xA3, 0x2D, 0x48, 0x2E, 0xC7, 0xEE, 0x86, 0x58, 0xE9, 0x86, 0x91, 0x55, 0x5B, 0x44, 0xC5, 0x93, 0x11,
//h:
  0x00,		0x01
};

const flea_u8_t flea_ec_gfp_brainpoolP384r1_domain_params [] =
{
  384 / 8,
//p:
  0x8C,		0xB9,		 0x1E,		0x82,	 0xA3, 0x38, 0x6D, 0x28, 0x0F, 0x5D, 0x6F, 0x7E, 0x50, 0xE6, 0x41, 0xDF, 0x15, 0x2F, 0x71, 0x09, 0xED, 0x54, 0x56, 0xB4, 0x12, 0xB1, 0xDA, 0x19, 0x7F, 0xB7, 0x11, 0x23, 0xAC, 0xD3, 0xA7, 0x29, 0x90, 0x1D, 0x1A, 0x71, 0x87, 0x47, 0x00, 0x13, 0x31, 0x07, 0xEC, 0x53,
//A:
  0x7B,		0xC3,		 0x82,		0xC6,	 0x3D, 0x8C, 0x15, 0x0C, 0x3C, 0x72, 0x08, 0x0A, 0xCE, 0x05, 0xAF, 0xA0, 0xC2, 0xBE, 0xA2, 0x8E, 0x4F, 0xB2, 0x27, 0x87, 0x13, 0x91, 0x65, 0xEF, 0xBA, 0x91, 0xF9, 0x0F, 0x8A, 0xA5, 0x81, 0x4A, 0x50, 0x3A, 0xD4, 0xEB, 0x04, 0xA8, 0xC7, 0xDD, 0x22, 0xCE, 0x28, 0x26,
//B:
  0x04,		0xA8,		 0xC7,		0xDD,	 0x22, 0xCE, 0x28, 0x26, 0x8B, 0x39, 0xB5, 0x54, 0x16, 0xF0, 0x44, 0x7C, 0x2F, 0xB7, 0x7D, 0xE1, 0x07, 0xDC, 0xD2, 0xA6, 0x2E, 0x88, 0x0E, 0xA5, 0x3E, 0xEB, 0x62, 0xD5, 0x7C, 0xB4, 0x39, 0x02, 0x95, 0xDB, 0xC9, 0x94, 0x3A, 0xB7, 0x86, 0x96, 0xFA, 0x50, 0x4C, 0x11,
//x(P_0):
  0x1D,		0x1C,		 0x64,		0xF0,	 0x68, 0xCF, 0x45, 0xFF, 0xA2, 0xA6, 0x3A, 0x81, 0xB7, 0xC1, 0x3F, 0x6B, 0x88, 0x47, 0xA3, 0xE7, 0x7E, 0xF1, 0x4F, 0xE3, 0xDB, 0x7F, 0xCA, 0xFE, 0x0C, 0xBD, 0x10, 0xE8, 0xE8, 0x26, 0xE0, 0x34, 0x36, 0xD6, 0x46, 0xAA, 0xEF, 0x87, 0xB2, 0xE2, 0x47, 0xD4, 0xAF, 0x1E,
//y(P_0):
  0x8A,		0xBE,		 0x1D,		0x75,	 0x20, 0xF9, 0xC2, 0xA4, 0x5C, 0xB1, 0xEB, 0x8E, 0x95, 0xCF, 0xD5, 0x52, 0x62, 0xB7, 0x0B, 0x29, 0xFE, 0xEC, 0x58, 0x64, 0xE1, 0x9C, 0x05, 0x4F, 0xF9, 0x91, 0x29, 0x28, 0x0E, 0x46, 0x46, 0x21, 0x77, 0x91, 0x81, 0x11, 0x42, 0x82, 0x03, 0x41, 0x26, 0x3C, 0x53, 0x15,
//q:
  0x00,
  0x8C,		0xB9,		 0x1E,		0x82,	 0xA3, 0x38, 0x6D, 0x28, 0x0F, 0x5D, 0x6F, 0x7E, 0x50, 0xE6, 0x41, 0xDF, 0x15, 0x2F, 0x71, 0x09, 0xED, 0x54, 0x56, 0xB3, 0x1F, 0x16, 0x6E, 0x6C, 0xAC, 0x04, 0x25, 0xA7, 0xCF, 0x3A, 0xB6, 0xAF, 0x6B, 0x7F, 0xC3, 0x10, 0x3B, 0x88, 0x32, 0x02, 0xE9, 0x04, 0x65, 0x65,
//h:
  0x00,		0x01
};
const flea_u8_t flea_ec_gfp_brainpoolP512r1_domain_params [] =
{
  512 / 8,
//p:
  0xAA,		0xDD,		 0x9D,		0xB8,	 0xDB, 0xE9, 0xC4, 0x8B, 0x3F, 0xD4, 0xE6, 0xAE, 0x33, 0xC9, 0xFC, 0x07, 0xCB, 0x30, 0x8D, 0xB3, 0xB3, 0xC9, 0xD2, 0x0E, 0xD6, 0x63, 0x9C, 0xCA, 0x70, 0x33, 0x08, 0x71, 0x7D, 0x4D, 0x9B, 0x00, 0x9B, 0xC6, 0x68, 0x42, 0xAE, 0xCD, 0xA1, 0x2A, 0xE6, 0xA3, 0x80, 0xE6, 0x28, 0x81, 0xFF, 0x2F, 0x2D, 0x82, 0xC6, 0x85, 0x28, 0xAA, 0x60, 0x56, 0x58, 0x3A, 0x48, 0xF3,
//A:
  0x78,		0x30,		 0xA3,		0x31,	 0x8B, 0x60, 0x3B, 0x89, 0xE2, 0x32, 0x71, 0x45, 0xAC, 0x23, 0x4C, 0xC5, 0x94, 0xCB, 0xDD, 0x8D, 0x3D, 0xF9, 0x16, 0x10, 0xA8, 0x34, 0x41, 0xCA, 0xEA, 0x98, 0x63, 0xBC, 0x2D, 0xED, 0x5D, 0x5A, 0xA8, 0x25, 0x3A, 0xA1, 0x0A, 0x2E, 0xF1, 0xC9, 0x8B, 0x9A, 0xC8, 0xB5, 0x7F, 0x11, 0x17, 0xA7, 0x2B, 0xF2, 0xC7, 0xB9, 0xE7, 0xC1, 0xAC, 0x4D, 0x77, 0xFC, 0x94, 0xCA,
//B:
  0x3D,		0xF9,		 0x16,		0x10,	 0xA8, 0x34, 0x41, 0xCA, 0xEA, 0x98, 0x63, 0xBC, 0x2D, 0xED, 0x5D, 0x5A, 0xA8, 0x25, 0x3A, 0xA1, 0x0A, 0x2E, 0xF1, 0xC9, 0x8B, 0x9A, 0xC8, 0xB5, 0x7F, 0x11, 0x17, 0xA7, 0x2B, 0xF2, 0xC7, 0xB9, 0xE7, 0xC1, 0xAC, 0x4D, 0x77, 0xFC, 0x94, 0xCA, 0xDC, 0x08, 0x3E, 0x67, 0x98, 0x40, 0x50, 0xB7, 0x5E, 0xBA, 0xE5, 0xDD, 0x28, 0x09, 0xBD, 0x63, 0x80, 0x16, 0xF7, 0x23,
//x(P_0):
  0x81,		0xAE,		 0xE4,		0xBD,	 0xD8, 0x2E, 0xD9, 0x64, 0x5A, 0x21, 0x32, 0x2E, 0x9C, 0x4C, 0x6A, 0x93, 0x85, 0xED, 0x9F, 0x70, 0xB5, 0xD9, 0x16, 0xC1, 0xB4, 0x3B, 0x62, 0xEE, 0xF4, 0xD0, 0x09, 0x8E, 0xFF, 0x3B, 0x1F, 0x78, 0xE2, 0xD0, 0xD4, 0x8D, 0x50, 0xD1, 0x68, 0x7B, 0x93, 0xB9, 0x7D, 0x5F, 0x7C, 0x6D, 0x50, 0x47, 0x40, 0x6A, 0x5E, 0x68, 0x8B, 0x35, 0x22, 0x09, 0xBC, 0xB9, 0xF8, 0x22,
//y(P_0):
  0x7D,		0xDE,		 0x38,		0x5D,	 0x56, 0x63, 0x32, 0xEC, 0xC0, 0xEA, 0xBF, 0xA9, 0xCF, 0x78, 0x22, 0xFD, 0xF2, 0x09, 0xF7, 0x00, 0x24, 0xA5, 0x7B, 0x1A, 0xA0, 0x00, 0xC5, 0x5B, 0x88, 0x1F, 0x81, 0x11, 0xB2, 0xDC, 0xDE, 0x49, 0x4A, 0x5F, 0x48, 0x5E, 0x5B, 0xCA, 0x4B, 0xD8, 0x8A, 0x27, 0x63, 0xAE, 0xD1, 0xCA, 0x2B, 0x2F, 0xA8, 0xF0, 0x54, 0x06, 0x78, 0xCD, 0x1E, 0x0F, 0x3A, 0xD8, 0x08, 0x92,
//q:
  0x00,
  0xAA,		0xDD,		 0x9D,		0xB8,	 0xDB, 0xE9, 0xC4, 0x8B, 0x3F, 0xD4, 0xE6, 0xAE, 0x33, 0xC9, 0xFC, 0x07, 0xCB, 0x30, 0x8D, 0xB3, 0xB3, 0xC9, 0xD2, 0x0E, 0xD6, 0x63, 0x9C, 0xCA, 0x70, 0x33, 0x08, 0x70, 0x55, 0x3E, 0x5C, 0x41, 0x4C, 0xA9, 0x26, 0x19, 0x41, 0x86, 0x61, 0x19, 0x7F, 0xAC, 0x10, 0x47, 0x1D, 0xB1, 0xD3, 0x81, 0x08, 0x5D, 0xDA, 0xDD, 0xB5, 0x87, 0x96, 0x82, 0x9C, 0xA9, 0x00, 0x69,
//h:
  0x00,		0x01
};

const flea_u8_t flea_ec_gfp_secp112r1_domain_params[] =
{
  112 / 8,
  //p:
  0xDB,		0x7C,		 0x2A,		0xBF,	 0x62, 0xE3, 0x5E, 0x66, 0x80, 0x76, 0xBE, 0xAD, 0x20, 0x8B,
  //A:
  0xDB,		0x7C,		 0x2A,		0xBF,	 0x62, 0xE3, 0x5E, 0x66, 0x80, 0x76, 0xBE, 0xAD, 0x20, 0x88,
  //B:
  0x65,		0x9E,		 0xF8,		0xBA,	 0x04, 0x39, 0x16, 0xEE, 0xDE, 0x89, 0x11, 0x70, 0x2B, 0x22,
  //x:
  0x09,		0x48,		 0x72,		0x39,	 0x99, 0x5A, 0x5E, 0xE7, 0x6B, 0x55, 0xF9, 0xC2, 0xF0, 0x98,
  //y:
  0xA8,		0x9C,		 0xE5,		0xAF,	 0x87, 0x24, 0xC0, 0xA2, 0x3E, 0x0E, 0x0F, 0xF7, 0x75, 0x00,
  //n:
  0x00,
  0xDB,		0x7C,		 0x2A,		0xBF,	 0x62, 0xE3, 0x5E, 0x76, 0x28, 0xDF, 0xAC, 0x65, 0x61, 0xC5,
  //h:
  0x00,		0x01
};

const flea_u8_t flea_ec_gfp_secp112r2_domain_params[] =
{
  112 / 8,
  // p:
  0xDB,		0x7C,		 0x2A,		0xBF,	 0x62,	0xE3, 0x5E,	 0x66, 0x80,	0x76, 0xBE,	 0xAD, 0x20,	0x8B,
  //A:
  0x61,		0x27,		 0xC2,		0x4C,	 0x05,	0xF3, 0x8A,	 0x0A, 0xAA,	0xF6, 0x5C,	 0x0E, 0xF0,	0x2C,
  //B:
  0x51,		0xDE,		 0xF1,		0x81,	 0x5D,	0xB5, 0xED,	 0x74, 0xFC,	0xC3, 0x4C,	 0x85, 0xD7,	0x09,
  // x:
  0x4B,		0xA3,		 0x0A,		0xB5,	 0xE8,	0x92, 0xB4,	 0xE1, 0x64,	0x9D, 0xD0,	 0x92, 0x86,	0x43,
  // y:
  0xAD,		0xCD,		 0x46,		0xF5,	 0x88,	0x2E, 0x37,	 0x47, 0xDE,	0xF3, 0x6E,	 0x95, 0x6E,	0x97,
  // n:
  0x00,
  0x36,		0xDF,		 0x0A,		0xAF,	 0xD8,	0xB8, 0xD7,	 0x59, 0x7C,	0xA1, 0x05,	 0x20, 0xD0,	0x4B,
  //h:
  0x00,		0x04
};


const flea_u8_t flea_ec_gfp_secp128r1_domain_params [] =
{
  128 / 8,
  //p:
  0xFF,		0xFF,		 0xFF,		0xFD,	 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  //A:
  0xFF,		0xFF,		 0xFF,		0xFD,	 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
  //B:
  0xE8,		0x75,		 0x79,		0xC1,	 0x10, 0x79, 0xF4, 0x3D, 0xD8, 0x24, 0x99, 0x3C, 0x2C, 0xEE, 0x5E, 0xD3,
  //x:
  0x16,		0x1F,		 0xF7,		0x52,	 0x8B, 0x89, 0x9B, 0x2D, 0x0C, 0x28, 0x60, 0x7C, 0xA5, 0x2C, 0x5B, 0x86,
  //y:
  0xCF,		0x5A,		 0xC8,		0x39,	 0x5B, 0xAF, 0xEB, 0x13, 0xC0, 0x2D, 0xA2, 0x92, 0xDD, 0xED, 0x7A, 0x83,
  //n:
  0x00,
  0xFF,		0xFF,		 0xFF,		0xFE,	 0x00, 0x00, 0x00, 0x00, 0x75, 0xA3, 0x0D, 0x1B, 0x90, 0x38, 0xA1, 0x15,
  //h:
  0x00,		0x01
};

const flea_u8_t flea_ec_gfp_secp128r2_domain_params [] =
{
  128 / 8,
  //p:
  0xFF,		0xFF,		 0xFF,		0xFD,	 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  //A:
  0xD6,		0x03,		 0x19,		0x98,	 0xD1, 0xB3, 0xBB, 0xFE, 0xBF, 0x59, 0xCC, 0x9B, 0xBF, 0xF9, 0xAE, 0xE1,
  //B:
  0x5E,		0xEE,		 0xFC,		0xA3,	 0x80, 0xD0, 0x29, 0x19, 0xDC, 0x2C, 0x65, 0x58, 0xBB, 0x6D, 0x8A, 0x5D,
  //x:
  0x7B,		0x6A,		 0xA5,		0xD8,	 0x5E, 0x57, 0x29, 0x83, 0xE6, 0xFB, 0x32, 0xA7, 0xCD, 0xEB, 0xC1, 0x40,
  //y:
  0x27,		0xB6,		 0x91,		0x6A,	 0x89, 0x4D, 0x3A, 0xEE, 0x71, 0x06, 0xFE, 0x80, 0x5F, 0xC3, 0x4B, 0x44,
  //n:
  0x00,
  0x3F,		0xFF,		 0xFF,		0xFF,	 0x7F, 0xFF, 0xFF, 0xFF, 0xBE, 0x00, 0x24, 0x72, 0x06, 0x13, 0xB5, 0xA3,
  //h:
  0x00,		0x04
};

const flea_u8_t flea_ec_gfp_secp160r1_domain_params [] =
{
  160 / 8, // field length
  // p
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff,
  // a
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xfc,
  // b
  0x1c, 0x97, 0xbe, 0xfc, 0x54, 0xbd, 0x7a, 0x8b, 0x65, 0xac, 0xf8, 0x9f, 0x81, 0xd4, 0xd4, 0xad, 0xc5, 0x65, 0xfa, 0x45,
  // x
  0x4A, 0x96, 0xB5, 0x68, 0x8E, 0xF5, 0x73, 0x28, 0x46, 0x64, 0x69, 0x89, 0x68, 0xC3, 0x8B, 0xB9, 0x13, 0xCB, 0xFC, 0x82,
  // y
  0x23, 0xA6, 0x28, 0x55, 0x31, 0x68, 0x94, 0x7D, 0x59, 0xDC, 0xC9, 0x12, 0x04, 0x23, 0x51, 0x37, 0x7A, 0xC5, 0xFB, 0x32,
  // n
  0x01,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xf4, 0xc8, 0xf9, 0x27, 0xae, 0xd3, 0xca, 0x75, 0x22, 0x57,
  // h
  0x00, 0x01
};

const flea_u8_t flea_ec_gfp_secp160r2_domain_params [] =
{
  160 / 8, // field length
  // p:
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xAC, 0x73,
  // a:
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xAC, 0x70,
  // b:
  0xB4, 0xE1, 0x34, 0xD3, 0xFB, 0x59, 0xEB, 0x8B, 0xAB, 0x57, 0x27, 0x49, 0x04, 0x66, 0x4D, 0x5A, 0xF5, 0x03, 0x88, 0xBA,
  // x:
  0x52, 0xDC, 0xB0, 0x34, 0x29, 0x3A, 0x11, 0x7E, 0x1F, 0x4F, 0xF1, 0x1B, 0x30, 0xF7, 0x19, 0x9D, 0x31, 0x44, 0xCE, 0x6D,
  // y:
  0xFE, 0xAF, 0xFE, 0xF2, 0xE3, 0x31, 0xF2, 0x96, 0xE0, 0x71, 0xFA, 0x0D, 0xF9, 0x98, 0x2C, 0xFE, 0xA7, 0xD4, 0x3F, 0x2E,
  // n
  0x01,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x1E, 0xE7, 0x86, 0xA8, 0x18, 0xF3, 0xA1, 0xA1, 0x6B,
  // h:
  0x00, 0x01
};

const flea_u8_t flea_ec_gfp_secp192r1_domain_params [] =
{
  192 / 8, // field length
  // p:
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  //a:
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
  //b:
  0x64, 0x21, 0x05, 0x19, 0xE5, 0x9C, 0x80, 0xE7, 0x0F, 0xA7, 0xE9, 0xAB, 0x72, 0x24, 0x30, 0x49, 0xFE, 0xB8, 0xDE, 0xEC, 0xC1, 0x46, 0xB9, 0xB1,
  //x:
  0x18, 0x8D, 0xA8, 0x0E, 0xB0, 0x30, 0x90, 0xF6, 0x7C, 0xBF, 0x20, 0xEB, 0x43, 0xA1, 0x88, 0x00, 0xF4, 0xFF, 0x0A, 0xFD, 0x82, 0xFF, 0x10, 0x12,
  //y:
  0x07, 0x19, 0x2B, 0x95, 0xFF, 0xC8, 0xDA, 0x78, 0x63, 0x10, 0x11, 0xED, 0x6B, 0x24, 0xCD, 0xD5, 0x73, 0xF9, 0x77, 0xA1, 0x1E, 0x79, 0x48, 0x11,
  //n:
  0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x99, 0xDE, 0xF8, 0x36, 0x14, 0x6B, 0xC9, 0xB1, 0xB4, 0xD2, 0x28, 0x31,
  //h:
  0x00, 0x01
};

const flea_u8_t flea_ec_gfp_secp224r1_domain_params [] =
{
  224 / 8, // field length
  //p:
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  //a:
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
  //b:
  0xB4, 0x05, 0x0A, 0x85, 0x0C, 0x04, 0xB3, 0xAB, 0xF5, 0x41, 0x32, 0x56, 0x50, 0x44, 0xB0, 0xB7, 0xD7, 0xBF, 0xD8, 0xBA, 0x27, 0x0B, 0x39, 0x43, 0x23, 0x55, 0xFF, 0xB4,
  //x:
  0xB7, 0x0E, 0x0C, 0xBD, 0x6B, 0xB4, 0xBF, 0x7F, 0x32, 0x13, 0x90, 0xB9, 0x4A, 0x03, 0xC1, 0xD3, 0x56, 0xC2, 0x11, 0x22, 0x34, 0x32, 0x80, 0xD6, 0x11, 0x5C, 0x1D, 0x21,
  //y:
  0xBD, 0x37, 0x63, 0x88, 0xB5, 0xF7, 0x23, 0xFB, 0x4C, 0x22, 0xDF, 0xE6, 0xCD, 0x43, 0x75, 0xA0, 0x5A, 0x07, 0x47, 0x64, 0x44, 0xD5, 0x81, 0x99, 0x85, 0x00, 0x7E, 0x34,
  //n:
  0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x16, 0xA2, 0xE0, 0xB8, 0xF0, 0x3E, 0x13, 0xDD, 0x29, 0x45, 0x5C, 0x5C, 0x2A, 0x3D,
  //h:
  0x00, 0x01
};

const flea_u8_t flea_ec_gfp_secp256r1_domain_params [] =
{
  256 / 8, // field length
  //p:
  0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  //a:
  0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
  //b:
  0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC, 0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6, 0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B,
  //x:
  0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
  //y:
  0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5,
  //n:
  0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
  //h:
  0x00, 0x01
};

const flea_u8_t flea_ec_gfp_secp384r1_domain_params [] =
{
  384 / 8, // field length
  //p:
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,	 0xFF, 0xFF, 0xFF, 0xFF,	0xFF, 0xFF, 0xFF, 0xFF,	 0xFF, 0xFF, 0xFF, 0xFF,	0xFF, 0xFF, 0xFF, 0xFF,	 0xFF, 0xFF, 0xFF, 0xFF,	0xFF, 0xFF, 0xFF, 0xFF,	 0xFE, 0xFF, 0xFF, 0xFF,	0xFF, 0x00, 0x00, 0x00,	 0x00, 0x00, 0x00, 0x00,	0x00, 0xFF, 0xFF, 0xFF,	 0xFF,
  //a:
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,	 0xFF, 0xFF, 0xFF, 0xFF,	0xFF, 0xFF, 0xFF, 0xFF,	 0xFF, 0xFF, 0xFF, 0xFF,	0xFF, 0xFF, 0xFF, 0xFF,	 0xFF, 0xFF, 0xFF, 0xFF,	0xFF, 0xFF, 0xFF, 0xFF,	 0xFE, 0xFF, 0xFF, 0xFF,	0xFF, 0x00, 0x00, 0x00,	 0x00, 0x00, 0x00, 0x00,	0x00, 0xFF, 0xFF, 0xFF,	 0xFC,
  //b:
  0xB3, 0x31, 0x2F, 0xA7, 0xE2, 0x3E, 0xE7,	 0xE4, 0x98, 0x8E, 0x05,	0x6B, 0xE3, 0xF8, 0x2D,	 0x19, 0x18, 0x1D, 0x9C,	0x6E, 0xFE, 0x81, 0x41,	 0x12, 0x03, 0x14, 0x08,	0x8F, 0x50, 0x13, 0x87,	 0x5A, 0xC6, 0x56, 0x39,	0x8D, 0x8A, 0x2E, 0xD1,	 0x9D, 0x2A, 0x85, 0xC8,	0xED, 0xD3, 0xEC, 0x2A,	 0xEF,
  //x:
  0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05,	 0x37, 0x8E, 0xB1, 0xC7,	0x1E, 0xF3, 0x20, 0xAD,	 0x74, 0x6E, 0x1D, 0x3B,	0x62, 0x8B, 0xA7, 0x9B,	 0x98, 0x59, 0xF7, 0x41,	0xE0, 0x82, 0x54, 0x2A,	 0x38, 0x55, 0x02, 0xF2,	0x5D, 0xBF, 0x55, 0x29,	 0x6C, 0x3A, 0x54, 0x5E,	0x38, 0x72, 0x76, 0x0A,	 0xB7,
  //y:
  0x36, 0x17, 0xDE, 0x4A, 0x96, 0x26, 0x2C,	 0x6F, 0x5D, 0x9E, 0x98,	0xBF, 0x92, 0x92, 0xDC,	 0x29, 0xF8, 0xF4, 0x1D,	0xBD, 0x28, 0x9A, 0x14,	 0x7C, 0xE9, 0xDA, 0x31,	0x13, 0xB5, 0xF0, 0xB8,	 0xC0, 0x0A, 0x60, 0xB1,	0xCE, 0x1D, 0x7E, 0x81,	 0x9D, 0x7A, 0x43, 0x1D,	0x7C, 0x90, 0xEA, 0x0E,	 0x5F,
  //n:
  0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,	 0xFF, 0xFF, 0xFF, 0xFF,	0xFF, 0xFF, 0xFF, 0xFF,	 0xFF, 0xFF, 0xFF, 0xFF,	0xFF, 0xFF, 0xFF, 0xFF,	 0xFF, 0xC7, 0x63, 0x4D,	0x81, 0xF4, 0x37, 0x2D,	 0xDF, 0x58, 0x1A, 0x0D,	0xB2, 0x48, 0xB0, 0xA7,	 0x7A, 0xEC, 0xEC, 0x19,	0x6A, 0xCC, 0xC5, 0x29,	 0x73,
  //h:
  0x00, 0x01
};

const flea_u8_t flea_ec_gfp_secp521r1_domain_params [] =
{
  (521 + 7) / 8, // field length
  //p:
  0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  //a:
  0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
  //b:
  0x00, 0x51, 0x95, 0x3E, 0xB9, 0x61, 0x8E, 0x1C, 0x9A, 0x1F, 0x92, 0x9A, 0x21, 0xA0, 0xB6, 0x85, 0x40, 0xEE, 0xA2, 0xDA, 0x72, 0x5B, 0x99, 0xB3, 0x15, 0xF3, 0xB8, 0xB4, 0x89, 0x91, 0x8E, 0xF1, 0x09, 0xE1, 0x56, 0x19, 0x39, 0x51, 0xEC, 0x7E, 0x93, 0x7B, 0x16, 0x52, 0xC0, 0xBD, 0x3B, 0xB1, 0xBF, 0x07, 0x35, 0x73, 0xDF, 0x88, 0x3D, 0x2C, 0x34, 0xF1, 0xEF, 0x45, 0x1F, 0xD4, 0x6B, 0x50, 0x3F, 0x00,
  //x:
  0x00, 0xC6, 0x85, 0x8E, 0x06, 0xB7, 0x04, 0x04, 0xE9, 0xCD, 0x9E, 0x3E, 0xCB, 0x66, 0x23, 0x95, 0xB4, 0x42, 0x9C, 0x64, 0x81, 0x39, 0x05, 0x3F, 0xB5, 0x21, 0xF8, 0x28, 0xAF, 0x60, 0x6B, 0x4D, 0x3D, 0xBA, 0xA1, 0x4B, 0x5E, 0x77, 0xEF, 0xE7, 0x59, 0x28, 0xFE, 0x1D, 0xC1, 0x27, 0xA2, 0xFF, 0xA8, 0xDE, 0x33, 0x48, 0xB3, 0xC1, 0x85, 0x6A, 0x42, 0x9B, 0xF9, 0x7E, 0x7E, 0x31, 0xC2, 0xE5, 0xBD, 0x66,
  //y:
  0x01, 0x18, 0x39, 0x29, 0x6A, 0x78, 0x9A, 0x3B, 0xC0, 0x04, 0x5C, 0x8A, 0x5F, 0xB4, 0x2C, 0x7D, 0x1B, 0xD9, 0x98, 0xF5, 0x44, 0x49, 0x57, 0x9B, 0x44, 0x68, 0x17, 0xAF, 0xBD, 0x17, 0x27, 0x3E, 0x66, 0x2C, 0x97, 0xEE, 0x72, 0x99, 0x5E, 0xF4, 0x26, 0x40, 0xC5, 0x50, 0xB9, 0x01, 0x3F, 0xAD, 0x07, 0x61, 0x35, 0x3C, 0x70, 0x86, 0xA2, 0x72, 0xC2, 0x40, 0x88, 0xBE, 0x94, 0x76, 0x9F, 0xD1, 0x66, 0x50,
  //n:
  0x00,
  0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFA, 0x51, 0x86, 0x87, 0x83, 0xBF, 0x2F, 0x96, 0x6B, 0x7F, 0xCC, 0x01, 0x48, 0xF7, 0x09, 0xA5, 0xD0, 0x3B, 0xB5, 0xC9, 0xB8, 0x89, 0x9C, 0x47, 0xAE, 0xBB, 0x6F, 0xB7, 0x1E, 0x91, 0x38, 0x64, 0x09,
  //h:
  0x00, 0x01
};

static const dp_id_ptr_entry_t dp_id_entry_table [] =
{
  { flea_secp112r1,				flea_ec_gfp_secp112r1_domain_params,			 sizeof(flea_ec_gfp_secp112r1_domain_params)										},
  { flea_secp112r2,				flea_ec_gfp_secp112r2_domain_params,			 sizeof(flea_ec_gfp_secp112r2_domain_params)										},
#if FLEA_ECC_MAX_MOD_BIT_SIZE >= 128
  { flea_secp128r1,				flea_ec_gfp_secp128r1_domain_params,			 sizeof(flea_ec_gfp_secp128r1_domain_params)										},
  { flea_secp128r2,				flea_ec_gfp_secp128r2_domain_params,			 sizeof(flea_ec_gfp_secp128r2_domain_params)										},
#endif
#if FLEA_ECC_MAX_MOD_BIT_SIZE >= 160
  { flea_secp160r1,				flea_ec_gfp_secp160r1_domain_params,			 sizeof(flea_ec_gfp_secp160r1_domain_params)										},
  { flea_secp160r2,				flea_ec_gfp_secp160r2_domain_params,			 sizeof(flea_ec_gfp_secp160r2_domain_params)										},
#endif
#if FLEA_ECC_MAX_MOD_BIT_SIZE >= 192
  { flea_secp192r1,				flea_ec_gfp_secp192r1_domain_params,			 sizeof(flea_ec_gfp_secp192r1_domain_params)										},
#endif
#if FLEA_ECC_MAX_MOD_BIT_SIZE >= 224
  { flea_secp224r1,				flea_ec_gfp_secp224r1_domain_params,			 sizeof(flea_ec_gfp_secp224r1_domain_params)										},
#endif
#if FLEA_ECC_MAX_MOD_BIT_SIZE >= 256
  { flea_secp256r1,				flea_ec_gfp_secp256r1_domain_params,			 sizeof(flea_ec_gfp_secp256r1_domain_params)										},
#endif
#if FLEA_ECC_MAX_MOD_BIT_SIZE >= 384
  { flea_secp384r1,				flea_ec_gfp_secp384r1_domain_params,			 sizeof(flea_ec_gfp_secp384r1_domain_params)										},
#endif
#if FLEA_ECC_MAX_MOD_BIT_SIZE >= 521
  { flea_secp521r1,				flea_ec_gfp_secp521r1_domain_params,			 sizeof(flea_ec_gfp_secp521r1_domain_params)										},
#endif
#if FLEA_ECC_MAX_MOD_BIT_SIZE >= 160
  { flea_brainpoolP160r1, flea_ec_gfp_brainpoolP160r1_domain_params, sizeof(flea_ec_gfp_brainpoolP160r1_domain_params)							},
#endif
#if FLEA_ECC_MAX_MOD_BIT_SIZE >= 192
  { flea_brainpoolP192r1, flea_ec_gfp_brainpoolP192r1_domain_params, sizeof(flea_ec_gfp_brainpoolP192r1_domain_params)							},
#endif
#if FLEA_ECC_MAX_MOD_BIT_SIZE >= 224
  { flea_brainpoolP224r1, flea_ec_gfp_brainpoolP224r1_domain_params, sizeof(flea_ec_gfp_brainpoolP224r1_domain_params)							},
#endif
#if FLEA_ECC_MAX_MOD_BIT_SIZE >= 256
  { flea_brainpoolP256r1, flea_ec_gfp_brainpoolP256r1_domain_params, sizeof(flea_ec_gfp_brainpoolP256r1_domain_params)							},
#endif
#if FLEA_ECC_MAX_MOD_BIT_SIZE >= 320
  { flea_brainpoolP320r1, flea_ec_gfp_brainpoolP320r1_domain_params, sizeof(flea_ec_gfp_brainpoolP320r1_domain_params)							},
#endif
#if FLEA_ECC_MAX_MOD_BIT_SIZE >= 384
  { flea_brainpoolP384r1, flea_ec_gfp_brainpoolP384r1_domain_params, sizeof(flea_ec_gfp_brainpoolP384r1_domain_params)							},
#endif
#if FLEA_ECC_MAX_MOD_BIT_SIZE >= 512
  { flea_brainpoolP512r1, flea_ec_gfp_brainpoolP512r1_domain_params, sizeof(flea_ec_gfp_brainpoolP512r1_domain_params)							}
#endif

};

const flea_ec_dom_par_id_t flea_gl_ec_dom_par_max_id = flea_secp521r1;

const flea_u8_t* flea_ec_dom_par__get_ptr_to_elem (const flea_u8_t* enc_dp, flea_ec_dom_par_element_id_t id)
{
  flea_u8_t field_length = enc_dp[0];

  if(id == flea_dp__n)
  {
    return enc_dp + 1 + 5 * field_length;
  }
  else if(id == flea_dp__h)
  {
    return enc_dp + 1 + 6 * field_length + 1; // final +1 because for n there is one more byte reserved
  }
  return enc_dp + 1 + field_length * id;
}

flea_al_u8_t flea_ec_dom_par__get_elem_len (const flea_u8_t* enc_dp, flea_ec_dom_par_element_id_t id)
{
  flea_u8_t field_length = enc_dp[0];

  if(id == flea_dp__n)
  {
    return field_length + 1;
  }
  else if(id == flea_dp__h)
  {
    return 2;
  }
  return field_length;
}

flea_al_u8_t flea_ec_dom_par__get_real_order_byte_len (const flea_u8_t* enc_dp__pc_u8)
{
  flea_al_u8_t order_byte_len__al_u8;
  flea_al_u8_t i__al_u8;
  const flea_u8_t* order_ptr__pc_u8;

  order_byte_len__al_u8 = flea_ec_dom_par__get_elem_len(enc_dp__pc_u8, flea_dp__n);
  order_ptr__pc_u8 = flea_ec_dom_par__get_ptr_to_elem(enc_dp__pc_u8, flea_dp__n);
  // remove leading zero bytes:
  for(i__al_u8 = 0; i__al_u8 < order_byte_len__al_u8; i__al_u8++)
  {
    if(order_ptr__pc_u8[i__al_u8] != 0)
    {
      break;
    }
  }
  return order_byte_len__al_u8 - i__al_u8;
}

const flea_u8_t* flea_ec_dom_par__get_predefined_dp_ptr (flea_ec_dom_par_id_t dp_id)
{
  flea_al_u8_t i;

  for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(dp_id_entry_table); i++)
  {
    if(dp_id == dp_id_entry_table[i].dp_id)
    {
      return dp_id_entry_table[i].dp_ptr;
    }
  }
  return NULL;
}
flea_al_u16_t flea_ec_dom_par__get_predefined_dp_len (flea_ec_dom_par_id_t dp_id)
{
  flea_al_u8_t i;

  for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(dp_id_entry_table); i++)
  {
    if(dp_id == dp_id_entry_table[i].dp_id)
    {
      return dp_id_entry_table[i].dp_len__u16;
    }
  }
  return 0;
}

static void flea_ec_dom_par__set_ru8_from_internal_format(flea_ref_cu8_t *result__pru8, const flea_u8_t *enc_dp__pcu8, flea_ec_dom_par_element_id_t dp_id)
{
  result__pru8->data__pcu8 = flea_ec_dom_par__get_ptr_to_elem(enc_dp__pcu8, dp_id);
  result__pru8->len__dtl = flea_ec_dom_par__get_elem_len(enc_dp__pcu8, dp_id);

  while(result__pru8->len__dtl && (result__pru8->data__pcu8[0] == 0))
  {
    result__pru8->len__dtl--;
    result__pru8->data__pcu8++;
  }
}

/*static void flea_ec_gfp_dom_par_t__set_from_internal_format(flea_ec_gfp_dom_par_t * result__pt, const flea_u8_t *enc_dp__pcu8)
{
 flea_ec_dom_par__set_ru8_from_internal_format(&result__pt->p__ru8, enc_dp__pcu8, flea_dp__p);
 flea_ec_dom_par__set_ru8_from_internal_format(&result__pt->a__ru8, enc_dp__pcu8, flea_dp__a);
 flea_ec_dom_par__set_ru8_from_internal_format(&result__pt->b__ru8, enc_dp__pcu8, flea_dp__b);
 flea_ec_dom_par__set_ru8_from_internal_format(&result__pt->gx__ru8, enc_dp__pcu8, flea_dp__Gx);
 flea_ec_dom_par__set_ru8_from_internal_format(&result__pt->gy__ru8, enc_dp__pcu8, flea_dp__Gy);
 flea_ec_dom_par__set_ru8_from_internal_format(&result__pt->n__ru8, enc_dp__pcu8, flea_dp__n);
 flea_ec_dom_par__set_ru8_from_internal_format(&result__pt->h__ru8, enc_dp__pcu8, flea_dp__h);
 
}*/

flea_err_t THR_flea_ec_gfp_dom_par_ref_t__set_by_builtin_id(flea_ec_gfp_dom_par_ref_t *dp_to_set__pt, flea_ec_dom_par_id_t id)
{
  const flea_u8_t* enc_dp__pcu8;
 FLEA_THR_BEG_FUNC();
 enc_dp__pcu8= flea_ec_dom_par__get_predefined_dp_ptr(id);
 if(!enc_dp__pcu8)
 {
  FLEA_THROW("unsupported built-in ECC domain parameter id", FLEA_ERR_ECC_INV_BUILTIN_DP_ID);
 }

 flea_ec_dom_par__set_ru8_from_internal_format(&dp_to_set__pt->p__ru8, enc_dp__pcu8, flea_dp__p);
 flea_ec_dom_par__set_ru8_from_internal_format(&dp_to_set__pt->a__ru8, enc_dp__pcu8, flea_dp__a);
 flea_ec_dom_par__set_ru8_from_internal_format(&dp_to_set__pt->b__ru8, enc_dp__pcu8, flea_dp__b);
 flea_ec_dom_par__set_ru8_from_internal_format(&dp_to_set__pt->gx__ru8, enc_dp__pcu8, flea_dp__Gx);
 flea_ec_dom_par__set_ru8_from_internal_format(&dp_to_set__pt->gy__ru8, enc_dp__pcu8, flea_dp__Gy);
 flea_ec_dom_par__set_ru8_from_internal_format(&dp_to_set__pt->n__ru8, enc_dp__pcu8, flea_dp__n);
 flea_ec_dom_par__set_ru8_from_internal_format(&dp_to_set__pt->h__ru8, enc_dp__pcu8, flea_dp__h);

FLEA_THR_FIN_SEC_empty(); 
}

#endif /* #ifdef FLEA_HAVE_ECC */
