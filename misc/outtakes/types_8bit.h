
#elif defined FLEA_PLTF_AVR_8BIT

#include <stdint.h>
typedef unsigned char       flea_u8_t;
typedef unsigned short      flea_u16_t;
typedef uint32_t            flea_u32_t;

typedef signed char         flea_s8_t;
typedef short               flea_s16_t;
typedef int32_t             flea_s32_t;

typedef unsigned char       flea_al_u8_t; // platform optimal 8 bit or more
typedef flea_u16_t          flea_al_u16_t;
typedef flea_s16_t          flea_al_s16_t;

typedef flea_u8_t              flea_uword_t;
#define FLEA_LOG2_WORD_BIT_SIZE 3
typedef flea_u16_t             flea_dbl_uword_t;
typedef flea_s16_t             flea_dbl_sword_t;

typedef flea_u32_t flea_cycles_t;


#else
#error no flea platform definition in flea/types.h 
#endif /* PLTF_X86 */
