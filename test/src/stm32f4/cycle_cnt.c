/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include "cycle_cnt.h"

volatile unsigned int cyc_start;
volatile unsigned int cyc_final;

volatile unsigned int *DWT_CYCCNT  = (volatile unsigned int *) 0xE0001004; // address of the register
volatile unsigned int *DWT_CONTROL = (volatile unsigned int *) 0xE0001000; // address of the register
volatile unsigned int *SCB_DEMCR   = (volatile unsigned int *) 0xE000EDFC; // address of the register
