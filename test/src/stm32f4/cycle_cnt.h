/***********************************
 *
 *
 * ___________________
 * ***** cryptosource 
 * *******************
 *
 * flea cryptographic library 
 *
 * (C) cryptosource GmbH 2014
 *
 * This software is made available to you only under the separately received license
 * conditions.
 *
 */

#ifndef __cyc_cnt_H_
#define __cyc_cnt_H_

extern volatile unsigned int cyc_start;
extern volatile unsigned int cyc_final;

extern volatile unsigned int *DWT_CYCCNT;
extern volatile unsigned int *DWT_CONTROL;
extern volatile unsigned int *SCB_DEMCR;

#define STOPWATCH_START() \
do {*SCB_DEMCR = *SCB_DEMCR | 0x01000000; \
 *DWT_CYCCNT = 0; \
*DWT_CONTROL = *DWT_CONTROL | 1 ; \
cyc_start = *DWT_CYCCNT;} while(0)

#define STOPWATCH_STOP() do { cyc_final = *DWT_CYCCNT; cyc_final = cyc_final - cyc_start; }while(0)

//#define STOPWATCH_GETTIME() (cyc[1])
#endif
