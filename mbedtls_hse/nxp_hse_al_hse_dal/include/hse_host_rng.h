/**
*   @file    	hse_host_rng.h
*
*   @brief   	This file implements services for random number generator.
*
*   @addtogroup [HSE_DAL]
*   @{
*/
/*==================================================================================================
*
*   Copyright 2022 NXP.
*
*   This software is owned or controlled by NXP and may only be used strictly in accordance with
*   the applicable license terms. By expressly accepting such terms or by downloading, installing,
*   activating and/or otherwise using the software, you are agreeing that you have read, and that
*   you agree to comply with and are bound by, such license terms. If you do not agree to
*   be bound by the applicable license terms, then you may not retain, install, activate or
*   otherwise use the software.
==================================================================================================*/

#ifndef HSE_HOST_RNG_H
#define HSE_HOST_RNG_H

#ifdef __cplusplus
extern "C"{
#endif

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/

#include "hse_interface.h"

/*==================================================================================================
*                              SOURCE FILE VERSION INFORMATION
==================================================================================================*/

/*==================================================================================================
*                                     FILE VERSION CHECKS
==================================================================================================*/

/*==================================================================================================
*                                          CONSTANTS
==================================================================================================*/

/*==================================================================================================
*                                      DEFINES AND MACROS
==================================================================================================*/

/*==================================================================================================
*                                             ENUMS
==================================================================================================*/

/*==================================================================================================
                                 STRUCTURES AND OTHER TYPEDEFS
==================================================================================================*/

/*==================================================================================================
                                 GLOBAL VARIABLE DECLARATIONS
==================================================================================================*/

/*==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================*/

/**
 * 	@brief		Random Number Generator service for class PTG3
 *
 *	@param[out]	pOutput
 *				The address where the random number will be stored
 *
 *	@param[in]	outputLength
 *				Length on the random number in bytes. It should not be more than 2048
 *              bytes, otherwise an error will be returned by HSE FW
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_RngPTG3
(
    uint8_t *pOutput,
    uint32_t outputLength
)
;

/**
 * 	@brief		Random Number Generator service for class DRG4
 *
 *	@param[out]	pOutput
 *				The address where the random number will be stored
 *
 *	@param[in]	outputLength
 *				Length on the random number in bytes. It should not be more than 2048
 *              bytes, otherwise an error will be returned by HSE FW
 *
 *  @return     The HSE Service response
 *
 */

#if !defined(S32N55)
hseSrvResponse_t HSE_RngDRG4
(
    uint8_t *pOutput,
    uint32_t outputLength
)
;


/**
 * 	@brief		Random Number Generator service for class DRG3
 *
 *	@param[out]	pOutput
 *				The address where the random number will be stored
 *
 *	@param[in]	outputLength
 *				Length on the random number in bytes. It should not be more than 2048
 *              bytes, otherwise an error will be returned by HSE FW
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_RngDRG3
(
	uint8_t *pOutput,
	uint32_t outputLength
);
#endif

#ifdef __cplusplus
}
#endif

#endif /* HSE_HOST_RNG_H */
