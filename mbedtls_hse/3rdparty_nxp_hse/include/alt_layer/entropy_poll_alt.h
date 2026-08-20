/*==================================================================================================
*
*   Copyright 2022, 2024 NXP.
*
*   This software is owned or controlled by NXP and may only be used strictly in accordance with
*   the applicable license terms. By expressly accepting such terms or by downloading, installing,
*   activating and/or otherwise using the software, you are agreeing that you have read, and that
*   you agree to comply with and are bound by, such license terms. If you do not agree to
*   be bound by the applicable license terms, then you may not retain, install, activate or
*   otherwise use the software.
==================================================================================================*/

#ifndef ENTROPY_POLL_ALT_H_
#define ENTROPY_POLL_ALT_H_

#ifdef __cplusplus
extern "C"{
#endif

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/

#if defined(MBEDTLS_CONFIG_FILE)
#include MBEDTLS_CONFIG_FILE
#else
#include "mbedtls/config.h"
#endif

#include <string.h>
#include "mbedtls/entropy.h"
#include "mbedtls/entropy_poll.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_TIMING_C)
#include "mbedtls/timing.h"
#endif
#if defined(MBEDTLS_HAVEGE_C)
#include "mbedtls/havege.h"
#endif
#if defined(MBEDTLS_ENTROPY_NV_SEED)
#include "mbedtls/platform.h"
#endif

#include "hse_host_rng.h"

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

#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)
#if defined(MBEDTLS_USE_NXP_HSE_CRYPTO)
#if defined(MBEDTLS_RNG_DRG3)
/**
 * 	@brief		RNG-DRG3 class random number generator.
 *
 *	@param[in]	data
 *				Input data
 *
 *  @param[out]	output
 *				Output buffer
 *
 *  @param[in]	len
 *				Input buffer length
 *
 * 	@param[out]	olen
 *				Output length
 *
 *	@return		\c 0 on success.
 *
 * 	@return     #MBEDTLS_ERR_ENTROPY_SOURCE_FAILED error in case of hardware failure.
 *
 */
int mbedtls_drg3_poll( void *data, unsigned char *output,
		size_t len, size_t *olen );
#endif /* MBEDTLS_RNG_DRG3 */

#if defined(MBEDTLS_RNG_DRG4)
/**
 * 	@brief		RNG-DRG4 class random number generator.
 *
 *	@param[in]	data
 *				Input data
 *
 *  @param[out]	output
 *				Output buffer
 *
 *  @param[in]	len
 *				Input buffer length
 *
 * 	@param[out]	olen
 *				Output length
 *
 *	@return		\c 0 on success.
 *
 * 	@return     #MBEDTLS_ERR_ENTROPY_SOURCE_FAILED error in case of hardware failure.
 *
 */
int mbedtls_drg4_poll( void *data, unsigned char *output,
		size_t len, size_t *olen );
#endif /* MBEDTLS_RNG_DRG4 */

#if defined(MBEDTLS_RNG_PTG3)
/**
 * 	@brief		RNG-PTG3 class random number generator.
 *
 *	@param[in]	data
 *				Input data
 *
 *  @param[out]	output
 *				Output buffer
 *
 *  @param[in]	len
 *				Input buffer length
 *
 * 	@param[out]	olen
 *				Output length
 *
 *	@return		\c 0 on success.
 *
 * 	@return     #MBEDTLS_ERR_ENTROPY_SOURCE_FAILED error in case of hardware failure.
 *
 */
int mbedtls_ptg3_poll( void *data, unsigned char *output,
		size_t len, size_t *olen );
#endif /* MBEDTLS_RNG_PTG3 */

#endif /* MBEDTLS_USE_NXP_HSE_CRYPTO */
#endif /* MBEDTLS_ENTROPY_HARDWARE_ALT */

#ifdef __cplusplus
}
#endif

#endif /* ENTROPY_POLL_ALT_H_ */
