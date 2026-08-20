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

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/
#ifndef NXP_HSE_DHM_H_
#define NXP_HSE_DHM_H_

#ifdef __cplusplus
extern "C"{
#endif

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_DHM_ALT) && defined(MBEDTLS_USE_NXP_HSE_CRYPTO)

#include "mbedtls/dhm.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "keystore_mgmt.h"
#include "hse_host_global.h"
#include "global_defs.h"
#include "device.h"
#include "hse_host_km_export_key.h"
#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

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
*											  ENUMS
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
 * 	@brief		This function loads DH key-pair, returns
 * 				public and private key-handles
 *
 * 	@param[in]	ctx
 * 				ECC operation
 * 				- EC_OPS_SIGN
 * 				- EC_OPS_VERIFY
 * 				- EC_OPS_SHAREDSECRET
 *
 * 	@param[out]	pubKeyHandle
 * 				Public key-handle
 *
 * 	@param[out]	prvKeyHandle
 * 				Private key-handle
 *
 *	@return		\c 0 on success.
 *
 * 	@return     #MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE error operation is
 * 				invalid
 *
 */
extern int nxp_dhm_loadkey( mbedtls_dhm_context *ctx, hseKeyHandle_t *pubKeyHandle, hseKeyHandle_t *privKeyHandle);

/**
 * 	@brief		Unload DH RAM key
 *
 * 	@param[in]	KeyHandle
 * 				Key-handle to RAM key
 *
 * 	@param[out]	None
 *
 *	@return		void
 *
 */
extern void nxp_hse_dhm_unloadkey( hseKeyHandle_t KeyHandle );

#endif /* MBEDTLS_DHM_ALT && MBEDTLS_USE_NXP_HSE_CRYPTO */

#ifdef __cplusplus
}
#endif

#endif /* NXP_HSE_DHM_H_ */
