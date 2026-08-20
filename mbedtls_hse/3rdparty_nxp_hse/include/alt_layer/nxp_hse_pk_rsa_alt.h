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

#ifndef NXP_HSE_PK_RSA_ALT_H_
#define NXP_HSE_PK_RSA_ALT_H_

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/
#include <stdint.h>
#include "mbedtls/rsa.h"
#include "mbedtls/x509_crt.h"

#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT) && defined(MBEDTLS_USE_NXP_HSE_CRYPTO)
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
 * 	@brief		This function configures the RSA context required for
 * 				PK RSA Alt support.
 *
 * 	@param[in]	keyHandle
 * 				RSA Keypair handle.
 *
 * 	@param[out]	ctx
 *				The RSA context to configure. This must not be NULL.
 *
 *  @return		0 on success, A non-zero error code on failure.
 *
 */
int nxp_hse_pk_rsa_alt_config( mbedtls_rsa_context *ctx, uint32_t keyHandle );

/**
 * 	@brief		This function loads RSA key-pair, returns public/private key-handle in PK ctx
 *
 * 	@param[in]	pk
 *				Pointer to the PK Context
 *
 * 	@param[in]	mode
 *				MBEDTLS_RSA_PUBLIC or MBEDTLS_RSA_PRIVATE
 *
 *  @return		\c 0 on success.
 *
 *	@return		#MBEDTLS_ERR_RSA_BAD_INPUT_DATA for bad input
 *				#MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION for unsupported
 *				operation
 *				#MBEDTLS_ERR_MPI_ALLOC_FAILED for memory allocation failure
 *
 */
int nxp_hse_rsa_load_pkey(mbedtls_pk_context *pk, int mode);

#endif /* MBEDTLS_PK_RSA_ALT_SUPPORT && MBEDTLS_USE_NXP_HSE_CRYPTO */
#endif /* NXP_HSE_PK_RSA_ALT_H_ */
