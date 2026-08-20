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

#ifndef X509_CRL_PARSE_FILE_H
#define X509_CRL_PARSE_FILE_H

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

#if !defined( MBEDTLS_FS_IO )
#include "mbedtls/x509_crl.h"

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

/*!
 * @brief Load one or more CRLs and add them to the chained list
 *
 * This function loads one or more CRLs and append them to the chained list
 *
 * @note				Multiple CRLs are accepted only if using PEM format
 *
 * @param[in]	path    filename to read the CRLs from (in PEM or DER encoding)
 *
 * @param[out]	chain   points to the start of the chain
 *
 * @return 		int		0 if successful, or a specific X509 or PEM error code
 */
extern int nxp_hse_x509_crl_parse_file( mbedtls_x509_crl *chain, const char *path );

#endif /* MBEDTLS_FS_IO */

#ifdef __cplusplus
}
#endif

#endif /* X509_CRL_PARSE_FILE_H */
