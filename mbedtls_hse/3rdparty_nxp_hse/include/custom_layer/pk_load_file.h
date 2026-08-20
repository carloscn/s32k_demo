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

#ifndef PK_LOAD_FILE_H
#define PK_LOAD_FILE_H

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

#if !defined( MBEDTLS_FS_IO)
#include "mbedtls/pk.h"

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
 * @brief Load data from file
 *
 * This function loads all data from a file into a given buffer.
 *
 * @param[in]	path	filename to read the data from
 *
 * @param[out]	buf		data buffer to which file data to be written
 *
 * @param[out]	n		size of the data
 *
 * @return 		int 	0, if success
 *						#MBEDTLS_ERR_PK_FILE_IO_ERROR, if file not found
 *						#MBEDTLS_ERR_PK_ALLOC_FAILED, if failed to allocate memory
 *
 */
extern int nxp_hse_pk_load_file( const char *path, unsigned char **buf, size_t *n );

/*!
 * @brief Load and parse a private key
 *
 * This function loads all data from a file and parse a private key
 * into a given ctx.
 *
 * @param[in]	path    	filename to read the private key from
 *
 * @param[in]	password  	Optional password to decrypt the file.
 *                  		Pass \c NULL if expecting a non-encrypted key.
 *                  		Pass a null-terminated string if expecting an encrypted
 *                  		key; a non-encrypted key will also be accepted.
 *                  		The empty password is not supported.
 *
 * @param[out]	ctx     	The PK context to fill. It must have been initialized
 *                  		but not set up.
 *
 * @note 					On entry, ctx must be empty, either freshly initialized
 *          				with mbedtls_pk_init() or reset with mbedtls_pk_free().
 *         					If you need a specific key type, check the result with
 *         					mbedtls_pk_can_do().
 *
 * @note					The key is also checked for correctness.
 *
 * @return					0 if successful, or a specific PK or PEM error code
 */
extern int nxp_hse_pk_parse_keyfile( mbedtls_pk_context *ctx, const char *path, const char *pwd );

/*!
 * @brief Load and parse a public key
 *
 * This function loads all data from a file and parse a public key
 * into a given ctx.
 *
 * @param[in]	path    	filename to read the public key from
 *
 * @param[out]	ctx     	The PK context to fill. It must have been initialized
 *                  		but not set up.
 *
 * @note 					On entry, ctx must be empty, either freshly initialized
 *          				with mbedtls_pk_init() or reset with mbedtls_pk_free().
 *         					If you need a specific key type, check the result with
 *         					mbedtls_pk_can_do().
 *
 * @note					The key is also checked for correctness.
 *
 * @return					0 if successful, or a specific PK or PEM error code
 */
extern int nxp_hse_pk_parse_public_keyfile( mbedtls_pk_context *ctx, const char *path );

#endif /* MBEDTLS_FS_IO */

#ifdef __cplusplus
}
#endif

#endif /* PK_LOAD_FILE_H */
