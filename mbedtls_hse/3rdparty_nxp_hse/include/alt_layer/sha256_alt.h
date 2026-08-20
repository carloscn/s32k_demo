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

#ifndef INCLUDE_MBEDTLS_SHA256_ALT_H_
#define INCLUDE_MBEDTLS_SHA256_ALT_H_

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

#include <stddef.h>
#include <stdint.h>
#include <hse_interface.h>

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

/**
 * \brief          The SHA-256 context structure.
 *
 *                 The structure is used both for SHA-256 and for SHA-224
 *                 checksum calculations. The choice between these two is
 *                 made in the call to mbedtls_sha256_starts_ret().
 */
typedef struct mbedtls_sha256_context
{
	uint32_t total[2]; 		 	 /*!< The number of Bytes processed.  */
#ifdef HSE_SPT_STREAM_CTX_IMPORT_EXPORT
	uint8_t stream_ctx[MAX_STREAMING_CONTEXT_SIZE];			/*!< Stream context to support cloning */
#else
	uint8_t stream_ctx[128U];			/*!< Stream context to support cloning */
#endif
	uint8_t buffer[64];	 /*!< The data block being processed. */
	uint8_t stream_start_send;	 /*!< Flag to track if stream start is issued or not */
	uint8_t is224;               /**< Determines which function to use:
				                  *   0: Use SHA-256, or 1: Use SHA-224. */
}
mbedtls_sha256_context;

/*==================================================================================================
                                 GLOBAL VARIABLE DECLARATIONS
==================================================================================================*/

/*==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================*/

#ifdef __cplusplus
}
#endif

#endif /* INCLUDE_MBEDTLS_SHA256_ALT_H_ */
