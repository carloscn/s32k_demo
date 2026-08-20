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

#ifndef MBEDTLS_MD5_ALT_H_
#define MBEDTLS_MD5_ALT_H_

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

#define MD5_OUTPUT_LENGTH								(uint32_t)(0x10U) /**< md5 output length. */

#define MBEDTLS_ERR_md5_ALT_BAD_INPUT_DATA				-0x0077 /**< Bad input parameters to function. */
#define MBEDTLS_ERR_md5_ALT_INVALID_INPUT_LENGTH		-0x0076 /**< md5 input length is invalid. */

/*==================================================================================================
*                                             ENUMS
==================================================================================================*/

/*==================================================================================================
                                 STRUCTURES AND OTHER TYPEDEFS
==================================================================================================*/

/**
 * \brief          MD5 context structure
 *
 * \warning        MD5 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
typedef struct mbedtls_md5_context
{
	uint32_t total[2];          /*!< number of bytes processed  */
#ifdef HSE_SPT_STREAM_CTX_IMPORT_EXPORT
	uint8_t stream_ctx[MAX_STREAMING_CONTEXT_SIZE];			/*!< Stream context to support cloning */
#else
	uint8_t stream_ctx[128U];			/*!< Stream context to support cloning */
#endif
    uint8_t buffer[64];   /*!< data block being processed */
	uint8_t stream_start_send;	/*!< Flag to track if stream start is issued or not */
}
mbedtls_md5_context;

/*==================================================================================================
                                 GLOBAL VARIABLE DECLARATIONS
==================================================================================================*/

/*==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================*/

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_MD5_ALT_H_ */
