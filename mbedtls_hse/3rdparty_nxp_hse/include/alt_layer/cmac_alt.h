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

#ifndef MBEDTLS_CMAC_ALT_H_
#define MBEDTLS_CMAC_ALT_H_

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

#include "aes_alt.h"
#include "mbedtls/cipher.h"
#include "hse_interface.h"
#include <stddef.h>
#include <stdint.h>

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
 * \brief The CMAC context structure.
 */
struct mbedtls_cmac_context_t
{
	uint8_t streamid;												/*!< StreamId*/
	uint8_t stream_start_send;										/*!< Flag to track if stream start is issued or not */
    unsigned char  unprocessed_block[MBEDTLS_CIPHER_BLKSIZE_MAX]; 	/**< Unprocessed data - either data that
     	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 *	was not block aligned and is still
     	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 * 	pending processing, or the final block. */
    size_t unprocessed_len;	   										/*!< The length of data pending processing. */

};

/*==================================================================================================
                                 GLOBAL VARIABLE DECLARATIONS
==================================================================================================*/

/*==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================*/


#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_CMAC_ALT_H_ */
