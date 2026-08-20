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

#ifndef MBEDTLS_HMAC_ALT_H_
#define MBEDTLS_HMAC_ALT_H_

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
#include "mbedtls/md.h"
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

/**
 * \brief          The HMAC context structure.
 *
 */
typedef struct mbedtls_hmac_context
{
	mbedtls_md_context_t *ctx_md;	/*!< Context of Message Digest */
	uint32_t total[2]; 		 			/*!< The number of Bytes processed. */
	uint32_t hmackeyhandle;
#ifdef HSE_SPT_STREAM_CTX_IMPORT_EXPORT
	uint8_t stream_ctx[MAX_STREAMING_CONTEXT_SIZE];			/*!< Stream context to support cloning */
#else
	uint8_t stream_ctx[128U];			/*!< Stream context to support cloning */
#endif
	uint8_t buffer[128];  		/*!< The data block being processed. */
	uint8_t key_preloaded_flag;
	uint8_t stream_start_send;
	uint8_t hashalg;
}
mbedtls_hmac_context;

/*==================================================================================================
                                 GLOBAL VARIABLE DECLARATIONS
==================================================================================================*/

/*==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================*/
void nxp_hse_hmac_init( mbedtls_hmac_context *ctx);
int nxp_hse_hmac_setup(mbedtls_hmac_context *ctx, mbedtls_md_context_t *ctx_md);
int nxp_hse_hmac_set_key(mbedtls_hmac_context *ctx, const unsigned char *key, size_t keybits );
int nxp_hse_hmac_starts_ret( mbedtls_hmac_context *ctx, const unsigned char *key, size_t keylen  );
int nxp_hse_hmac_update_ret( mbedtls_hmac_context *ctx,
							   const unsigned char *input,
							   size_t ilen );
int nxp_hse_hmac_finish_ret( mbedtls_hmac_context *ctx,
                               unsigned char *output );
int nxp_hse_hmac_ret( mbedtls_hmac_context *ctx,
                     const unsigned char *key, size_t keylen,
                     const unsigned char *input, size_t ilen,
                     unsigned char *output);
int nxp_hse_hmac_reset(mbedtls_hmac_context *ctx);
void nxp_hse_hmac_free( mbedtls_hmac_context *ctx );



#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_HMAC_ALT_H_ */
