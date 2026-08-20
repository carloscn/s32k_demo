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

#if defined(MBEDTLS_USE_NXP_HSE_CRYPTO) && defined(MBEDTLS_SHA512_ALT)
#include <string.h>

#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha512.h"
#include "mbedtls/error.h"
#include "keystore_mgmt.h"
#include "device.h"
#include "hse_host_hash.h"

/*==================================================================================================
 *                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
 ==================================================================================================*/

typedef enum {
    IS512 = (0x00UL),
    IS384 = (0x01UL),
}sha3_Type_t;

/*==================================================================================================
 *                                       LOCAL MACROS
 ==================================================================================================*/

#define SHA2_512_OUTPUT_LENGTH				((uint32_t)(0x40UL)) /**< SHA3-512 output length. */
#define SHA2_384_OUTPUT_LENGTH				((uint32_t)(0x30UL)) /**< SHA3-384 output length. */

/* Parameter validation macros. */
#define SHA512_ALT_VALIDATE_RET(cond)        \
MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_SHA512_BAD_INPUT_DATA )
#define SHA512_ALT_VALIDATE(cond)            \
MBEDTLS_INTERNAL_VALIDATE( cond )

/*==================================================================================================
 *                                      LOCAL CONSTANTS
 ==================================================================================================*/

/*==================================================================================================
 *                                      LOCAL VARIABLES
 ==================================================================================================*/

/*==================================================================================================
 *                                      GLOBAL CONSTANTS
 ==================================================================================================*/

/*==================================================================================================
 *                                      GLOBAL VARIABLES
 ==================================================================================================*/

/*==================================================================================================
 *                                   LOCAL FUNCTION PROTOTYPES
 ==================================================================================================*/
/**
 * 	@brief		Process the input data in ongoing stream context or starts the SHA512 streaming
 * 				operation if stream operation is not started
 *
 * 	@param[in]	ctx
 * 				The SHA512 Context
 *
 * 	@param[in]	data
 *              Input data
 *
 *	@param[out]	num_bytes
 *				Input data length
 *
 *  @return		\c 0 on success.
 *
 *	@return		#MBEDTLS_ERR_SHA512_BAD_INPUT_DATA for bad input
 *
 *	@return		#MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED for hardware accelator failure
 *
 */
static int Sha512_process( mbedtls_sha512_context *ctx,
						   const unsigned char *data, uint32_t num_bytes );

/*==================================================================================================
 *                                       LOCAL FUNCTIONS
 ==================================================================================================*/
/*************************************************************************************************
* Description:  Process the input data in ongoing stream context or starts the SHA512 streaming
* operation if stream operation is not started
************************************************************************************************/
static int Sha512_process( mbedtls_sha512_context *ctx,
						   const unsigned char *data, uint32_t num_bytes )
{
    int ret;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
    KeymgmtErrCodeT err;
    hseHashAlgo_t hashalg;
    uint8_t streamId = INVALID_STREAM_ID;

#if !defined(MBEDTLS_SHA512_NO_SHA384)
    hashalg = ctx->is384?HSE_HASH_ALGO_SHA2_384:HSE_HASH_ALGO_SHA2_512;
#else
    hashalg = HSE_HASH_ALGO_SHA2_512;
#endif

	/* Allocate Stream ID */
	err = KeystoreMgmt_FindAllocateStreamSlot(&streamId);
	if(err != KEYMGMT_ERR_SUCCESS)
	{
		return MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED;
	}

    if(ctx->stream_start_send == FALSE)
    {
		/* Send the request */
		srvResponse = HSE_HashStreamStart(streamId,
			hashalg, data, num_bytes, NULL, NULL) ;

		/* Check the response and mark stream_start_send as TRUE */
		if(HSE_SRV_RSP_OK == srvResponse)
		{
			ctx->stream_start_send = TRUE;
		}
    }
    else
    {
		/* Import stream context */
		err = KeyStoreMgmt_ImportStreamCtx(streamId, ctx->stream_ctx);
		if(err != KEYMGMT_ERR_SUCCESS)
		{
			/* Release stream channel */
			(void)KeystoreMgmt_FreeStreamSlot(streamId);

			return MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED;
		}

		/* Send the request */
		srvResponse = HSE_HashStreamUpdate(streamId,
			hashalg, data, num_bytes, NULL, NULL ) ;
    }

    /* Check the response */
    if( HSE_SRV_RSP_OK != srvResponse )
	{
		if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
		{
			/* Return with Error Code */
			ret = MBEDTLS_ERR_SHA512_BAD_INPUT_DATA ;
		}
		else
		{
			/* Return with Error Code */
			ret = MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED ;
		}
    }

    else
    {
    	/* Export Stream Context */
    	(void)KeyStoreMgmt_ExportStreamCtx(streamId, ctx->stream_ctx);

		/* Return with NO_ERROR on success */
		ret = NO_ERROR ;
    }

	/* Release stream channel */
	(void)KeystoreMgmt_FreeStreamSlot(streamId);

    return( ret );
}

/*==================================================================================================
 *                                       GLOBAL FUNCTIONS
 ==================================================================================================*/

/*************************************************************************************************
 * Description:  This function initializes the specified SHA512 context.
 ************************************************************************************************/
void mbedtls_sha512_init( mbedtls_sha512_context *ctx )
{
    /* Simple sanity check */
    SHA512_ALT_VALIDATE( ctx != NULL ) ;

    memset( ctx, 0, sizeof( mbedtls_sha512_context ) );
    return;
}

/*************************************************************************************************
 * Description:  This function starts a SHA-512 checksum calculation.
 ************************************************************************************************/
int mbedtls_sha512_starts_ret( mbedtls_sha512_context *ctx, int is384 )
{
	SHA512_ALT_VALIDATE_RET( ctx != NULL );

	memset(ctx, 0x00, sizeof(mbedtls_sha512_context));

#if !defined(MBEDTLS_SHA512_NO_SHA384)
	SHA512_ALT_VALIDATE_RET( is384 == 0 || is384 == 1 );
#else
	SHA512_ALT_VALIDATE_RET( is384 == 0 );
#endif

	#if !defined(MBEDTLS_SHA512_NO_SHA384)
		ctx->is384 = is384;
	#endif
	return( 0 );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha512_starts( mbedtls_sha512_context *ctx,
	int is384 )
{
    mbedtls_sha512_starts_ret( ctx, is384 );
}
#endif
#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha512_process( mbedtls_sha512_context *ctx,
	const unsigned char data[128] )
{
    mbedtls_internal_sha512_process( ctx, data );
}
#endif
/*************************************************************************************************
 * Description:  This function feeds an input buffer into an ongoing SHA-512 checksum calculation.
 ************************************************************************************************/
int mbedtls_sha512_update_ret( mbedtls_sha512_context *ctx,
							   const unsigned char *input,
							   size_t ilen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint32_t left, fill;

    /* Simple sanity check */
    SHA512_ALT_VALIDATE_RET( ctx != NULL );
    SHA512_ALT_VALIDATE_RET( ilen == 0 || input != NULL );

    if( ilen == 0 )
    {
    	return( 0 );
    }

    left = ctx->total[0] & 0x7F;
    fill = 128 - left;

    ctx->total[0] += (uint32_t) ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < (uint32_t) ilen )
	{
    	ctx->total[1]++;
	}

    /* Process if buffer left to be processed is >= 64 bytes */
    if( left && ilen >= fill )
    {
		memcpy( (void *) (ctx->buffer + left), input, fill );

		if( ( ret = Sha512_process( ctx, ctx->buffer, 128) ) != 0 )
		{
			return( ret );
		}

		input += fill;
		ilen  -= fill;
		left = 0;
    }

    if( ilen >= 128 )
    {
		uint32_t bytes_processed = (ilen/128)*128;
		if( ( ret = Sha512_process( ctx, input,  bytes_processed) ) != 0 )
		{
			return( ret );
		}

		input += bytes_processed;
		ilen  -= bytes_processed;
    }

    /* Copy pending data to buffer to eb processed later */
    if( ilen > 0 )
    {
    	memcpy( (void *) (ctx->buffer + left), input, ilen );
    }

    return( 0 ) ;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha512_update( mbedtls_sha512_context *ctx,
	const unsigned char *input,
	size_t ilen )
{
    mbedtls_sha512_update_ret( ctx, input, ilen );
}
#endif

/*************************************************************************************************
 * Description:  This function finishes the SHA-512 operation, and writes the result to the output buffer.
 ************************************************************************************************/
int mbedtls_sha512_finish_ret( mbedtls_sha512_context *ctx,
							   unsigned char output[64] )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
    uint32_t used;
    uint32_t hashlen;
    hseHashAlgo_t hashalg;
    uint8_t streamId = INVALID_STREAM_ID;
    KeymgmtErrCodeT err;

    /* Simple sanity check */
    SHA512_ALT_VALIDATE_RET( ctx != NULL ) ;
    SHA512_ALT_VALIDATE_RET( (unsigned char *)output != NULL ) ;

    used = ctx->total[0] & 0x7F;

#if !defined(MBEDTLS_SHA512_NO_SHA384)
    if(ctx->is384 == IS512)
    {
		hashalg = HSE_HASH_ALGO_SHA2_512;
		hashlen = SHA2_512_OUTPUT_LENGTH;
    }
    else
    {
		hashalg = HSE_HASH_ALGO_SHA2_384;
		hashlen = SHA2_384_OUTPUT_LENGTH;
    }
#else
    hashalg = HSE_HASH_ALGO_SHA2_512;
    hashlen = SHA2_512_OUTPUT_LENGTH;
#endif

	/* Send the request */
	if(ctx->stream_start_send == FALSE)
	{
		/* We have less than 1 block of data to be processed.
			we use one-shot method in this case
		*/
		srvResponse = HSE_Hash( hashalg, ctx->buffer, used, output, &hashlen ) ;
	}
	else
	{
		/* Allocate Stream ID */
		err = KeystoreMgmt_FindAllocateStreamSlot(&streamId);
		if(err != KEYMGMT_ERR_SUCCESS)
		{
			return MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED;
		}

		/* Import stream context */
		err = KeyStoreMgmt_ImportStreamCtx(streamId, ctx->stream_ctx);
		if(err != KEYMGMT_ERR_SUCCESS)
		{
			return MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED;
		}

		/* Send the request */
	    srvResponse = HSE_HashStreamFinish( streamId,
		    hashalg, ctx->buffer, used, output, &hashlen ) ;
	}

    /* Check the response */
    if( HSE_SRV_RSP_OK != srvResponse )
    {
		if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_SHA512_BAD_INPUT_DATA ;
		}
		else
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED ;
		}
    }
    else
    {
		/* Return with NO_ERROR on success */
		ret = NO_ERROR ;
		ctx->stream_start_send = FALSE;

		/* Release stream channel */
		(void)KeystoreMgmt_FreeStreamSlot(streamId);

		/* Initialize Stream Context */
		memset(ctx->stream_ctx, 0, sizeof(ctx->stream_ctx));

		ctx->total[0] = 0U ;
		ctx->total[1] = 0U ;
    }

    /* Return the service response */
    return( ret ) ;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha512_finish( mbedtls_sha512_context *ctx,
	unsigned char output[64] )
{
    mbedtls_sha512_finish_ret( ctx, output );
}
#endif
/*************************************************************************************************
 * Description:  This function clones the state of a SHA-512 context.
 ************************************************************************************************/
void mbedtls_sha512_clone( mbedtls_sha512_context *dst,
						   const mbedtls_sha512_context *src )
{
    SHA512_ALT_VALIDATE( dst != NULL );
    SHA512_ALT_VALIDATE( src != NULL );
    *dst = *src;
    return;
}

/*************************************************************************************************
 * Description:  This function calculates the SHA-512 checksum of a buffer.
 ************************************************************************************************/
int mbedtls_sha512_ret( const unsigned char *input,
						size_t ilen,
						unsigned char output[64],
						int is384 )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
    uint32_t hashlen;
    hseHashAlgo_t hashalg;
    mbedtls_sha512_context ctx;

#if !defined(MBEDTLS_SHA512_NO_SHA384)
    SHA512_ALT_VALIDATE_RET( is384 == 0 || is384 == 1 );
#else
    SHA512_ALT_VALIDATE_RET( is384 == 0 );
#endif
    SHA512_ALT_VALIDATE_RET( ilen == 0 || input != NULL );
    SHA512_ALT_VALIDATE_RET( (unsigned char *)output != NULL ) ;

    /* Input length should be block multiple */
    mbedtls_sha512_init(&ctx);

    do
	{
		/* Operation to be performed for SHA2-256 */
		if( IS512 == is384 )
		{
			/* SHA2-256 */
			hashalg = HSE_HASH_ALGO_SHA2_512 ;
			hashlen = SHA2_512_OUTPUT_LENGTH;
		}
		/* Operation to be performed for SHA2-224 */
		else if( IS384 == is384 )
		{
			/* SHA2-224 */
			hashalg = HSE_HASH_ALGO_SHA2_384 ;
			hashlen = SHA2_384_OUTPUT_LENGTH;
		}
		else
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_SHA512_BAD_INPUT_DATA ;
			break;
		}

	#if !defined(MBEDTLS_SHA512_NO_SHA384)
		ctx.is384 = is384;
	#endif

		/* Send the request */
		srvResponse = HSE_Hash( hashalg, input, ilen, output, &hashlen ) ;

		/* Check the response */
		if( HSE_SRV_RSP_OK != srvResponse )
		{
			if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
			{
				/* Return with Error Codes */
				ret = MBEDTLS_ERR_SHA512_BAD_INPUT_DATA ;
			}
			else
			{
				/* Return with Error Codes */
				ret = MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED ;
			}
		}
		else
		{
			/* Return with NO_ERROR on success */
			ret = NO_ERROR ;
		}
	}while(0);

    mbedtls_sha512_free(&ctx);

    /* Return the service response */
    return( ret ) ;
}

/*************************************************************************************************
 * Description:  This function processes a single data block within the ongoing SHA-512 computation.
 ************************************************************************************************/
int mbedtls_internal_sha512_process( mbedtls_sha512_context *ctx,
									 const unsigned char data[128] )
{
    int ret;

    SHA512_ALT_VALIDATE_RET( ctx != NULL );
    SHA512_ALT_VALIDATE_RET( (const unsigned char *)data != NULL );

    /* Process the data block */
    ret = Sha512_process(ctx, data, 128);

    return( ret );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha512( const unsigned char *input,
	size_t ilen,
	unsigned char output[64],
	int is384 )
{
    mbedtls_sha512_ret( input, ilen, output, is384 );
}
#endif
/*************************************************************************************************
 * Description:  This function releases and clears the specified SHA512 context.
 ************************************************************************************************/
void mbedtls_sha512_free( mbedtls_sha512_context *ctx )
{
    /* Simple sanity check */
    if( ctx == NULL)
    {
    	return;
    }

    /* Securely zeroize the SHA512 context */
    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_sha512_context ) ) ;
}

#endif /* MBEDTLS_SHA512_ALT */
