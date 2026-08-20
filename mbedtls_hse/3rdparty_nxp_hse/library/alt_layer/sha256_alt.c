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

#if defined(MBEDTLS_SHA256_ALT)
#include <string.h>

#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"
#include "mbedtls/error.h"
#include "keystore_mgmt.h"
#include "device.h"
#include "hse_host_hash.h"

/*==================================================================================================
 *                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
 ==================================================================================================*/

typedef enum {
    IS256 = (0x00UL),
    IS224 = (0x01UL),
}sha2_Type_t;

/*==================================================================================================
 *                                       LOCAL MACROS
 ==================================================================================================*/

#define SHA_256_OUTPUT_LENGTH				((uint32_t)(0x20UL)) /**< SHA-256 output length. */
#define SHA_224_OUTPUT_LENGTH				((uint32_t)(0x1CUL)) /**< SHA-224 output length. */

/* Parameter validation macros. */
#define SHA256_ALT_VALIDATE_RET(cond)     \
MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_SHA256_BAD_INPUT_DATA )
#define SHA256_ALT_VALIDATE(cond) 		  \
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
 * 	@brief		Process the input data in ongoing stream context or starts the SHA256 streaming
 * 				operation if stream operation is not started
 *
 * 	@param[in]	ctx
 * 				The SHA256 Context
 *
 * 	@param[in]	data
 *              Input data
 *
 *	@param[out]	num_bytes
 *				Input data length
 *
 *  @return		\c 0 on success.
 *
 *	@return		#MBEDTLS_ERR_SHA256_BAD_INPUT_DATA for bad input
 *
 *	@return		#MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED for hardware accelator failure
 *
 */
static int Sha256_process( mbedtls_sha256_context *ctx,
						   const unsigned char *data, uint32_t num_bytes );

/*==================================================================================================
 *                                       LOCAL FUNCTIONS
 ==================================================================================================*/
/*************************************************************************************************
* Description:  Process the input data in ongoing stream context or starts the SHA256 streaming
* operation if stream operation is not started
************************************************************************************************/
static int Sha256_process( mbedtls_sha256_context *ctx,
						   const unsigned char *data, uint32_t num_bytes )
{
    int ret;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
    KeymgmtErrCodeT err;
    hseHashAlgo_t hashalg;
    uint8_t streamId = INVALID_STREAM_ID;

    hashalg = ctx->is224?HSE_HASH_ALGO_SHA2_224:HSE_HASH_ALGO_SHA2_256;

	err = KeystoreMgmt_FindAllocateStreamSlot(&streamId);
	if(err != KEYMGMT_ERR_SUCCESS)
	{
		return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
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

			return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
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
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_SHA256_BAD_INPUT_DATA ;
		}
		else
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED ;
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
 * Description:  This function initializes the specified SHA256 context.
 ************************************************************************************************/
void mbedtls_sha256_init( mbedtls_sha256_context *ctx )
{
    /* Simple sanity check */
    SHA256_ALT_VALIDATE( ctx != NULL ) ;

    memset( ctx, 0, sizeof( mbedtls_sha256_context ) );
    return;
}

/*************************************************************************************************
 * Description:  This function starts a SHA-256 checksum calculation.
 ************************************************************************************************/
int mbedtls_sha256_starts_ret( mbedtls_sha256_context *ctx, int is224 )
{
    SHA256_ALT_VALIDATE_RET( ctx != NULL ) ;
    SHA256_ALT_VALIDATE_RET( is224 == 0 || is224 == 1 );


	memset(ctx, 0x00, sizeof(mbedtls_sha256_context));

    ctx->is224 = is224;

    return( 0 );

}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha256_starts( mbedtls_sha256_context *ctx )
{
    mbedtls_sha256_starts_ret( ctx );
}
#endif
/*************************************************************************************************
 * Description:  This function feeds an input buffer into an ongoing SHA-256 checksum calculation.
 ************************************************************************************************/
int mbedtls_sha256_update_ret( mbedtls_sha256_context *ctx,
							   const unsigned char *input,
							   size_t ilen )
{

    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint32_t left, fill;

    /* Simple sanity check */
    SHA256_ALT_VALIDATE_RET( ctx != NULL );
    SHA256_ALT_VALIDATE_RET( ilen == 0 || input != NULL );

    if( ilen == 0 )
    {
    	return( 0 );
    }

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

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

        if( ( ret = Sha256_process( ctx, ctx->buffer, 64) ) != 0 )
        {
        	return( ret );
        }

		input += fill;
		ilen  -= fill;
		left = 0;
    }

    if( ilen >= 64 )
    {
    	uint32_t bytes_processed = (ilen/64)*64;

        if( ( ret = Sha256_process( ctx, input,  bytes_processed) ) != 0 )
        {
        	return( ret );
        }

		input += bytes_processed;
		ilen  -= bytes_processed;
    }

    /* Copy pending data to buffer to be processed later */
    if( ilen > 0 )
    {
    	memcpy( (void *) (ctx->buffer + left), input, ilen );
    }

    return( 0 ) ;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha256_update( mbedtls_sha256_context *ctx,
	const unsigned char *input,
	size_t ilen )
{
    mbedtls_sha256_update_ret( ctx, input, ilen );
}
#endif

/*************************************************************************************************
 * Description:  This function finishes the SHA-256 operation, and writes the result to the output buffer.
 ************************************************************************************************/
int mbedtls_sha256_finish_ret( mbedtls_sha256_context *ctx,
							   unsigned char output[32] )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
    uint32_t used;
    uint32_t hashlen;
    hseHashAlgo_t hashalg;
    KeymgmtErrCodeT err;
    uint8_t streamId = INVALID_STREAM_ID;

    /* Simple sanity check */
    SHA256_ALT_VALIDATE_RET( ctx != NULL ) ;
    SHA256_ALT_VALIDATE_RET( (unsigned char *)output != NULL ) ;

    used = ctx->total[0] & 0x3F;

    if(ctx->is224 == IS256)
    {
		hashalg = HSE_HASH_ALGO_SHA2_256;
		hashlen = SHA_256_OUTPUT_LENGTH;
    }
    else
    {
		hashalg = HSE_HASH_ALGO_SHA2_224;
		hashlen = SHA_224_OUTPUT_LENGTH;
    }

	/* Send the request */
	if(ctx->stream_start_send == FALSE)
	{
		/* We have less than 1 block of data to be processed.
			we use oneshot method in this case
		*/
		srvResponse = HSE_Hash( hashalg, ctx->buffer, used, output, &hashlen ) ;
	}
	else
	{
		/* Allocate Stream ID */
		err = KeystoreMgmt_FindAllocateStreamSlot(&streamId);
		if(err != KEYMGMT_ERR_SUCCESS)
		{
			return( MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED);
		}

		/* Import stream context */
		err = KeyStoreMgmt_ImportStreamCtx(streamId, ctx->stream_ctx);
		if(err != KEYMGMT_ERR_SUCCESS)
		{
			return( MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED );
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
			/* Return with Error Code */
			ret = MBEDTLS_ERR_SHA256_BAD_INPUT_DATA ;
		}
		else
		{
			/* Return with Error Code */
			ret = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED ;
		}
    }

    else
    {
		/* Return with NO_ERROR on success */
		ret = NO_ERROR ;
		ctx->stream_start_send = FALSE;
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
void mbedtls_sha1_finish( mbedtls_sha1_context *ctx,
	unsigned char output[20] )
{
    mbedtls_sha1_finish_ret( ctx, output );
}
#endif
/*************************************************************************************************
 * Description:  This function clones the state of a SHA-256 context.
 ************************************************************************************************/
void mbedtls_sha256_clone( mbedtls_sha256_context *dst,
						   const mbedtls_sha256_context *src )
{
    SHA256_ALT_VALIDATE( dst != NULL );
    SHA256_ALT_VALIDATE( src != NULL );

    *dst = *src;
    return;
}

/*************************************************************************************************
 * Description:  This function calculates the SHA-256 checksum of a buffer.
 ************************************************************************************************/
int mbedtls_sha256_ret( const unsigned char *input,
					    size_t ilen,
						unsigned char output[32],
						int is224 )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
    uint32_t hashlen;
    hseHashAlgo_t hashalg;
    mbedtls_sha256_context ctx;

    SHA256_ALT_VALIDATE_RET( ilen == 0 || input != NULL );
    SHA256_ALT_VALIDATE_RET( (unsigned char *)output != NULL ) ;

    /* Input length should be block multiple */
    mbedtls_sha256_init(&ctx);

    do
    {
		/* Operation to be performed for SHA2-256 */
		if( IS256 == is224 )
		{
			/* SHA2-256 */
			hashalg = HSE_HASH_ALGO_SHA2_256 ;
			hashlen = SHA_256_OUTPUT_LENGTH;
		}

		/* Operation to be performed for SHA2-224 */
		else if( IS224 == is224 )
		{
			/* SHA2-224 */
			hashalg = HSE_HASH_ALGO_SHA2_224 ;
			hashlen = SHA_224_OUTPUT_LENGTH;
		}
		else
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_SHA256_BAD_INPUT_DATA ;
			break;
		}

		ctx.is224 = is224;

		/* Send the request */
		srvResponse = HSE_Hash( hashalg, input, ilen, output, &hashlen ) ;

		/* Check the response */
		if( HSE_SRV_RSP_OK != srvResponse )
		{
			if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
			{
				/* Return with Error Code */
				ret = MBEDTLS_ERR_SHA256_BAD_INPUT_DATA ;
			}
			else
			{
				/* Return with Error Code */
				ret = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED ;
			}
		}
		else
		{
			/* Return with NO_ERROR on success */
			ret = NO_ERROR ;
		}
    }while(0);

    mbedtls_sha256_free( &ctx );

    /* Return the service response */
    return( ret ) ;
}

/*************************************************************************************************
 * Description:  This function processes a single data block within the ongoing
 * SHA-256 computation.
 ************************************************************************************************/
int mbedtls_internal_sha256_process( mbedtls_sha256_context *ctx,
									 const unsigned char data[64] )
{
    int ret;

    SHA256_ALT_VALIDATE_RET( ctx != NULL );
    SHA256_ALT_VALIDATE_RET( (const unsigned char *)data != NULL );

    /* Process the data block */
    ret = Sha256_process(ctx, data, 64);

    return( ret );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha256_process( mbedtls_sha256_context *ctx,
	const unsigned char data[64] )
{
    mbedtls_internal_sha256_process( ctx, data );
}
#endif
/*************************************************************************************************
 * Description:  This function releases and clears the specified SHA256 context.
 ************************************************************************************************/
void mbedtls_sha256_free( mbedtls_sha256_context *ctx )
{
    /* Simple sanity check */
    if( ctx == NULL)
    {
    	return;
    }

    /* Securely zeroize the SHA256 context */
    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_sha256_context ) );
}

#endif /* MBEDTLS_SHA256_ALT */
