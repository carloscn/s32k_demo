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

#if defined(MBEDTLS_MD5_ALT)
#include <string.h>

#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/md5.h"
#include "mbedtls/error.h"
#include "keystore_mgmt.h"
#include "device.h"
#include "hse_host_hash.h"

/*==================================================================================================
*                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL MACROS
==================================================================================================*/

/* Parameter validation macros. */
#define MD5_ALT_VALIDATE_RET(cond)                             \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_md5_ALT_BAD_INPUT_DATA )
#define MD5_ALT_VALIDATE(cond)  \
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
 * 	@brief		Process the input data in ongoing stream context or starts the MD5 streaming
 * 				operation if stream operation is not started
 *
 * 	@param[in]	ctx
 * 				The MD5 Context
 *
 * 	@param[in]	data
 *              Input data
 *
 *	@param[out]	num_bytes
 *				Input data length
 *
 *  @return		\c 0 on success.
 *
 *	@return		#MBEDTLS_ERR_MD_BAD_INPUT_DATA for bad input
 *
 *	@return		#MBEDTLS_ERR_MD5_HW_ACCEL_FAILED for hardware accelator failure
 *
 */
static int Md5_process( mbedtls_md5_context *ctx,
						   const unsigned char *data, uint32_t num_bytes );

/*==================================================================================================
*                                       LOCAL FUNCTIONS
==================================================================================================*/
/*************************************************************************************************
* Description:  Process the input data in ongoing stream context or starts the MD5 streaming
* operation if stream operation is not started
************************************************************************************************/
static int Md5_process( mbedtls_md5_context *ctx,
				   	   	const unsigned char *data, uint32_t num_bytes )
{
    int ret;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
    KeymgmtErrCodeT err;
    uint8_t streamId = INVALID_STREAM_ID;

	/* Allocate Stream ID */
	err = KeystoreMgmt_FindAllocateStreamSlot(&streamId);
	if(err != KEYMGMT_ERR_SUCCESS)
	{
		return( MBEDTLS_ERR_MD5_HW_ACCEL_FAILED );
	}

	if(ctx->stream_start_send == FALSE)
	{
#if defined(HSE_HASH_ALGO_MD5)
		/* Send the request */
		srvResponse = HSE_HashStreamStart(streamId,
				HSE_HASH_ALGO_MD5, data, num_bytes, NULL, NULL) ;

		/* Check the response and mark stream_start_send as TRUE */
		if(HSE_SRV_RSP_OK == srvResponse)
		{
			ctx->stream_start_send = TRUE;
		}
#else
		(void)data;
		(void)num_bytes;
		/* MD5 obsolete */
		srvResponse = HSE_SRV_RSP_NOT_SUPPORTED;
#endif /* HSE_HASH_ALGO_MD5 */
	}
	else
	{
		/* Import stream context */
		err = KeyStoreMgmt_ImportStreamCtx(streamId, ctx->stream_ctx);
		if(err != KEYMGMT_ERR_SUCCESS)
		{
			/* Release stream channel */
			(void)KeystoreMgmt_FreeStreamSlot(streamId);

			return( MBEDTLS_ERR_MD5_HW_ACCEL_FAILED );
		}

#if defined(HSE_HASH_ALGO_MD5)
		/* Send the request */
		srvResponse = HSE_HashStreamUpdate(streamId,
			HSE_HASH_ALGO_MD5, data, num_bytes, NULL, NULL ) ;
#else
		(void)data;
		(void)num_bytes;
		/* MD5 obsolete */
		srvResponse = HSE_SRV_RSP_NOT_SUPPORTED;
#endif /* HSE_HASH_ALGO_MD5 */
	}

	/* Check the response */
	if(HSE_SRV_RSP_OK != srvResponse)
	{
		/* Return with Error Codes */
		ret = MBEDTLS_ERR_MD5_HW_ACCEL_FAILED ;
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

	return ( ret );
}

/*==================================================================================================
*                                       GLOBAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
* Description:  This function initializes the specified MD5 context.
************************************************************************************************/
void mbedtls_md5_init( mbedtls_md5_context *ctx )
{
	/* Simple sanity check */
    MD5_ALT_VALIDATE( ctx != NULL ) ;

    memset( ctx, 0, sizeof( mbedtls_md5_context ) );
    return;
}

/*************************************************************************************************
* Description:  This function starts a md5 checksum calculation.
************************************************************************************************/
int mbedtls_md5_starts_ret( mbedtls_md5_context *ctx )
{
	/* Simple sanity check */
	MD5_ALT_VALIDATE_RET( ctx != NULL ) ;

	memset(ctx, 0x00, sizeof(mbedtls_md5_context));

	return (0);
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_md5_starts( mbedtls_md5_context *ctx )
{
    mbedtls_md5_starts_ret( ctx );
}
#endif

/*************************************************************************************************
* Description:  This function feeds an input buffer into an ongoing md5 checksum calculation.
************************************************************************************************/
int mbedtls_md5_update_ret( mbedtls_md5_context *ctx,
                            const unsigned char *input,
                            size_t ilen )
{

	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	uint32_t left, fill;

	/* Simple sanity check */
	MD5_ALT_VALIDATE_RET( ctx != NULL );
	MD5_ALT_VALIDATE_RET( ilen == 0 || input != NULL );

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

		if( ( ret = Md5_process( ctx, ctx->buffer, 64) ) != 0 )
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
		if( ( ret = Md5_process( ctx, input,  bytes_processed) ) != 0 )
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

	/* Return the service response */
	return( 0 ) ;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_md5_update( mbedtls_md5_context *ctx,
                         const unsigned char *input,
                         size_t ilen )
{
    mbedtls_md5_update_ret( ctx, input, ilen );
}
#endif

/*************************************************************************************************
* Description:  This function finishes the md5 operation, and writes the result to the output buffer.
************************************************************************************************/
int mbedtls_md5_finish_ret( mbedtls_md5_context *ctx,
                            unsigned char output[16] )
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;

#if defined(HSE_HASH_ALGO_MD5)
	uint32_t used;
	/* hashlen :Output length */
	uint32_t hashlen = MD5_OUTPUT_LENGTH ;
#endif /* HSE_HASH_ALGO_MD5 */
    uint8_t streamId = INVALID_STREAM_ID;
    KeymgmtErrCodeT err;

	/* Simple sanity check */
	MD5_ALT_VALIDATE_RET( ctx != NULL ) ;
	MD5_ALT_VALIDATE_RET( (unsigned char *)output != NULL ) ;

#if defined(HSE_HASH_ALGO_MD5)
	used = ctx->total[0] & 0x3F;
#endif /* HSE_HASH_ALGO_MD5 */

	/* Send the request */
	if(ctx->stream_start_send == FALSE)
	{
#if defined(HSE_HASH_ALGO_MD5)
		/* We have less than 1 block of data to be processed.
			we use oneshot method in this case
		*/
		srvResponse = HSE_Hash( HSE_HASH_ALGO_MD5, ctx->buffer, used, output, &hashlen ) ;
#else
		/* MD5 obsolete */
		srvResponse = HSE_SRV_RSP_NOT_SUPPORTED;
#endif /* HSE_HASH_ALGO_MD5 */
	}
	else
	{
		/* Allocate Stream ID */
		err = KeystoreMgmt_FindAllocateStreamSlot(&streamId);
		if(err != KEYMGMT_ERR_SUCCESS)
		{
			return( MBEDTLS_ERR_MD5_HW_ACCEL_FAILED );
		}

		/* Import stream context */
		err = KeyStoreMgmt_ImportStreamCtx(streamId, ctx->stream_ctx);
		if(err != KEYMGMT_ERR_SUCCESS)
		{
			return( MBEDTLS_ERR_MD5_HW_ACCEL_FAILED );
		}

#if defined(HSE_HASH_ALGO_MD5)
		/* Send the request */
	    srvResponse = HSE_HashStreamFinish( streamId,
	    		HSE_HASH_ALGO_MD5, ctx->buffer, used, output, &hashlen ) ;
#else
		/* MD5 obsolete */
		srvResponse = HSE_SRV_RSP_NOT_SUPPORTED;
#endif /* HSE_HASH_ALGO_MD5 */
	}

    /* Check the response */
    if(HSE_SRV_RSP_OK != srvResponse)
    {
    	/* Return with Error Codes */
    	ret = MBEDTLS_ERR_MD5_HW_ACCEL_FAILED ;
    }
    else
    {
    	/* Return with NO_ERROR on success */
    	ret = NO_ERROR ;
		ctx->stream_start_send = FALSE;
		(void)KeystoreMgmt_FreeStreamSlot(streamId);
		memset(ctx->stream_ctx, 0, sizeof(ctx->stream_ctx));

		ctx->total[0] = 0U ;
		ctx->total[1] = 0U ;
    }

	/* Return the service response */
	return( ret ) ;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_md5_finish( mbedtls_md5_context *ctx,
                         unsigned char output[16] )
{
    mbedtls_md5_finish_ret( ctx, output );
}
#endif

/*************************************************************************************************
* Description:  Clone (the state of) an MD5 context.
************************************************************************************************/
void mbedtls_md5_clone( mbedtls_md5_context *dst,
                        const mbedtls_md5_context *src )
{
	MD5_ALT_VALIDATE( dst != NULL );
	MD5_ALT_VALIDATE( src != NULL );

    *dst = *src;
    return;
}

/*************************************************************************************************
* Description:  This function calculates the md5 checksum of a buffer.
************************************************************************************************/
int mbedtls_md5_ret( const unsigned char *input,
                     size_t ilen,
                     unsigned char output[16] )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;

#if defined(HSE_HASH_ALGO_MD5)
	/* hashlen :Output length */
	uint32_t hashlen = MD5_OUTPUT_LENGTH ;
#endif /* HSE_HASH_ALGO_MD5 */
	mbedtls_md5_context ctx;

	/* Simple sanity check */
    MD5_ALT_VALIDATE_RET( ilen == 0 || input != NULL );
	MD5_ALT_VALIDATE_RET( (unsigned char *)output != NULL ) ;

	/* Input length should be block multiple */
	mbedtls_md5_init(&ctx);

#if defined(HSE_HASH_ALGO_MD5)
	/* Send the request */
    srvResponse = HSE_Hash( HSE_HASH_ALGO_MD5, input, ilen, output, &(hashlen) ) ;
#else
    /* MD5 obsolete */
	srvResponse = HSE_SRV_RSP_NOT_SUPPORTED;
#endif /* HSE_HASH_ALGO_MD5 */

    /* Check the response */
    if(HSE_SRV_RSP_OK != srvResponse)
    {
    	/* Return with Error Codes */
    	ret = MBEDTLS_ERR_MD5_HW_ACCEL_FAILED ;
    }
    else
    {
    	/* Return with NO_ERROR on success */
    	ret = NO_ERROR ;
    }

	mbedtls_md5_free(&ctx);

	/* Return the service response */
	return( ret ) ;
}

/*************************************************************************************************
* Description:  MD5 process data block.
************************************************************************************************/
int mbedtls_internal_md5_process( mbedtls_md5_context *ctx,
                                  const unsigned char data[64] )
{
	int ret;

    MD5_ALT_VALIDATE_RET( ctx != NULL );
    MD5_ALT_VALIDATE_RET( (const unsigned char *)data != NULL );

	/* Process the data block */
	ret = Md5_process(ctx, data, 64);

	return ret;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_md5_process( mbedtls_md5_context *ctx,
                          const unsigned char data[64] )
{
    (void)mbedtls_internal_md5_process( ctx, data );
}
#endif
/*************************************************************************************************
* Description:  This function releases and clears the specified MD5 context.
************************************************************************************************/
void mbedtls_md5_free( mbedtls_md5_context *ctx )
{
	/* Simple sanity check */
    if( ctx == NULL)
    {
    	return ;
    }

    /* Securely zeroize the SHA1 context */
    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_md5_context ) ) ;

    return;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_md5( const unsigned char *input,
                  size_t ilen,
                  unsigned char output[16] )
{
    mbedtls_md5_ret( input, ilen, output );
}
#endif
#endif /* MBEDTLS_MD5_ALT */
