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

#if defined(MBEDTLS_USE_NXP_HSE_CRYPTO)&&defined(MBEDTLS_HMAC_ALT)
#include <string.h>
#include "device.h"
#include "global_defs.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/md_internal.h"
#include "mbedtls/md.h"
#include "hmac_alt.h"
#include "mbedtls/error.h"
#include "keystore_mgmt.h"
#include "hse_host_mac.h"
#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

/*==================================================================================================
*                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL MACROS
==================================================================================================*/

/* Parameter validation macros. */
#define HMAC_ALT_VALIDATE_RET(cond)        \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_MD_BAD_INPUT_DATA )
#define HMAC_ALT_VALIDATE(cond)            \
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
 * 	@brief		Process the input data in ongoing stream context or starts the HMAC streaming
 * 				operation if stream operation is not started
 *
 * 	@param[in]	ctx
 * 				The HMAC Context
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
 *	@return		#MBEDTLS_ERR_MD_HW_ACCEL_FAILED for hardware accelator failure
 *
 */
static int Hmac_process( mbedtls_hmac_context *ctx,
						 const unsigned char *data, uint32_t num_bytes );

/*==================================================================================================
*                                       LOCAL FUNCTIONS
==================================================================================================*/
/*************************************************************************************************
* Description:  Process the input data in ongoing stream context or starts the HMAC streaming
* operation if stream operation is not started
************************************************************************************************/
static int Hmac_process( mbedtls_hmac_context *ctx,
						 const unsigned char *data, uint32_t num_bytes )
{
	int ret;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
	KeymgmtErrCodeT err;
	uint8_t streamId = INVALID_STREAM_ID;

	err = KeystoreMgmt_FindAllocateStreamSlot(&streamId);
	if(err != KEYMGMT_ERR_SUCCESS)
	{
		return( MBEDTLS_ERR_MD_ALLOC_FAILED );
	}

	if(ctx->stream_start_send == FALSE)
	{
		/* Send the request */
		srvResponse = HSE_HmacStart(streamId, HSE_AUTH_DIR_GENERATE,
				ctx->hashalg, ctx->hmackeyhandle, data, num_bytes, NULL, NULL) ;

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
			return( MBEDTLS_ERR_MD_HW_ACCEL_FAILED );
		}
		/* Send the request */
		srvResponse = HSE_HmacUpdate(streamId, HSE_AUTH_DIR_GENERATE,
				ctx->hashalg, ctx->hmackeyhandle, data, num_bytes, NULL, NULL ) ;
	}

	/* Check the response */
	if(HSE_SRV_RSP_OK != srvResponse)
	{
		if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_MD_BAD_INPUT_DATA ;
		}
		else
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_MD_HW_ACCEL_FAILED ;
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

	return ret;
}

/*==================================================================================================
*                                       GLOBAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
* Description:  This function initializes the specified HMAC context.
************************************************************************************************/
void nxp_hse_hmac_init( mbedtls_hmac_context *ctx)
{
	/* Simple sanity check */
    HMAC_ALT_VALIDATE( ctx != NULL ) ;

    memset( ctx, 0, sizeof( mbedtls_hmac_context ) );
	ctx->hmackeyhandle = HSE_INVALID_KEY_HANDLE;
}

/*************************************************************************************************
* Description:  Setup the HMAC context
************************************************************************************************/
int nxp_hse_hmac_setup(mbedtls_hmac_context *ctx, mbedtls_md_context_t *ctx_md)
{
	const mbedtls_md_info_t *md_info;

	if(ctx_md == NULL)
	{
		return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
	}

	md_info = ctx_md->md_info;

	if( (ctx == NULL) || (md_info==NULL) )
	{
		return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
	}

	switch(md_info->type)
	{
#if defined(MBEDTLS_MD5_C)
		case MBEDTLS_MD_MD5:
#if defined(MBEDTLS_USE_NXP_HSE_HASH_MD5_HMAC_HASH_384_512) && defined(HSE_HASH_ALGO_MD5)
			ctx->hashalg = HSE_HASH_ALGO_MD5;
			break;
#else
			return( MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE );
#endif /* MBEDTLS_USE_NXP_HSE_HASH_MD5_HMAC_HASH_384_512 */
#endif /* MBEDTLS_MD5_C */
#if defined(MBEDTLS_SHA1_C)
		case MBEDTLS_MD_SHA1:
			ctx->hashalg = HSE_HASH_ALGO_SHA_1;
			break;
#endif /* MBEDTLS_SHA1_C */
#if defined(MBEDTLS_SHA256_C)
		case MBEDTLS_MD_SHA256:
			ctx->hashalg = HSE_HASH_ALGO_SHA2_256;
			break;
		case MBEDTLS_MD_SHA224:
			ctx->hashalg = HSE_HASH_ALGO_SHA2_224;
			break;
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA512_C)
		case MBEDTLS_MD_SHA512:
#if defined(MBEDTLS_USE_NXP_HSE_HASH_MD5_HMAC_HASH_384_512) || defined (MBEDTLS_USE_NXP_HSE_HMAC_HASH_384_512)
			ctx->hashalg = HSE_HASH_ALGO_SHA2_512;
#else /* MBEDTLS_SHA512_C */
			return MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
#endif /* MBEDTLS_USE_NXP_HSE_HASH_MD5_HMAC_HASH_384_512 */
			break;
#if !defined(MBEDTLS_SHA512_NO_SHA384)
		case MBEDTLS_MD_SHA384:
#if defined(MBEDTLS_USE_NXP_HSE_HASH_MD5_HMAC_HASH_384_512) || defined (MBEDTLS_USE_NXP_HSE_HMAC_HASH_384_512)
			ctx->hashalg = HSE_HASH_ALGO_SHA2_384;
#else
			return MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
#endif /* MBEDTLS_USE_NXP_HSE_HASH_MD5_HMAC_HASH_384_512 */
			break;
#endif /* !defined(MBEDTLS_SHA512_NO_SHA384) */
#endif /* MBEDTLS_SHA512_C */
		default:
			return( MBEDTLS_ERR_MD_BAD_INPUT_DATA);

	}
	ctx->ctx_md = ctx_md;
	return( 0 );
}

/*************************************************************************************************
* Description:  This function sets the HMAC key
************************************************************************************************/
int nxp_hse_hmac_set_key(mbedtls_hmac_context *ctx, const unsigned char *key, size_t keylen )
{
	int ret = 0;
	KeymgmtErrCodeT err = KEYMGMT_ERR_SUCCESS;
	key_import_param_t key_import_param;
	uint32_t keybits = BYTES_TO_BITS((keylen & (~KEYLOADED_FLAG)))|(keylen & KEYLOADED_FLAG);
    unsigned char tmpkey[MBEDTLS_MD_MAX_SIZE];
	uint32_t key_length = 0U;

    memset(&key_import_param, 0x00, sizeof(key_import_param_t));

	/* Simple sanity check */
	if( (ctx == NULL) || (key == NULL))
	{
		return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
	}

	key_length = BITS_TO_BYTES(keybits & (~KEYLOADED_FLAG));

	if(keybits & KEYLOADED_FLAG)
	{
		/* Load Key Handle from keydata - First four bytes contain the key handle */
		ctx->hmackeyhandle = (hseKeyHandle_t)(key[0]|(key[1]<<8)|(key[2]<<16)|(key[3]<<24));
		ctx->key_preloaded_flag = TRUE;
		return NO_ERROR;
	}

	if(key_length > ctx->ctx_md->md_info->block_size)
	{
#if defined (MBEDTLS_USE_NXP_HSE_HMAC_LARGE_KEYSIZE_WORKAROUND)
		/* Calculate Hash of Key to be used as key */
		mbedtls_md_context_t md_ctx;

		/* Initialize Message Digest Context */
		mbedtls_md_init(&md_ctx);
		do
		{
			/* Setup Message Digest */
			if( (ret = mbedtls_md_setup(&md_ctx,ctx->ctx_md->md_info, 0)) != 0)
			{
				break;
			}
			/* Calculate Hash of Key  */
			if( (ret = mbedtls_md(md_ctx.md_info, key, key_length, tmpkey)) != 0)
			{
				break;
			}
			key = tmpkey;
			keylen = ctx->ctx_md->md_info->size;
		} while(0);

		/* Free Message Digest Context */
		mbedtls_md_free(&md_ctx);
#else
		keylen = key_length;
#endif /* MBEDTLS_USE_NXP_HSE_HMAC_LARGE_KEYSIZE_WORKAROUND */
	}
	else if(key_length < BITS_TO_BYTES(HSE_MIN_HMAC_KEY_BITS_LEN))
	{
		uint32_t i;
		/* Pad the key upto minimum HMACkey bit length */
		for(i = 0; i < key_length; i++)
		{
			tmpkey[i] = key[i];
		}
		/* Padding the key by 0s upto block length */
		while(i < BITS_TO_BYTES(HSE_MIN_HMAC_KEY_BITS_LEN))
		{
			tmpkey[i++] = 0;
		}
		key = tmpkey;
		keylen = BITS_TO_BYTES(HSE_MIN_HMAC_KEY_BITS_LEN);
	}

	/* Import Key in HSE Key Store */
	key_import_param.key_catalog = HSE_KEY_CATALOG_ID_RAM;
	key_import_param.key_type = HSE_KEY_TYPE_HMAC;
	key_import_param.key_param.sym_key_param.key = key;
	key_import_param.key_param.sym_key_param.size = BYTES_TO_BITS(keylen);

	if(ctx->hmackeyhandle != HSE_INVALID_KEY_HANDLE)
	{
		err = KeyStoreMgmt_ImportKey(ctx->hmackeyhandle, &key_import_param);
	}
	else
	{
		err = KeystoreMgmt_FindImportSlot(&key_import_param, &ctx->hmackeyhandle);
	}
	if(err != KEYMGMT_ERR_SUCCESS)
	{
		ret = MBEDTLS_ERR_MD_HW_ACCEL_FAILED;
	}
	else
	{
		ret = NO_ERROR;
	}

	/* Zeroise Temp Key */
	mbedtls_platform_zeroize( tmpkey, sizeof( tmpkey) );

	/* Return the service response */
	return( ret ) ;
}

/*************************************************************************************************
* Description:  This function starts a HMAC checksum calculation.
************************************************************************************************/
int nxp_hse_hmac_starts_ret( mbedtls_hmac_context *ctx, const unsigned char *key, size_t keylen )
{
	ctx->total[0] = 0;
	ctx->total[1] = 0;

	/* Allocate HMAC Key from KeyStore or reload on the same key handle */
	return (nxp_hse_hmac_set_key(ctx, key, keylen));
}

/*************************************************************************************************
* Description:  This function feeds an input buffer into an ongoing HMAC checksum calculation.
************************************************************************************************/
int nxp_hse_hmac_update_ret( mbedtls_hmac_context *ctx,
							   const unsigned char *input,
							   size_t ilen )
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	uint32_t left, fill, blocksize;

	/* Simple sanity check */
	HMAC_ALT_VALIDATE_RET( ctx != NULL );
	HMAC_ALT_VALIDATE_RET( ilen == 0 || input != NULL );

	if( ilen == 0 )
	{
		return( 0 );
	}

	blocksize = ctx->ctx_md->md_info->block_size;
	left = ctx->total[0] & (blocksize - 1);
	fill = blocksize - left;

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

		if( ( ret = Hmac_process( ctx, ctx->buffer, blocksize) ) != 0 )
			return( ret );

		input += fill;
		ilen  -= fill;
		left = 0;
	}

	if( ilen >= blocksize )
	{
		uint32_t bytes_processed = (ilen/blocksize)*blocksize;
		if( ( ret = Hmac_process( ctx, input,  bytes_processed) ) != 0 )
			return( ret );

		input += bytes_processed;
		ilen  -= bytes_processed;
	}

	/* Copy pending data to buffer to be processed later */
	if( ilen > 0 )
	{
		memcpy( (void *) (ctx->buffer + left), input, ilen );
	}

	/* Return the service response */
	return( 0 ) ;
}

/*************************************************************************************************
* Description:  This function finishes the HMAC operation, and writes the result to the output buffer.
************************************************************************************************/
int nxp_hse_hmac_finish_ret( mbedtls_hmac_context *ctx,
							 unsigned char *output )
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
	uint32_t left;
	uint32_t hashlen, blocksize;
	uint8_t streamId = INVALID_STREAM_ID;
	KeymgmtErrCodeT err;

	/* Simple sanity check */
	HMAC_ALT_VALIDATE_RET( ctx != NULL ) ;
	HMAC_ALT_VALIDATE_RET( (unsigned char *)output != NULL ) ;

	if(ctx->hmackeyhandle == HSE_INVALID_KEY_HANDLE)
	{
		return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
	}

	blocksize = ctx->ctx_md->md_info->block_size;
	left = ctx->total[0] & (blocksize - 1);

	hashlen = ctx->ctx_md->md_info->size;

	/* Send the request */
	if((ctx->stream_start_send == FALSE) && (left != 0))
	{
		/* We have less than 1 block of data to be processed.
		   we use oneshot method in this case
		*/
		srvResponse = HSE_Hmac( HSE_AUTH_DIR_GENERATE, ctx->hashalg, 	\
			ctx->hmackeyhandle, ctx->buffer, left, output, &hashlen ) ;
	}
	else
	{
		/* Allocate Stream ID */
		err = KeystoreMgmt_FindAllocateStreamSlot(&streamId);
		if(err != KEYMGMT_ERR_SUCCESS)
		{
			return MBEDTLS_ERR_MD_ALLOC_FAILED;
		}
		/* Import stream context */
		err = KeyStoreMgmt_ImportStreamCtx(streamId, ctx->stream_ctx);
		if(err != KEYMGMT_ERR_SUCCESS)
		{
			return MBEDTLS_ERR_MD_HW_ACCEL_FAILED;
		}

		srvResponse = HSE_HmacFinish( streamId, HSE_AUTH_DIR_GENERATE,
				ctx->hashalg, ctx->hmackeyhandle, ctx->buffer, left, output, &hashlen ) ;
	}
	/* Check the response */
	if(HSE_SRV_RSP_OK != srvResponse)
	{
		if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_MD_BAD_INPUT_DATA ;
		}
		else
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_MD_HW_ACCEL_FAILED ;
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
	}

	/* Return the service response */
	return( ret ) ;
}

/*************************************************************************************************
* Description:  This function calculates the HMAC checksum of a buffer.
************************************************************************************************/
int nxp_hse_hmac_ret( mbedtls_hmac_context *ctx,
                     const unsigned char *key, size_t keylen,
                     const unsigned char *input, size_t ilen,
                     unsigned char *output)
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
	uint32_t hashlen;
	uint32_t keybits = keylen;

    if( ctx == NULL || ctx->ctx_md == NULL || ctx->ctx_md->md_info == NULL || \
		key == NULL || 						   \
		input == NULL || output == NULL)
    {
    	return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
    }

	if(ilen == 0)
	{
		return( NO_ERROR );
	}

	/* Update Hash Output size*/
	hashlen = ctx->ctx_md->md_info->size;

	do
	{
		/* Load Key */
		if((ret = nxp_hse_hmac_set_key(ctx, key, keybits)) != 0)
		{
			break;
		}

		/* Send the request */
		srvResponse = HSE_Hmac( HSE_AUTH_DIR_GENERATE, ctx->hashalg, ctx->hmackeyhandle, input, ilen, output, &hashlen ) ;

		/* Check the response */
		if(HSE_SRV_RSP_OK != srvResponse)
		{
			if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
			{
				/* Return with Error Codes */
				ret = MBEDTLS_ERR_MD_BAD_INPUT_DATA ;
			}
			else
			{
				/* Return with Error Codes */
				ret = MBEDTLS_ERR_MD_HW_ACCEL_FAILED ;
			}
		}
		else
		{
			/* Return with NO_ERROR on success */
			ret = NO_ERROR ;
		}
	}while( 0 );

	/* Return the service response */
	return( ret ) ;
}

/*************************************************************************************************
* Description:  Reset the hmac context.
************************************************************************************************/
int nxp_hse_hmac_reset(mbedtls_hmac_context *ctx)
{
	int ret = 0;

	ctx->total[0] = 0;
	ctx->total[1] = 0;

    /* Mark the stream_start_send as FALSE to allow start request to be send again*/
	ctx->stream_start_send = FALSE;

    /* Return the service response */
	return( ret ) ;
}

/*************************************************************************************************
* Description:  This function releases and clears the specified HMAC context.
************************************************************************************************/
void nxp_hse_hmac_free( mbedtls_hmac_context *ctx )
{
	/* Simple sanity check */
    if( ctx == NULL)
    {
    	return ;
    }

	if ( (ctx->hmackeyhandle != HSE_INVALID_KEY_HANDLE) && (ctx->key_preloaded_flag == FALSE))
	{
		(void)KeyStoreMgmt_FreeKey(ctx->hmackeyhandle);
	}

    /* Securely zeroize the hmac context */
    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_hmac_context ) ) ;
    ctx->hmackeyhandle = HSE_INVALID_KEY_HANDLE;
}

#endif /* #if defined(MBEDTLS_USE_NXP_HSE_CRYPTO)&&defined(MBEDTLS_HMAC_ALT) */
