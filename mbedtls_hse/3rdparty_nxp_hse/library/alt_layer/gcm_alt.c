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

#if defined(MBEDTLS_GCM_ALT)
#include <string.h>
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/gcm.h"
#include "keystore_mgmt.h"
#include "device.h"
#include "hse_host_mac.h"
#include "hse_host_aead.h"

/*==================================================================================================
*                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL MACROS
==================================================================================================*/

/* Parameter validation macros. */
#define GCM_ALT_VALIDATE_RET( cond ) \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_GCM_BAD_INPUT )
#define GCM_ALT_VALIDATE( cond ) \
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

/*==================================================================================================
*                                       LOCAL FUNCTIONS
==================================================================================================*/

/*==================================================================================================
*                                       GLOBAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
* Description:  This function initializes the specified GCM context.
************************************************************************************************/
void mbedtls_gcm_init( mbedtls_gcm_context *ctx )
{
	/* Simple sanity check */
	GCM_ALT_VALIDATE( ctx != NULL ) ;

    memset( ctx, 0, sizeof( mbedtls_gcm_context ) );

	/* Set Stream ID to invalid */
	ctx->streamid = INVALID_STREAM_ID;
}

/*************************************************************************************************
* Description:  This function sets the GCM encryption and decryption
*  key / GCM key schedule (encryption and decryption).
************************************************************************************************/
int mbedtls_gcm_setkey( mbedtls_gcm_context *ctx,
                        mbedtls_cipher_id_t cipher,
                        const unsigned char *key,
                        unsigned int keybits )
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	const mbedtls_cipher_info_t *cipher_info;

	/* Simple sanity check */
    GCM_ALT_VALIDATE_RET( ctx != NULL) ;
    GCM_ALT_VALIDATE_RET( key != NULL ) ;

    cipher_info = mbedtls_cipher_info_from_values( cipher, (keybits & (~KEYLOADED_FLAG)), MBEDTLS_MODE_ECB );

	if( cipher_info == NULL )
	{
		return( MBEDTLS_ERR_GCM_BAD_INPUT );
	}

	if( cipher_info->block_size != 16 )
	{
		return( MBEDTLS_ERR_GCM_BAD_INPUT );
	}

	mbedtls_cipher_free( &ctx->cipher_ctx );

	if( ( ret = mbedtls_cipher_setup( &ctx->cipher_ctx, cipher_info ) ) != 0 )
	{
		return( ret );
	}

	if( ( ret = mbedtls_cipher_setkey( &ctx->cipher_ctx, key, keybits,
							   MBEDTLS_ENCRYPT ) ) != 0 )
	{
		return( ret );
	}

	/* Return the service response */
	return( ret ) ;
}

/*************************************************************************************************
* Description: This function performs GCM encryption or decryption of a buffer.
************************************************************************************************/
int mbedtls_gcm_crypt_and_tag( mbedtls_gcm_context *ctx,
                               int mode,
                               size_t length,
							   const unsigned char *iv,
							   size_t iv_len,
							   const unsigned char *add,
							   size_t add_len,
							   const unsigned char *input,
							   unsigned char *output,
							   size_t tag_len,
							   unsigned char *tag )
{
	int ret = 0;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
	mbedtls_aes_context *aes_ctx;

	/* Simple sanity check */
	GCM_ALT_VALIDATE_RET( ctx != NULL ) ;
	GCM_ALT_VALIDATE_RET( iv != NULL ) ;
	GCM_ALT_VALIDATE_RET( add_len == 0 || add != NULL ) ;
	GCM_ALT_VALIDATE_RET( length == 0 || input != NULL );
	GCM_ALT_VALIDATE_RET( length == 0 || output != NULL );
	GCM_ALT_VALIDATE_RET( tag != NULL );

	aes_ctx = (mbedtls_aes_context*)ctx->cipher_ctx.cipher_ctx;

	if(aes_ctx && aes_ctx->aesKeyHandle == 0)
	{
		/* Return with Error Codes */
		return ( MBEDTLS_ERR_GCM_BAD_INPUT ) ;
	}

	/*--------- GCM Encrypt Request ---------*/
	switch(mode)
	{
		case MBEDTLS_GCM_ENCRYPT:
		{
			/* Send the request */
			srvResponse = HSE_AeadGcmEncrypt( aes_ctx->aesKeyHandle,
				(uint8_t*)iv, (uint32_t)iv_len,
				(uint8_t*)add, (uint32_t)add_len,
				(uint8_t*)input, (uint32_t)length,
				(uint32_t)tag_len, (uint8_t*)tag,
				(uint8_t*)output ) ;
			break;
		}
		case MBEDTLS_GCM_DECRYPT:
		{
			/* Send the request */
			srvResponse = HSE_AeadGcmDecrypt( aes_ctx->aesKeyHandle,
				(uint8_t*)iv, (uint32_t)iv_len,
				(uint8_t*)add, (uint32_t)add_len,
				(uint8_t*)input, (uint32_t)length,
				(uint32_t)tag_len, (uint8_t*)tag,
				(uint8_t*)output ) ;
			break;
		}
		default:
		{
			/* Return with Error Codes */
			return ( MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE );
		}
	}

 if (srvResponse != HSE_SRV_RSP_OK)
	{

		if(srvResponse == HSE_SRV_RSP_VERIFY_FAILED)
		{
			ret = MBEDTLS_ERR_GCM_AUTH_FAILED;
		}
#if defined(S32N55)
		else if(srvResponse == HSE_SRV_RSP_OPERATION_FAILED)
		{
			ret = MBEDTLS_ERR_GCM_AUTH_FAILED;

		}
#endif
		else if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_GCM_BAD_INPUT ;
		}
		else
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED ;
		}
	}

	else
	{
		ret = NO_ERROR;
	}

	return ( ret );
}

/*************************************************************************************************
* Description: This function performs a GCM authenticated decryption of a buffer.
************************************************************************************************/
int mbedtls_gcm_auth_decrypt( mbedtls_gcm_context *ctx,
							  size_t length,
							  const unsigned char *iv,
							  size_t iv_len,
							  const unsigned char *add,
							  size_t add_len,
							  const unsigned char *tag,
							  size_t tag_len,
							  const unsigned char *input,
							  unsigned char *output )
{
	int ret = 0;

	/* Simple sanity check */
	GCM_ALT_VALIDATE_RET( ctx != NULL ) ;
	GCM_ALT_VALIDATE_RET( iv != NULL ) ;
	GCM_ALT_VALIDATE_RET( (0 == add_len) || (add != NULL) ) ;
	GCM_ALT_VALIDATE_RET( tag != NULL ) ;
    GCM_ALT_VALIDATE_RET( length == 0 || input != NULL );
    GCM_ALT_VALIDATE_RET( length == 0 || output != NULL );
    GCM_ALT_VALIDATE_RET( tag != NULL );

    if( ( ret = mbedtls_gcm_crypt_and_tag( ctx, MBEDTLS_GCM_DECRYPT, length,
                                   iv, iv_len, add, add_len,
                                   input, output, tag_len, (unsigned char *)tag ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

/*************************************************************************************************
* Description: This function starts a GCM encryption or decryption operation.
************************************************************************************************/
int mbedtls_gcm_starts( mbedtls_gcm_context *ctx,
						int mode,
						const unsigned char *iv,
						size_t iv_len,
						const unsigned char *add,
						size_t add_len )
{
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
	KeymgmtErrCodeT err;
	mbedtls_aes_context *aes_ctx;
	int ret = 0;

	/* Simple sanity check */
	GCM_ALT_VALIDATE_RET( ctx != NULL ) ;
	GCM_ALT_VALIDATE_RET( iv != NULL ) ;
	GCM_ALT_VALIDATE_RET( (0 == add_len) || (add != NULL) ) ;

    /* IV and AD are limited to 2^64 bits, so 2^61 bytes */
    /* IV is not allowed to be zero length */
    if( (iv_len == 0) || (((uint64_t) iv_len  ) >> 61 != 0) || (((uint64_t) add_len ) >> 61 != 0) )
    {
        return( MBEDTLS_ERR_GCM_BAD_INPUT );
    }

	aes_ctx = (mbedtls_aes_context*)ctx->cipher_ctx.cipher_ctx;

	if(aes_ctx && aes_ctx->aesKeyHandle == 0)
	{
		/* Return with Error Codes */
		return( MBEDTLS_ERR_GCM_BAD_INPUT );
	}

	switch(mode)
	{
		case MBEDTLS_GCM_ENCRYPT:
			ctx->cipher_dir = HSE_CIPHER_DIR_ENCRYPT;
			break;
		case MBEDTLS_GCM_DECRYPT:
			ctx->cipher_dir = HSE_CIPHER_DIR_DECRYPT;
			break;
		default:
			return MBEDTLS_ERR_GCM_BAD_INPUT;
	}

	/* Allocate Stream ID */
	if(ctx->streamid == INVALID_STREAM_ID)
	{
		err = KeystoreMgmt_FindAllocateStreamSlot(&ctx->streamid);
		if(err != KEYMGMT_ERR_SUCCESS)
		{
			return( MBEDTLS_ERR_GCM_HW_ACCEL_FAILED );
		}
	}

	/* Send the request */
	srvResponse = HSE_AeadGcmStreamStart( ctx->streamid, ctx->cipher_dir, aes_ctx->aesKeyHandle, \
			(uint8_t*)iv, (uint32_t)iv_len, (uint8_t*)add, (uint32_t)add_len ) ;

	/* Check the response */
	if( HSE_SRV_RSP_OK != srvResponse )
	{
		if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_GCM_BAD_INPUT ;
		}
		else
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED ;
		}
	}
	else
	{
		/* Return with NO_ERROR on success */
		ret = NO_ERROR ;
	}

	return ret;
}

/*************************************************************************************************
* Description:  This function feeds an input buffer into an ongoing GCM encryption or decryption operation.
************************************************************************************************/
int mbedtls_gcm_update( mbedtls_gcm_context *ctx,
						size_t length,
						const unsigned char *input,
						unsigned char *output )
{
	int ret = 0;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;

	/* Simple sanity check */
    GCM_ALT_VALIDATE_RET( ctx != NULL );
    GCM_ALT_VALIDATE_RET( length == 0 || input != NULL );
    GCM_ALT_VALIDATE_RET( length == 0 || output != NULL );

    /* Check for Overlap condition */
    if(( output > input) && ((size_t) ( output - input ) < length) )
    {
    	return( MBEDTLS_ERR_GCM_BAD_INPUT );
    }

	if(length == 0)
	{
		return ( 0 );
	}

	if((length % MBEDTLS_MAX_BLOCK_LENGTH)!= 0)
	{
		/* Return with Error Codes */
		return( MBEDTLS_ERR_GCM_BAD_INPUT );
	}

	if(ctx->streamid == INVALID_STREAM_ID)
	{
		/* Return with Error Codes */
		return( MBEDTLS_ERR_GCM_BAD_INPUT ) ;
	}

	/* Send the request */
	srvResponse = HSE_AeadGcmStreamUpdate( ctx->streamid, ctx->cipher_dir, (uint8_t*)input, (uint32_t)length, (uint8_t*)output ) ;

	/* Check the response */
	if( HSE_SRV_RSP_OK != srvResponse )
	{
		if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_GCM_BAD_INPUT ;
		}
		else
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED ;
		}
	}
	else
	{
		/* Return with NO_ERROR on success */
		ret = NO_ERROR ;
	}

	/* Return the service response */
	return( ret ) ;
}

/*************************************************************************************************
* Description: This function finishes the GCM operation and generates the authentication tag.
************************************************************************************************/
int mbedtls_gcm_finish( mbedtls_gcm_context *ctx,
						unsigned char *tag,
						size_t tag_len )
{
	int ret = 0;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;

	/* Simple sanity check */
	GCM_ALT_VALIDATE_RET( ctx != NULL ) ;
	GCM_ALT_VALIDATE_RET( tag != NULL ) ;

    if( tag_len > 16 || tag_len < 4 )
    {
    	 return( MBEDTLS_ERR_GCM_BAD_INPUT );
    }

	/* Send the request */
	srvResponse = HSE_AeadGcmStreamFinish( ctx->streamid, ctx->cipher_dir, NULL, 0U, (uint32_t)tag_len, (uint8_t*)tag , NULL) ;

	/* Check the response */
	if( HSE_SRV_RSP_OK != srvResponse )
	{
		if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_GCM_BAD_INPUT ;
			//ret = MBEDTLS_ERR_CIPHER_AUTH_FAILED;
		}
//		else if(HSE_SRV_RSP_OPERATION_FAILED == srvResponse)
//		{
//			ret = MBEDTLS_ERR_CIPHER_AUTH_FAILED;
//		}
		else if(HSE_SRV_RSP_VERIFY_FAILED == srvResponse)
		{
			ret = MBEDTLS_ERR_CIPHER_AUTH_FAILED;
		}
		else
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_GCM_HW_ACCEL_FAILED ;
		}
	}
	else
	{
		/* Return with NO_ERROR on success */
		ret = NO_ERROR ;
		if(ctx->streamid != INVALID_STREAM_ID)
		{
			(void)KeystoreMgmt_FreeStreamSlot(ctx->streamid);
			/* Set Stream ID to invalid */
			ctx->streamid = (hseStreamId_t) (-1);
		}
	}

	/* Return the service response */
	return( ret ) ;
}

/*************************************************************************************************
* Description:  This function releases and clears the specified GCM context.
************************************************************************************************/
void mbedtls_gcm_free( mbedtls_gcm_context *ctx )
{
	/* Simple sanity check */
    if( ctx == NULL)
    {
    	return ;
    }

	/* Free Cipher Context */
	mbedtls_cipher_free(&ctx->cipher_ctx);
	if(ctx->streamid != INVALID_STREAM_ID)
	{
		(void)KeystoreMgmt_FreeStreamSlot(ctx->streamid);
	}

    /* Securely zeroize the GCM context */
    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_gcm_context ) ) ;

	/* Set Stream ID to invalid */
	ctx->streamid = (hseStreamId_t) (-1);
}

#endif /* MBEDTLS_GCM_ALT */
