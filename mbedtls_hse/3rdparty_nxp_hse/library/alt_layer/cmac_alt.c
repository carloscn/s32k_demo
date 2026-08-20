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

#if defined(MBEDTLS_CMAC_ALT)
#include <string.h>

#include "mbedtls/cmac.h"
#include "mbedtls/error.h"
#include "mbedtls/platform_util.h"
#include "keystore_mgmt.h"
#include "device.h"
#include "hse_host_mac.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc     calloc
#define mbedtls_free       free
#endif /* MBEDTLS_PLATFORM_C */

/*==================================================================================================
 *                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
 ==================================================================================================*/

/*==================================================================================================
 *                                       LOCAL MACROS
 ==================================================================================================*/

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
 * 	@brief		Initialize the CMAC context
 *
 * 	@param[in]	ctx
 *				The cipher context used for the CMAC operation,
 *
 * 	@param[in]	key
 *				The key to use.
 *
 *	@param[in]	keylen
 *				The key length in Bytes.
 *
 *  @return		\c 0 on success.
 *
 *	@return		#MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA for invalid input
 *
 */
static int InitializeCmacCtx(mbedtls_cipher_context_t *ctx, const unsigned char *key, size_t keylen);

/*==================================================================================================
 *                                       LOCAL FUNCTIONS
 ==================================================================================================*/

/*************************************************************************************************
* Description:  Initialize the CMAC context
************************************************************************************************/
static int InitializeCmacCtx(mbedtls_cipher_context_t *ctx, const unsigned char *key, size_t keylen)
{
    mbedtls_cipher_type_t type;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_cmac_context_t *cmac_ctx;

    if( (ctx == NULL) || (ctx->cipher_info == NULL) || (key == NULL) )
    {
    	return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    }

    type = ctx->cipher_info->type;

    switch( type )
    {
        case MBEDTLS_CIPHER_AES_128_ECB:
        case MBEDTLS_CIPHER_AES_192_ECB:
        case MBEDTLS_CIPHER_AES_256_ECB:
            break;
        default:
            return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    }

    cmac_ctx = (mbedtls_cmac_context_t*)mbedtls_calloc(1, sizeof(mbedtls_cmac_context_t));
    if( cmac_ctx == NULL )
    {
    	return( MBEDTLS_ERR_CIPHER_ALLOC_FAILED );
    }

    ctx->cmac_ctx = cmac_ctx;

    /* Set Stream ID to invalid value */
    cmac_ctx->streamid = (hseStreamId_t)INVALID_STREAM_ID;

    ret = mbedtls_cipher_setkey( ctx, key, (int)keylen, MBEDTLS_ENCRYPT );

    return ( ret );
}

/*==================================================================================================
 *                                       GLOBAL FUNCTIONS
 ==================================================================================================*/

/*************************************************************************************************
 * Description: This function calculates the full generic CMAC on the input
 * 				buffer with the provided key.
 ************************************************************************************************/
int mbedtls_cipher_cmac( const mbedtls_cipher_info_t *cipher_info,
						 const unsigned char *key, size_t keylen,
						 const unsigned char *input, size_t ilen,
						 unsigned char *output )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
    mbedtls_aes_context *aes_ctx;
    mbedtls_cipher_context_t ctx;
    /* Must be static, not a stack local: its address is passed to HSE_Cmac()
     * as the in/out tag-length pointer, and HSE (a separate AHB bus master)
     * cannot see the stack, which on this target lives in DTCM - same
     * DTCM-invisibility issue s32k312_provision's D-cache notes describe for
     * HSE-visible buffers generally. Without this, HSE_Cmac() here returned
     * HSE_SRV_RSP_INVALID_PARAM even with input/output/key material already
     * in valid static SRAM. */
    static uint32_t pTagLen = 0U ;

    if( (cipher_info == NULL) || (key == NULL) || (input == NULL) || (output == NULL) )
    {
    	 return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    }

    mbedtls_cipher_init( &ctx );

    do
    {
		if( ( ret = mbedtls_cipher_setup( &ctx, cipher_info ) ) != 0 )
		{
			break;
		}

		if( (ret = InitializeCmacCtx(&ctx, key, keylen)) != 0)
		{
			break;
		}

		aes_ctx = (mbedtls_aes_context*)ctx.cipher_ctx;
		pTagLen = MBEDTLS_MAX_BLOCK_LENGTH ;
		srvResponse = HSE_Cmac( HSE_AUTH_DIR_GENERATE, aes_ctx->aesKeyHandle, input, ilen, output, &pTagLen ) ;

		/* Check the response */
		if( HSE_SRV_RSP_OK != srvResponse )
		{
			if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
			{
				/* Return with Error Codes */
				ret = MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA ;
			}
			else
			{
				/* Return with Error Codes */
				ret = MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED ;
			}
		}
		else
		{
			/* Return with NO_ERROR on success */
			ret = NO_ERROR ;
		}

    } while(0);

    mbedtls_cipher_free(&ctx);

    /* Return the service response */
    return ret ;
}

/*************************************************************************************************
 * Description: This function sets the CMAC key, and prepares to authenticate the input data.
 ************************************************************************************************/
int mbedtls_cipher_cmac_starts( mbedtls_cipher_context_t *ctx,
								const unsigned char *key, size_t keybits )
{
	int ret = 0;

	if((ret = InitializeCmacCtx(ctx, key,keybits)) != 0)
	{
		return ret;
	}

	/* Return the service response */
	return ret ;
}

/*************************************************************************************************
 * Description: This function feeds an input buffer into an ongoing CMAC computation.
 ************************************************************************************************/
int mbedtls_cipher_cmac_update( mbedtls_cipher_context_t *ctx,
								const unsigned char *input, size_t ilen )
{
    int ret = 0;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
	KeymgmtErrCodeT err;
	mbedtls_aes_context *aes_ctx;
    mbedtls_cmac_context_t *cmac_ctx;
    uint32_t block_size;
    size_t n;

    if( (ctx == NULL) || (ctx->cipher_info == NULL) || (input == NULL) || (ctx->cmac_ctx == NULL) )
    {
    	 return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    }

    if(ctx->cmac_ctx->stream_start_send == FALSE)
    {
    	/* Allocate Stream ID */
    	if(ctx->cmac_ctx->streamid == (hseStreamId_t)INVALID_STREAM_ID)
    	{
    		err = KeystoreMgmt_FindAllocateStreamSlot(&ctx->cmac_ctx->streamid);
    		if(err != KEYMGMT_ERR_SUCCESS)
    		{
    			return ( MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED );
    		}
    	}

    	/* Start CMAC processing in Streaming mode */
    	aes_ctx = (mbedtls_aes_context*)ctx->cipher_ctx;
    	srvResponse = HSE_CmacStart(ctx->cmac_ctx->streamid, HSE_AUTH_DIR_GENERATE, aes_ctx->aesKeyHandle, NULL, 0);

    	/* Check the response */
    	if( HSE_SRV_RSP_OK == srvResponse )
    	{
    		ctx->cmac_ctx->stream_start_send = TRUE;
    	}
    	else if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
		{
			return ( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA ) ;
		}
		else
		{
			return ( MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED );
		}
    }

    cmac_ctx = ctx->cmac_ctx;
    block_size = ctx->cipher_info->block_size;

    /* When we have some unfinished data and new input is > block size */
    if((cmac_ctx->unprocessed_len > 0) &&
	    (ilen > (block_size - cmac_ctx->unprocessed_len )))
    {

    	/* fill the unprocessed buffer */
        memcpy( &cmac_ctx->unprocessed_block[cmac_ctx->unprocessed_len],
                input,
                block_size - cmac_ctx->unprocessed_len );

		srvResponse = HSE_CmacUpdate(cmac_ctx->streamid, HSE_AUTH_DIR_GENERATE,
				(const unsigned char* )&cmac_ctx->unprocessed_block, block_size);

		/* Check the response */
		if(srvResponse != HSE_SRV_RSP_OK)
		{
			return MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED;
		}

        input += block_size - cmac_ctx->unprocessed_len;
        ilen -= block_size - cmac_ctx->unprocessed_len;
        cmac_ctx->unprocessed_len = 0;
    }

    /* n is the number of blocks excluding any final partial block */
    n = ( ilen + block_size - 1) / block_size;

    if(n>1)
    {
		/* Process only when there is atleast 1 block */
		srvResponse = HSE_CmacUpdate(cmac_ctx->streamid, 
									HSE_AUTH_DIR_GENERATE, 
									input, ((n-1)*block_size) ) ;

		/* Check the response */
		if( HSE_SRV_RSP_OK != srvResponse )
		{
			if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
			{
				/* Return with Error Codes */
				ret = MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA ;
			}
			else
			{
				/* Return with Error Codes */
				ret = MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED ;
			}
		}

		input += (n-1)*block_size;
		ilen -= (n-1)*block_size;
    }

    /* If there is data left over that wasn't aligned to a block */
    if( ilen > 0 )
    {
        memcpy( &cmac_ctx->unprocessed_block[cmac_ctx->unprocessed_len],
                input, ilen );
        cmac_ctx->unprocessed_len += ilen;
    }

    return( ret ) ;
}

/*************************************************************************************************
 * Description: This function finishes the CMAC operation, and writes the result to the output buffer.
 ************************************************************************************************/
int mbedtls_cipher_cmac_finish( mbedtls_cipher_context_t *ctx,
								unsigned char *output )
{
    int ret = 0;
    mbedtls_cmac_context_t* cmac_ctx;
    mbedtls_aes_context *aes_ctx;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
    /* static, not stack-local - see the identical comment in
     * mbedtls_cipher_cmac() above (this function isn't currently on the
     * validated call path, but has the exact same bug). */
    static uint32_t pTagLen = 0 ;

    if( (ctx == NULL) || (ctx->cipher_info == NULL) || (ctx->cmac_ctx == NULL) ||
	    (output == NULL) || (ctx->cipher_ctx == NULL))
    {
    	return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    }

	cmac_ctx = ctx->cmac_ctx;

	/* Update Tag length as per Cipher block size */
	pTagLen = mbedtls_cipher_get_block_size(ctx);

	if((ctx->cmac_ctx->stream_start_send == FALSE) && (0 == cmac_ctx->unprocessed_len))
	{
		aes_ctx = (mbedtls_aes_context*)ctx->cipher_ctx;
		srvResponse = HSE_Cmac( HSE_AUTH_DIR_GENERATE, aes_ctx->aesKeyHandle, NULL, 0, output, &pTagLen ) ;
	}

	else
	{
	    srvResponse = HSE_CmacFinish(cmac_ctx->streamid, 
						HSE_AUTH_DIR_GENERATE, 
						cmac_ctx->unprocessed_block, 
						cmac_ctx->unprocessed_len,
						output, &pTagLen) ;
	}

	/* Check the response */
	if( HSE_SRV_RSP_OK != srvResponse )
	{
		if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA ;
		}
		else
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED ;
		}
	}
    else
    {
		/* Return with NO_ERROR on success */
		ret = NO_ERROR ;
    }

    mbedtls_platform_zeroize( cmac_ctx->unprocessed_block,
                              sizeof( cmac_ctx->unprocessed_block ) );
    cmac_ctx->unprocessed_len = 0;

	/* Free the StreamId */
    (void)KeystoreMgmt_FreeStreamSlot(cmac_ctx->streamid);
    cmac_ctx->streamid = INVALID_STREAM_ID;
    ctx->cmac_ctx->stream_start_send = FALSE;

    /* Return the service response */
    return( ret ) ;
}

/*************************************************************************************************
 * Description: This function prepares the authentication of another message
 * with the same key as the previous CMAC operation.
 ************************************************************************************************/
int mbedtls_cipher_cmac_reset( mbedtls_cipher_context_t *ctx )
{
    int ret = 0;
    KeymgmtErrCodeT err;
    unsigned char output[MBEDTLS_CIPHER_BLKSIZE_MAX];
    mbedtls_aes_context *aes_ctx;
    hseSrvResponse_t srvResponse;
    mbedtls_cmac_context_t* cmac_ctx;

    if( (ctx == NULL) || (ctx->cipher_info == NULL) || \
    		(ctx->cmac_ctx == NULL) || (ctx->cipher_ctx == NULL) )
	{
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
	}

    cmac_ctx = ctx->cmac_ctx;

    if(cmac_ctx->streamid != (hseStreamId_t)INVALID_STREAM_ID)
    {
		/* We are here because finish is not called previously, so we need
		 * to call finish to cleanup previous context and discard the result */
		(void)mbedtls_cipher_cmac_finish(ctx, (unsigned char*)&output);
    }

    /* Reset the internal state */
    cmac_ctx->unprocessed_len = 0;
    mbedtls_platform_zeroize( cmac_ctx->unprocessed_block, sizeof( cmac_ctx->unprocessed_block ) );
    ctx->cmac_ctx->stream_start_send = FALSE;
    do
    {
		/* Allocate Stream ID */
		err = KeystoreMgmt_FindAllocateStreamSlot(&cmac_ctx->streamid);
		if(err != KEYMGMT_ERR_SUCCESS)
		{
		    ret = MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED;
		    break;
		}

		/* Restart CMAC processing in Streaming mode */
		aes_ctx = (mbedtls_aes_context*)ctx->cipher_ctx;
		srvResponse = HSE_CmacStart(ctx->cmac_ctx->streamid, HSE_AUTH_DIR_GENERATE,
			aes_ctx->aesKeyHandle, NULL,0);
		if(srvResponse != HSE_SRV_RSP_OK)
		{
		    ret = MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED;
		}
		else
		{
		    ret = NO_ERROR;
		}
    }while(0);

    return ret;
}

/*************************************************************************************************
 * Description: This function implements the AES-CMAC-PRF-128
 * pseudorandom function, as defined in <em>RFC-4615.
 ************************************************************************************************/
int mbedtls_aes_cmac_prf_128( const unsigned char *key, size_t key_len,
							  const unsigned char *input, size_t in_len,
							  unsigned char output[16] )
{
    int ret = 0;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
    uint32_t varKeyHandleCmac = HSE_INVALID_KEY_HANDLE;
    uint32_t cmacKeysize = MBEDTLS_MAX_BLOCK_LENGTH ;

    /* Key for CMAC */
    uint8_t cmacKey[MBEDTLS_AES_BLOCK_SIZE] = {0} ;
    key_import_param_t key_import_param;
    KeymgmtErrCodeT err = KEYMGMT_ERR_SUCCESS;

    memset(&key_import_param, 0x00, sizeof(key_import_param_t));

    /* Simple sanity check */
    if((key == NULL) || (input == NULL) || (output == NULL))
    {
		return ( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA )  ;
    }

    if(MBEDTLS_AES_BLOCK_SIZE != key_len)
    {
		/* Key for cmac_prf_128 */
		uint8_t zero_key[MBEDTLS_AES_BLOCK_SIZE] = {0};

		/* Import the AES key for cipher operations on data */
		key_import_param.key_catalog = HSE_KEY_CATALOG_ID_RAM;
		key_import_param.key_type = HSE_KEY_TYPE_AES;
		key_import_param.key_param.sym_key_param.key = zero_key;
		key_import_param.key_param.sym_key_param.size = HSE_KEY128_BITS;

		err = KeystoreMgmt_FindImportSlot(&key_import_param, &varKeyHandleCmac);
		if(err != KEYMGMT_ERR_SUCCESS)
		{
		    return MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED;
		}

		/* Generate CMAC */
		srvResponse = HSE_Cmac(HSE_AUTH_DIR_GENERATE, varKeyHandleCmac, (const uint8_t*)key,
				key_len, (uint8_t*)&cmacKey, &cmacKeysize) ;

		/* Check the response */
		if( HSE_SRV_RSP_OK != srvResponse )
		{
			if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
			{
				/* Return with Error Codes */
				ret = MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA ;
			}
			else
			{
				/* Return with Error Codes */
				ret = MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED ;
			}
		}

		/* Free the key slot for now */
		(void)KeyStoreMgmt_FreeKey(varKeyHandleCmac);
		varKeyHandleCmac = HSE_INVALID_KEY_HANDLE;
    }
    else
    {
    	memcpy(cmacKey, key, MBEDTLS_AES_BLOCK_SIZE);
    }

    /* Import the CMAC key for cipher operations on data */
    key_import_param.key_catalog = HSE_KEY_CATALOG_ID_RAM;
    key_import_param.key_type = HSE_KEY_TYPE_AES;
    key_import_param.key_param.sym_key_param.key = cmacKey;
    key_import_param.key_param.sym_key_param.size = HSE_KEY128_BITS;

    err = KeystoreMgmt_FindImportSlot(&key_import_param, &varKeyHandleCmac);
    if(err != KEYMGMT_ERR_SUCCESS)
    {
		return MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED;
    }

    /* Generate CMAC */
    srvResponse = HSE_Cmac(HSE_AUTH_DIR_GENERATE, varKeyHandleCmac, input, in_len, output, &cmacKeysize) ;

	/* Check the response */
	if( HSE_SRV_RSP_OK != srvResponse )
	{
		if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA ;
		}
		else
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED ;
		}
	}
    else
    {
    	/* Return with NO_ERROR on success */
    	ret = NO_ERROR ;
    }

	/* Free the key slot for now */
	(void)KeyStoreMgmt_FreeKey(varKeyHandleCmac);

    /* Securely zeroize the cmac key */
    mbedtls_platform_zeroize((void *)cmacKey, sizeof(cmacKey)) ;

    /* Return the service response */
    return( ret ) ;
}
#endif /* MBEDTLS_CMAC_ALT */
