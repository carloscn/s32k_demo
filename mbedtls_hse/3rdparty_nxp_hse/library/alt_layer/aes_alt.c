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

#if defined(MBEDTLS_AES_ALT)
#include <string.h>
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/aes.h"
#include "mbedtls/error.h"
#include "keystore_mgmt.h"
#include "device.h"
#include "hse_host_cipher.h"

/*==================================================================================================
*                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL MACROS
==================================================================================================*/

#ifndef MBEDTLS_AES_BLOCK_SIZE
#define MBEDTLS_AES_BLOCK_SIZE			((uint32_t)(0x10UL))
#endif /* MBEDTLS_AES_BLOCK_SIZE */

/* Parameter validation macros. */
#define AES_ALT_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_AES_BAD_INPUT_DATA )
#define AES_ALT_VALIDATE( cond )        \
    MBEDTLS_INTERNAL_VALIDATE( cond )

#define AES_BLOCK_LENGTH 				((uint32_t)(0x10UL))
#define AES_IV_LENGTH					((uint32_t)(0x10UL))

#if defined(MBEDTLS_CIPHER_MODE_XTS)
/* Endianess with 64 bits values */
#ifndef GET_UINT64_LE
#define GET_UINT64_LE(n,b,i)                            \
{                                                       \
    (n) = ( (uint64_t) (b)[(i) + 7] << 56 )             \
        | ( (uint64_t) (b)[(i) + 6] << 48 )             \
        | ( (uint64_t) (b)[(i) + 5] << 40 )             \
        | ( (uint64_t) (b)[(i) + 4] << 32 )             \
        | ( (uint64_t) (b)[(i) + 3] << 24 )             \
        | ( (uint64_t) (b)[(i) + 2] << 16 )             \
        | ( (uint64_t) (b)[(i) + 1] <<  8 )             \
        | ( (uint64_t) (b)[(i)    ]       );            \
}
#endif /* GET_UINT64_LE */

#ifndef PUT_UINT64_LE
#define PUT_UINT64_LE(n,b,i)                            \
{                                                       \
    (b)[(i) + 7] = (unsigned char) ( (n) >> 56 );       \
    (b)[(i) + 6] = (unsigned char) ( (n) >> 48 );       \
    (b)[(i) + 5] = (unsigned char) ( (n) >> 40 );       \
    (b)[(i) + 4] = (unsigned char) ( (n) >> 32 );       \
    (b)[(i) + 3] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i)    ] = (unsigned char) ( (n)       );       \
}
#endif /* PUT_UINT64_LE */

#endif /* MBEDTLS_CIPHER_MODE_XTS */
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
#if defined(MBEDTLS_CIPHER_MODE_XTS)
/**
 * 	@brief		Decode input aes-xts keys into tweak and crypt key
 *
 * 	@param[in]	key
 * 				The AES-XTS input key
 *
 * 	@param[in]	keybits
 *              The AES-XTS keysize in bits
 *
 *	@param[out]	key1
 *				The crypt key
 *
 *	@param[out]	key1bits
 *              The crypt keybits
 *
 *	@param[out]	key2
 *				The tweak key
 *
 *	@param[out]	key2bits
 *				The tweak keybits 
 *
 *  @return		\c 0 on success.
 *
 *	@return		#MBEDTLS_ERR_AES_INVALID_KEY_LENGTH for invalid 
 *				keybits
 *
 */
static int mbedtls_aes_xts_decode_keys( const unsigned char *key,
                                        unsigned int keybits,
                                        const unsigned char **key1,
                                        unsigned int *key1bits,
                                        const unsigned char **key2,
                                        unsigned int *key2bits );
/**
 * 	@brief		 GF(2^128) multiplication function
 * 				 This function multiplies a field element by x in the polynomial field
 * 				 representation. It uses 64-bit word operations to gain speed but compensates
 * 				 for machine endianess and hence works correctly on both big and little
 * 				 endian machines.
 *
 * 	@param[in]	r[16]
 * 				input field
 *
 * 	@param[in]	x[16]
 *              multiplying factor
 *
 *  @return		\c 0 on success.
 *
 */
static void mbedtls_gf128mul_x_ble( unsigned char r[16],
                                    const unsigned char x[16] );

#endif /* MBEDTLS_CIPHER_MODE_XTS */
/*==================================================================================================
*                                       LOCAL FUNCTIONS
==================================================================================================*/
#if defined(MBEDTLS_CIPHER_MODE_XTS)
/*************************************************************************************************
* Description:  Decode input aes-xts keys into tweak and crypt key
************************************************************************************************/
static int mbedtls_aes_xts_decode_keys( const unsigned char *key,
                                        unsigned int keybits,
                                        const unsigned char **key1,
                                        unsigned int *key1bits,
                                        const unsigned char **key2,
                                        unsigned int *key2bits )
{
	const unsigned int half_keybits = ((keybits & (~KEYLOADED_FLAG))/ 2U);
	const unsigned int half_keybytes = ((half_keybits & (~KEYLOADED_FLAG)) / 8U);
	uint32_t key_preloaded_flag = keybits & KEYLOADED_FLAG;

	keybits = keybits & (~KEYLOADED_FLAG);
	switch( keybits )
	{
		case HSE_KEY256_BITS: break;
		case HSE_KEY512_BITS: break;
		default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
	}

	*key1bits = (key_preloaded_flag | half_keybits);
	*key2bits = (key_preloaded_flag | half_keybits);

	*key1 = &key[0];
	if(0U != key_preloaded_flag)
	{
		*key2 = &key[sizeof(uint32_t)];
	}
	else
	{
		*key2 = &key[half_keybytes];
	}

	return ( 0 );
}

/*************************************************************************************************
* Description:   GF(2^128) multiplication function
 * 				 This function multiplies a field element by x in the polynomial field
 * 				 representation. It uses 64-bit word operations to gain speed but compensates
 * 				 for machine endianess and hence works correctly on both big and little
 * 				 endian machines.
************************************************************************************************/
static void mbedtls_gf128mul_x_ble( unsigned char r[16],
                                    const unsigned char x[16] )
{
    uint64_t a, b, ra, rb;

    GET_UINT64_LE( a, x, 0 );
    GET_UINT64_LE( b, x, 8 );

    ra = ( a << 1 )  ^ 0x0087 >> ( 8 - ( ( b >> 63 ) << 3 ) );
    rb = ( a >> 63 ) | ( b << 1 );

    PUT_UINT64_LE( ra, r, 0 );
    PUT_UINT64_LE( rb, r, 8 );
}

#endif /* MBEDTLS_CIPHER_MODE_XTS */

/*==================================================================================================
*                                       GLOBAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
* Description:  This function initializes the specified AES context.
************************************************************************************************/
void mbedtls_aes_init( mbedtls_aes_context *ctx )
{
	/* Simple sanity check */
	AES_ALT_VALIDATE( ctx != NULL ) ;

    memset(ctx, 0, sizeof(mbedtls_aes_context));

    /* Initialize key handle */
	ctx->aesKeyHandle = HSE_INVALID_KEY_HANDLE;
}

/*************************************************************************************************
* Description:  This function sets the AES encryption key / AES key schedule (encryption).
************************************************************************************************/
int mbedtls_aes_setkey_enc( mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits )
{
	int ret = 0;
	KeymgmtErrCodeT err = KEYMGMT_ERR_SUCCESS;
	key_import_param_t key_import_param = {0};
	uint32_t key_length = 0U;

	memset(&key_import_param, 0x00, sizeof(key_import_param_t));

	if( (ctx == NULL) || (key == NULL) )
	{
		return(MBEDTLS_ERR_AES_BAD_INPUT_DATA);
	}
	else
	{
		key_length = (keybits & (~KEYLOADED_FLAG)) ;
		switch(key_length)
		{
			case HSE_KEY128_BITS:
			case HSE_KEY192_BITS:
			case HSE_KEY256_BITS:
				break;
			default :
				return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
		}

		if(ctx->aesKeyHandle != HSE_INVALID_KEY_HANDLE)
		{
			if(ctx->keySize != key_length)
			{
				/* Erase Previous key only if key_preloaded is not true */
				if(ctx->key_preloaded_flag == FALSE)
				{
					/* If previous key size is not same as new key then
					erase current key and allocate new key */
					(void)KeyStoreMgmt_FreeKey(ctx->aesKeyHandle);
					ctx->aesKeyHandle = INVALID_KEYHANDLE;
					ctx->keySize = 0U;
				}
			}
			else
			{
				/* Either we can Load Key on the same handle or return Error */
				key_import_param.key_catalog = HSE_KEY_CATALOG_ID_RAM;
				key_import_param.key_type = HSE_KEY_TYPE_AES;
				key_import_param.key_param.sym_key_param.key = key;
				key_import_param.key_param.sym_key_param.size = key_length;

				err = KeyStoreMgmt_ImportKey(ctx->aesKeyHandle, &key_import_param);
				if(err != KEYMGMT_ERR_SUCCESS)
				{
					return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
				}

				ctx->key_preloaded_flag = FALSE;
				return ( NO_ERROR );
			}
		}

		if(keybits & KEYLOADED_FLAG)
		{
			/* Load Key Handle from keydata - First four bytes contain the key handle */
			ctx->aesKeyHandle = (hseKeyHandle_t)(key[0]|(key[1]<<8)|(key[2]<<16)|(key[3]<<24));
			ctx->key_preloaded_flag = TRUE;
			ctx->keySize = key_length;

			return ( NO_ERROR );
		}
		else
		{
			/* Import Key */
			key_import_param.key_catalog = HSE_KEY_CATALOG_ID_RAM;
			key_import_param.key_type = HSE_KEY_TYPE_AES;
			key_import_param.key_param.sym_key_param.key = key;
			key_import_param.key_param.sym_key_param.size = key_length;

			err = KeystoreMgmt_FindImportSlot(&key_import_param, &ctx->aesKeyHandle);
		}

		if(err != KEYMGMT_ERR_SUCCESS)
		{
			ret = MBEDTLS_ERR_AES_HW_ACCEL_FAILED;
		}
		else
		{
			ctx->key_preloaded_flag = FALSE;
			ctx->keySize = key_length;
			ret = NO_ERROR;
		}
	}

	/* Return the service response */
	return( ret ) ;
}

/*************************************************************************************************
* Description:  This function sets the AES decryption key / AES key schedule (decryption).
************************************************************************************************/
int mbedtls_aes_setkey_dec( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
	return mbedtls_aes_setkey_enc(ctx, key, keybits);
}

/*************************************************************************************************
* Description:  AES-ECB block encryption/decryption.
************************************************************************************************/
int mbedtls_aes_crypt_ecb( mbedtls_aes_context *ctx,
                           int mode,
                           const unsigned char input[16],
                           unsigned char output[16] )
{
	int ret = 0;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

	/* Simple sanity check */
	AES_ALT_VALIDATE_RET( ctx != NULL ) ;
	AES_ALT_VALIDATE_RET(input != NULL) ;
	AES_ALT_VALIDATE_RET(output != NULL)  ;
	AES_ALT_VALIDATE_RET( mode == MBEDTLS_AES_ENCRYPT ||
                      	  mode == MBEDTLS_AES_DECRYPT ) ;

    /*--------- AES ECB Encrypt Request ---------*/
    if( MBEDTLS_AES_ENCRYPT == mode )
    {
		/* Send the request */
		srvResponse = HSE_AesEncrypt( HSE_CIPHER_BLOCK_MODE_ECB, ctx->aesKeyHandle, NULL,
				0UL, input, AES_BLOCK_LENGTH, output ) ;

		/* Check the response */
		if( HSE_SRV_RSP_OK != srvResponse )
		{
			if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
			{
				/* Return with Error Codes */
				ret = MBEDTLS_ERR_AES_BAD_INPUT_DATA ;
			}
			else
			{
				/* Return with Error Code */
				ret = MBEDTLS_ERR_AES_HW_ACCEL_FAILED ;
			}
		}

	    else
	    {
	    	/* Return with NO_ERROR on success */
	    	ret = NO_ERROR ;
	    }
    }

    /*--------- AES ECB Decrypt Request ---------*/
    else
    {
		/* Send the request */
		srvResponse = HSE_AesDecrypt( HSE_CIPHER_BLOCK_MODE_ECB, ctx->aesKeyHandle, NULL,
				0UL, input, AES_BLOCK_LENGTH, output ) ;

		/* Check the response */
		if( HSE_SRV_RSP_OK != srvResponse )
		{
			if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
			{
				/* Return with Error Code */
				ret = MBEDTLS_ERR_AES_BAD_INPUT_DATA ;
			}
			else
			{
				/* Return with Error Code */
				ret = MBEDTLS_ERR_AES_HW_ACCEL_FAILED ;
			}
		}

	    else
	    {
	    	/* Return with NO_ERROR on success */
	    	ret = NO_ERROR ;
	    }
    }

	/* Return the service response */
	return( ret ) ;
}

/*************************************************************************************************
* Description:  AES-CBC buffer encryption/decryption
************************************************************************************************/
#if defined(MBEDTLS_CIPHER_MODE_CBC)
int mbedtls_aes_crypt_cbc( mbedtls_aes_context *ctx,
						   int mode,
						   size_t length,
						   unsigned char iv[16],
						   const unsigned char *input,
						   unsigned char *output )
{
	int ret = 0;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

	/* Simple sanity check */
	AES_ALT_VALIDATE_RET( ctx != NULL ) ;
	AES_ALT_VALIDATE_RET( iv != NULL ) ;
	AES_ALT_VALIDATE_RET( input != NULL ) ;
	AES_ALT_VALIDATE_RET( output != NULL ) ;
	AES_ALT_VALIDATE_RET( mode == MBEDTLS_AES_ENCRYPT ||
                      	  mode == MBEDTLS_AES_DECRYPT ) ;

	/* Input length should be block multiple */
	if( (FALSE == length) || (FALSE != (length % AES_BLOCK_LENGTH)) )
	{
		/* Return with Error Codes */
		return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH ;
	}

    /*--------- AES CBC Encrypt Request ---------*/
    if( MBEDTLS_AES_ENCRYPT == mode )
    {
		/* Send the request */
		srvResponse = HSE_AesEncrypt( HSE_CIPHER_BLOCK_MODE_CBC, ctx->aesKeyHandle,
				iv, AES_IV_LENGTH, input, length, output ) ;

		/* Check the response */
		if( HSE_SRV_RSP_OK != srvResponse )
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_AES_HW_ACCEL_FAILED ;
		}

	    else
	    {
	    	/* Copy last 16 bytes of output to iv */
			uint32_t bytes_processed = ((length / MBEDTLS_AES_BLOCK_SIZE) * MBEDTLS_AES_BLOCK_SIZE);
			memcpy(iv, &output[length -  bytes_processed], MBEDTLS_AES_BLOCK_SIZE);

	    	/* Return with NO_ERROR on success */
	    	ret = NO_ERROR ;
	    }
	}

    /*--------- AES ECB Decrypt Request ---------*/
    else
    {
		/* Copy last 16bytes of input to iv */
		uint32_t bytes_processed = (length / MBEDTLS_AES_BLOCK_SIZE) * MBEDTLS_AES_BLOCK_SIZE;
		uint8_t temp[MBEDTLS_AES_BLOCK_SIZE];

		memcpy(temp, &input[length - bytes_processed], MBEDTLS_AES_BLOCK_SIZE);

		/* Send the request */
		srvResponse = HSE_AesDecrypt( HSE_CIPHER_BLOCK_MODE_CBC, ctx->aesKeyHandle,
				iv, AES_IV_LENGTH, input, length, output ) ;

		/* Check the response */
		if( HSE_SRV_RSP_OK != srvResponse )
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_AES_HW_ACCEL_FAILED ;
		}

	    else
	    {
	    	/* Copy the temp buffer to iv */
			memcpy(iv, temp, MBEDTLS_AES_BLOCK_SIZE);

	    	/* Return with NO_ERROR on success */
	    	ret = NO_ERROR ;
	    }
	}

	/* Return the service response */
	return( ret ) ;
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
/*************************************************************************************************
* Description:   AES-CFB128 buffer encryption/decryption
************************************************************************************************/
int mbedtls_aes_crypt_cfb128( mbedtls_aes_context *ctx,
						      int mode,
						      size_t length,
						      size_t *iv_off,
						      unsigned char iv[16],
						      const unsigned char *input,
						      unsigned char *output )
{
	int ret = 0;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;
	size_t n, num_blks;

	/* Simple sanity check */
    AES_ALT_VALIDATE_RET( ctx != NULL );
    AES_ALT_VALIDATE_RET( mode == MBEDTLS_AES_ENCRYPT ||
                      	  mode == MBEDTLS_AES_DECRYPT );
    AES_ALT_VALIDATE_RET( iv_off != NULL );
    AES_ALT_VALIDATE_RET( iv != NULL );
    AES_ALT_VALIDATE_RET( input != NULL );
    AES_ALT_VALIDATE_RET( output != NULL );

	n = *iv_off;

    if( n > (MBEDTLS_AES_BLOCK_SIZE - 1))
    {
    	return( MBEDTLS_ERR_AES_BAD_INPUT_DATA );
    }

	/*--------- AES CFB Encrypt Request ---------*/
	if( MBEDTLS_AES_ENCRYPT == mode )
	{
		do
		{
			/* check for partial block processing in the last call */
			for( ; ((length > 0) && (n > 0)); length--)
			{
				/* Update iv & output for partial block processing */
				unsigned char c;
	            c = *input++;
	            *output = (unsigned char)( c ^ iv[n] );
	            iv[n] = (unsigned char) *output;
	            output++;

				/* Increment n using Modulo 16 */
	            n = ( n + 1 ) & 0x0F;

			}
			/* Process rest of the data */
			num_blks = length / MBEDTLS_AES_BLOCK_SIZE;

			if(num_blks > 0)
			{
				/* Process complete blocks */
				uint32_t bytes_processed = (num_blks * MBEDTLS_AES_BLOCK_SIZE);

				/* Send the request */
				srvResponse = HSE_AesEncrypt( HSE_CIPHER_BLOCK_MODE_CFB, ctx->aesKeyHandle,
						iv, AES_IV_LENGTH, input, bytes_processed, output ) ;

				/* Check the response */
				if( HSE_SRV_RSP_OK != srvResponse )
				{
					/* Return with Error Codes */
					ret = MBEDTLS_ERR_AES_HW_ACCEL_FAILED;
					break;
				}

				/* Copy last AES Block Size from output to iv */
				memcpy((void*)iv, (const uint8_t*)&output[bytes_processed - MBEDTLS_AES_BLOCK_SIZE], MBEDTLS_AES_BLOCK_SIZE);

				/* Adjust length, input &  output pointer */
				length -= bytes_processed;
				output = &output[bytes_processed];
				input = &input[bytes_processed];
				n = 0;
			}

			/* Process partial block data */
			if(length > 0)
			{
				/* Calculate new iv = AES_ECB(iv) */
				srvResponse = HSE_AesEncrypt(HSE_CIPHER_BLOCK_MODE_ECB, ctx->aesKeyHandle,	\
					NULL, 0U, (const uint8_t*)iv, MBEDTLS_AES_BLOCK_SIZE, (uint8_t*)iv);

				if(srvResponse != HSE_SRV_RSP_OK)
				{
					ret = MBEDTLS_ERR_AES_HW_ACCEL_FAILED;
					break;
				}

				/* cfb_output = XOR(Input,  iv) */
				for(;((length > 0)); length--)
				{
					/* Update iv & output for partial block processing */
					unsigned char c;
					c = *input++;
					*output = (unsigned char)( c ^ iv[n] );
					iv[n] = (unsigned char) *output;
					output++;
					/* Increment n using Modulo 16 */
					n = ( n + 1 ) & 0x0F;
				}
			}
		}while(0);
	}
	else
	{
		/* AEC-CFB - Decrypt */
		do
		{
			/* check for partial block processing in the last call */
			for( ; ((length > 0) && (n > 0)); length--)
			{
				/* Update iv & output for partial block processing */
				 *output++ = (unsigned char)( iv[n] ^ *input );
				 iv[n] = *input;
				 input++;
				/* Increment n using Modulo 16 */
	            n = ( n + 1 ) & 0x0F;
			}

			/* process rest of the data */
			num_blks = length / MBEDTLS_AES_BLOCK_SIZE;
			if(num_blks > 0)
			{
				/* Process complete blocks */
				uint32_t bytes_processed = (num_blks * MBEDTLS_AES_BLOCK_SIZE);

				/* Send the request */
				srvResponse = HSE_AesDecrypt( HSE_CIPHER_BLOCK_MODE_CFB, ctx->aesKeyHandle,
						iv, AES_IV_LENGTH, input, bytes_processed, output ) ;

				/* Check the response */
				if( HSE_SRV_RSP_OK != srvResponse )
				{
					if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
					{
						/* Return with Error Codes */
						ret = MBEDTLS_ERR_AES_BAD_INPUT_DATA ;
					}
					else
					{
						/* Return with Error Codes */
						ret = MBEDTLS_ERR_AES_HW_ACCEL_FAILED ;
					}
					break;
				}

				/* Copy last AES Block Size from input to iv */
				memcpy((void*)iv, (const uint8_t*)&input[bytes_processed - MBEDTLS_AES_BLOCK_SIZE], MBEDTLS_AES_BLOCK_SIZE);

				/* Adjust length, input &  output pointer */
				length -= bytes_processed;
				output = &output[bytes_processed];
				input = &input[bytes_processed];
				n = 0;
			}

			/* Process partial block data */
			if(length > 0)
			{
				/* Calculate new iv = AES_ECB(iv) */
				srvResponse = HSE_AesEncrypt(HSE_CIPHER_BLOCK_MODE_ECB, ctx->aesKeyHandle,	\
					NULL, 0U, (const uint8_t*)iv, MBEDTLS_AES_BLOCK_SIZE, (uint8_t*)iv);

				if(srvResponse != HSE_SRV_RSP_OK)
				{
					ret = MBEDTLS_ERR_AES_HW_ACCEL_FAILED;
					break;
				}

				/* cfb_output = XOR(Input,  iv) */
				for(;((length > 0)); length--)
				{
					/* Update iv & output for partial block processing */
					*output++ = (unsigned char)( iv[n] ^ *input );
					 iv[n] = *input;
					 input++;
					/* Increment n using Modulo 16 */
					n = ( n + 1 ) & 0x0F;
				}
			}
		}while(0);
	}

	/* Update iv_off */
	*iv_off = n;

	/* Return the service response */
	return( ret ) ;
}

/*************************************************************************************************
* Description:   AES-CFB-8 buffer encryption/decryption
************************************************************************************************/
int mbedtls_aes_crypt_cfb8( mbedtls_aes_context *ctx,
							int mode,
							size_t length,
							unsigned char iv[16],
							const unsigned char *input,
							unsigned char *output )
{
	(void)ctx;
	(void)mode;
	(void)length;
	(void)iv;
	(void)input;
	(void)output;
	return MBEDTLS_ERR_AES_FEATURE_UNAVAILABLE ;
}
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_OFB)
/*************************************************************************************************
* Description:  AES-OFB (Output Feedback Mode) buffer encryption/decryption
************************************************************************************************/
int mbedtls_aes_crypt_ofb( mbedtls_aes_context *ctx,
                           size_t length,
                           size_t *iv_off,
						   unsigned char iv[16],
						   const unsigned char *input,
						   unsigned char *output )
{
	int ret = 0;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;
	size_t n, i, num_blks;

	/* Simple sanity check */
    AES_ALT_VALIDATE_RET( ctx != NULL );
    AES_ALT_VALIDATE_RET( iv_off != NULL );
    AES_ALT_VALIDATE_RET( iv != NULL );
    AES_ALT_VALIDATE_RET( input != NULL );
    AES_ALT_VALIDATE_RET( output != NULL );

    n = *iv_off;
    if(n >= MBEDTLS_AES_BLOCK_SIZE)
    {
        return (MBEDTLS_ERR_AES_BAD_INPUT_DATA) ;
    }

	do
	{
		/* Check for partial block processing in the last call */
		for( ; ((length > 0) && (n > 0)); length--)
		{
			/* Update output for partial block processing */
			*output++ =  *input++ ^ iv[n];

			/* Increment n using Modulo 16 */
			n = ( n + 1 ) & 0x0F;
		}

		/* process rest of the data */
		num_blks = length / MBEDTLS_AES_BLOCK_SIZE;

		if(num_blks > 0)
		{
			/* Process complete blocks */
			uint32_t bytes_processed = (num_blks * MBEDTLS_AES_BLOCK_SIZE);

			/* Send the request */
			srvResponse = HSE_AesEncrypt( HSE_CIPHER_BLOCK_MODE_OFB, ctx->aesKeyHandle,
					iv, AES_IV_LENGTH, input, bytes_processed, output ) ;

			/* Check the response */
			if( HSE_SRV_RSP_OK != srvResponse )
			{
				if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
				{
					/* Return with Error Codes */
					ret = MBEDTLS_ERR_AES_BAD_INPUT_DATA ;
				}
				else
				{
					/* Return with Error Codes */
					ret = MBEDTLS_ERR_AES_HW_ACCEL_FAILED ;
				}
				break;
			}

			/* New iv = XOR(output, input) of last block size */
			for(i = 0; i < MBEDTLS_AES_BLOCK_SIZE; i++)
			{
				iv[i] = output[bytes_processed - MBEDTLS_AES_BLOCK_SIZE + i] ^ \
				input[bytes_processed - MBEDTLS_AES_BLOCK_SIZE + i];
			}

			/* Adjust length, input &  output pointer */
			length -= bytes_processed;
			output = &output[bytes_processed];
			input = &input[bytes_processed];
			n = 0;
		}

		/* Process partial block data */
		if(length > 0)
		{
			/*Calculate new iv = AES_ECB(iv)*/
			srvResponse = HSE_AesEncrypt(HSE_CIPHER_BLOCK_MODE_ECB, ctx->aesKeyHandle,	\
				NULL, 0U, (const uint8_t*)iv, MBEDTLS_AES_BLOCK_SIZE, (uint8_t*)iv);

			if(srvResponse != HSE_SRV_RSP_OK)
			{
				ret = MBEDTLS_ERR_AES_HW_ACCEL_FAILED;
				break;
			}

			/* ofb_output = XOR(Input,	iv) */
			for(;((length > 0)); length--)
			{
				/* Update output for partial block processing */
				*output++ =  *input++ ^ iv[n];

				/* Increment n using Modulo 16 */
				n = ( n + 1 ) & 0x0F;
			}
		}
	}while(0);

	/* Update iv_off */
	*iv_off = n;

	/* Return the service response */
	return( ret ) ;
}
#endif /* MBEDTLS_CIPHER_MODE_OFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
/*************************************************************************************************
* Description: AES-CTR buffer encryption/decryption
************************************************************************************************/
int mbedtls_aes_crypt_ctr( mbedtls_aes_context *ctx,
                       	   size_t length,
						   size_t *nc_off,
						   unsigned char nonce_counter[16],
						   unsigned char stream_block[16],
						   const unsigned char *input,
						   unsigned char *output )
{
	int ret = 0;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;
	size_t n, i, j, num_blks;

	/* Simple sanity check */
    AES_ALT_VALIDATE_RET( ctx != NULL );
    AES_ALT_VALIDATE_RET( nc_off != NULL );
    AES_ALT_VALIDATE_RET( nonce_counter != NULL );
    AES_ALT_VALIDATE_RET( stream_block != NULL );
    AES_ALT_VALIDATE_RET( input != NULL );
    AES_ALT_VALIDATE_RET( output != NULL );

	/*--------- AES CTR Request ---------*/
	n = *nc_off;

    if(n >= MBEDTLS_AES_BLOCK_SIZE)
    {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }

	do
	{
		/* check for partial block processing in the last call */
		for( ; ((length > 0) && (n > 0)); length--)
		{
			/* Update output for partial block processing */
			*output++ =  *input++ ^ stream_block[n];

			/* Increment n using Modulo 16 */
			n = ( n + 1 ) & 0x0F;
		}

		/* process rest of the data */
		num_blks = length / MBEDTLS_AES_BLOCK_SIZE;

		if(num_blks > 0)
		{
			/* Process complete blocks */
			uint32_t bytes_processed = (num_blks * MBEDTLS_AES_BLOCK_SIZE);

			/* Send the request */
			srvResponse = HSE_AesEncrypt( HSE_CIPHER_BLOCK_MODE_CTR, ctx->aesKeyHandle,
					nonce_counter, AES_IV_LENGTH, input, bytes_processed, output ) ;

			/* Check the response */
			if( HSE_SRV_RSP_OK != srvResponse )
			{
				if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
				{
					/* Return with Error Codes */
					ret = MBEDTLS_ERR_AES_BAD_INPUT_DATA ;
				}
				else
				{
					/* Return with Error Codes */
					ret = MBEDTLS_ERR_AES_HW_ACCEL_FAILED ;
				}
				break;
			}

			/* Update stream_block and nonce_counter new stream = XOR(output, input) of last block size */
			for(i = 0; i < MBEDTLS_AES_BLOCK_SIZE; i++)
			{
				stream_block[i] = output[bytes_processed - MBEDTLS_AES_BLOCK_SIZE + i] ^ \
				input[bytes_processed - MBEDTLS_AES_BLOCK_SIZE + i];
			}

			/* Update Nonce_counter */
			for(i = 0; i < num_blks; i++)
			{
				for(j = MBEDTLS_AES_BLOCK_SIZE; j > 0 ; j--)
				{
					if( ++nonce_counter[j - 1] != 0 )
					{
						break;
					}
				}
			}

			/* Adjust length, input &  output pointer */
			length -= bytes_processed;
			output = &output[bytes_processed];
			input = &input[bytes_processed];
			n = 0;
		}

		/* Process partial block data */
		if(length > 0)
		{
			/* Calculate new iv = AES_ECB(iv) */
			srvResponse = HSE_AesEncrypt(HSE_CIPHER_BLOCK_MODE_ECB, ctx->aesKeyHandle,	\
				NULL, 0U, (const uint8_t*)nonce_counter, MBEDTLS_AES_BLOCK_SIZE, (uint8_t*)stream_block);
			if(srvResponse != HSE_SRV_RSP_OK)
			{
				ret = MBEDTLS_ERR_AES_HW_ACCEL_FAILED;
				break;
			}

			/* Update Nonce Counter by 1 as we have processed 1 AES-ECB Block */
			for(j = MBEDTLS_AES_BLOCK_SIZE; j > 0 ; j--)
			{
				if( ++nonce_counter[j - 1] != 0 )
				{
					break;
				}
			}

			/* ctr_output = XOR(Input,	nonce_counter) */
			for(;((length > 0)); length--)
			{
				/* Update output for partial block processing */
				*output++ =  *input++ ^ stream_block[n];

				/* Increment n using Modulo 16 */
				n = ( n + 1 ) & 0x0F;
			}
		}
	}while( 0 );

	*nc_off = n;

	/* Return the service response */
	return( ret ) ;
}
#endif /* MBEDTLS_CIPHER_MODE_CTR */

/*************************************************************************************************
* Description:  This function releases and clears the specified AES context.
************************************************************************************************/
void mbedtls_aes_free( mbedtls_aes_context *ctx )
{
	if(ctx == NULL)
	{
		return;
	}

	if((ctx->aesKeyHandle != HSE_INVALID_KEY_HANDLE) && (ctx->key_preloaded_flag == FALSE))
	{
		(void)KeyStoreMgmt_FreeKey(ctx->aesKeyHandle);
	}

	/* Securely zeroize the AES context */
	mbedtls_platform_zeroize( ctx, sizeof( mbedtls_aes_context ) ) ;
	return ;
}

#if defined(MBEDTLS_CIPHER_MODE_XTS)
/*************************************************************************************************
* Description:  This function initializes the specified AES XTS context.
************************************************************************************************/
void mbedtls_aes_xts_init( mbedtls_aes_xts_context *ctx )
{
	AES_ALT_VALIDATE( ctx != NULL );

	/* Initialize the context */
    mbedtls_aes_init( &ctx->crypt );
    mbedtls_aes_init( &ctx->tweak );
}

/*************************************************************************************************
* Description:  This function releases and clears the specified AES XTS context.
************************************************************************************************/
void mbedtls_aes_xts_free( mbedtls_aes_xts_context *ctx )
{
    if( ctx == NULL )
    {
    	return;
    }

    /* Free crypt and tweak  */
    mbedtls_aes_free( &ctx->crypt );
    mbedtls_aes_free( &ctx->tweak );

	/* Securely zeroize the AES XTS context */
	mbedtls_platform_zeroize( ctx, sizeof( mbedtls_aes_xts_context ) ) ;
	
	return ;
}

/*************************************************************************************************
* Description:   This function prepares an XTS context for encryption and sets the encryption key.
************************************************************************************************/
int mbedtls_aes_xts_setkey_enc( mbedtls_aes_xts_context *ctx,
                                const unsigned char *key,
                                unsigned int keybits )
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	const unsigned char *key1 = NULL, *key2 = NULL;
	unsigned int key1bits = 0U, key2bits = 0U;

	AES_ALT_VALIDATE_RET( ctx != NULL );
	AES_ALT_VALIDATE_RET( key != NULL );

	/* Break keybits into key1bits and key2bits */
	ret = mbedtls_aes_xts_decode_keys( key, keybits, &key1, &key1bits, &key2, &key2bits );
	if( ret != 0 )
	{
		return ret;
	}

	/* Set the tweak key. Always set tweak key for the encryption mode. */
	ret = mbedtls_aes_setkey_enc( &ctx->tweak, key2, key2bits );
	if( ret != 0 )
	{
		return ret;
	}

	/* Set crypt key for encryption */
	return mbedtls_aes_setkey_enc( &ctx->crypt, key1, key1bits );
}

/*************************************************************************************************
* Description:  This function prepares an XTS context for decryption and sets the decryption key.
************************************************************************************************/
int mbedtls_aes_xts_setkey_dec( mbedtls_aes_xts_context *ctx,
                                const unsigned char *key,
                                unsigned int keybits )
{
	return mbedtls_aes_xts_setkey_enc(ctx, key, keybits);
}

/*************************************************************************************************
* Description:  This function performs an AES-XTS encryption or decryption
* operation for an entire XTS data unit.
************************************************************************************************/
int mbedtls_aes_crypt_xts( mbedtls_aes_xts_context *ctx,
                           int mode,
                           size_t length,
                           const unsigned char data_unit[16],
                           const unsigned char *input,
                           unsigned char *output )
{
    hseSrvResponse_t ret = HSE_SRV_RSP_GENERAL_ERROR;
    uint8_t SectorVal[8] = {0};

    /* Simple sanity check */
    AES_ALT_VALIDATE_RET( ctx != NULL );
    AES_ALT_VALIDATE_RET( mode == MBEDTLS_AES_ENCRYPT ||
                      mode == MBEDTLS_AES_DECRYPT );
    AES_ALT_VALIDATE_RET( data_unit != NULL );
    AES_ALT_VALIDATE_RET( input != NULL );
    AES_ALT_VALIDATE_RET( output != NULL );

    /* Data units must be at least 16 bytes long and must be multiple of 16 bytes */
    if(length < 16)
    {
        return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
    }

    /* NIST SP 800-38E disallows data units larger than 2**20 blocks. */
    if( length > ( 1 << 20 ) * 16 )
    {
        return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
    }

    /* Last 8 byte of data_unit must be 0 */
    if(memcmp(data_unit+8, SectorVal, 8U) != 0U)
    {
        return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
    }
#ifdef HSE_SPT_XTS_AES

    uint64_t SectorIndex = 0;
    uint8_t cipherDir = 0;

    if((length % AES_BLOCK_LENGTH) == 0U)
    {
        /* Copying Sector index from data_unit
         * taking first 8 bytes
         */
        for (uint32_t i = 0U; i < sizeof(SectorIndex); i++)
        {
            uint64_t temp = data_unit[i];
            SectorIndex = (SectorIndex | (temp << (i * 8U)));
        }
        /* Assign the cipher direction */
        cipherDir = (mode == MBEDTLS_AES_ENCRYPT) ? HSE_CIPHER_DIR_ENCRYPT : HSE_CIPHER_DIR_DECRYPT;

        /* Perform the AES-XTS Operation */
        ret = HSE_AesXTS(cipherDir, ctx->crypt.aesKeyHandle, ctx->tweak.aesKeyHandle,\
                SectorIndex, length, length, input, output);

        if( HSE_SRV_RSP_OK != ret )
        {
            /* Return with error on failure */
            ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        }
        else
        {
            /* Return with NO_ERROR on success */
            ret = NO_ERROR ;
        }

        /* Return the service response */
        return( ret ) ;
    }
#endif /* HSE_SPT_XTS_AES */
    {
        size_t blocks = (length / MBEDTLS_AES_BLOCK_SIZE);
        size_t leftover = (length % MBEDTLS_AES_BLOCK_SIZE);
        unsigned char tweak[16] = {0};
        unsigned char prev_tweak[16] = {0};
        unsigned char tmp[16] = {0};
        /* Compute the tweak */
        ret = mbedtls_aes_crypt_ecb( &ctx->tweak, MBEDTLS_AES_ENCRYPT,
                                     data_unit, tweak );
        if( ret != 0 )
        {
            return( ret );
        }
        while( blocks-- )
        {
            size_t i = 0;
#ifdef HSE_SPT_XTS_AES
            if(( mode == MBEDTLS_AES_DECRYPT ) && blocks == 0 )
#else
            if( leftover && ( mode == MBEDTLS_AES_DECRYPT ) && blocks == 0 )
#endif /* HSE_SPT_XTS_AES */
            {
                /* We are on the last block in a decrypt operation that has
                 * leftover bytes, so we need to use the next tweak for this block,
                 * and this tweak for the lefover bytes. Save the current tweak for
                 * the leftovers and then update the current tweak for use on this,
                 * the last full block. */
                memcpy( prev_tweak, tweak, sizeof( tweak ) );
                mbedtls_gf128mul_x_ble( tweak, tweak );
            }
            for( i = 0; i < MBEDTLS_AES_BLOCK_SIZE; i++ )
            {
                tmp[i] = input[i] ^ tweak[i];
            }

            ret = mbedtls_aes_crypt_ecb( &ctx->crypt, mode, tmp, tmp );

            if( ret != 0 )
            {
                return( ret );
            }
            for( i = 0; i < MBEDTLS_AES_BLOCK_SIZE; i++ )
            {
                output[i] = tmp[i] ^ tweak[i];
            }
            /* Update the tweak for the next block. */
            mbedtls_gf128mul_x_ble( tweak, tweak );
            output += 16;
            input += 16;
        }
#ifdef HSE_SPT_XTS_AES

#else
          if( leftover )
#endif /* HSE_SPT_XTS_AES */
          {
            /* If we are on the leftover bytes in a decrypt operation, we need to
             * use the previous tweak for these bytes (as saved in prev_tweak). */
            unsigned char *t = mode == MBEDTLS_AES_DECRYPT ? prev_tweak : tweak;
            /* We are now on the final part of the data unit, which doesn't divide
             * evenly by 16. It's time for ciphertext stealing. */
            size_t i;
            unsigned char *prev_output = output - 16;
            /* Copy ciphertext bytes from the previous block to our output for each
             * byte of cyphertext we won't steal. At the same time, copy the
             * remainder of the input for this final round (since the loop bounds
             * are the same). */
            for( i = 0; i < leftover; i++ )
            {
                output[i] = prev_output[i];
                tmp[i] = input[i] ^ t[i];
            }
            /* Copy ciphertext bytes from the previous block for input in this
             * round. */
            for( ; i < MBEDTLS_AES_BLOCK_SIZE; i++ )
            {
                tmp[i] = prev_output[i] ^ t[i];
            }
            ret = mbedtls_aes_crypt_ecb( &ctx->crypt, mode, tmp, tmp );
            if( ret != 0 )
            {
                return( ret );
            }
            /* Write the result back to the previous block, overriding the previous
             * output we copied. */
            for( i = 0; i < MBEDTLS_AES_BLOCK_SIZE; i++ )
            {
                prev_output[i] = tmp[i] ^ t[i];
            }
        }
        return( 0 );
    }
}
#endif /* MBEDTLS_CIPHER_MODE_XTS */

#endif /* MBEDTLS_AES_ALT */
