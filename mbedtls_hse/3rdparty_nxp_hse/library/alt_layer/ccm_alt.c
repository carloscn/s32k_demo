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

#if defined(MBEDTLS_CCM_ALT)
#include <string.h>
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/ccm.h"
#include "mbedtls/aes.h"
#include "device.h"
#include "hse_host_aead.h"
#include "keystore_mgmt.h"

/*==================================================================================================
*                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL MACROS
==================================================================================================*/

#ifndef MBEDTLS_AES_BLOCK_SIZE
#define MBEDTLS_AES_BLOCK_SIZE	 	((uint32_t)(0x10UL))
#endif

/* Parameter validation macros. */
#define CCM_ALT_VALIDATE_RET( cond ) \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_CCM_BAD_INPUT )
#define CCM_ALT_VALIDATE( cond ) \
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
 * 	@brief		This function encrypts a buffer using CCM.
 *
 * 	@param[in]	ctx
 * 				The CCM context to use for encryption.
 *
 * 	@param[in]	length
 *              The length of the input data in Bytes.
 *
 *	@param[in]	iv
 *				The initialization vector (nonce). This must be a readable
 *              buffer of at least \p iv_len Bytes.
 *
 *	@param[in]	iv_len
 *              The length of the nonce in Bytes: 7, 8, 9, 10, 11, 12,
 *              or 13. The length L of the message length field is
 *              15 - \p iv_len.
 *
 *	@param[in]	add
 *				The additional data field. If \p add_len is greater than
 *              zero, \p add must be a readable buffer of at least that
 *              length.
 *
 *	@param[in]	add_len
 *				The length of additional data in Bytes.
 *
 *  @param[in]	input
 *				The buffer holding the input data. If \p length is greater
 *              than zero, \p input must be a readable buffer of at least
 *              that length.
 *
 *	@param[out]	output
 *              The buffer holding the output data. If \p length is greater
 *              than zero, \p output must be a writable buffer of at least
 *              that length.
 *
 *	@param[out]	tag
 *				The buffer holding the authentication field. This must be a
 *              readable buffer of at least \p tag_len Bytes.
 *
 *	@param[in]	tag_len
 *				The length of the authentication field to generate in Bytes:
 *              4, 6, 8, 10, 12, 14 or 16.
 *
 *  @return		\c 0 on success.
 *
 *	@return		A CCM or cipher-specific error code on failure.
 *
 */
static int ccm_auth_int_encrypt( mbedtls_ccm_context *ctx, size_t length,
                                 const unsigned char *iv, size_t iv_len,
                                 const unsigned char *add, size_t add_len,
                                 const unsigned char *input, unsigned char *output,
                                 unsigned char *tag, size_t tag_len );

/**
 * 	@brief		This function performs a CCM authenticated decryption of a
 *              buffer.
 *
 * 	@param[in]	ctx
 * 				The CCM context to use for decryption.
 *
 * 	@param[in]	length
 *              The length of the input data in Bytes.
 *
 *	@param[in]	iv
 *				The initialization vector (nonce). This must be a readable
 *              buffer of at least \p iv_len Bytes.
 *
 *	@param[in]	iv_len
 *              The length of the nonce in Bytes: 7, 8, 9, 10, 11, 12,
 *              or 13. The length L of the message length field is
 *              15 - \p iv_len.
 *
 *	@param[in]	add
 *				The additional data field. If \p add_len is greater than
 *              zero, \p add must be a readable buffer of at least that
 *              length.
 *
 *	@param[in]	add_len
 *				The length of additional data in Bytes.
 *
 *  @param[in]	input
 *				The buffer holding the input data. If \p length is greater
 *              than zero, \p input must be a readable buffer of at least
 *              that length.
 *
 *	@param[out]	output
 *              The buffer holding the output data. If \p length is greater
 *              than zero, \p output must be a writable buffer of at least
 *              that length.
 *
 *	@param[out]	tag
 *				The buffer holding the authentication field. This must be a
 *              readable buffer of at least \p tag_len Bytes.
 *
 *	@param[in]	tag_len
 *				The length of the authentication field to generate in Bytes:
 *              4, 6, 8, 10, 12, 14 or 16.
 *
 *  @return		\c 0 on success.
 *
 *  @return     #MBEDTLS_ERR_CCM_AUTH_FAILED if the tag does not match.
 *  @return     A cipher-specific error code on calculation failure.
 *
 */
static int ccm_auth_int_decrypt( mbedtls_ccm_context *ctx, size_t length,
                              const unsigned char *iv, size_t iv_len,
                              const unsigned char *add, size_t add_len,
                              const unsigned char *input, unsigned char *output,
                              const unsigned char *tag, size_t tag_len );

/*==================================================================================================
*                                       LOCAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
* Description:  This function encrypts a buffer using CCM.
************************************************************************************************/
static int ccm_auth_int_encrypt( mbedtls_ccm_context *ctx, size_t length,
                                 const unsigned char *iv, size_t iv_len,
                                 const unsigned char *add, size_t add_len,
                                 const unsigned char *input, unsigned char *output,
                                 unsigned char *tag, size_t tag_len )
{
	int ret = 0;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
	mbedtls_aes_context *aes_ctx;
	uint8_t tmptag[MBEDTLS_AES_BLOCK_SIZE];
	bool_t istaglenzero = (bool_t)FALSE;
    unsigned char input_len_check;
    size_t len_left;

	/* Simple sanity check */
	CCM_ALT_VALIDATE_RET( ctx != NULL ) ;
	CCM_ALT_VALIDATE_RET( iv != NULL ) ;
	CCM_ALT_VALIDATE_RET( add_len == 0 || add != NULL ) ;
    CCM_ALT_VALIDATE_RET( length == 0 || input != NULL );
    CCM_ALT_VALIDATE_RET( length == 0 || output != NULL );
    CCM_ALT_VALIDATE_RET( tag_len == 0 || tag != NULL );

    if( tag_len == 0 )
    {
    	tag = tmptag;
		tag_len = sizeof(tmptag);
		istaglenzero = (bool_t)TRUE;
    }

    /*
     * Check length requirements: SP800-38C A.1
     * Additional requirement: a < 2^16 - 2^8 to simplify the code.
     * 'length' checked later (when writing it to the first block)
     *
     * Also, loosen the requirements to enable support for CCM* (IEEE 802.15.4).
     */
    if( (tag_len == 2) || (tag_len > 16) || (tag_len % 2 != 0) )
    {
    	return( MBEDTLS_ERR_CCM_BAD_INPUT );
    }

    /* Also implies q is within bounds */
    if( (iv_len < 7) || (iv_len > 13) )
    {
        return( MBEDTLS_ERR_CCM_BAD_INPUT );
    }

    if( add_len > 0xFF00 )
    {
        return( MBEDTLS_ERR_CCM_BAD_INPUT );
    }

    input_len_check = 16 - 1 - (unsigned char) iv_len;

    len_left = length;
    for(uint8_t i = 0; i < input_len_check; i++)
    {
    	len_left >>= 8 ;
    }

    if( len_left > 0 )
    {
    	return( MBEDTLS_ERR_CCM_BAD_INPUT );
    }

	aes_ctx = (mbedtls_aes_context*)ctx->cipher_ctx.cipher_ctx;

	if((!aes_ctx) || (aes_ctx->aesKeyHandle == HSE_INVALID_KEY_HANDLE))
	{
		return ( MBEDTLS_ERR_CCM_BAD_INPUT );
	}

	/* Send the request */
	srvResponse = HSE_AeadCcmEncrypt( aes_ctx->aesKeyHandle, (uint8_t*)iv, (uint32_t)iv_len, (uint8_t*)add,
			(uint32_t)add_len, (uint8_t*)input, (uint32_t)length, (uint32_t)tag_len, (uint8_t*)tag, (uint8_t*)output ) ;

	/* Check the response */
	if( HSE_SRV_RSP_OK != srvResponse )
	{
		if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_CCM_BAD_INPUT ;
		}
		else
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_CCM_HW_ACCEL_FAILED ;
		}
	}

	else
	{
		/* Return with NO_ERROR on success */
		ret = NO_ERROR ;
	}

	/* Zeroize TempTag when tag_length is 0 originally */
	if(istaglenzero == (bool_t)TRUE)
	{
		mbedtls_platform_zeroize(tmptag, sizeof(tmptag));
	}

	/* Return the service response */
	return( ret ) ;
}

/*************************************************************************************************
* Description:  This function performs a CCM authenticated decryption of a buffer.
************************************************************************************************/
static int ccm_auth_int_decrypt( mbedtls_ccm_context *ctx, size_t length,
                              const unsigned char *iv, size_t iv_len,
                              const unsigned char *add, size_t add_len,
                              const unsigned char *input, unsigned char *output,
                              const unsigned char *tag, size_t tag_len )
{
	int ret = 0;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
	mbedtls_aes_context *aes_ctx;
    unsigned char input_len_check;
    size_t len_left;

	/* Simple sanity check */
    if( tag_len == 0 )
    {
    	return( MBEDTLS_ERR_CCM_BAD_INPUT );
    }

    /*
	 * Check length requirements: SP800-38C A.1
	 * Additional requirement: a < 2^16 - 2^8 to simplify the code.
	 * 'length' checked later (when writing it to the first block)
	 *
	 * Also, loosen the requirements to enable support for CCM* (IEEE 802.15.4).
	 */
	if( (tag_len == 2) || (tag_len > 16) || (tag_len % 2 != 0) )
	{
		return( MBEDTLS_ERR_CCM_BAD_INPUT );
	}

	/* Also implies q is within bounds */
	if( (iv_len < 7) || (iv_len > 13) )
	{
		return( MBEDTLS_ERR_CCM_BAD_INPUT );
	}

	if( add_len > 0xFF00 )
	{
		return( MBEDTLS_ERR_CCM_BAD_INPUT );
	}

	input_len_check = 16 - 1 - (unsigned char) iv_len;

    len_left = length;
    for(uint8_t i = 0; i < input_len_check; i++)
    {
    	len_left >>= 8 ;
    }

    if( len_left > 0 )
    {
    	return( MBEDTLS_ERR_CCM_BAD_INPUT );
    }

	aes_ctx = (mbedtls_aes_context*)ctx->cipher_ctx.cipher_ctx;

	if((!aes_ctx) || (aes_ctx->aesKeyHandle == HSE_INVALID_KEY_HANDLE))
	{
		return ( MBEDTLS_ERR_CCM_BAD_INPUT );
	}

	/* Send the request */
	srvResponse = HSE_AeadCcmDecrypt( aes_ctx->aesKeyHandle, (uint8_t*)iv, (uint32_t)iv_len, (uint8_t*)add, (uint32_t)add_len,
			(uint8_t*)input, (uint32_t)length, (uint32_t)tag_len, (uint8_t*)tag, (uint8_t*)output ) ;

	/* Check the response */
	if( HSE_SRV_RSP_OK != srvResponse )
	{
		if(HSE_SRV_RSP_VERIFY_FAILED == srvResponse)
		{
			ret = MBEDTLS_ERR_CCM_AUTH_FAILED;
			mbedtls_platform_zeroize( output, length );
		}
		/*added for S32N55 */
#if defined(S32N55)
		else if(HSE_SRV_RSP_OPERATION_FAILED == srvResponse)
		{
			ret = MBEDTLS_ERR_CCM_AUTH_FAILED;
		    mbedtls_platform_zeroize( output, length );
		}
#endif
		else if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_CCM_BAD_INPUT ;
		}
		else
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_CCM_HW_ACCEL_FAILED ;
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

/*==================================================================================================
*                                       GLOBAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
* Description:  This function initializes the specified CCM context.
************************************************************************************************/
void mbedtls_ccm_init( mbedtls_ccm_context *ctx )
{
	/* Simple sanity check */
	CCM_ALT_VALIDATE( ctx != NULL ) ;

    memset( ctx, 0, sizeof( mbedtls_ccm_context ) );
}

/*************************************************************************************************
* Description:  This function sets the CCM encryption and decryption
*  key / CCM key schedule (encryption and decryption).
************************************************************************************************/
int mbedtls_ccm_setkey( mbedtls_ccm_context *ctx,
                        mbedtls_cipher_id_t cipher,
                        const unsigned char *key,
                        unsigned int keybits )
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	const mbedtls_cipher_info_t *cipher_info;

	CCM_ALT_VALIDATE_RET( ctx != NULL );
	CCM_ALT_VALIDATE_RET( key != NULL );

	cipher_info = mbedtls_cipher_info_from_values( cipher, (keybits & ~KEYLOADED_FLAG),
												   MBEDTLS_MODE_ECB );
	if( cipher_info == NULL )
	{
		return( MBEDTLS_ERR_CCM_BAD_INPUT );
	}

	if( cipher_info->block_size != 16 )
	{
		return( MBEDTLS_ERR_CCM_BAD_INPUT );
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

	return ( 0 );
}

/*************************************************************************************************
* Description: This function encrypts a buffer using CCM and generates encrypted output
* and MAC tag.
************************************************************************************************/
int mbedtls_ccm_encrypt_and_tag( mbedtls_ccm_context *ctx, size_t length,
                                 const unsigned char *iv, size_t iv_len,
                                 const unsigned char *add, size_t add_len,
                                 const unsigned char *input, unsigned char *output,
                                 unsigned char *tag, size_t tag_len )
{
	/* Simple sanity check */
	CCM_ALT_VALIDATE_RET( ctx != NULL ) ;
	CCM_ALT_VALIDATE_RET( iv != NULL ) ;
	CCM_ALT_VALIDATE_RET( add_len == 0 || add != NULL ) ;
    CCM_ALT_VALIDATE_RET( length == 0 || input != NULL );
    CCM_ALT_VALIDATE_RET( length == 0 || output != NULL );
    CCM_ALT_VALIDATE_RET( tag_len == 0 || tag != NULL );

    if( tag_len == 0 )
    {
    	return( MBEDTLS_ERR_CCM_BAD_INPUT );
    }

	return ccm_auth_int_encrypt(ctx, length, iv, iv_len, add, add_len, input, output, tag, tag_len);
}

/*************************************************************************************************
* Description:  This function encrypts a buffer using CCM*.
************************************************************************************************/
int mbedtls_ccm_star_encrypt_and_tag( mbedtls_ccm_context *ctx, size_t length,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *add, size_t add_len,
                         const unsigned char *input, unsigned char *output,
                         unsigned char *tag, size_t tag_len )
{
    CCM_ALT_VALIDATE_RET( ctx != NULL );
    CCM_ALT_VALIDATE_RET( iv != NULL );
    CCM_ALT_VALIDATE_RET( add_len == 0 || add != NULL );
    CCM_ALT_VALIDATE_RET( length == 0 || input != NULL );
    CCM_ALT_VALIDATE_RET( length == 0 || output != NULL );
    CCM_ALT_VALIDATE_RET( tag_len == 0 || tag != NULL );

    return( ccm_auth_int_encrypt( ctx, length, iv, iv_len,	\
		add, add_len, input, output, tag, tag_len ) );
}

/*************************************************************************************************
* Description: This function decrypts a buffer using CCM and generates decrypted output
* and verifies MAC tag.
************************************************************************************************/
int mbedtls_ccm_auth_decrypt( mbedtls_ccm_context *ctx, size_t length,
                              const unsigned char *iv, size_t iv_len,
                              const unsigned char *add, size_t add_len,
                              const unsigned char *input, unsigned char *output,
                              const unsigned char *tag, size_t tag_len )
{
	CCM_ALT_VALIDATE_RET( ctx != NULL ) ;
	CCM_ALT_VALIDATE_RET( iv != NULL ) ;
	CCM_ALT_VALIDATE_RET( add_len == 0 || add != NULL ) ;
    CCM_ALT_VALIDATE_RET( length == 0 || input != NULL );
    CCM_ALT_VALIDATE_RET( length == 0 || output != NULL );
    CCM_ALT_VALIDATE_RET( tag_len == 0 || tag != NULL );

    if( tag_len == 0 )
    {
    	return( MBEDTLS_ERR_CCM_BAD_INPUT );
    }

	return ccm_auth_int_decrypt(ctx, length, iv, iv_len, add, add_len, input, output, tag, tag_len);
}

/*************************************************************************************************
* Description:  This function performs a CCM* authenticated decryption of a buffer.
************************************************************************************************/
int mbedtls_ccm_star_auth_decrypt( mbedtls_ccm_context *ctx, size_t length,
                      const unsigned char *iv, size_t iv_len,
                      const unsigned char *add, size_t add_len,
                      const unsigned char *input, unsigned char *output,
                      const unsigned char *tag, size_t tag_len )
{
	
	CCM_ALT_VALIDATE_RET( ctx != NULL ) ;
	CCM_ALT_VALIDATE_RET( iv != NULL ) ;
	CCM_ALT_VALIDATE_RET( add_len == 0 || add != NULL ) ;
    CCM_ALT_VALIDATE_RET( length == 0 || input != NULL );
    CCM_ALT_VALIDATE_RET( length == 0 || output != NULL );
    CCM_ALT_VALIDATE_RET( tag_len == 0 || tag != NULL );

	return ccm_auth_int_decrypt(ctx, length, iv, iv_len, add, add_len, input, output, tag, tag_len);
}

/*************************************************************************************************
* Description:  This function releases and clears the specified CCM context.
************************************************************************************************/
void mbedtls_ccm_free( mbedtls_ccm_context *ctx )
{
	/* Simple sanity check */
    if( ctx == NULL)
    {
    	return ;
    }

    mbedtls_cipher_free( &ctx->cipher_ctx );

    /* Securely zeroize the CCM context */
    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_ccm_context ) ) ;
}
#endif /* MBEDTLS_CCM_ALT */
