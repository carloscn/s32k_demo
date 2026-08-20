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
#include "keystore_mgmt.h"
#include "nxp_hse_tls_ssl.h"
#include "hse_host_cipher.h"
#include "hse_host_sign.h"
#include "mbedtls/ssl_ciphersuites.h"
#include "nxp_hse_pk_rsa_alt.h"

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

#if defined (MBEDTLS_USE_NXP_HSE_CRYPTO)
/**
 * @brief				nxp_hse_compute_key_expansion
 * @details				perform key expansion using master keyhandle
 *
 * @param[in]			md_type
 *						message digest algo.
 *
 * @param[in]			secret
 * 						hold the master keyhandle
 *
 * @param[in]			slen
 * 						length of secret material
 *
 * @param[in]			label
 * 						The label of the TLS1.2 PRF operations
 *
 * @param[in]			random
 * 						The seed for TLS 1.2 PRF.
 *
 * @parm[in]			rlen
 * 						length of seed
 *
 * @param[out]			dstbuf
 * 						pointer to output buffer. hold the keyhandle for
 * 						MAC (Encryption/decryption) and DATA (Encryption/decryption)
 *
 * @param[in]			dlen
 * 						length of output buffer
 *
 * 	@return				return type		: int
 *
 * 	@retval				Success			: 0
 *
 * 	@retval				Failed			:
 * 	 					#MBEDTLS_ERR_SSL_INVALID_MAC if invalid hash id
 * 						#MBEDTLS_ERR_SSL_HW_ACCEL_FAILED
 */
static int nxp_hse_compute_key_expansion(mbedtls_md_type_t md_type, const unsigned char *secret,
		const char *label, const unsigned char *random, size_t rlen,
        unsigned char *dstbuf, size_t dlen);

/**
 * @brief				nxp_hse_handshake_finished
 * @details				perform handshake finished using master keyhandle
 *
 * @param[in]			md_type
 *						message digest algo.
 *
 * @param[in]			secret
 * 						hold the master keyhandle
 *
 * @param[in]			slen
 * 						length of secret material
 *
 * @param[in]			label
 * 						The label of the TLS1.2 PRF operations
 *
 * @param[in]			random
 * 						The seed for TLS 1.2 PRF.
 *
 * @parm[in]			rlen
 * 						length of seed
 *
 * @param[out]			dstbuf
 * 						pointer to output buffer.
 *
 * @param[in]			dlen
 * 						length of output buffer
 *
 * 	@return				return type		: int
 *
 * 	@retval				Success			: 0
 *
 * 	@retval				Failed			:
 * 						#MBEDTLS_ERR_SSL_INVALID_MAC if invalid hash id
 * 						#MBEDTLS_ERR_SSL_HW_ACCEL_FAILED
 *
 */
static int nxp_hse_handshake_finished(mbedtls_md_type_t md_type, const unsigned char *secret,
		const char *label, const unsigned char *random, size_t rlen,
        unsigned char *dstbuf, size_t dlen);

/**
 * @brief				nxp_hse_compute_master_secret
 * @details				perform to compute master keyhandle using pre-master and psk keyhandle
 *
 * @param[in]			md_type
 *						message digest algo.
 *
 * @param[in]			secret
 * 						hold the pre-master/psk keyhandle
 *
 * @param[in]			slen
 * 						length of secret material
 *
 * @param[in]			label
 * 						The label of the TLS1.2 PRF operations
 *
 * @param[in]			random
 * 						The seed for TLS 1.2 PRF.
 *
 * @parm[in]			rlen
 * 						length of seed
 *
 * @param[out]			dstbuf
 * 						pointer to output buffer. hold the keyhandle for master keyhandle
 *
 * @param[in]			dlen
 * 						length of output buffer
 *
 * 	@return				return type		: int
 *
 * 	@retval				Success			: 0
 *
 * 	@retval				Failed			: MBEDTLS_ERR_SSL_HW_ACCEL_FAILED
 *
 */
static int nxp_hse_compute_master_secret(mbedtls_md_type_t md_type, const unsigned char *secret,
		const char *label, const unsigned char *random, size_t rlen, unsigned char *dstbuf);

#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
/**
 * 	@brief				nxp_hse_rsa_loadkey
 * 	@details			This function loads RSA key-pair, returns public/private key-handle in ctx
 *
 * 	@param[in]			ctx
 *						Pointer to the RSA Context
 *
 * 	@param[in]			mode
 *						MBEDTLS_RSA_PUBLIC or MBEDTLS_RSA_PRIVATE
 *
 *  @return				return type		: int
 *
 * 	@retval				Success			: 0
 *
 * 	@retval				Failed			:
 * 						#MBEDTLS_ERR_RSA_BAD_INPUT_DATA for bad input
 *						#MBEDTLS_ERR_MPI_ALLOC_FAILED for memory allocation failure
 *
 */
static int nxp_hse_rsa_loadkey(mbedtls_rsa_context *ctx, int mode);
#endif /*MBEDTLS_KEY_EXCHANGE_RSA_ENABLED || MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED*/

/*==================================================================================================
*                                       LOCAL FUNCTIONS
==================================================================================================*/

#if defined (MBEDTLS_DEBUG_C)
static int16_t export_key(uint32_t keyHandle)
{
	hseKeyInfo_t KeyInfo;
	hseSrvResponse_t srvResponse;
	uint8_t keybuff[4096/8];
	uint8_t keybuff1[4096/8];
	uint32_t outbuffsize, i;
	int16_t ret = 0;
	uint32_t authKeyHandle = HSE_INVALID_KEY_HANDLE, copykeyslot = HSE_INVALID_KEY_HANDLE, decKeyHandle = HSE_INVALID_KEY_HANDLE;
	uint8_t export_key[16]={
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, \
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
	};

	cipher_t cipherParam = {0};

	outbuffsize= sizeof(keybuff);

	key_import_param_t key_import_param = {
			HSE_KEY_TYPE_AES,
			HSE_KEY_CATALOG_ID_NVM,
			0U,
			{
					{
							(const uint8_t*)&export_key,
							128
					}
			}
		};

	key_import_param_t key_import_param_copy = {
			HSE_KEY_TYPE_HMAC,
			HSE_KEY_CATALOG_ID_RAM,
			0U,
			{
					{
							NULL,
							HSE_KEY1024_BITS
					}
			}
	};

	if(copykeyslot == HSE_INVALID_KEY_HANDLE)
	{
		KeystoreMgmt_FindAllocateSlot(&key_import_param_copy, &copykeyslot);
	}

	if(authKeyHandle == HSE_INVALID_KEY_HANDLE)
	{
		KeystoreMgmt_FindAllocateSlot(&key_import_param, &authKeyHandle);
		srvResponse = HSE_ImportSymKey(authKeyHandle, \
				HSE_KEY_TYPE_AES, \
				(HSE_KF_USAGE_ENCRYPT|HSE_KF_USAGE_DECRYPT|HSE_KF_USAGE_KEY_PROVISION), \
				(const uint8_t*)&export_key, 16);
	}

	if(decKeyHandle == HSE_INVALID_KEY_HANDLE)
	{
		KeystoreMgmt_FindImportSlot(&key_import_param, &decKeyHandle);
	}

	mbedtls_printf("AuthKey=0x%08x\n", authKeyHandle);
	mbedtls_printf("");
	memset(keybuff, 0, sizeof(keybuff));

	srvResponse = HSE_GetKeyInfo(keyHandle, &KeyInfo);
	if(srvResponse == HSE_SRV_RSP_OK)
	{
		uint16_t offset = 0, keywrite = 0, keylen = 0;
		/* Copy Key to copykeyslot */
		KeyInfo.keyFlags = HSE_KF_USAGE_VERIFY|HSE_KF_USAGE_SIGN|HSE_KF_ACCESS_EXPORTABLE;
		KeyInfo.keyType = HSE_KEY_TYPE_HMAC;
		keylen = KeyInfo.keyBitLen;

		if(keylen > HSE_KEY1024_BITS)
		{
			KeyInfo.keyBitLen = HSE_KEY1024_BITS;
			do{
				keywrite += KeyInfo.keyBitLen;
				srvResponse = HSE_KeyDeriveCopyKey(keyHandle, offset, copykeyslot, KeyInfo);
				if(srvResponse != HSE_SRV_RSP_OK)
				{
					ret = -1;
					goto exit;
				}
				offset = BITS_TO_BYTES(offset + keywrite);
				KeyInfo.keyBitLen = keylen-keywrite;
			}while(KeyInfo.keyBitLen);
		}
		else
		{
			srvResponse = HSE_KeyDeriveCopyKey(keyHandle, offset, copykeyslot, KeyInfo);
			if(srvResponse != HSE_SRV_RSP_OK)
			{
				ret = -1;
				goto exit;
			}
		}

		srvResponse = HSE_GetKeyInfo(copykeyslot, &KeyInfo); /* Export Encrypted Key */

		cipherParam.cipherKeyHandle 						= authKeyHandle;
		cipherParam.cipherScheme.symCipher.cipherAlgo 		= HSE_CIPHER_ALGO_AES;
		cipherParam.cipherScheme.symCipher.cipherBlockMode 	= HSE_CIPHER_BLOCK_MODE_ECB;

		srvResponse = HSE_ExportEncKey(copykeyslot, &KeyInfo, &cipherParam, NULL,
										NULL, 0U, NULL, 0U, keybuff, &outbuffsize);

		if(srvResponse == HSE_SRV_RSP_OK)
		{
			srvResponse = HSE_AesDecrypt( HSE_CIPHER_BLOCK_MODE_ECB, decKeyHandle, \
					NULL, 0UL, keybuff, outbuffsize, keybuff1);

			//mbedtls_printf("\nMaster Secret 0x%08x\n", keyHandle);

			for(i = 0; i< outbuffsize; i++)
			{
				if((i%16) == 0)
				mbedtls_printf("\n");
				mbedtls_printf("%02x ", keybuff1[i]);
			}
			mbedtls_printf("\r\n");
		}
		else
		{
			ret = -1;
			goto exit;
		}
	}
exit:

	(void)KeyStoreMgmt_FreeKey(authKeyHandle);
	(void)KeyStoreMgmt_FreeKey(decKeyHandle);
	(void)KeyStoreMgmt_FreeKey(copykeyslot);
	authKeyHandle = HSE_INVALID_KEY_HANDLE;
	decKeyHandle  = HSE_INVALID_KEY_HANDLE;
	copykeyslot   = HSE_INVALID_KEY_HANDLE;
	return ret;

}
#endif
/*************************************************************************************************
* Description:  nxp_hse_compute_key_expansion
************************************************************************************************/
static int nxp_hse_compute_key_expansion(mbedtls_md_type_t md_type, const unsigned char *secret,
		const char *label, const unsigned char *random, size_t rlen,
        unsigned char *dstbuf, size_t dlen)
{
	int ret = -1;				/* Hold the return status of API */
	hseKeyHandle_t expansionKeyHandle = INVALID_KEYHANDLE;	/* Hold the expansion keyhandle which will be used for key expansion */
	uint8_t iv_block[32] = {0};	/* buffer to hold the IV generated during key expansion */
	TlsPRFKeys_t tlsKeys;		/* Hold the 4 keyhandle generated during key expansion */
	hseKeyInfo_t keyInfo;		/* Hold the information about key to be extract */
	uint32_t Iv_len = 0U;		/* Length of IV to be computed */
	uint32_t Key_len = 0U;		/* Length of Key to be computed */
	uint16_t offset = 0U;		/* Offest of key present in key expansion */
	uint32_t HashLength = 0U;	/* length of message digest */

	key_import_param_t key_import_param;					/* Structure to be used by HSE for keyhandle computation */
	hseKdfTLS12PrfScheme_t tls12Prf;						/* Structure used by HSE for calculating key expansion */
	hseKeyHandle_t masterkeyhandle = INVALID_KEYHANDLE ;	/* Hold the master keyhandle value */

#if defined (MBEDTLS_DEBUG_C)
	mbedtls_ssl_context *ssl;
    ssl = mbedtls_calloc(1,sizeof(mbedtls_ssl_context));
    ssl -> conf = mbedtls_calloc(1,sizeof(mbedtls_ssl_config));
    mbedtls_ssl_conf_dbg( (mbedtls_ssl_config *)(ssl -> conf) , nxp_hse_debug_prints, stdout );
#endif /* MBEDTLS_DEBUG_C */

	memset(&key_import_param, 0x00, sizeof(key_import_param_t));
	memset(&tls12Prf, 0x00, sizeof(hseKdfTLS12PrfScheme_t));
	memset(&tlsKeys, 0xFF, sizeof(TlsPRFKeys_t));
	memset(&keyInfo, 0x00, sizeof(hseKeyInfo_t));

	/* Copying the IV, key_len and hash length from destination buffer */
	memcpy(&Iv_len, (dstbuf + (sizeof(uint32_t) * 0)), sizeof(uint32_t));
	memcpy(&Key_len, (dstbuf + (sizeof(uint32_t) * 1)), sizeof(uint32_t));
	memcpy(&HashLength, (dstbuf + (sizeof(uint32_t) * 2)), sizeof(uint32_t));

	/* Copying the master keyhandle from secret buffer */
	memcpy(&masterkeyhandle, secret, sizeof(hseKeyHandle_t));
	memset(dstbuf, 0x00, dlen);

	key_import_param.key_catalog = HSE_KEY_CATALOG_ID_RAM;
	key_import_param.key_type = HSE_KEY_TYPE_SHARED_SECRET;
	key_import_param.key_param.sym_key_param.size = BYTES_TO_BITS((Key_len * 2) + (HashLength * 2));

	switch(md_type)
	{
#if !defined(S32N55)
		case MBEDTLS_MD_SHA1:      /**< The SHA-1 message digest. */
		{
#ifdef HSE_KDF_SHA_1
			tls12Prf.hmacHash = HSE_KDF_SHA_1;
			break;
#else
			return ( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE ) ;
#endif
		}
#endif
		case MBEDTLS_MD_SHA224:    /**< The SHA-224 message digest. */
		{
			tls12Prf.hmacHash = HSE_KDF_SHA2_224;
			break;
		}
		case MBEDTLS_MD_SHA256:    /**< The SHA-256 message digest. */
		{
			tls12Prf.hmacHash = HSE_KDF_SHA2_256;
			break;
		}
		case MBEDTLS_MD_SHA384:    /**< The SHA-384 message digest. */
		{
			tls12Prf.hmacHash = HSE_KDF_SHA2_384;
			break;
		}
		case MBEDTLS_MD_SHA512:    /**< The SHA-512 message digest. */
		{
			tls12Prf.hmacHash = HSE_KDF_SHA2_512;
			break;
		}
		default:
		{
			NXP_HSE_MBEDTLS_SSL_DEBUG_MSG(3, ("HASH algorithm 0x%02x not supported", md_type));
			ret = MBEDTLS_ERR_SSL_INVALID_MAC;
			goto exit;
		}
	}

	/* Find and allocate expansion Key Slot */
	if(KEYMGMT_ERR_SUCCESS == KeystoreMgmt_FindAllocateSlot(&key_import_param, &expansionKeyHandle))
	{
	    /* Use master secret key in first step for expansion */
	    tls12Prf.srcKeyHandle = masterkeyhandle;
	    tls12Prf.targetKeyHandle = expansionKeyHandle;
	    tls12Prf.keyMatLength = ( (2 * Key_len) + (2 * HashLength)) ;
	    tls12Prf.seedLength = rlen;
	    tls12Prf.pSeed = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(random));
	    tls12Prf.labelLength = strlen(label);
	    tls12Prf.pLabel = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(label));
	    tls12Prf.outputLength = (2 * Iv_len);
	    tls12Prf.pOutput = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(iv_block));

	    ret = HSE_Tls12Prf(&tls12Prf);
	    if(HSE_SRV_RSP_OK != ret )
	    {
	    	NXP_HSE_MBEDTLS_SSL_DEBUG_MSG(3, ("Derive Expansion key fail\n"));
	    	(void)KeyStoreMgmt_FreeKey(masterkeyhandle);
	    	ret = MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
	    	goto exit;
	    }
	    else
	    {
	    	NXP_HSE_MBEDTLS_SSL_DEBUG_BUF(4, "calculated IV", iv_block, tls12Prf.outputLength);
	    	memcpy(dstbuf + sizeof(TlsPRFKeys_t), (iv_block), tls12Prf.outputLength);
	    	NXP_HSE_MBEDTLS_SSL_DEBUG_MSG(3, ("Derive Expansion key pass\n"));
	    	ret = 0;
	    }
	}
	else
	{
		goto exit;
	}

	if(0 != HashLength)
	{
		/*===================================Derive Client Write Mac Key=============================*/
		/* Import Key in HSE Key Store */
		keyInfo.keyType = HSE_KEY_TYPE_HMAC;
		keyInfo.keyFlags = (HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY | HSE_KF_USAGE_DERIVE);
		keyInfo.keyBitLen = (8U * HashLength);
		offset = 0U;

		key_import_param.key_catalog = HSE_KEY_CATALOG_ID_RAM;
		key_import_param.key_type = keyInfo.keyType;
		key_import_param.key_param.sym_key_param.size = keyInfo.keyBitLen;

		/* Find and allocate Key Slot */
		if(KEYMGMT_ERR_SUCCESS == KeystoreMgmt_FindAllocateSlot(&key_import_param, &tlsKeys.client_write_MAC_key))
		{
			if(HSE_SRV_RSP_OK == HSE_KeyDeriveCopyKey(expansionKeyHandle, offset, tlsKeys.client_write_MAC_key, keyInfo))
			{
				NXP_HSE_MBEDTLS_SSL_DEBUG_MSG(3, ("Derive MAC Decryption key pass\n"));
				ret = 0;
			}
			else
			{
				NXP_HSE_MBEDTLS_SSL_DEBUG_MSG(3, ("Derive  MAC Decryption key fail\n"));
				ret = MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
				goto exit;
			}
		}
		else
		{
			ret = MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
			goto exit;
		}
		/*===================================Derive Server Write Mac Key=============================*/
		/* Import Key in HSE Key Store */
		keyInfo.keyType = HSE_KEY_TYPE_HMAC;
		keyInfo.keyFlags = (HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY | HSE_KF_USAGE_DERIVE);
		keyInfo.keyBitLen = (8U * HashLength);
		offset += HashLength;

		key_import_param.key_catalog = HSE_KEY_CATALOG_ID_RAM;
		key_import_param.key_type = keyInfo.keyType;
		key_import_param.key_param.sym_key_param.size = keyInfo.keyBitLen;

		/* Find and allocate Key Slot */
		if(KEYMGMT_ERR_SUCCESS == KeystoreMgmt_FindAllocateSlot(&key_import_param, &tlsKeys.server_write_MAC_key))
		{
			if(HSE_SRV_RSP_OK == HSE_KeyDeriveCopyKey(expansionKeyHandle, offset, tlsKeys.server_write_MAC_key, keyInfo))
			{
				NXP_HSE_MBEDTLS_SSL_DEBUG_MSG(3, ("Derive MAC Encryption Key pass"));
				ret = 0;
			}
			else
			{
				NXP_HSE_MBEDTLS_SSL_DEBUG_MSG(3, ("Derive MAC Encryption key fail"));
				ret = MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
				goto exit;
			}
		}
		else
		{
			ret = MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
			goto exit;
		}
	}

/*
* ===================================Derive Client Write Crypt Key=============================
*/
	if(0 != Key_len) //Derive crypt key should not be performed for NULL ciphersuites
	{
		/* Import Key in HSE Key Store */
		keyInfo.keyType = HSE_KEY_TYPE_AES;
		keyInfo.keyFlags = (HSE_KF_USAGE_ENCRYPT | HSE_KF_USAGE_DECRYPT |
							HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY | HSE_KF_USAGE_DERIVE);
		keyInfo.keyBitLen = (8U * Key_len);
		offset += HashLength;

		key_import_param.key_catalog = HSE_KEY_CATALOG_ID_RAM;
		key_import_param.key_type = keyInfo.keyType;
		key_import_param.key_param.sym_key_param.size = keyInfo.keyBitLen;

		/* Find and allocate Key Slot */
		if(KEYMGMT_ERR_SUCCESS == KeystoreMgmt_FindAllocateSlot(&key_import_param, &tlsKeys.client_write_key))
		{
			if(HSE_SRV_RSP_OK == HSE_KeyDeriveCopyKey(expansionKeyHandle, offset, tlsKeys.client_write_key, keyInfo))
			{
				NXP_HSE_MBEDTLS_SSL_DEBUG_MSG(3, ("Derive Decryption Key pass"));
				ret = 0;
			}
			else
			{
				NXP_HSE_MBEDTLS_SSL_DEBUG_MSG(3, ("Derive Decryption Key pass"));
				ret = MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
				goto exit;
			}
		}
		else
		{
			ret = MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
			goto exit;
		}


	/*
	* ===================================Derive Server Write Crypt Key=============================
	*/

		/* Import Key in HSE Key Store */
		keyInfo.keyType = HSE_KEY_TYPE_AES;
		keyInfo.keyFlags = (HSE_KF_USAGE_ENCRYPT | HSE_KF_USAGE_DECRYPT |
								HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY | HSE_KF_USAGE_DERIVE);
		keyInfo.keyBitLen = (8U * Key_len);
		offset += Key_len;

		key_import_param.key_catalog = HSE_KEY_CATALOG_ID_RAM;
		key_import_param.key_type = keyInfo.keyType;
		key_import_param.key_param.sym_key_param.size = keyInfo.keyBitLen ;

		/* Find and allocate Key Slot */
		if(KEYMGMT_ERR_SUCCESS == KeystoreMgmt_FindAllocateSlot(&key_import_param, &tlsKeys.server_write_key))
		{
			if(HSE_SRV_RSP_OK == HSE_KeyDeriveCopyKey(expansionKeyHandle, offset, tlsKeys.server_write_key, keyInfo))
			{
				NXP_HSE_MBEDTLS_SSL_DEBUG_MSG(3, ("Derive Encryption Key pass"));
				ret = 0;
			}
			else
			{
				NXP_HSE_MBEDTLS_SSL_DEBUG_MSG(3, ("Derive Encryption Key fail"));
				ret = MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
				goto exit;
			}
		}
		else
		{
			ret = MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
			goto exit;
		}
	}
	/* Copy the keys to destination buffer */
	memcpy(dstbuf, &tlsKeys, sizeof(TlsPRFKeys_t));
exit:

	/* Unload expansionkeyHandle */
	(void)KeyStoreMgmt_FreeKey(expansionKeyHandle);
	NXP_HSE_MBEDTLS_SSL_DEBUG_RET(3, "nxp_hse_key_expansion", ret);

#if defined (MBEDTLS_DEBUG_C)
	mbedtls_free((mbedtls_ssl_config *)ssl -> conf);
	mbedtls_free(ssl);
#endif /* MBEDTLS_DEBUG_C */

	return ret;
}

/*************************************************************************************************
* Description:  nxp_hse_handshake_finished
************************************************************************************************/
static int nxp_hse_handshake_finished(mbedtls_md_type_t md_type, const unsigned char *secret,
		const char *label, const unsigned char *random, size_t rlen,
        unsigned char *dstbuf, size_t dlen)
{
	int ret = NO_ERROR;						/* Hold the return status of API */
	hseKeyHandle_t masterkeyhandle;		/* Hold the master keyhandle value */
	hseKdfTLS12PrfScheme_t tls12Prf;	/* Structure used by HSE for calculating key expansion */

#if defined (MBEDTLS_DEBUG_C)
	mbedtls_ssl_context *ssl;
    ssl = mbedtls_calloc(1,sizeof(mbedtls_ssl_context));
    ssl -> conf = mbedtls_calloc(1,sizeof(mbedtls_ssl_config));
    mbedtls_ssl_conf_dbg( (mbedtls_ssl_config *)(ssl -> conf) , nxp_hse_debug_prints, stdout );
#endif /* MBEDTLS_DEBUG_C */

	memset(&tls12Prf, 0x00, sizeof(hseKdfTLS12PrfScheme_t));

	switch(md_type)
	{
#if defined(S32N55)
		case MBEDTLS_MD_SHA1:      /**< The SHA-1 message digest. */
		{
#ifdef HSE_KDF_SHA_1
			tls12Prf.hmacHash = HSE_KDF_SHA_1;
			break;
#else
			return ( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE ) ;
#endif
		}
#endif
		case MBEDTLS_MD_SHA224:    /**< The SHA-224 message digest. */
		{
			tls12Prf.hmacHash = HSE_KDF_SHA2_224;
			break;
		}
		case MBEDTLS_MD_SHA256:    /**< The SHA-256 message digest. */
		{
			tls12Prf.hmacHash = HSE_KDF_SHA2_256;
			break;
		}
		case MBEDTLS_MD_SHA384:    /**< The SHA-384 message digest. */
		{
			tls12Prf.hmacHash = HSE_KDF_SHA2_384;
			break;
		}
		case MBEDTLS_MD_SHA512:    /**< The SHA-512 message digest. */
		{
			tls12Prf.hmacHash = HSE_KDF_SHA2_512;
			break;
		}
		default:
		{
			NXP_HSE_MBEDTLS_SSL_DEBUG_MSG(1, ("HASH algorithm 0x%02x not supported", md_type));
			ret = MBEDTLS_ERR_SSL_INVALID_MAC;
			goto exit;
		}
	}

	memcpy(&masterkeyhandle, secret, sizeof(hseKeyHandle_t));

	/* Use master secret key */
	tls12Prf.srcKeyHandle = masterkeyhandle;
	tls12Prf.seedLength = rlen;
	tls12Prf.pSeed = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(random));
	tls12Prf.labelLength = strlen(label);
	tls12Prf.pLabel = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(label));
	tls12Prf.outputLength = dlen;
	tls12Prf.pOutput = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(dstbuf));

	if(HSE_SRV_RSP_OK != HSE_Tls12Prf(&tls12Prf))
	{
		NXP_HSE_MBEDTLS_SSL_DEBUG_MSG(3, ("TLS PRF for %s fail", label));
		ret = MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
		goto exit;
	}
	else
	{
		NXP_HSE_MBEDTLS_SSL_DEBUG_MSG(3, ("TLS PRF for %s pass", label));
		MBEDTLS_SSL_DEBUG_BUF(4, "handshake_finished : ", dstbuf, dlen);
		ret = 0;
	}

exit:
	NXP_HSE_MBEDTLS_SSL_DEBUG_RET(3, "nxp_hse_handshake_finished", ret);

#if defined (MBEDTLS_DEBUG_C)
    mbedtls_free((mbedtls_ssl_config *)ssl -> conf);
    mbedtls_free(ssl);
#endif /* MBEDTLS_DEBUG_C */

	return ret;
}

/*************************************************************************************************
* Description:  Compute master secret
************************************************************************************************/
static int nxp_hse_compute_master_secret(mbedtls_md_type_t md_type, const unsigned char *secret,
		const char *label, const unsigned char *random, size_t rlen, unsigned char *dstbuf)
{
	int ret = NO_ERROR;							/* Hold the return status of API */
	key_import_param_t key_import_param;	/* Hold the return status of API */
	hseKdfTLS12PrfScheme_t tls12Prf;		/* Structure used by HSE for calculating master key */
	Tls_Prf_KeyHandle_T Keyhandles;			/* Buffer to hold the keyhandles */
	hseKeyHandle_t masterKeyHandle = INVALID_KEYHANDLE;	/* Hold the master keyhandle value */
	uint8_t keyMatLength = 48U;				/* The key material length (in bytes) */
	uint8_t keyExchangeType = MBEDTLS_KEY_EXCHANGE_NONE;

#if defined (MBEDTLS_DEBUG_C)
	mbedtls_ssl_context *ssl;
    ssl = mbedtls_calloc(1,sizeof(mbedtls_ssl_context));
    ssl -> conf = mbedtls_calloc(1,sizeof(mbedtls_ssl_config));
    mbedtls_ssl_conf_dbg( (mbedtls_ssl_config *)(ssl -> conf) , nxp_hse_debug_prints, stdout );
#endif /* MBEDTLS_DEBUG_C */

	memset(&key_import_param, 0x00, sizeof(key_import_param_t));
	memset(&tls12Prf, 0x00, sizeof(hseKdfTLS12PrfScheme_t));

	/* Get source key handle */
	memcpy(&Keyhandles.src_keyhandle, secret, sizeof(hseKeyHandle_t));

	/* Get psk key handle */
	memcpy(&Keyhandles.psk_keyhandle, secret+sizeof(hseKeyHandle_t), sizeof(hseKeyHandle_t));

	/* Get the Key Exchange Type */
	memcpy(&keyExchangeType, secret+(2*(sizeof(hseKeyHandle_t))), sizeof(uint8_t));

	/* Find and allocate master secret Key Slot */
	key_import_param.key_catalog = HSE_KEY_CATALOG_ID_RAM;
	key_import_param.key_type = HSE_KEY_TYPE_SHARED_SECRET;
	key_import_param.key_param.sym_key_param.size = BYTES_TO_BITS(keyMatLength);

	switch(md_type)
	{
#if !defined(S32N55)
		case MBEDTLS_MD_SHA1:      /**< The SHA-1 message digest. */
		{
#ifdef HSE_KDF_SHA_1
			tls12Prf.hmacHash = HSE_KDF_SHA_1;
			break;
#else
			return ( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE ) ;
#endif
		}
#endif
		case MBEDTLS_MD_SHA224:    /**< The SHA-224 message digest. */
		{
			tls12Prf.hmacHash = HSE_KDF_SHA2_224;
			break;
		}
		case MBEDTLS_MD_SHA256:    /**< The SHA-256 message digest. */
		{
			tls12Prf.hmacHash = HSE_KDF_SHA2_256;
			break;
		}
		case MBEDTLS_MD_SHA384:    /**< The SHA-384 message digest. */
		{
			tls12Prf.hmacHash = HSE_KDF_SHA2_384;
			break;
		}
		case MBEDTLS_MD_SHA512:    /**< The SHA-512 message digest. */
		{
			tls12Prf.hmacHash = HSE_KDF_SHA2_512;
			break;
		}
		default:
		{
			NXP_HSE_MBEDTLS_SSL_DEBUG_MSG(1, ("HASH algorithm 0x%02x not supported", md_type));
			ret = MBEDTLS_ERR_SSL_INVALID_MAC;
			goto exit;
		}
	}

	if(KEYMGMT_ERR_SUCCESS == KeystoreMgmt_FindAllocateSlot(&key_import_param, &masterKeyHandle))
	{
		/* Use pre-master secret key to generate master secret key*/
		tls12Prf.srcKeyHandle = Keyhandles.src_keyhandle;

		/* Check key exchange type and get PSK key handle if KEY_EXCHANGE_PSK_* */
		switch(keyExchangeType)
		{
		case MBEDTLS_KEY_EXCHANGE_PSK:
			tls12Prf.tlsPskUsage = HSE_TLS_KEY_EXCHANGE_PSK;
			tls12Prf.pskKeyHandle = Keyhandles.psk_keyhandle;
			break;

		case MBEDTLS_KEY_EXCHANGE_ECDHE_PSK:
			tls12Prf.tlsPskUsage = HSE_TLS_KEY_EXCHANGE_ECDHE_PSK;
			tls12Prf.pskKeyHandle = Keyhandles.psk_keyhandle;
			break;

#ifdef HSE_SPT_TLS12_RSA_PRE_MASTER_SECRET_GEN
		case MBEDTLS_KEY_EXCHANGE_RSA_PSK:
			tls12Prf.tlsPskUsage = HSE_TLS_KEY_EXCHANGE_RSA_PSK;
			tls12Prf.pskKeyHandle = Keyhandles.psk_keyhandle;
			break;
#endif /* HSE_SPT_TLS12_RSA_PRE_MASTER_SECRET_GEN */

#ifdef HSE_SPT_CLASSIC_DH
		case MBEDTLS_KEY_EXCHANGE_DHE_PSK:
			tls12Prf.tlsPskUsage = HSE_TLS_KEY_EXCHANGE_DHE_PSK;
			tls12Prf.pskKeyHandle = Keyhandles.psk_keyhandle;
			break;
#endif /* HSE_SPT_CLASSIC_DH */

		case MBEDTLS_KEY_EXCHANGE_NONE:
			tls12Prf.tlsPskUsage = HSE_TLS_PSK_NOT_USED;
			break;

		}

		tls12Prf.targetKeyHandle = masterKeyHandle;
		tls12Prf.keyMatLength = keyMatLength;
		tls12Prf.seedLength = rlen;
		tls12Prf.pSeed = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(random));
		tls12Prf.labelLength = strlen(label);
		tls12Prf.pLabel = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(label));

		if(HSE_SRV_RSP_OK != HSE_Tls12Prf(&tls12Prf))
		{
			NXP_HSE_MBEDTLS_SSL_DEBUG_MSG(1, ("TLS PRF for master key fail"));
			ret = MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
			goto exit;
		}
		else
		{
#if defined (MBEDTLS_DEBUG_C)
			mbedtls_printf("Shared Secret\r\n");
			//export_key(Keyhandles.src_keyhandle);
			mbedtls_printf("Master Secret\r\n");
			//export_key(masterKeyHandle);
#endif
			NXP_HSE_MBEDTLS_SSL_DEBUG_MSG(1, ("TLS PRF for master key pass"));
			memcpy(dstbuf, &(masterKeyHandle), sizeof(hseKeyHandle_t));
			ret = 0;
		}

		NXP_HSE_MBEDTLS_SSL_DEBUG_MSG(1, ("Master key allocated: %02x\n", masterKeyHandle));
	}
	else
	{
		ret = MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
		goto exit;
	}

exit:
	if((Keyhandles.src_keyhandle != INVALID_KEYHANDLE) && (Keyhandles.src_keyhandle != 0))
	{
		NXP_HSE_MBEDTLS_SSL_DEBUG_MSG(1, ("Pre-Master key to free: %02x\n", Keyhandles.src_keyhandle));
		(void)KeyStoreMgmt_FreeKey(Keyhandles.src_keyhandle);
	}
	Keyhandles.src_keyhandle = INVALID_KEYHANDLE;

	NXP_HSE_MBEDTLS_SSL_DEBUG_RET(1, "nxp_hse_compute_master_secret", ret);

#if defined (MBEDTLS_DEBUG_C)
    mbedtls_free((mbedtls_ssl_config *)ssl -> conf);
    mbedtls_free(ssl);
#endif /* MBEDTLS_DEBUG_C */
	return(ret);
}

#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)

/*************************************************************************************************
* Description:  This function loads RSA key-pair, returns public/private key-handle in ctx
************************************************************************************************/
static int nxp_hse_rsa_loadkey(mbedtls_rsa_context *ctx, int mode)
{
	int ret = NO_ERROR;
	KeymgmtErrCodeT err;
	uint32_t size_N, size_E, size_D;
	unsigned char *N = NULL, *E = NULL, *D = NULL;
	key_import_param_t key_import_param;

	/* Check for key already loaded */
	if(ctx->keyHandle != HSE_INVALID_KEY_HANDLE)
	{
		return( ret );
	}

	memset(&key_import_param, 0x00, sizeof(key_import_param_t));

	do
	{
		/* Allocate Memory Buffer for N & E */
		size_N = mbedtls_mpi_size(&ctx->N);

		if(size_N < BITS_TO_BYTES(HSE_KEY1024_BITS))
		{
			return ( MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION );
		}

		size_E = mbedtls_mpi_size(&ctx->E);

		N = (uint8_t*)mbedtls_calloc( 1, size_N);
		E = (uint8_t*)mbedtls_calloc( 1, size_E);
		if((N == NULL) || (E == NULL))
		{
			/* Return error */
			ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
			break;
		}

		/* Copy mpi structure to binary */
		mbedtls_mpi_write_binary(&ctx->N, N, size_N);
		mbedtls_mpi_write_binary(&ctx->E, E, size_E);

		/* Load the key based upon operation */
		if(mode == MBEDTLS_RSA_PUBLIC)
		{
			/* Load Public Key */
			key_import_param.key_type = HSE_KEY_TYPE_RSA_PUB;
			key_import_param.key_flag = (HSE_KF_USAGE_KEY_PROVISION | HSE_KF_USAGE_ENCRYPT);
			key_import_param.key_catalog = HSE_KEY_CATALOG_ID_NVM;
			key_import_param.key_param.rsa_pubkey_param.N = N;
			key_import_param.key_param.rsa_pubkey_param.E = E;
			key_import_param.key_param.rsa_pubkey_param.size_N = BYTES_TO_BITS(size_N);
			key_import_param.key_param.rsa_pubkey_param.size_E = size_E;
		}
		else if (mode == MBEDTLS_RSA_PRIVATE)
		{
			/* Allocate Memory Buffer for D */
			size_D = mbedtls_mpi_size(&ctx->D);

			D = (uint8_t*)mbedtls_calloc( 1, size_D);

			if (NULL == D)
			{
				/* Return error */
				ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
				break;
			}

			/* Copy mpi structure to binary */
			mbedtls_mpi_write_binary(&ctx->D, D, size_D);

			/* Load Key-pair Key */
			key_import_param.key_type = HSE_KEY_TYPE_RSA_PAIR;
			key_import_param.key_catalog = HSE_KEY_CATALOG_ID_NVM;
			key_import_param.key_param.rsa_keypair_param.N = N;
			key_import_param.key_param.rsa_keypair_param.E = E;
			key_import_param.key_param.rsa_keypair_param.D = D;
			key_import_param.key_param.rsa_keypair_param.N_len = BYTES_TO_BITS(size_N);
			key_import_param.key_param.rsa_keypair_param.E_len = size_E;

			ctx->privkey_flag = 1U;
		}

		err = KeystoreMgmt_FindImportSlot(&key_import_param, &ctx->keyHandle);
		if(err != KEYMGMT_ERR_SUCCESS)
		{
			ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
			if(mode == MBEDTLS_RSA_PRIVATE)
			{
				ctx->privkey_flag = 0U;
			}
			break;
		}
		else
		{
			ret = NO_ERROR;
		}
	} while(0);

	/* Free N, E and D Buffers */
	if (NULL != N)
	{
		mbedtls_platform_zeroize(N, size_N);
		mbedtls_free(N);
		N = NULL;
	}

	if (NULL != E)
	{
		mbedtls_free(E);
		E = NULL;
	}

	if (NULL != D)
	{
		mbedtls_platform_zeroize(D, size_D);
		mbedtls_free(D);
		D = NULL;
	}

	return (ret);
}
#endif /* MBEDTLS_KEY_EXCHANGE_RSA_ENABLED ||  MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED*/

/*==================================================================================================
*                                       GLOBAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
 * Description: Populate a transform structure with session keys and all the other necessary
 * 				information.
************************************************************************************************/

int nxp_hse_ssl_populate_transform( mbedtls_ssl_transform *transform,
                                   int ciphersuite,
                                   const unsigned char master[48],
#if defined(MBEDTLS_SSL_SOME_MODES_USE_MAC)
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
                                   int encrypt_then_mac,
#endif /* MBEDTLS_SSL_ENCRYPT_THEN_MAC */
#if defined(MBEDTLS_SSL_TRUNCATED_HMAC)
                                   int trunc_hmac,
#endif /* MBEDTLS_SSL_TRUNCATED_HMAC */
#endif /* MBEDTLS_SSL_SOME_MODES_USE_MAC */
                                   ssl_tls_prf_t tls_prf,
                                   const unsigned char randbytes[64],
                                   int minor_ver,
                                   unsigned endpoint,
#if !defined(MBEDTLS_SSL_HW_RECORD_ACCEL)
                                   const
#endif
                                   mbedtls_ssl_context *ssl )
{
    int ret = NO_ERROR; /* API status */
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    int psa_fallthrough;
#endif /* MBEDTLS_USE_PSA_CRYPTO */
    unsigned char keyblk[256]; 						/* In/Out buffer for prf function */
    TlsPRFKeys_t tlsprfKeyHandles; 					/* Hold the session keyHandles */
    size_t mac_key_len = 0;							/* Hold the MAC key len */
    size_t iv_copy_len = 0; 						/* Hold the value of IV to be used for Encryption and Decryption operations */
    hseKeyHandle_t enc_key = INVALID_KEYHANDLE; 	/* Reference variable */
    hseKeyHandle_t dec_key = INVALID_KEYHANDLE; 	/* Reference variable */
    hseKeyHandle_t mac_enc_key = INVALID_KEYHANDLE; /* Reference variable */
    hseKeyHandle_t mac_dec_key = INVALID_KEYHANDLE; /* Reference variable */
    unsigned keylen = 0; 							/* Hold the symmetric key len */
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info; /* Info about ciphersuite to be used for connection*/
    const mbedtls_cipher_info_t *cipher_info; 		/* Info about cipher to be used for encryption and decryption*/
    const mbedtls_md_info_t *md_info; 				/* Info about message digest to be used for encryption and decryption*/

#if !defined(MBEDTLS_DEBUG_C)
    ssl = NULL; /* make sure we don't use it except for those cases */
    (void) ssl;
#endif /* !defined(MBEDTLS_DEBUG_C) */

    /* Some data just needs copying into the structure */
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC) && \
    defined(MBEDTLS_SSL_SOME_MODES_USE_MAC)
    transform->encrypt_then_mac = encrypt_then_mac;
#endif
    transform->minor_ver = minor_ver;

#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION)
    memcpy( transform->randbytes, randbytes, sizeof( transform->randbytes ) );
#endif /* MBEDTLS_SSL_CONTEXT_SERIALIZATION */

    /* Get various info structures */
    ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( ciphersuite );
    if( ciphersuite_info == NULL )
    {
    	NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "ciphersuite info for %d not found", ciphersuite ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    cipher_info = mbedtls_cipher_info_from_type( ciphersuite_info->cipher );
    if( cipher_info == NULL )
    {
    	NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "cipher info for %d not found", ciphersuite_info->cipher ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    md_info = mbedtls_md_info_from_type( ciphersuite_info->mac );
    if( md_info == NULL )
    {
    	NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "mbedtls_md info for %d not found", ciphersuite_info->mac ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    /* Copy own and peer's CID if the use of the CID
     * extension has been negotiated. */
    if( ssl->handshake->cid_in_use == MBEDTLS_SSL_CID_ENABLED )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "Copy CIDs into SSL transform" ) );

        transform->in_cid_len = ssl->own_cid_len;
        memcpy( transform->in_cid, ssl->own_cid, ssl->own_cid_len );
        NXP_HSE_MBEDTLS_SSL_DEBUG_BUF( 3, "Incoming CID", transform->in_cid,
                               transform->in_cid_len );

        transform->out_cid_len = ssl->handshake->peer_cid_len;
        memcpy( transform->out_cid, ssl->handshake->peer_cid,
                ssl->handshake->peer_cid_len );
        NXP_HSE_MBEDTLS_SSL_DEBUG_BUF( 3, "Outgoing CID", transform->out_cid,
                               transform->out_cid_len );
    }
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

    /* Determine the appropriate key, IV and MAC length */
    keylen = (cipher_info->key_bitlen / 8U);

#if defined(MBEDTLS_GCM_C) || defined(MBEDTLS_CCM_C)
    if( (cipher_info->mode == MBEDTLS_MODE_GCM) || (cipher_info->mode == MBEDTLS_MODE_CCM) )
    {
        size_t explicit_ivlen;
        transform->maclen = 0;
        mac_key_len = 0;
        transform->taglen = (ciphersuite_info->flags & MBEDTLS_CIPHERSUITE_SHORT_TAG ? 8 : 16 );

        /* All modes haves 96-bit IVs, but the length of the static parts vary
         * with mode and version:
         * - For GCM and CCM in TLS 1.2, there's a static IV of 4 Bytes
         *   (to be concatenated with a dynamically chosen IV of 8 Bytes)
         * - all modes in TLS 1.3, there's a static IV of 12 Bytes
         * (to be XOR'ed with the 8 Byte record sequence number).
         */
        transform->ivlen = 12;
#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
        if( minor_ver == MBEDTLS_SSL_MINOR_VERSION_4 )
        {
            transform->fixed_ivlen = 12;
        }
        else
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
        {
           transform->fixed_ivlen = 4;
        }

        /* Minimum length of encrypted record */
        explicit_ivlen = transform->ivlen - transform->fixed_ivlen;
        transform->minlen = explicit_ivlen + transform->taglen;
    }
    else
#endif /* MBEDTLS_GCM_C || MBEDTLS_CCM_C */
#if defined(MBEDTLS_SSL_SOME_MODES_USE_MAC)
    if( cipher_info->mode == MBEDTLS_MODE_STREAM ||
        cipher_info->mode == MBEDTLS_MODE_CBC )
    {
        /* Initialize HMAC contexts */
        if( ( ret = mbedtls_md_setup( &transform->md_ctx_enc, md_info, 1 ) ) != 0 ||
            ( ret = mbedtls_md_setup( &transform->md_ctx_dec, md_info, 1 ) ) != 0 )
        {
            NXP_HSE_MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_md_setup", ret );
            goto end;
        }

        /* Get MAC length */
        mac_key_len = mbedtls_md_get_size( md_info );
        transform->maclen = mac_key_len;

#if defined(MBEDTLS_SSL_TRUNCATED_HMAC)
        /*
         * If HMAC is to be truncated, we shall keep the leftmost bytes,
         * (rfc 6066 page 13 or rfc 2104 section 4),
         * so we only need to adjust the length here.
         */
        if( trunc_hmac == MBEDTLS_SSL_TRUNC_HMAC_ENABLED )
        {
            transform->maclen = MBEDTLS_SSL_TRUNCATED_HMAC_LEN;

#if defined(MBEDTLS_SSL_TRUNCATED_HMAC_COMPAT)
            /* Fall back to old, non-compliant version of the truncated
             * HMAC implementation which also truncates the key
             * (Mbed TLS versions from 1.3 to 2.6.0) */
            mac_key_len = transform->maclen;
#endif
        }
#endif /* MBEDTLS_SSL_TRUNCATED_HMAC */

        /* IV length */
        transform->ivlen = cipher_info->iv_size;

        /* Minimum length */
        if( cipher_info->mode == MBEDTLS_MODE_STREAM )
        {
        	transform->minlen = transform->maclen;
        }
        else
        {
            /*
             * GenericBlockCipher:
             * 1. if EtM is in use: one block plus MAC
             *    otherwise: * first multiple of blocklen greater than maclen
             * 2. IV except for SSL3 and TLS 1.0
             */
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
            if( encrypt_then_mac == MBEDTLS_SSL_ETM_ENABLED )
            {
                transform->minlen = transform->maclen + cipher_info->block_size;
            }
            else
#endif /* MBEDTLS_SSL_ENCRYPT_THEN_MAC */
            {
                transform->minlen = transform->maclen
                                  + cipher_info->block_size
                                  - transform->maclen % cipher_info->block_size;
            }

#if defined(MBEDTLS_SSL_PROTO_SSL3) || defined(MBEDTLS_SSL_PROTO_TLS1)
            if( minor_ver == MBEDTLS_SSL_MINOR_VERSION_0 ||
                minor_ver == MBEDTLS_SSL_MINOR_VERSION_1 )
                ; /* No need to adjust minlen */
            else
#endif /* defined(MBEDTLS_SSL_PROTO_SSL3) || defined(MBEDTLS_SSL_PROTO_TLS1) */
#if defined(MBEDTLS_SSL_PROTO_TLS1_1) || defined(MBEDTLS_SSL_PROTO_TLS1_2)
            if( minor_ver == MBEDTLS_SSL_MINOR_VERSION_2 ||
                minor_ver == MBEDTLS_SSL_MINOR_VERSION_3 )
            {
                transform->minlen += transform->ivlen;
            }
            else
#endif /* defined(MBEDTLS_SSL_PROTO_TLS1_1) || defined(MBEDTLS_SSL_PROTO_TLS1_2) */
            {
            	NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
                ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
                goto end;
            }
        }
    }
    else
#endif /* MBEDTLS_SSL_SOME_MODES_USE_MAC */
    {
    	NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "keylen: %u, minlen: %u, ivlen: %u, maclen: %u",
                                (unsigned) keylen,
                                (unsigned) transform->minlen,
                                (unsigned) transform->ivlen,
                                (unsigned) transform->maclen ) );

    /* Copying metadata for PRF */
    memcpy(keyblk + (sizeof(uint32_t) * 0), &transform->ivlen, sizeof(uint32_t));
    memcpy(keyblk + (sizeof(uint32_t) * 1), &keylen, sizeof(uint32_t));
    memcpy(keyblk + (sizeof(uint32_t) * 2), &mac_key_len, sizeof(uint32_t));

    /* Compute key block using the PRF */
    ret = tls_prf( master, 48, "key expansion", randbytes, 64, keyblk, 256);
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "prf", ret );
        return( ret );
    }

    NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 3, ( "ciphersuite = %s", mbedtls_ssl_get_ciphersuite_name( ciphersuite ) ) );
    NXP_HSE_MBEDTLS_SSL_DEBUG_BUF( 3, "master secret", master, 48 );
    NXP_HSE_MBEDTLS_SSL_DEBUG_BUF( 4, "random bytes", randbytes, 64 );
    NXP_HSE_MBEDTLS_SSL_DEBUG_BUF( 4, "key block", keyblk, 256 );

    /* Finally setup the cipher contexts, IVs and MAC secrets */
    iv_copy_len = ( transform->fixed_ivlen ) ?
                          transform->fixed_ivlen : transform->ivlen;
#if defined(MBEDTLS_SSL_CLI_C)
    if( endpoint == MBEDTLS_SSL_IS_CLIENT )
    {

    	memcpy(&tlsprfKeyHandles, keyblk, sizeof(TlsPRFKeys_t));
    	enc_key = tlsprfKeyHandles.client_write_key;
    	dec_key = tlsprfKeyHandles.server_write_key;
    	mac_enc_key = tlsprfKeyHandles.client_write_MAC_key;
    	mac_dec_key = tlsprfKeyHandles.server_write_MAC_key;
    	/* This is not used in TLS v1.1 */
        memcpy( transform->iv_enc, keyblk + sizeof(TlsPRFKeys_t),  iv_copy_len);
        memcpy( transform->iv_dec, (keyblk + sizeof(TlsPRFKeys_t) + iv_copy_len),
        		iv_copy_len );
    }
    else
#endif /* MBEDTLS_SSL_CLI_C */
#if defined(MBEDTLS_SSL_SRV_C)
    if( endpoint == MBEDTLS_SSL_IS_SERVER )
    {
    	memcpy(&tlsprfKeyHandles, keyblk, sizeof(TlsPRFKeys_t));

    	enc_key = tlsprfKeyHandles.server_write_key;
    	dec_key = tlsprfKeyHandles.client_write_key;
    	mac_enc_key = tlsprfKeyHandles.server_write_MAC_key;
    	mac_dec_key = tlsprfKeyHandles.client_write_MAC_key;
    	/* This is not used in TLS v1.1 */
        memcpy( transform->iv_dec, keyblk + sizeof(TlsPRFKeys_t),  iv_copy_len );
        memcpy( transform->iv_enc, (keyblk + sizeof(TlsPRFKeys_t) + iv_copy_len),
        		iv_copy_len );
    }
    else
#endif /* MBEDTLS_SSL_SRV_C */
    {
    	NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        goto end;
    }

#if defined(MBEDTLS_SSL_SOME_MODES_USE_MAC)
#if defined(MBEDTLS_SSL_PROTO_SSL3)
    if( minor_ver == MBEDTLS_SSL_MINOR_VERSION_0 )
    {
        if( mac_key_len > sizeof( transform->mac_enc ) )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
            goto end;
        }

        memcpy( transform->mac_enc, mac_enc, mac_key_len );
        memcpy( transform->mac_dec, mac_dec, mac_key_len );
    }
    else
#endif /* MBEDTLS_SSL_PROTO_SSL3 */
#if defined(MBEDTLS_SSL_PROTO_TLS1) || defined(MBEDTLS_SSL_PROTO_TLS1_1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if( minor_ver >= MBEDTLS_SSL_MINOR_VERSION_1 )
    {
        /* For HMAC-based ciphersuites, initialize the HMAC transforms.
           For AEAD-based ciphersuites, there is nothing to do here. */
        if( mac_key_len != 0 )
        {
			 mbedtls_md_hmac_starts( &transform->md_ctx_enc, (const unsigned char *)(&mac_enc_key), (mac_key_len) | KEYLOADED_FLAG);
			 mbedtls_md_hmac_starts( &transform->md_ctx_dec, (const unsigned char *)(&mac_dec_key), (mac_key_len) | KEYLOADED_FLAG );
        }
    }
    else
#endif
    {
    	NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        goto end;
    }
#endif /* MBEDTLS_SSL_SOME_MODES_USE_MAC */

#if defined(MBEDTLS_USE_PSA_CRYPTO)

    /* Only use PSA-based ciphers for TLS-1.2.
     * That's relevant at least for TLS-1.0, where
     * we assume that mbedtls_cipher_crypt() updates
     * the structure field for the IV, which the PSA-based
     * implementation currently doesn't. */
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_3 )
    {
        ret = mbedtls_cipher_setup_psa( &transform->cipher_ctx_enc,
                                        cipher_info, transform->taglen );
        if( ret != 0 && ret != MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_setup_psa", ret );
            goto end;
        }

        if( ret == 0 )
        {
            NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 3, ( "Successfully setup PSA-based encryption cipher context" ) );
            psa_fallthrough = 0;
        }
        else
        {
            NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "Failed to setup PSA-based cipher context for record encryption - fall through to default setup." ) );
            psa_fallthrough = 1;
        }
    }
    else
        psa_fallthrough = 1;
#else
    psa_fallthrough = 1;
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

    if( psa_fallthrough == 1 )
#endif /* MBEDTLS_USE_PSA_CRYPTO */
    if( ( ret = mbedtls_cipher_setup( &transform->cipher_ctx_enc,
                                 cipher_info ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_setup", ret );
        goto end;
    }

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    /* Only use PSA-based ciphers for TLS-1.2.
     * That's relevant at least for TLS-1.0, where
     * we assume that mbedtls_cipher_crypt() updates
     * the structure field for the IV, which the PSA-based
     * implementation currently doesn't. */
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_3 )
    {
        ret = mbedtls_cipher_setup_psa( &transform->cipher_ctx_dec,
                                        cipher_info, transform->taglen );
        if( ret != 0 && ret != MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_setup_psa", ret );
            goto end;
        }

        if( ret == 0 )
        {
            NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 3, ( "Successfully setup PSA-based decryption cipher context" ) );
            psa_fallthrough = 0;
        }
        else
        {
            NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "Failed to setup PSA-based cipher context for record decryption - fall through to default setup." ) );
            psa_fallthrough = 1;
        }
    }
    else
        psa_fallthrough = 1;
#else
    psa_fallthrough = 1;
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

    if( psa_fallthrough == 1 )
#endif /* MBEDTLS_USE_PSA_CRYPTO */
    if( ( ret = mbedtls_cipher_setup( &transform->cipher_ctx_dec,
                                 cipher_info ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_setup", ret );
        goto end;
    }

	if( ( ret = mbedtls_cipher_setkey( &transform->cipher_ctx_enc, (const unsigned char *)(&enc_key),
									   cipher_info->key_bitlen|KEYLOADED_FLAG,
									   MBEDTLS_ENCRYPT ) ) != 0 )
	{
		MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_setkey", ret );
		goto end;
	}

	if( ( ret = mbedtls_cipher_setkey( &transform->cipher_ctx_dec, (const unsigned char *)(&dec_key),
							   cipher_info->key_bitlen|KEYLOADED_FLAG,
							   MBEDTLS_DECRYPT ) ) != 0 )
	{
		MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_setkey", ret );
		goto end;
	}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
    if( cipher_info->mode == MBEDTLS_MODE_CBC )
    {
        if( ( ret = mbedtls_cipher_set_padding_mode( &transform->cipher_ctx_enc,
                                             MBEDTLS_PADDING_NONE ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_set_padding_mode", ret );
            goto end;
        }

        if( ( ret = mbedtls_cipher_set_padding_mode( &transform->cipher_ctx_dec,
                                             MBEDTLS_PADDING_NONE ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_set_padding_mode", ret );
            goto end;
        }
    }
#endif /* MBEDTLS_CIPHER_MODE_CBC */

end:
    mbedtls_platform_zeroize( keyblk, sizeof( keyblk ) );
    return( ret );
}

/*************************************************************************************************
 * Description: Compute the keyhandle using key material
************************************************************************************************/
int nxp_hse_tls_prf_generic( mbedtls_md_type_t md_type,
                            const unsigned char *secret, size_t slen,
                            const char *label,
                            const unsigned char *random, size_t rlen,
                            unsigned char *dstbuf, size_t dlen )
{
	(void)slen;

	if(0U == (strncmp(label, "master secret", strlen(label))))
	{
		return (nxp_hse_compute_master_secret(md_type, secret, label, random, rlen, dstbuf));
	}
#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
	else if(0 == (strncmp(label, "extended master secret", strlen(label))))
	{
		return (nxp_hse_compute_master_secret(md_type, secret, label, random, rlen, dstbuf));
	}
#endif
	else if(0U == (strncmp(label, "key expansion", strlen(label))))
	{
		return (nxp_hse_compute_key_expansion(md_type, secret, label, random, rlen, dstbuf, dlen));
	}
	else if((0U == (strncmp(label, "client finished", strlen(label)))) ||
			(0U == (strncmp(label, "server finished", strlen(label)))))
	{
		return (nxp_hse_handshake_finished(md_type, secret, label, random, rlen, dstbuf, dlen));
	}

	return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
}

/*************************************************************************************************
 * Description: Compute the psk and premaster keyhandle using key material
************************************************************************************************/
int nxp_hse_mbedtls_ssl_psk_derive_premaster( mbedtls_ssl_context *ssl, mbedtls_key_exchange_type_t key_ex )
{
    unsigned char *p = ssl->handshake->premaster;
    size_t psk_len = 0;
    Tls_Prf_KeyHandle_T KeyHandles;
    const uint8_t *psk_keyhandle;

#if defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
	unsigned char *end = p + sizeof( ssl->handshake->premaster );
#endif /* MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED */

	/* Initialize key handles with invalid value */
    memset(&KeyHandles, 0xFF, sizeof(Tls_Prf_KeyHandle_T));

    /* Get PSK */
    if( mbedtls_ssl_get_psk( ssl, &(psk_keyhandle), &psk_len ) == MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED )
    {
        /*
         * This should never happen because the existence of a PSK is always
         * checked before calling this function
         */
        NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /*
     * PMS = struct {
     *     opaque other_secret<0..2^16-1>;
     *     opaque psk<0..2^16-1>;
     * };
     * with "other_secret" depending on the particular key exchange
     */
#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
    if( key_ex == MBEDTLS_KEY_EXCHANGE_PSK )
    {
    	memcpy(&KeyHandles.psk_keyhandle, psk_keyhandle, sizeof(hseKeyHandle_t));
    }
    else
#endif /* MBEDTLS_KEY_EXCHANGE_PSK_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
    if( key_ex == MBEDTLS_KEY_EXCHANGE_RSA_PSK )
    {
        /*
         * other_secret already set by the ClientKeyExchange message,
         * and is 48 bytes long
         */
        if( end - p < 2 )
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

         /* Get PMS key Handle */
        memcpy(&KeyHandles.src_keyhandle, p+2, sizeof(hseKeyHandle_t));

        /* Get PSK Key handle */
        memcpy(&KeyHandles.psk_keyhandle, psk_keyhandle, sizeof(hseKeyHandle_t));
    }
    else
#endif /* MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
    if( key_ex == MBEDTLS_KEY_EXCHANGE_DHE_PSK )
    {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        size_t len;

        /* Write length only when we know the actual value */
        if( ( ret = mbedtls_dhm_calc_secret( &ssl->handshake->dhm_ctx,
                                      p + 2, end - ( p + 2 ), &len,
                                      ssl->conf->f_rng, ssl->conf->p_rng ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_dhm_calc_secret", ret );
            return( ret );
        }

        MBEDTLS_SSL_DEBUG_MPI( 3, "DHM: K ", &ssl->handshake->dhm_ctx.K  );

        /* Get DH secret key Handle */
       memcpy(&KeyHandles.src_keyhandle, p+2, sizeof(hseKeyHandle_t));

       /* Get PSK Key handle */
       memcpy(&KeyHandles.psk_keyhandle, psk_keyhandle, sizeof(hseKeyHandle_t));
    }
    else
#endif /* MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
    if( key_ex == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK )
    {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        size_t zlen;

        if( ( ret = mbedtls_ecdh_calc_secret( &ssl->handshake->ecdh_ctx, &zlen,
                                       (unsigned char *)(&KeyHandles.src_keyhandle), sizeof(hseKeyHandle_t),
                                       ssl->conf->f_rng, ssl->conf->p_rng ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ecdh_calc_secret", ret );
            return( ret );
        }

        memcpy(&KeyHandles.psk_keyhandle, psk_keyhandle, sizeof(hseKeyHandle_t));
        NXP_HSE_MBEDTLS_SSL_DEBUG_ECDH( 3, &ssl->handshake->ecdh_ctx,
                                MBEDTLS_DEBUG_ECDH_Z );
    }
    else
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED */
    {
        NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Get Pre-master secret and PSK key handles */
    memcpy(p, &KeyHandles, sizeof(Tls_Prf_KeyHandle_T));

    /* Set Pre-master secret and PSK key handles len */
    ssl->handshake->pmslen = sizeof(Tls_Prf_KeyHandle_T);

	return(NO_ERROR);
}

/*************************************************************************************************
 * Description: Compute HMAC of variable-length data with constant flow
************************************************************************************************/
int nxp_hse_mbedtls_ssl_cf_hmac(
        mbedtls_md_context_t *ctx,
        const unsigned char *add_data, size_t add_data_len,
        const unsigned char *data, size_t data_len_secret,
        unsigned char *output)
{
#if defined (MBEDTLS_DEBUG_C)
	mbedtls_ssl_context *ssl;
    ssl = mbedtls_calloc(1,sizeof(mbedtls_ssl_context));
    ssl -> conf = mbedtls_calloc(1,sizeof(mbedtls_ssl_config));
    mbedtls_ssl_conf_dbg( (mbedtls_ssl_config *)(ssl -> conf) , nxp_hse_debug_prints, stdout );
    NXP_HSE_MBEDTLS_SSL_DEBUG_BUF( 4, "add_data", add_data, add_data_len );
    NXP_HSE_MBEDTLS_SSL_DEBUG_BUF( 4, "Input data", data, data_len_secret );
    mbedtls_free((mbedtls_ssl_config *)ssl -> conf);
    mbedtls_free(ssl);
#endif /* MBEDTLS_DEBUG_C */
    mbedtls_md_hmac_update( ctx, add_data, add_data_len );

    mbedtls_md_hmac_update( ctx, data, data_len_secret );

    mbedtls_md_hmac_finish( ctx, output );

    mbedtls_md_hmac_reset( ctx );

	return (NO_ERROR);
}

/*************************************************************************************************
 * Description: Import PSK to the HSE and return PSK key handle
************************************************************************************************/
int nxp_hse_load_psk(unsigned char *psk, size_t psk_len)
{
	key_import_param_t key_import_param;
    hseKeyHandle_t psk_keyhandle = INVALID_KEYHANDLE;

    /* Check if length of PSK is valid */
	switch(BYTES_TO_BITS(psk_len))
	{
		case HSE_KEY128_BITS:
		case HSE_KEY192_BITS:
		case HSE_KEY256_BITS:
			break;
		default :
			return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
	}

	memset(&key_import_param, 0x00, sizeof(key_import_param_t));

	 /* Find and allocate PSK Key Slot */
    key_import_param.key_catalog = HSE_KEY_CATALOG_ID_NVM;
    key_import_param.key_type = HSE_KEY_TYPE_AES;
    key_import_param.key_param.sym_key_param.key = psk;
    key_import_param.key_param.sym_key_param.size = BYTES_TO_BITS(psk_len);

	if(KEYMGMT_ERR_SUCCESS != (KeystoreMgmt_FindAllocateSlot(&key_import_param, &psk_keyhandle)))
	{
		return (KEYMGMT_ERR_SLOT_NOT_FOUND);
	}

	/* Import PSK Key to Key Slot */
	if(HSE_SRV_RSP_OK != (HSE_ImportSymKey(psk_keyhandle,
		key_import_param.key_type,
		(HSE_KF_USAGE_DERIVE|HSE_KF_USAGE_ENCRYPT|HSE_KF_USAGE_DECRYPT|HSE_KF_USAGE_SIGN|HSE_KF_USAGE_VERIFY),
		key_import_param.key_param.sym_key_param.key,
		BITS_TO_BYTES(key_import_param.key_param.sym_key_param.size))))
		{
			return (KEYMGMT_ERR_KEY_IMPORT_FAILED);
		}

	/* Zeroize the PSK key */
	mbedtls_platform_zeroize(psk, psk_len);

	/* Copy PSK key handle */
	memcpy(psk, &psk_keyhandle, sizeof(hseKeyHandle_t));

	return (NO_ERROR);
}

/*************************************************************************************************
 * Description: Fetch the keyhandle from cipher context
************************************************************************************************/
hseKeyHandle_t nxp_hse_cipher_get_keyhandle(mbedtls_cipher_context_t *ctx)
{
	if (NULL!=ctx->cipher_info && NULL!=ctx->cipher_info->type )
{

	switch(ctx->cipher_info->type)
	{
		case MBEDTLS_CIPHER_AES_128_ECB:          /**< AES cipher with 128-bit ECB mode. */
		case MBEDTLS_CIPHER_AES_192_ECB:          /**< AES cipher with 192-bit ECB mode. */
		case MBEDTLS_CIPHER_AES_256_ECB:		  /**< AES cipher with 256-bit ECB mode. */
		{
			hseKeyHandle_t keyhandle = ((mbedtls_aes_context *)ctx->cipher_ctx)->aesKeyHandle;
			return(keyhandle);
		}
		break;

		case MBEDTLS_CIPHER_AES_128_GCM:          /**< AES cipher with 128-bit GCM mode. */
		case MBEDTLS_CIPHER_AES_192_GCM:		  /**< AES cipher with 192-bit GCM mode. */
		case MBEDTLS_CIPHER_AES_256_GCM:		  /**< AES cipher with 256-bit GCM mode. */
		{
			return (nxp_hse_cipher_get_keyhandle(&(((mbedtls_gcm_context *)(ctx->cipher_ctx))->cipher_ctx)));
		}
		break;

		case MBEDTLS_CIPHER_AES_128_CBC:          /**< AES cipher with 128-bit CBC mode. */
		case MBEDTLS_CIPHER_AES_192_CBC:          /**< AES cipher with 192-bit CBC mode. */
		case MBEDTLS_CIPHER_AES_256_CBC:          /**< AES cipher with 256-bit CBC mode. */
		{
			return (((mbedtls_aes_context *)(ctx->cipher_ctx))->aesKeyHandle);
		}
		break;

		case MBEDTLS_CIPHER_AES_128_CCM:          /**< AES cipher with 128-bit CCM mode. */
		case MBEDTLS_CIPHER_AES_192_CCM:          /**< AES cipher with 192-bit CCM mode. */
		case MBEDTLS_CIPHER_AES_256_CCM:          /**< AES cipher with 256-bit CCM mode. */
		{
			return (nxp_hse_cipher_get_keyhandle(&(((mbedtls_ccm_context *)(ctx->cipher_ctx))->cipher_ctx)));
		}
		break;

		default:
			break;
	}
}

	return INVALID_KEYHANDLE;
}

/*************************************************************************************************
 * Description: Fetch the keyhandle from message-digest context
************************************************************************************************/
hseKeyHandle_t nxp_hse_hmac_get_keyhandle( mbedtls_md_context_t *ctx )
{
	if (NULL!=ctx->md_info && NULL!=ctx->md_info->type )
{
	switch(ctx->md_info->type)
	{
		//case MBEDTLS_MD_SHA1:      /**< The SHA-1 message digest. */
		case MBEDTLS_MD_SHA256:    /**< The SHA-256 message digest. */
		case MBEDTLS_MD_SHA384:    /**< The SHA-384 message digest. */
		{
			hseKeyHandle_t keyhandle = (((mbedtls_hmac_context *)(ctx->hmac_ctx))->hmackeyhandle);
			return (keyhandle);
		}
		break;

		default:
			break;
	}
}
	return INVALID_KEYHANDLE;
}

/*************************************************************************************************
 * Description: Set the keyhandle to INVALID_KEYHANDLE in cipher context
************************************************************************************************/
void nxp_hse_cipher_set_keyhandle(mbedtls_cipher_context_t *ctx)
{
	if (NULL!=ctx->cipher_info && NULL!=ctx->cipher_info->type )
{
	switch(ctx->cipher_info->type)
	{
		case MBEDTLS_CIPHER_AES_128_ECB:          /**< AES cipher with 128-bit ECB mode. */
		case MBEDTLS_CIPHER_AES_192_ECB:          /**< AES cipher with 192-bit ECB mode. */
		case MBEDTLS_CIPHER_AES_256_ECB:		  /**< AES cipher with 256-bit ECB mode. */
		{
			((mbedtls_aes_context *)ctx->cipher_ctx)->aesKeyHandle = INVALID_KEYHANDLE;
		}
		break;

		case MBEDTLS_CIPHER_AES_128_GCM:          /**< AES cipher with 128-bit GCM mode. */
		case MBEDTLS_CIPHER_AES_192_GCM:		  /**< AES cipher with 192-bit GCM mode. */
		case MBEDTLS_CIPHER_AES_256_GCM:		  /**< AES cipher with 256-bit GCM mode. */
		{
			nxp_hse_cipher_set_keyhandle(&(((mbedtls_gcm_context *)(ctx->cipher_ctx))->cipher_ctx));
		}
		break;

		case MBEDTLS_CIPHER_AES_128_CBC:          /**< AES cipher with 128-bit CBC mode. */
		case MBEDTLS_CIPHER_AES_192_CBC:          /**< AES cipher with 192-bit CBC mode. */
		case MBEDTLS_CIPHER_AES_256_CBC:          /**< AES cipher with 256-bit CBC mode. */
		{
			((mbedtls_aes_context *)(ctx->cipher_ctx))->aesKeyHandle = INVALID_KEYHANDLE;
		}
		break;

		case MBEDTLS_CIPHER_AES_128_CCM:          /**< AES cipher with 128-bit CCM mode. */
		case MBEDTLS_CIPHER_AES_192_CCM:          /**< AES cipher with 192-bit CCM mode. */
		case MBEDTLS_CIPHER_AES_256_CCM:          /**< AES cipher with 256-bit CCM mode. */
		{
			nxp_hse_cipher_set_keyhandle(&(((mbedtls_ccm_context *)(ctx->cipher_ctx))->cipher_ctx));
		}
		break;

		default:
			break;
	}
}
	return;
}

/*************************************************************************************************
 * Description: Set the keyhandle to INVALID_KEYHANDLE in message-digest context
************************************************************************************************/
void nxp_hse_hmac_set_keyhandle( mbedtls_md_context_t *ctx )
{
	if (NULL!=ctx->md_info && NULL!=ctx->md_info->type)
{
	switch(ctx->md_info->type)
	{
		//case MBEDTLS_MD_SHA1:      /**< The SHA-1 message digest. */
		case MBEDTLS_MD_SHA256:    /**< The SHA-256 message digest. */
		case MBEDTLS_MD_SHA384:    /**< The SHA-384 message digest. */
		{
			((mbedtls_hmac_context *)(ctx->hmac_ctx))->hmackeyhandle = INVALID_KEYHANDLE;
		}
		break;

		default:
			break;
	}
}
	return;
}

/*************************************************************************************************
 * Description: Free the keyhandle form HSE
************************************************************************************************/
void nxp_hse_FreeKeys(const hseKeyHandle_t key1, const hseKeyHandle_t key2)
{
	nxp_hse_FreeKeyhandle((const uint8_t*)&key1);
	nxp_hse_FreeKeyhandle((const uint8_t*)&key2);
	return;
}

/*************************************************************************************************
 * Description: Free the keyhandle form HSE
************************************************************************************************/
void nxp_hse_FreeKeyhandle(const uint8_t* pKeyhandle)
{
	if(NULL == pKeyhandle)
	{
		return;
	}

	hseKeyHandle_t keyHandle = INVALID_KEYHANDLE;

	memcpy(&keyHandle, pKeyhandle, sizeof(hseKeyHandle_t));

    if((0U != keyHandle) && (HSE_INVALID_KEY_HANDLE != keyHandle))
    {
#if defined (MBEDTLS_DEBUG_C)
    	mbedtls_printf("\nFree: %s:%d:Keyhandle : 0x%02x\n", __FILE__, __LINE__, keyHandle);
#endif
    	(void)KeyStoreMgmt_FreeKey(keyHandle);
    }
}

#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)

/*************************************************************************************************
 * Description: Generate a pre-master secret and encrypt it with the peer public key
************************************************************************************************/
int nxp_hse_ssl_write_encrypted_pms(mbedtls_ssl_context *ssl,
        size_t offset, size_t *olen, size_t pms_offset )
{
	int ret = NO_ERROR;
	uint32_t pmsLen = 0U, encPmsLen = 0U;
    hseKeyHandle_t pmsKeyHandle = HSE_INVALID_KEY_HANDLE;
	mbedtls_pk_context * peer_pk;
	key_import_param_t key_import_param = {0};
	key_gen_param_t key_gen_param = {0};
	cipher_t cipherParam = {0};

	size_t len_bytes = ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_0 ? 0 : 2;
	unsigned char *p = ssl->handshake->premaster + pms_offset;

    if( offset + len_bytes > MBEDTLS_SSL_OUT_CONTENT_LEN )
    {
    	NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small for encrypted pms" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    /*
     * Generate (part of) the pre-master as
     *  struct {
     *      ProtocolVersion client_version;
     *      opaque random[46];
     *  } PreMasterSecret;
     */
    mbedtls_ssl_write_version( ssl->conf->max_major_ver,
                               ssl->conf->max_minor_ver,
                               ssl->conf->transport,
							   key_gen_param.key_param.shared_sec_gen_param.pms_param.rsa_pms_gen_param.protocolVersion);

	/* Set PMS length */
	pmsLen = 48U;

	/* Allocate key slot for RSA Pre-Master secret */
    key_import_param.key_type 						= HSE_KEY_TYPE_SHARED_SECRET;
    key_import_param.key_catalog 					= HSE_KEY_CATALOG_ID_RAM;
    key_import_param.key_param.sym_key_param.size 	= BYTES_TO_BITS(pmsLen);

    if(KEYMGMT_ERR_SUCCESS != (KeystoreMgmt_FindAllocateSlot(&key_import_param, &pmsKeyHandle)))
    {
    	NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "RSA Pre-Master secret key slot allocation failed" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    key_gen_param.key_type 		= key_import_param.key_type;
    key_gen_param.key_catalog 	= key_import_param.key_catalog;
    /* Size of PMS in bits */
	key_gen_param.key_param.shared_sec_gen_param.keybitlen 			= BYTES_TO_BITS(pmsLen);
	key_gen_param.key_param.shared_sec_gen_param.shared_sec_type 	= KEYMGMT_SHARED_SEC_KEY_GEN_TYPE_RSA_PMS;

    /*
     * Generate the pre-master secret
     */
    if(KEYMGMT_ERR_SUCCESS != (KeystoreMgmt_Genkey(pmsKeyHandle, &key_gen_param)))
    {
    	NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "RSA Pre-Master secret generation failed" ) );
    	return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    NXP_HSE_MBEDTLS_SSL_DEBUG_MSG(1, ("Pre-Master Secret generated"));

#if !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    peer_pk = &ssl->handshake->peer_pubkey;
#else /* !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
    if( ssl->session_negotiate->peer_cert == NULL )
    {
        /* Should never happen */
    	NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }
    peer_pk = &ssl->session_negotiate->peer_cert->pk;
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */

    if( ! mbedtls_pk_can_do( peer_pk, MBEDTLS_PK_RSA ) )
    {
    	NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "certificate key type mismatch" ) );
        return( MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH );
    }

    mbedtls_rsa_context * rsa_ctx = (mbedtls_rsa_context *) peer_pk->pk_ctx;

    encPmsLen = pmsLen;

    /* Import Peer Public key and get key handle */
    if(ret != nxp_hse_rsa_loadkey(rsa_ctx, MBEDTLS_RSA_PUBLIC))
    {
    	NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "RSA Peer public key import failed" ) );
    	return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Get peer public key handle */
    cipherParam.cipherKeyHandle = rsa_ctx->keyHandle;

    /* Set the RSA cipher scheme */
    if(rsa_ctx->padding == MBEDTLS_RSA_PKCS_V15)
    {
    	cipherParam.cipherScheme.rsaCipher.rsaAlgo = HSE_RSA_ALGO_RSAES_PKCS1_V15;
    }
    else if(rsa_ctx->padding == MBEDTLS_RSA_PKCS_V21)
    {
    	cipherParam.cipherScheme.rsaCipher.rsaAlgo = HSE_RSA_ALGO_RSAES_OAEP;

    	/* Choose HSE Supported HASH Algorithm */
    	switch(	rsa_ctx->hash_id )
    	{
#if !defined(S32N55)
    		case MBEDTLS_MD_SHA1:
    			cipherParam.cipherScheme.rsaCipher.sch.rsaOAEP.hashAlgo = HSE_HASH_ALGO_SHA_1;
    			break ;
#endif
    		case MBEDTLS_MD_SHA224:
    			cipherParam.cipherScheme.rsaCipher.sch.rsaOAEP.hashAlgo = HSE_HASH_ALGO_SHA2_224;
    			break ;
    		case MBEDTLS_MD_SHA256:
    			cipherParam.cipherScheme.rsaCipher.sch.rsaOAEP.hashAlgo = HSE_HASH_ALGO_SHA2_256;
    			break ;
    		case MBEDTLS_MD_SHA384:
    			cipherParam.cipherScheme.rsaCipher.sch.rsaOAEP.hashAlgo = HSE_HASH_ALGO_SHA2_384;
    			break ;
    		case MBEDTLS_MD_SHA512:
    			cipherParam.cipherScheme.rsaCipher.sch.rsaOAEP.hashAlgo = HSE_HASH_ALGO_SHA2_512;
    			break ;
    		case MBEDTLS_MD_MD5:
    		case MBEDTLS_MD_MD2:
    		case MBEDTLS_MD_MD4:
    		case MBEDTLS_MD_RIPEMD160:
    			return ( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
    		default:
    			return ( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    	}
    }

    /* Send request to HSE for the Encryption of PMS and export Encrypted PMS*/
    if( HSE_SRV_RSP_OK != (HSE_EncryptPms(pmsKeyHandle, &cipherParam, ssl->out_msg + offset + len_bytes, &encPmsLen )))
    {
    	NXP_HSE_MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_rsa_pkcs1_encrypt", -1 );
    	return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

	/* Copy PMS key handle */
	memcpy(p, &pmsKeyHandle, sizeof(hseKeyHandle_t));

	/* Set PMS length */
	ssl->handshake->pmslen = pmsLen;

	/* Set Encrypted PMS length */
    *olen = encPmsLen;

    NXP_HSE_MBEDTLS_SSL_DEBUG_BUF(4, "encrypted pms secret", ssl->out_msg + offset + len_bytes, *olen);

#if defined(MBEDTLS_SSL_PROTO_TLS1) || defined(MBEDTLS_SSL_PROTO_TLS1_1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if( len_bytes == 2 )
    {
        ssl->out_msg[offset+0] = (unsigned char)( *olen >> 8 );
        ssl->out_msg[offset+1] = (unsigned char)( *olen      );
        *olen += 2;
    }
#endif

#if !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    /* We don't need the peer's public key anymore. Free it. */
    mbedtls_pk_free( peer_pk );
#endif /* !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */

    (void)KeyStoreMgmt_FreeKey(rsa_ctx->keyHandle);
    rsa_ctx->keyHandle = HSE_INVALID_KEY_HANDLE;
    return ret;
}

/*************************************************************************************************
 * Description: Decrypt encrypted pre-master secret
************************************************************************************************/
int nxp_hse_ssl_decrypt_encrypted_pms(	mbedtls_ssl_context *ssl,
        								const unsigned char *p,
										const unsigned char *end,
										unsigned char *peer_pms,
										size_t *peer_pmslen,
										size_t peer_pmssize)
{
    hseKeyHandle_t pmsKeyHandle = HSE_INVALID_KEY_HANDLE, authKeyHandle = HSE_INVALID_KEY_HANDLE;
    int ret = -1;
	key_import_param_t key_import_param = {0};
	hseKeyInfo_t KeyInfo = {0};
	cipher_t cipherParam = {0};
	mbedtls_pk_context *private_key = mbedtls_ssl_own_key( ssl );
    mbedtls_pk_context *public_key = &mbedtls_ssl_own_cert( ssl )->pk;
    size_t len = mbedtls_pk_get_len( public_key );
    uint8_t keyContainer[1056] = {0U}, tag[16U] = {0U} , keysize;
    uint16_t keyInfoOffset, keyDataOffset, offset = 0U;
    uint32_t tagLen;
    hseSrvResponse_t hseResponse = HSE_SRV_RSP_GENERAL_ERROR;
    key_import_param_t key_import_auth_param = {0};
    mbedtls_aes_context aes;
    keyContainer_t authKeyContainer;
    hseAuthScheme_t authScheme;

    /*key to compute tag of key container and authenticate key container*/
    uint8_t aes128ProvisionKey[] = {0x6f, 0xe1, 0x2c, 0x66, 0x07, 0x19, 0x1f, 0x4f, 0x08, 0x00, 0x81, 0x21, 0x40, 0x25, 0x8a, 0x98};

    /*IV to compute tag of Key container*/
    uint8_t iv[] = { 0xff, 0xbc, 0x51, 0x6a, 0x8f, 0xbe, 0x61, 0x52, 0xaa, 0x42, 0x8c, 0xdd, 0x80, 0x0c, 0x06, 0x2d };

    /*
     * Prepare to decrypt the pre-master using own private RSA key
     */
#if defined(MBEDTLS_SSL_PROTO_TLS1) || defined(MBEDTLS_SSL_PROTO_TLS1_1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if( ssl->minor_ver != MBEDTLS_SSL_MINOR_VERSION_0 )
    {
        if ( p + 2 > end ) {
        	NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client key exchange message" ) );
            return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE );
        }
        if( *p++ != ( ( len >> 8 ) & 0xFF ) ||
            *p++ != ( ( len      ) & 0xFF ) )
        {
        	NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client key exchange message" ) );
            return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE );
        }
    }
#endif

    if( p + len != end )
    {
    	NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client key exchange message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE );
    }

    if( ! mbedtls_pk_can_do( private_key, MBEDTLS_PK_RSA ) )
    {
    	NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "got no RSA private key" ) );
        return( MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED );
    }


	/* Allocate Shared secret type key slot for PMS */
    key_import_param.key_type 						= HSE_KEY_TYPE_SHARED_SECRET;
    key_import_param.key_catalog 					= HSE_KEY_CATALOG_ID_RAM;
    key_import_param.key_param.sym_key_param.size 	= BYTES_TO_BITS(peer_pmssize);

    if(KEYMGMT_ERR_SUCCESS != (KeystoreMgmt_FindAllocateSlot(&key_import_param, &pmsKeyHandle)))
    {
    	NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( 1, ( "RSA Pre-Master secret key slot allocation failed" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Get RSA Pre-master decryption key handle */
    ret = nxp_hse_rsa_load_pkey(private_key, MBEDTLS_RSA_PRIVATE);
    if(ret != 0)
	{
		mbedtls_printf( " failed\n  !  nxp_hse_rsa_load_pkey returned %d\n\n", ret );
		goto exit;
	}

    /* Get the rsa context to get private key handle */
    mbedtls_rsa_context * rsa_ctx = (mbedtls_rsa_context *) private_key->pk_ctx;

    cipherParam.cipherKeyHandle = rsa_ctx->keyHandle;

    /* Set the cipher scheme */
    if(rsa_ctx->padding == MBEDTLS_RSA_PKCS_V15)
    {
    	cipherParam.cipherScheme.rsaCipher.rsaAlgo = HSE_RSA_ALGO_RSAES_PKCS1_V15;
    }
    else if(rsa_ctx->padding == MBEDTLS_RSA_PKCS_V21)
    {
    	cipherParam.cipherScheme.rsaCipher.rsaAlgo = HSE_RSA_ALGO_RSAES_OAEP;

    	/* Choose HSE Supported HASH Algorithm */
    	switch(	rsa_ctx->hash_id )
    	{
#if !defined(S32N55)
    		case MBEDTLS_MD_SHA1:
    			cipherParam.cipherScheme.rsaCipher.sch.rsaOAEP.hashAlgo = HSE_HASH_ALGO_SHA_1;
    			break ;
#endif
    		case MBEDTLS_MD_SHA224:
    			cipherParam.cipherScheme.rsaCipher.sch.rsaOAEP.hashAlgo = HSE_HASH_ALGO_SHA2_224;
    			break ;
    		case MBEDTLS_MD_SHA256:
    			cipherParam.cipherScheme.rsaCipher.sch.rsaOAEP.hashAlgo = HSE_HASH_ALGO_SHA2_256;
    			break ;
    		case MBEDTLS_MD_SHA384:
    			cipherParam.cipherScheme.rsaCipher.sch.rsaOAEP.hashAlgo = HSE_HASH_ALGO_SHA2_384;
    			break ;
    		case MBEDTLS_MD_SHA512:
    			cipherParam.cipherScheme.rsaCipher.sch.rsaOAEP.hashAlgo = HSE_HASH_ALGO_SHA2_512;
    			break ;
    		case MBEDTLS_MD_MD5:
    		case MBEDTLS_MD_MD2:
    		case MBEDTLS_MD_MD4:
    		case MBEDTLS_MD_RIPEMD160:
    			return ( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
    		default:
    			return ( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    	}
    }

    /* Send request to HSE for the Decryption of PMS and import decrypted PMS*/
    KeyInfo.keyType = key_import_param.key_type;
    KeyInfo.keyFlags = HSE_KF_USAGE_DERIVE | HSE_KF_ACCESS_EXPORTABLE;
    KeyInfo.keyBitLen = BYTES_TO_BITS(peer_pmssize);

    MBEDTLS_SSL_DEBUG_BUF(4, "pms secret to decrypt", p, len);

    keyInfoOffset = offset;
    (void)memcpy(&keyContainer[offset], &KeyInfo, sizeof(KeyInfo));
    offset += sizeof(KeyInfo);

    keyDataOffset = offset;
    (void)memcpy(&keyContainer[offset], p, len);

    /*AES key to compute GAMC Tag of Key container*/
    mbedtls_aes_init( &aes );
    keysize = NUM_OF_ELEMS(aes128ProvisionKey)*8;

    if( (ret = mbedtls_aes_setkey_enc( &aes,aes128ProvisionKey ,keysize ) )!= 0)
	{
		MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_aes_setkey_enc", ret );
		goto exit;
	}

    /*compute tag of key container*/
    tagLen = (uint16_t)NUM_OF_ELEMS(tag);
    hseResponse = HSE_Gmac(HSE_AUTH_DIR_GENERATE, aes.aesKeyHandle, keyContainer,
    							NUM_OF_ELEMS(keyContainer), iv, NUM_OF_ELEMS(iv), tag,(uint32_t *)&tagLen);

    if(hseResponse != HSE_SRV_RSP_OK)
    {
    	MBEDTLS_SSL_DEBUG_RET( 1, "HSE_Gmac", hseResponse );
    	ret = MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
    	goto exit;
    }

    /*Auth key to Authenticate tag of Key container*/
    key_import_auth_param.key_catalog = HSE_KEY_CATALOG_ID_NVM;
    key_import_auth_param.key_type	 = HSE_KEY_TYPE_AES;
    key_import_auth_param.key_param.sym_key_param.size = keysize;
    key_import_auth_param.key_param.sym_key_param.key  = aes128ProvisionKey;
    key_import_auth_param.key_flag = (HSE_KF_USAGE_KEY_PROVISION | HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY |
    									HSE_KF_USAGE_ENCRYPT | HSE_KF_USAGE_DECRYPT);

    ret = KeystoreMgmt_FindImportSlot(&key_import_auth_param, &authKeyHandle);
    if(ret != KEYMGMT_ERR_SUCCESS)
    {
    	MBEDTLS_SSL_DEBUG_RET( 1, "KeystoreMgmt_FindImportSlot", ret );
    	goto exit;
    }
    /*auth scheme used to verify tag of key container*/
    authScheme.macScheme.macAlgo = HSE_MAC_ALGO_GMAC;
    authScheme.macScheme.sch.gmac.pIV =  Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(iv));
    authScheme.macScheme.sch.gmac.ivLength = NUM_OF_ELEMS(iv);

    /*Auth key container to authenticate encrypted key*/
    authKeyContainer.keyContainerLen = NUM_OF_ELEMS(keyContainer);
    authKeyContainer.pKeyContainer   = (HOST_ADDR)(uintptr_t)keyContainer;
    authKeyContainer.authKeyHandle   = authKeyHandle;
    memcpy(&authKeyContainer.authScheme, &authScheme, sizeof(hseAuthScheme_t) );
#if defined(S32N55)
    authKeyContainer.authLen          =tagLen;
    authKeyContainer.pAuth          = (HOST_ADDR)(uintptr_t)tag;
#else
    authKeyContainer.authLen[0]       = tagLen;
    authKeyContainer.authLen[1]       = 0;
    authKeyContainer.pAuth[0]          = (HOST_ADDR)(uintptr_t)tag;
    authKeyContainer.pAuth[1]        = (HOST_ADDR)(uintptr_t)NULL;
#endif
	hseResponse = HSE_ImportEncAuthKey(pmsKeyHandle, &cipherParam,(uint32_t)len, &authKeyContainer, keyInfoOffset, keyDataOffset);
	if(hseResponse != HSE_SRV_RSP_OK)
    {
		 /* Get decrypted PMS key handle and size */
		memcpy(peer_pms, &pmsKeyHandle, sizeof(hseKeyHandle_t));
		*peer_pmslen = peer_pmssize;
		(void)mbedtls_aes_free(&aes);
		(void)KeyStoreMgmt_FreeKey(authKeyHandle);
		authKeyHandle = HSE_INVALID_KEY_HANDLE;

		(void)KeyStoreMgmt_FreeKey(rsa_ctx->keyHandle);
		rsa_ctx->keyHandle = HSE_INVALID_KEY_HANDLE;

		return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

exit:
	 /* Get decrypted PMS key handle and size */
	memcpy(peer_pms, &pmsKeyHandle, sizeof(hseKeyHandle_t));
	*peer_pmslen = peer_pmssize;
	(void)mbedtls_aes_free(&aes);

	(void)KeyStoreMgmt_FreeKey(authKeyHandle);
	authKeyHandle = HSE_INVALID_KEY_HANDLE;

	(void)KeyStoreMgmt_FreeKey(rsa_ctx->keyHandle);
	rsa_ctx->keyHandle = HSE_INVALID_KEY_HANDLE;

    return(ret);
}

#endif /* MBEDTLS_KEY_EXCHANGE_RSA_ENABLED ||  MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED */

#if defined(MBEDTLS_SSL_PROTO_TLS1) || defined(MBEDTLS_SSL_PROTO_TLS1_1)

/*************************************************************************************************
 * Description	: Compute the keyhandle
 * Note			: TBD
************************************************************************************************/
int tls1_prf( const unsigned char *secret, size_t slen,
                     const char *label,
                     const unsigned char *random, size_t rlen,
                     unsigned char *dstbuf, size_t dlen )
{
    size_t nb, hs;
    size_t i, j, k;
    const unsigned char *S1, *S2;
    unsigned char *tmp;
    size_t tmp_len = 0;
    unsigned char h_i[20];
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t md_ctx;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    mbedtls_md_init( &md_ctx );

    tmp_len = 20 + strlen( label ) + rlen;
    tmp = mbedtls_calloc( 1, tmp_len );
    if( tmp == NULL )
    {
        ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto exit;
    }

    hs = ( slen + 1 ) / 2;
    S1 = secret;
    S2 = secret + slen - hs;

    nb = strlen( label );
    memcpy( tmp + 20, label, nb );
    memcpy( tmp + 20 + nb, random, rlen );
    nb += rlen;

    /*
     * First compute P_md5(secret,label+random)[0..dlen]
     */
    if( ( md_info = mbedtls_md_info_from_type( MBEDTLS_MD_MD5 ) ) == NULL )
    {
        ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        goto exit;
    }

    if( ( ret = mbedtls_md_setup( &md_ctx, md_info, 1 ) ) != 0 )
    {
        goto exit;
    }

    mbedtls_md_hmac_starts( &md_ctx, S1, hs );
    mbedtls_md_hmac_update( &md_ctx, tmp + 20, nb );
    mbedtls_md_hmac_finish( &md_ctx, 4 + tmp );

    for( i = 0; i < dlen; i += 16 )
    {
        mbedtls_md_hmac_reset ( &md_ctx );
        mbedtls_md_hmac_update( &md_ctx, 4 + tmp, 16 + nb );
        mbedtls_md_hmac_finish( &md_ctx, h_i );

        mbedtls_md_hmac_reset ( &md_ctx );
        mbedtls_md_hmac_update( &md_ctx, 4 + tmp, 16 );
        mbedtls_md_hmac_finish( &md_ctx, 4 + tmp );

        k = ( i + 16 > dlen ) ? dlen % 16 : 16;

        for( j = 0; j < k; j++ )
            dstbuf[i + j]  = h_i[j];
    }

    mbedtls_md_free( &md_ctx );

    /*
     * XOR out with P_sha1(secret,label+random)[0..dlen]
     */
    if( ( md_info = mbedtls_md_info_from_type( MBEDTLS_MD_SHA1 ) ) == NULL )
    {
        ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        goto exit;
    }

    if( ( ret = mbedtls_md_setup( &md_ctx, md_info, 1 ) ) != 0 )
    {
        goto exit;
    }

    mbedtls_md_hmac_starts( &md_ctx, S2, hs );
    mbedtls_md_hmac_update( &md_ctx, tmp + 20, nb );
    mbedtls_md_hmac_finish( &md_ctx, tmp );

    for( i = 0; i < dlen; i += 20 )
    {
        mbedtls_md_hmac_reset ( &md_ctx );
        mbedtls_md_hmac_update( &md_ctx, tmp, 20 + nb );
        mbedtls_md_hmac_finish( &md_ctx, h_i );

        mbedtls_md_hmac_reset ( &md_ctx );
        mbedtls_md_hmac_update( &md_ctx, tmp, 20 );
        mbedtls_md_hmac_finish( &md_ctx, tmp );

        k = ( i + 20 > dlen ) ? dlen % 20 : 20;

        for( j = 0; j < k; j++ )
            dstbuf[i + j] = (unsigned char)( dstbuf[i + j] ^ h_i[j] );
    }

exit:
    mbedtls_md_free( &md_ctx );

    mbedtls_platform_zeroize( tmp, tmp_len );
    mbedtls_platform_zeroize( h_i, sizeof( h_i ) );

    mbedtls_free( tmp );
    return( ret );
}
#endif /* MBEDTLS_SSL_PROTO_TLS1) || MBEDTLS_SSL_PROTO_TLS1_1 */

#endif /* MBEDTLS_USE_NXP_HSE_CRYPTO */
