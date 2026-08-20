/**
*   @file    	hse_host_km_import_key.c
*
*   @brief   	This file implements wrappers for key import.
*
*   @addtogroup [HSE_DAL]
*   @{
*/
/*==================================================================================================
*
*   (c) Copyright 2022 NXP.
*
*   This software is owned or controlled by NXP and may only be used strictly in accordance with
*   the applicable license terms. By expressly accepting such terms or by downloading, installing,
*   activating and/or otherwise using the software, you are agreeing that you have read, and that
*   you agree to comply with and are bound by, such license terms. If you do not agree to
*   be bound by the applicable license terms, then you may not retain, install, activate or
*   otherwise use the software.
==================================================================================================*/

#ifdef __cplusplus
extern "C"
{
#endif

/*==================================================================================================
 *                                        INCLUDE FILES
 ==================================================================================================*/

#include "Hse_Ip.h"
#include "hse_host_global.h"
#include "string.h"
#include "global_defs.h"
#include "hse_host_km_utils.h"
#if defined(D_CACHE_ENABLE_MBEDTLS)
#include "Cache_Ip.h"
#include "alignment.h"
#endif /* D_CACHE_ENABLE_MBEDTLS */

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
 * 	@brief		Get the bit length based on the Curve ID
 *
 * 	@param[in]	eccCurveId
 *				ECC Curve ID
 *
 *  @return     Curve bit length
 *
 */
static uint16_t GetKeyBitLen(hseEccCurveId_t eccCurveId);

/**
 * 	@brief		Get length of ECC/ED public key based on Curve ID
 *
 * 	@param[in]	eccCurveId
 *				ECC Curve ID
 *
 *  @return     Curve bit length
 *
 */
static uint16_t GetPubKeyLen(hseEccCurveId_t eccCurveId);

#ifdef HSE_SPT_STREAM_CTX_IMPORT_EXPORT
/**
 * 	@brief		Import/Exports on-going stream context
 *
 * 	@param[in]	operation
 *				Specifies the operation to be performed with the streaming context: Import/Export
 *
 *	@param[in]	streamId
 *				Specifies the stream to be exported or overwritten if imported
 *
 *	@param[in/out]	pStreamCtx
 *				The output buffer where the streaming context will be copied (export) or
 *              the input buffer from which HSE will copy the streaming context (import).
 *               Length of the buffer should be at least #MAX_STREAMING_CONTEXT_SIZE bytes
 *
 *  @return     HSE service response.
 *
 */
static hseSrvResponse_t HSE_ImportExportStream
(
	hseStreamContextOp_t operation,
	hseStreamId_t streamId,
	void*  pStreamCtx
);
#endif /* HSE_SPT_STREAM_CTX_IMPORT_EXPORT */

/*==================================================================================================
 *                                       LOCAL FUNCTIONS
 ==================================================================================================*/

/*************************************************************************************************
* Description:  Get the bit length based on the Curve ID
************************************************************************************************/
static uint16_t GetKeyBitLen(hseEccCurveId_t eccCurveId)
{
    switch(eccCurveId)
    {
        case HSE_EC_SEC_SECP256R1:
            return 256U;

        case HSE_EC_SEC_SECP384R1:
            return 384U;

        case HSE_EC_SEC_SECP521R1:
            return 521U;

        case HSE_EC_BRAINPOOL_BRAINPOOLP256R1:
            return 256U;

        case HSE_EC_BRAINPOOL_BRAINPOOLP320R1:
            return 320U;

        case HSE_EC_BRAINPOOL_BRAINPOOLP384R1:
            return 384U;

        case HSE_EC_BRAINPOOL_BRAINPOOLP512R1:
            return 512U;

        case HSE_EC_25519_ED25519:
            return 256U;

        case HSE_EC_25519_CURVE25519:
            return 256U;

#ifdef HSE_SPT_EC_448_CURVE448
        case HSE_EC_448_CURVE448:
#endif /* HSE_SPT_EC_448_CURVE448 */

#ifdef HSE_SPT_EC_448_ED448
        case HSE_EC_448_ED448:
#endif /* HSE_SPT_EC_448_ED448 */
            return 448U;
        default:
            return 0U;
    }
}

/*************************************************************************************************
* Description:  Get length of ECC/ED public key based on Curve ID
************************************************************************************************/
static uint16_t GetPubKeyLen(hseEccCurveId_t eccCurveId)
{
    return ( (HSE_EC_25519_ED25519 == eccCurveId) || (HSE_EC_25519_CURVE25519 == eccCurveId)

#ifdef HSE_SPT_EC_448_CURVE448
    		|| (HSE_EC_448_CURVE448 == eccCurveId)
#endif /* HSE_SPT_EC_448_CURVE448 */

#ifdef HSE_SPT_EC_448_ED448
			|| (HSE_EC_448_ED448 == eccCurveId)
#endif /* HSE_SPT_EC_448_ED448 */
		) ?
       BITS_TO_BYTES(GetKeyBitLen(eccCurveId)) :       /* If   ED curve (Twisted/Montgomery) - Q length is curveBitLen */
	   BITS_TO_BYTES(GetKeyBitLen(eccCurveId)) * 2U;   /* Else Qx||Qy length is 2 * curveBitLen */
}

#ifdef HSE_SPT_STREAM_CTX_IMPORT_EXPORT
/*************************************************************************************************
* Description:	Import/Exports on-going stream context
************************************************************************************************/
static hseSrvResponse_t HSE_ImportExportStream
(
	hseStreamContextOp_t operation,
	hseStreamId_t streamId,
	void*  pStreamCtx
)
{
	uint8_t u8MuChannel;
	hseSrvDescriptor_t *pHseSrvDesc;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

	/* Get a free channel on MU0 */
    u8MuChannel = Hse_Ip_GetFreeChannel(APP_MU_INSTANCE_U8);
    if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
    {
    	goto exit;
    }

	/* Alloc free descriptor */
    pHseSrvDesc = &MbedTLS_aSrvDescriptor[u8MuChannel];
	memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));

#if defined(D_CACHE_ENABLE_MBEDTLS)
    uint8_t *pAlignStreamCtx = NULL;
    uint16_t nonSgtBuffLen = 0;

    if(NULL_PTR != pStreamCtx)
    {
    	if(operation == HSE_IMPORT_STREAMING_CONTEXT)
    	{
    		nonSgtBuffLen = alignNonSgtBuff(pStreamCtx, MAX_STREAMING_CONTEXT_SIZE, 32);
        	if(nonSgtBuffLen != NO_BUFF_ALLOC)
        	{
    			/* Flush Input Data Buffer to memory */
        		pAlignStreamCtx = nxp_hse_callocH(nonSgtBuffLen, 32);
        		if(NULL_PTR == pAlignStreamCtx)
        		{
        			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
        			goto exit;
        		}

        		if(NULL_PTR != pAlignStreamCtx)
        		{
            		memcpy(pAlignStreamCtx, pStreamCtx, MAX_STREAMING_CONTEXT_SIZE);
        			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignStreamCtx, MAX_STREAMING_CONTEXT_SIZE);
        			pHseSrvDesc->hseSrv.importExportStreamCtx.pStreamContext = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignStreamCtx));
        	    	nonSgtBuffLen = 0;
        		}
        	}
        	else
        	{
    			/* Flush Input Data Buffer to memory */
    			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pStreamCtx, MAX_STREAMING_CONTEXT_SIZE);
    			pHseSrvDesc->hseSrv.importExportStreamCtx.pStreamContext = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pStreamCtx));
        	}
    	}
    	else
    	{
    		nonSgtBuffLen = alignNonSgtBuff(pStreamCtx, MAX_STREAMING_CONTEXT_SIZE, 32);
        	if(nonSgtBuffLen != NO_BUFF_ALLOC)
        	{
    			/* Flush Input Data Buffer to memory */
        		pAlignStreamCtx = nxp_hse_callocH(nonSgtBuffLen, 32);
        		if(NULL_PTR == pAlignStreamCtx)
        		{
        			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
        			goto exit;
        		}

        		if(NULL_PTR != pAlignStreamCtx)
        		{
        			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA,FALSE,  (uint32_t)pAlignStreamCtx, MAX_STREAMING_CONTEXT_SIZE);


            		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pAlignStreamCtx, MAX_STREAMING_CONTEXT_SIZE);
        			pHseSrvDesc->hseSrv.importExportStreamCtx.pStreamContext = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignStreamCtx));
        	    	nonSgtBuffLen = 0;
        		}
        	}
        	else
        	{
        		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pStreamCtx, MAX_STREAMING_CONTEXT_SIZE);


    			/* Flush Input Data Buffer to memory */
        		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pStreamCtx, MAX_STREAMING_CONTEXT_SIZE);
    			pHseSrvDesc->hseSrv.importExportStreamCtx.pStreamContext = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pStreamCtx));
        	}
    	}
    }

#endif /* D_CACHE_ENABLE_MBEDTLS */

	/* Complete service parameters */
	pHseSrvDesc->srvId 											= HSE_SRV_ID_IMPORT_EXPORT_STREAM_CTX;
	pHseSrvDesc->hseSrv.importExportStreamCtx.operation 		= operation;
	pHseSrvDesc->hseSrv.importExportStreamCtx.streamId 			= streamId;

#if !defined(D_CACHE_ENABLE_MBEDTLS)
	pHseSrvDesc->hseSrv.importExportStreamCtx.pStreamContext 	= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pStreamCtx));
#endif

	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

	/* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

#if defined(D_CACHE_ENABLE_MBEDTLS)
    if(srvResponse == HSE_SRV_RSP_OK)
    {
    	if(operation == HSE_EXPORT_STREAMING_CONTEXT)
    	{
    		if(NULL_PTR != pAlignStreamCtx)
    		{
    			memcpy(pStreamCtx, pAlignStreamCtx, MAX_STREAMING_CONTEXT_SIZE);
    		}
    	}
    }
#endif

exit:

#if defined(D_CACHE_ENABLE_MBEDTLS)
	if(NULL_PTR != pAlignStreamCtx)
	{
		nxp_hse_freeH(pAlignStreamCtx);
		pAlignStreamCtx = NULL;
	}
#endif

	return srvResponse;
}
#endif

/*==================================================================================================
 *                                       GLOBAL FUNCTIONS
 ==================================================================================================*/

/*************************************************************************************************
* Description:  Imports a key given the key handle, key info and key value(s)
************************************************************************************************/
hseSrvResponse_t HSE_ImportKey
(
    uint8_t u8MuInstance,
    hseKeyHandle_t targetKeyHandle,
    hseKeyInfo_t *pKeyInfo,
    const uint8_t *pKey0, uint32_t keyLen0,
    const uint8_t *pKey1, uint32_t keyLen1,
    const uint8_t *pKey2, uint32_t keyLen2
)
{
    uint8_t u8MuChannel;
    hseSrvDescriptor_t *pHseSrvDesc;
    hseImportKeySrv_t *pImportKeyReq;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

    /* Get a free channel on u8MuInstance */
    u8MuChannel = Hse_Ip_GetFreeChannel(u8MuInstance);
    if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
    {
    	goto exit;
    }

    /* NVM key slots can be updated (i.e. importing in a non-empty slot) only if authenticated */
    if(HSE_KEY_CATALOG_ID_NVM == GET_CATALOG_ID(targetKeyHandle))
    {
        hseKeyInfo_t keyInfo;
        srvResponse = HSE_GetKeyInfo(targetKeyHandle, &keyInfo);
        if(HSE_SRV_RSP_OK == srvResponse)
        {
            /* NVM slot is already populated - CANNOT update without authentication (see `HSE_UpdateNvmKey_Example`) */
            /* Erase the key to enable import in plain */
            srvResponse = HSE_EraseKey(targetKeyHandle, HSE_ERASE_NOT_USED);
            if(HSE_SRV_RSP_OK != srvResponse)
            {
            	 goto exit;
            }
        }
        /* Other status than OK or EMPTY is an error */
        else if(HSE_SRV_RSP_KEY_EMPTY != srvResponse)
        {
            goto exit;
        }
    }

    /* Complete the service descriptor placed in shared memory */
	pHseSrvDesc = &MbedTLS_aSrvDescriptor[u8MuChannel];
	memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));
	pImportKeyReq = &(pHseSrvDesc->hseSrv.importKeyReq);

#if defined(D_CACHE_ENABLE_MBEDTLS)

	uint8_t *pAlignKey0 = NULL;
	uint8_t *pAlignKey1 = NULL ;
	uint8_t *pAlignKey2 = NULL ;
	uint16_t nonSgtBuffLen = 0;

    if(NULL_PTR != pKeyInfo)
    {
		/* Flush Input Data Buffer to memory */
		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32)pKeyInfo, sizeof(hseKeyInfo_t));
    }

    if(NULL_PTR != pKey0)
    {
    	nonSgtBuffLen = alignNonSgtBuff(pKey0, keyLen0, 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
			/* Flush Input Data Buffer to memory */
    		pAlignKey0 = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignKey0)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		memcpy(pAlignKey0, pKey0, keyLen0);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignKey0, keyLen0);
			pImportKeyReq->pKey[0] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignKey0));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
    		/* Flush Input Data Buffer to memory */
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32)pKey0, keyLen0);
    		pImportKeyReq->pKey[0] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKey0));
    	}
    }

    if(NULL_PTR != pKey1)
    {
    	nonSgtBuffLen = alignNonSgtBuff(pKey1, keyLen1, 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
			/* Flush Input Data Buffer to memory */
    		pAlignKey1 = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignKey1)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		memcpy(pAlignKey1, pKey1, keyLen1);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignKey1, keyLen1);
			pImportKeyReq->pKey[1] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignKey1));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
    		/* Flush Input Data Buffer to memory */
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32)pKey1, keyLen1);
    		pImportKeyReq->pKey[1] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKey1));
    	}
    }

    if(NULL_PTR != pKey2)
    {
		nonSgtBuffLen = alignNonSgtBuff(pKey2, keyLen2, 32);
		if(nonSgtBuffLen != NO_BUFF_ALLOC)
		{
			/* Flush Input Data Buffer to memory */
			pAlignKey2 = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignKey2)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

			memcpy(pAlignKey2, pKey2, keyLen2);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignKey2, keyLen2);
			pImportKeyReq->pKey[2] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignKey2));
			nonSgtBuffLen = 0;
		}
		else
		{
			/* Flush Input Data Buffer to memory */
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32)pKey2, keyLen2);
			pImportKeyReq->pKey[2] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKey2));
		}

    }

#endif /* D_CACHE_ENABLE_MBEDTLS */
#if defined (S32N55)
	pHseSrvDesc->srvId              = HSE_SRV_ID_KEY_IMPORT;
#else
    pHseSrvDesc->srvId              = HSE_SRV_ID_IMPORT_KEY;
#endif
    pImportKeyReq->targetKeyHandle  = targetKeyHandle;
    pImportKeyReq->pKeyInfo         = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKeyInfo));
    pImportKeyReq->keyLen[0]        = keyLen0;
    pImportKeyReq->keyLen[1]        = keyLen1;
    pImportKeyReq->keyLen[2]        = keyLen2;

#if !defined(D_CACHE_ENABLE_MBEDTLS)
    pImportKeyReq->pKey[0]          = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKey0));
    pImportKeyReq->pKey[1]          = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKey1));
    pImportKeyReq->pKey[2]          = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKey2));
#endif

    /* Key imported in plain - not encrypted => cipherKeyHandle = HSE_INVALID_KEY_HANDLE */
    pImportKeyReq->cipher.cipherKeyHandle   = HSE_INVALID_KEY_HANDLE;
    /* Key imported without authentication - not signed => authKeyHandle = HSE_INVALID_KEY_HANDLE */
    pImportKeyReq->keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;

	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

    /* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(u8MuInstance, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

exit:

#if defined(D_CACHE_ENABLE_MBEDTLS)

	if(NULL_PTR != pAlignKey0)
	{
		nxp_hse_freeH(pAlignKey0);
		pAlignKey0 = NULL;
	}

	if(NULL_PTR != pAlignKey1)
	{
		nxp_hse_freeH(pAlignKey1);
		pAlignKey1 = NULL;
	}

	if(NULL_PTR != pAlignKey2)
	{
		nxp_hse_freeH(pAlignKey2);
		pAlignKey2 = NULL;
	}
#endif

    return srvResponse;
}

/*************************************************************************************************
* Description:  Imports a symmetric key given the key handle, type (AES/HMAC) and key flags
************************************************************************************************/
hseSrvResponse_t HSE_ImportSymKey
(
    hseKeyHandle_t handle,
    hseKeyType_t type,
    hseKeyFlags_t flags,
    const uint8_t *pKey,
    uint32_t len
)
{
    /* Declare the information about the key to be imported */
#if defined(D_CACHE_ENABLE_MBEDTLS)
    hseKeyInfo_t keyInfo __attribute__((aligned (32))) = {
    		.keyType 	= type,                    	/* Will import a symmetric key (AES/HMAC) */
			.keyFlags 	= flags,                  	/* Usage flags for this key (e.g. ENCRYPT/DECRYPT/SIGN/VERIFY/PROVISION/DERIVE) */
			.keyBitLen 	= BYTES_TO_BITS(len),    	/* The length in bits (for AES - 128/192/256; for HMAC any value in the
                                                		[HSE_MIN_HMAC_KEY_BITS_LEN..HSE_MAX_HMAC_KEY_BITS_LEN] boundaries) */
			.keyCounter = 0UL,                  	/* Relevant only for NVM keys - must be > than previous */
			.smrFlags 	= 0UL,                    	/* Not used here - default value */
    };
#else
    hseKeyInfo_t keyInfo = {
    		.keyType 	= type,             	/* Will import a symmetric key (AES/HMAC) */
            .keyFlags 	= flags,                /* Usage flags for this key (e.g. ENCRYPT/DECRYPT/SIGN/VERIFY/PROVISION/DERIVE) */
            .keyBitLen 	= BYTES_TO_BITS(len),   /* The length in bits (for AES - 128/192/256; for HMAC any value in the
                                                    [HSE_MIN_HMAC_KEY_BITS_LEN..HSE_MAX_HMAC_KEY_BITS_LEN] boundaries) */
            .keyCounter = 0UL,                  /* Relevant only for NVM keys - must be > than previous */
            .smrFlags 	= 0UL,                  /* Not used here - default value */
    };

#endif /* D_CACHE_ENABLE_MBEDTLS  || NXP_ALIGN_DATA */

    return HSE_ImportKey(MU0, handle, &keyInfo, NULL, 0UL, NULL, 0UL, pKey, len);

}

/*************************************************************************************************
* Description:  Imports an ECC key (pub/pair) given the key handle, type (PUB/PAIR),
* flags and curve
************************************************************************************************/
hseSrvResponse_t HSE_ImportEccKey
(
    hseKeyHandle_t handle,
    hseKeyType_t type,
    hseKeyFlags_t flags,
	uint16_t keyBitLen,
    hseEccCurveId_t eccCurveId,
    const uint8_t* pPubKey,
    const uint8_t* pPrivKey
)
{
	uint16_t pubKeyLen = 0U;
	uint16_t privKeyLen = 0U;

	if(eccCurveId == HSE_EC_USER_CURVE1)
	{
	    /* Get the public key length */
	    pubKeyLen = (BITS_TO_BYTES(keyBitLen))*2U;
	    /* pPrivKey may be NULL (when importing an ECC_PUB type) */

	}
	else
	{
	    /* Get the public key length */
	    pubKeyLen = GetPubKeyLen(eccCurveId);
	    /* pPrivKey may be NULL (when importing an ECC_PUB type) */
	    privKeyLen = (NULL != pPrivKey) ? BITS_TO_BYTES(GetKeyBitLen(eccCurveId)) : 0U;
	}

    /* Declare the information about the key to be imported */
#if defined(D_CACHE_ENABLE_MBEDTLS)
    hseKeyInfo_t keyInfo __attribute__((aligned (32))) = {
        .keyType 				= type,			/* Will import an ECC key (public / pair) */
        .keyFlags 				= flags,		/* Usage flags for this key (e.g. SIGN/VERIFY/PROVISION/EXCHANGE) */
        .keyBitLen 				= keyBitLen,	/* Base length in bits of the key - for ECC corresponds to Curve bit length */
        .keyCounter 			= 0UL,			/* Relevant only for NVM keys - must be > than previous */
        .smrFlags 				= 0UL,			/* Not used here - default value */
        .specific.eccCurveId 	= eccCurveId,	/* Specific for ECC key - curve ID */
    };
#else
    hseKeyInfo_t keyInfo = {
        .keyType 				= type,			/* Will import an ECC key (public / pair) */
        .keyFlags 				= flags,		/* Usage flags for this key (e.g. SIGN/VERIFY/PROVISION/EXCHANGE) */
        .keyBitLen 				= keyBitLen,	/* Base length in bits of the key - for ECC corresponds to Curve bit length */
        .keyCounter 			= 0UL,			/* Relevant only for NVM keys - must be > than previous */
        .smrFlags 				= 0UL,			/* Not used here - default value */
        .specific.eccCurveId 	= eccCurveId,	/* Specific for ECC key - curve ID */
    };
#endif /* D_CACHE_ENABLE_MBEDTLS  || NXP_ALIGN_DATA */

    return HSE_ImportKey(MU0, handle, &keyInfo, pPubKey, pubKeyLen, NULL, 0UL, pPrivKey, privKeyLen);
}

/*************************************************************************************************
* Description:  Imports a RSA key (pub/pair) given the key handle, type
* (PUB/PAIR), flags and public exponent length
************************************************************************************************/
hseSrvResponse_t HSE_ImportRsaKey
(
    hseKeyHandle_t handle,
    hseKeyType_t type,
    hseKeyFlags_t flags,
    const uint8_t* pN,
    uint16_t modLen,
    const uint8_t* pE,
    uint16_t eLen,
    const uint8_t* pD
)
{
    /* pD may be NULL (when importing an RSA_PUB type) */
    uint16_t dLen = (NULL != pD) ? modLen : 0U;

    /* Declare the information about the key to be imported */
#if defined(D_CACHE_ENABLE_MBEDTLS)
    hseKeyInfo_t keyInfo __attribute__((aligned (32))) = {
        .keyType 					= type,						/* Will import a RSA key (public / pair) */
        .keyFlags 					= flags,					/* Usage flags for this key (e.g. SIGN/VERIFY/PROVISION/EXCHANGE) */
        .keyBitLen 					= BYTES_TO_BITS(modLen),	/* Length of modulus in bits */
        .keyCounter 				= 0UL,						/* Relevant only for NVM keys - must be > than previous */
        .smrFlags 					= 0UL,						/* Not used here - default value */
        .specific.pubExponentSize 	= eLen,						/* Specific for RSA key - size of public exponent */
    };
#else
    hseKeyInfo_t keyInfo = {
        .keyType 					= type,						/* Will import a RSA key (public / pair) */
        .keyFlags 					= flags,					/* Usage flags for this key (e.g. SIGN/VERIFY/PROVISION/EXCHANGE) */
        .keyBitLen 					= BYTES_TO_BITS(modLen),	/* Length of modulus in bits */
        .keyCounter 				= 0UL,						/* Relevant only for NVM keys - must be > than previous */
        .smrFlags 					= 0UL,						/* Not used here - default value */
        .specific.pubExponentSize 	= eLen,						/* Specific for RSA key - size of public exponent */
    };
#endif /* D_CACHE_ENABLE_MBEDTLS  || NXP_ALIGN_DATA */

    return HSE_ImportKey(MU0, handle, &keyInfo, pN, modLen, pE, eLen, pD, dLen);
}

/*************************************************************************************************
* Description:  Imports a Symmetric key in an authenticated key container
************************************************************************************************/
#if defined(S32N55)
hseSrvResponse_t HSE_ImportAuthSymKey
(
    const hseKeyHandle_t targetHandle,
    const hseKeyHandle_t authHandle,
    const hseAuthScheme_t *pAuthScheme,
    const uint8_t *pKeyContainer,
    const uint16_t containerLen,
    const uint16_t keyInfoOffset,
    const uint16_t keyDataOffset,
    const uint16_t keyLen,
	const uint8_t *pAuth,
	const uint16_t authLen
)
{
	    uint8_t u8MuChannel;
	    hseSrvDescriptor_t *pHseSrvDesc;
	    hseImportKeySrv_t *pImportKeyReq;
	    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

	    /* Get a free channel on u8MuInstance */
	      u8MuChannel = Hse_Ip_GetFreeChannel(APP_MU_INSTANCE_U8);
	      if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
	      {
	       	goto exit;
	      }

#if defined (D_CACHE_ENABLE_MBEDTLS)
	      if(NULL_PTR !=pKeyContainer)
	      {
	    	  Cache_Ip_CleanByAddr(CACHE_IP_CORE,CACHE_IP_DATA,FALSE,(uint32)pKeyContainer,containerLen);
	      }
	      if(NULL_PTR !=pAuth)
	      {
	    	  Cache_Ip_CleanByAddr(CACHE_IP_CORE,CACHE_IP_DATA,FALSE,(uint32)pAuth,authLen);
	      }
	      if(NULL_PTR !=pAuthScheme)
	      {
	    	  Cache_Ip_CleanByAddr(CACHE_IP_CORE,CACHE_IP_DATA,FALSE,(uint32)pAuthScheme,sizeof(hseAuthScheme_t));
	      }
#endif	   /*D_CACHE_EANBLE  */

	      /* Clear service descriptor */
	      pHseSrvDesc = &MbedTLS_aSrvDescriptor[u8MuChannel];

	      pImportKeyReq = &(pHseSrvDesc->hseSrv.importKeyReq);
	      memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));

	      /*Fill service descriptor attributes   */
	      pHseSrvDesc->srvId              = HSE_SRV_ID_KEY_IMPORT;
	      pImportKeyReq->targetKeyHandle  = targetHandle;
	      pImportKeyReq->pKeyInfo         = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(&pKeyContainer[keyInfoOffset]));
	      pImportKeyReq->pKey[2]          = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(&pKeyContainer[keyDataOffset]));
	      pImportKeyReq->keyLen[2]        = keyLen;

	      /* Key imported in plain - not encrypted => cipherKeyHandle = HSE_INVALID_KEY_HANDLE */
	      pImportKeyReq->cipher.cipherKeyHandle   = HSE_INVALID_KEY_HANDLE;

	      /* Key imported authenticated */
	      pImportKeyReq->keyContainer.authKeyHandle 		= authHandle;
	      (void)memcpy(&pImportKeyReq->keyContainer.authScheme, pAuthScheme, sizeof(hseAuthScheme_t));
	      pImportKeyReq->keyContainer.pKeyContainer 		= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKeyContainer));
	      pImportKeyReq->keyContainer.keyContainerLen	 	= containerLen;
	      pImportKeyReq->keyContainer.pAuth 			= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAuth));
	      pImportKeyReq->keyContainer.authLen			= authLen;

	      /* Build the request to be sent to Hse Ip layer */
	          MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
	          MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

	          /* Send the request synchronously */
	          srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

	      exit:
	          return srvResponse;
	      }

#else
hseSrvResponse_t HSE_ImportAuthSymKey
(
    const hseKeyHandle_t targetHandle,
    const hseKeyHandle_t authHandle,
    const hseAuthScheme_t *pAuthScheme,
    const uint8_t *pKeyContainer,
    const uint16_t containerLen,
    const uint16_t keyInfoOffset,
    const uint16_t keyDataOffset,
    const uint16_t keyLen,
    const uint8_t *pAuth0,
    const uint8_t *pAuth1,
    const uint16_t authLen0,
    const uint16_t authLen1
)
{
    uint8_t u8MuChannel;
    hseSrvDescriptor_t *pHseSrvDesc;
    hseImportKeySrv_t *pImportKeyReq;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

    /* Get a free channel on u8MuInstance */
    u8MuChannel = Hse_Ip_GetFreeChannel(APP_MU_INSTANCE_U8);
    if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
    {
    	goto exit;
    }

#if defined(D_CACHE_ENABLE_MBEDTLS)

    if(NULL_PTR != pKeyContainer)
    {
		/* Flush Input Data Buffer to memory */
		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32)pKeyContainer, containerLen);
    }

    if(NULL_PTR != pAuth0)
    {
		/* Flush Input Data Buffer to memory */
		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32)pAuth0, authLen0);
    }

    if(NULL_PTR != pAuth1)
    {
		/* Flush Input Data Buffer to memory */
		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32)pAuth1, authLen1);
    }

    if(NULL_PTR != pAuthScheme)
    {
		/* Flush Input Data Buffer to memory */
		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32)pAuthScheme, sizeof(hseAuthScheme_t));
    }

#endif /* D_CACHE_ENABLE_MBEDTLS */

    /* Clear service descriptor */
    pHseSrvDesc = &MbedTLS_aSrvDescriptor[u8MuChannel];

    pImportKeyReq = &(pHseSrvDesc->hseSrv.importKeyReq);
    memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));

    /* Fill descriptor attributes */

    pHseSrvDesc->srvId              = HSE_SRV_ID_IMPORT_KEY;

    pImportKeyReq->targetKeyHandle  = targetHandle;
    pImportKeyReq->pKeyInfo         = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(&pKeyContainer[keyInfoOffset]));
    pImportKeyReq->pKey[2]          = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(&pKeyContainer[keyDataOffset]));
    pImportKeyReq->keyLen[2]        = keyLen;

    /* Key imported in plain - not encrypted => cipherKeyHandle = HSE_INVALID_KEY_HANDLE */
    pImportKeyReq->cipher.cipherKeyHandle   = HSE_INVALID_KEY_HANDLE;

    /* Key imported authenticated */
    pImportKeyReq->keyContainer.authKeyHandle 		= authHandle;
    (void)memcpy(&pImportKeyReq->keyContainer.authScheme, pAuthScheme, sizeof(hseAuthScheme_t));
    pImportKeyReq->keyContainer.pKeyContainer 		= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKeyContainer));
    pImportKeyReq->keyContainer.keyContainerLen	 	= containerLen;
    pImportKeyReq->keyContainer.pAuth[0] 			= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAuth0));
    pImportKeyReq->keyContainer.pAuth[1] 			= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAuth1));
    pImportKeyReq->keyContainer.authLen[0] 			= authLen0;
    pImportKeyReq->keyContainer.authLen[1] 			= authLen1;

	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

    /* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

exit:
    return srvResponse;
}
#endif
/*******************************************************************************************************
* Description: Imports Encrypted and authenticated key given Auth key container and Cipher Container
********************************************************************************************************/



hseSrvResponse_t HSE_ImportEncAuthKey
(
	hseKeyHandle_t targetKeyHandle,
	cipher_t *cipherParam,
	uint32_t PmskeyLen,
	keyContainer_t *authKeyContainer,
	uint16_t keyInfoOffset, uint16_t keyDataOffset
)

{
    uint8_t u8MuChannel;
    hseSrvDescriptor_t *pHseSrvDesc;
    hseImportKeySrv_t *pImportKeyReq;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

    /* Get a free channel on u8MuInstance */
    u8MuChannel = Hse_Ip_GetFreeChannel(APP_MU_INSTANCE_U8);
    if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
    {
    	goto exit;
    }

    /* NVM key slots can be updated (i.e. importing in a non-empty slot) only if authenticated */
    if(HSE_KEY_CATALOG_ID_NVM == GET_CATALOG_ID(targetKeyHandle))
    {
        hseKeyInfo_t keyInfo;
        srvResponse = HSE_GetKeyInfo(targetKeyHandle, &keyInfo);
        if(HSE_SRV_RSP_OK == srvResponse)
        {
            /* NVM slot is already populated - CANNOT update without authentication (see `HSE_UpdateNvmKey_Example`) */
            /* Erase the key to enable import in plain */
            srvResponse = HSE_EraseKey(targetKeyHandle, HSE_ERASE_NOT_USED);
            if(HSE_SRV_RSP_OK != srvResponse)
                goto exit;
        }
        /* Other status than OK or EMPTY is an error */
        else if(HSE_SRV_RSP_KEY_EMPTY != srvResponse)
        {
            goto exit;
        }
    }

/* Complete the service descriptor placed in shared memory */
	pHseSrvDesc = &MbedTLS_aSrvDescriptor[u8MuChannel];
	memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));
	pImportKeyReq = &(pHseSrvDesc->hseSrv.importKeyReq);

#if defined(D_CACHE_ENABLE_MBEDTLS)

	uint16_t nonSgtBuffLen		= 0;

	uint8_t *pAlignAuthContainer = NULL;
	uint8_t *pAlignAuth0		 = NULL;
	uint8_t *pAlignAuth1		 = NULL;
	uint8_t *pKeyInfo = NULL;
	if(NULL_PTR != pKeyInfo)
	{
		/* Flush Input Data Buffer to memory */
		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32)pKeyInfo, sizeof(hseKeyInfo_t));
	}

    if(NULL_PTR != authKeyContainer)
    {
    	nonSgtBuffLen = alignNonSgtBuff(authKeyContainer->pKeyContainer, authKeyContainer->keyContainerLen, 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
    		pAlignAuthContainer = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignAuthContainer)
    		{
				srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
				goto exit;
			}

    		memcpy(pAlignAuthContainer, authKeyContainer->pKeyContainer, authKeyContainer->keyContainerLen);
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignAuthContainer, authKeyContainer->keyContainerLen);

    		pImportKeyReq->keyContainer.pKeyContainer = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignAuthContainer));
    		pImportKeyReq->pKeyInfo 		          = (HOST_ADDR)(pAlignAuthContainer+keyInfoOffset);
    		pImportKeyReq->pKey[2]				      = (HOST_ADDR)(pAlignAuthContainer+keyDataOffset);
    	}
    	else
    	{
    				/* Flush Input Data Buffer to memory */
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32)authKeyContainer->pKeyContainer, authKeyContainer->keyContainerLen);

    		pImportKeyReq->keyContainer.pKeyContainer = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(authKeyContainer->pKeyContainer));
    	    pImportKeyReq->pKeyInfo 		          = (HOST_ADDR)((authKeyContainer->pKeyContainer)+keyInfoOffset);
    	    pImportKeyReq->pKey[2]				      = (HOST_ADDR)((authKeyContainer->pKeyContainer)+keyDataOffset);
    	}
#if defined(S32N55)
    	if(NULL_PTR != authKeyContainer->pAuth)
#else
        if(NULL_PTR != authKeyContainer->pAuth[0])
#endif
    	{
    		uint8_t len = authKeyContainer->authScheme.macScheme.sch.gmac.ivLength ;
#if defined(S32N55)
    		nonSgtBuffLen = alignNonSgtBuff(authKeyContainer->pAuth, len , 32);
#else
    		nonSgtBuffLen = alignNonSgtBuff(authKeyContainer->pAuth[0], len , 32);
#endif
    	    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	    	{
    				/* Flush Input Data Buffer to memory */
    	    		pAlignAuth0 = nxp_hse_callocH(nonSgtBuffLen, 32);
    	    		if(NULL_PTR == pAlignAuth0)
    	    		{
    	    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    	    			goto exit;
    	    		}
#if defined(S32N55)
    	    		memcpy(pAlignAuth0, authKeyContainer->pAuth, len);
#else
    	    		memcpy(pAlignAuth0, authKeyContainer->pAuth[0], len);
#endif
    				Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignAuth0, len);
#if defined(S32N55)
    				pImportKeyReq->keyContainer.pAuth = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignAuth0));
#else
    				pImportKeyReq->keyContainer.pAuth[0] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignAuth0));
#endif
    		    	nonSgtBuffLen = 0;
    	    	}
    	    	else
    	    	{
    	    		/* Flush Input Data Buffer to memory */
#if defined(S32N55)
    	    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32)authKeyContainer->pAuth, len);
    	    		pImportKeyReq->keyContainer.pAuth = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(authKeyContainer->pAuth));
#else
    	    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32)authKeyContainer->pAuth[0], len);
					pImportKeyReq->keyContainer.pAuth[0] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(authKeyContainer->pAuth[0]));
#endif
    	    	}
    	}
    	else
    	{
#if defined(S32N55)
    		pImportKeyReq->keyContainer.pAuth = NULL;
#else
    		pImportKeyReq->keyContainer.pAuth[0] = NULL;
#endif
    	}
#if !defined(S32N55)
    	if(NULL_PTR != authKeyContainer->pAuth[1])
    	{
    		uint8_t len = authKeyContainer->authScheme.macScheme.sch.gmac.ivLength ;

    		nonSgtBuffLen = alignNonSgtBuff(authKeyContainer->pAuth[1], len , 32);
    	    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	    	{
    				/* Flush Input Data Buffer to memory */
    	    		pAlignAuth1 = nxp_hse_callocH(nonSgtBuffLen, 32);
    	    		if(NULL_PTR == pAlignAuth1)
    	    		{
    	    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    	    			goto exit;
    	    		}

    	    		memcpy(pAlignAuth1, authKeyContainer->pAuth[1], len);
    				Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignAuth1, len);
    				pImportKeyReq->keyContainer.pAuth[1] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignAuth1));
    		    	nonSgtBuffLen = 0;
    	    	}
    	    	else
    	    	{
    	    		/* Flush Input Data Buffer to memory */
    	    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32)authKeyContainer->pAuth[1], len);
    	    		pImportKeyReq->keyContainer.pAuth[0] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(authKeyContainer->pAuth[1]));
    	    	}
    	}
    	else
    	{
    		pImportKeyReq->keyContainer.pAuth[1] = NULL;
    	}
#endif
    }
    else
    {
    	pImportKeyReq->keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;
    }
#else /* ! D_CACHE_ENABLE_MBEDTLS */

    if(NULL_PTR == authKeyContainer)
    {
		pImportKeyReq->keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;
    }
    else
    {
    	pImportKeyReq->pKeyInfo 		              = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR((authKeyContainer->pKeyContainer)+keyInfoOffset));
    	pImportKeyReq->pKey[2]						  = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR((authKeyContainer->pKeyContainer)+keyDataOffset));
    	pImportKeyReq->keyContainer.keyContainerLen   = authKeyContainer->keyContainerLen;
    	pImportKeyReq->keyContainer.pKeyContainer     = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR((uint32_t)authKeyContainer->pKeyContainer));
    	pImportKeyReq->keyContainer.authKeyHandle	  = authKeyContainer->authKeyHandle;
    	(void)memcpy(&pImportKeyReq->keyContainer.authScheme, &authKeyContainer->authScheme, sizeof(hseAuthScheme_t));
#if defined(S32N55)
    	pImportKeyReq->keyContainer.authLen 	 	  = authKeyContainer->authLen;
    	pImportKeyReq->keyContainer.pAuth		  = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(authKeyContainer->pAuth));
#else
    	pImportKeyReq->keyContainer.authLen[0] 	 	  = authKeyContainer->authLen[0];
    	pImportKeyReq->keyContainer.authLen[1] 	 	  = authKeyContainer->authLen[1];
    	pImportKeyReq->keyContainer.pAuth[0]		  = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(authKeyContainer->pAuth[0]));
    	pImportKeyReq->keyContainer.pAuth[1]		  = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(authKeyContainer->pAuth[1]));
#endif
    }

#endif /* D_CACHE_ENABLE_MBEDTLS */

#if defined(S32N55)
    pHseSrvDesc->srvId              = HSE_SRV_ID_KEY_IMPORT;
#else
    pHseSrvDesc->srvId              = HSE_SRV_ID_IMPORT_KEY;
#endif
    pImportKeyReq->targetKeyHandle  = targetKeyHandle;
    pImportKeyReq->keyLen[2]        = PmskeyLen;

    if(NULL_PTR != cipherParam)
    {
    	pImportKeyReq->cipher.cipherKeyHandle = cipherParam->cipherKeyHandle;
    	pImportKeyReq->cipher.cipherScheme = cipherParam->cipherScheme;
    }
    else
    {
    	 /* Key imported in plain - not encrypted => cipherKeyHandle = HSE_INVALID_KEY_HANDLE */
    	pImportKeyReq->cipher.cipherKeyHandle = HSE_INVALID_KEY_HANDLE;
    }

	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

    /* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

exit:

#if defined(D_CACHE_ENABLE_MBEDTLS)

		nxp_hse_freeH(pAlignAuthContainer);
		pAlignAuthContainer = NULL;

		nxp_hse_freeH(pAlignAuth0);
		pAlignAuth0 = NULL;

		nxp_hse_freeH(pAlignAuth1);
		pAlignAuth1 = NULL;

#endif

    return srvResponse;
}

#ifdef HSE_SPT_CLASSIC_DH
/*************************************************************************************************
* Description:  Imports a Dh key (pub/pair)
************************************************************************************************/
hseSrvResponse_t HSE_ImportDhKey
(
    hseKeyHandle_t handle,
    hseKeyType_t type,
    hseKeyFlags_t flags,
	uint16_t keyLen,
	const uint8_t* pPrimeMod,
    const uint8_t* pPubKey,
    const uint8_t* pPrivKey,
	uint16_t privKeyLen
)
{

	uint16_t pubKeyLen = 0U;

	/* DH public key length is of same size as of DH prime modulus P */
	pubKeyLen = keyLen;

    /* Declare the information about the key to be imported */
#if defined(D_CACHE_ENABLE_MBEDTLS)
    hseKeyInfo_t keyInfo __attribute__((aligned (32))) = {
        .keyType 				= type,						/* Will import an DH key (public / pair) */
        .keyFlags 				= flags,					/* Usage flags for this key (e.g. SIGN/VERIFY/PROVISION/EXCHANGE) */
        .keyBitLen 				= BYTES_TO_BITS(keyLen),	/*  */
        .keyCounter 			= 0UL,						/* Relevant only for NVM keys - must be > than previous */
        .smrFlags 				= 0UL,						/* Not used here - default value */
    };
#else
    hseKeyInfo_t keyInfo = {
        .keyType 				= type,						/* Will import an ECC key (public / pair) */
        .keyFlags 				= flags,					/* Usage flags for this key (e.g. SIGN/VERIFY/PROVISION/EXCHANGE) */
        .keyBitLen 				= BYTES_TO_BITS(keyLen),	/* DH prime modulus p length in bits */
        .keyCounter 			= 0UL,						/* Relevant only for NVM keys - must be > than previous */
        .smrFlags 				= 0UL,						/* Not used here - default value */
    };
#endif /* D_CACHE_ENABLE_MBEDTLS */

    return HSE_ImportKey(MU0, handle, &keyInfo, pPrimeMod, keyLen, pPubKey, pubKeyLen, pPrivKey, privKeyLen);
}
#endif/* HSE_SPT_CLASSIC_DH */

/*************************************************************************************************
* Description:  Imports on-going stream context
************************************************************************************************/
hseSrvResponse_t HSE_ImportStream
(
    hseStreamId_t streamId,
    void*  pStreamCtx
)
{
	if ((streamId == (hseStreamId_t )-1) ||
		(NULL == pStreamCtx))
	{
		return HSE_SRV_RSP_INVALID_PARAM;
	}

#ifdef HSE_SPT_STREAM_CTX_IMPORT_EXPORT
    /* Send the request synchronously */
	return HSE_ImportExportStream(HSE_IMPORT_STREAMING_CONTEXT,
									streamId, pStreamCtx);
#else
	return  HSE_SRV_RSP_NOT_SUPPORTED;
#endif /* HSE_SPT_STREAM_CTX_IMPORT_EXPORT */

}

/*************************************************************************************************
* Description:  Exports on-going stream context
************************************************************************************************/
hseSrvResponse_t HSE_ExportStream
(
    hseStreamId_t streamId,
    void*  pStreamCtx
)
{
	if ((streamId == (hseStreamId_t )-1) ||
		(NULL == pStreamCtx))
	{
		return HSE_SRV_RSP_INVALID_PARAM;
	}

#ifdef HSE_SPT_STREAM_CTX_IMPORT_EXPORT
    /* Send the request synchronously */
	return HSE_ImportExportStream(HSE_EXPORT_STREAMING_CONTEXT,
									streamId, pStreamCtx);
#else
	return  HSE_SRV_RSP_NOT_SUPPORTED;
#endif /* HSE_SPT_STREAM_CTX_IMPORT_EXPORT */
}

#ifdef __cplusplus
}
#endif
