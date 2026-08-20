/**
*   @file    	hse_host_km_export_key.c
*
*   @brief   	This file implements wrappers for key export.
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
#include "string.h"
#include "global_defs.h"
#include "hse_host_global.h"
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

#if defined ( D_CACHE_ENABLE_MBEDTLS )
#if defined (CPU_SAF8544) || defined(S32N55)
#define CRYPTO_43_HSE_START_SEC_VAR_CLEARED_UNSPECIFIED_NO_CACHEABLE
#include "Crypto_43_HSE_MemMap.h"

uint32_t pAlignKeyLen0[1];
uint32_t pAlignKeyLen1[1];
uint32_t pAlignKeyLen2[1];

#define CRYPTO_43_HSE_STOP_SEC_VAR_CLEARED_UNSPECIFIED_NO_CACHEABLE
#include "Crypto_43_HSE_MemMap.h"
#else
#define CRYPTO_START_SEC_VAR_CLEARED_UNSPECIFIED_NO_CACHEABLE
#include "Crypto_MemMap.h"

uint32_t pAlignKeyLen0[1];
uint32_t pAlignKeyLen1[1];
uint32_t pAlignKeyLen2[1];

#define CRYPTO_STOP_SEC_VAR_CLEARED_UNSPECIFIED_NO_CACHEABLE
#include "Crypto_MemMap.h"
#endif

#endif

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
			)?
       BITS_TO_BYTES(GetKeyBitLen(eccCurveId)) :       /* If   ED curve (Twisted/Montgomery) - Q length is curveBitLen */
	   BITS_TO_BYTES(GetKeyBitLen(eccCurveId)) * 2U;   /* Else Qx||Qy length is 2 * curveBitLen */
}

/*==================================================================================================
 *                                       GLOBAL FUNCTIONS
 ==================================================================================================*/

/*************************************************************************************************
* Description:  Exports a key given the key handle
************************************************************************************************/
hseSrvResponse_t HSE_ExportKey
(
    hseKeyHandle_t targetKeyHandle,
    hseKeyInfo_t *pKeyInfo,
    uint8_t *pKey0, uint32_t *pKeyLen0,
    uint8_t *pKey1, uint32_t *pKeyLen1,
    uint8_t *pKey2, uint32_t *pKeyLen2
)
{
    uint8_t u8MuChannel;
    hseSrvDescriptor_t *pHseSrvDesc;
    hseExportKeySrv_t *pExportKeyReq;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

    /* Get a free channel on MU0 */
    u8MuChannel = Hse_Ip_GetFreeChannel(APP_MU_INSTANCE_U8);
    if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
    {
    	goto exit;
    }

    /* Complete the service descriptor placed in shared memory */
    pHseSrvDesc = &MbedTLS_aSrvDescriptor[u8MuChannel];
    memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));
    pExportKeyReq = &(pHseSrvDesc->hseSrv.exportKeyReq);

#if defined (D_CACHE_ENABLE_MBEDTLS)
	uint8_t *pAlignKey0 		= NULL;
	uint8_t *pAlignKey1 		= NULL ;
	uint8_t *pAlignKey2 		= NULL ;
	uint16_t nonSgtBuffLen 		= 0;

    if(NULL_PTR != pKey0)
    {
    	/* Check if cached buffer allocation is required*/
    	nonSgtBuffLen = alignNonSgtBuff(pKey0, *pKeyLen0, 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
    		pAlignKey0 = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignKey0)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignKey0, *pKeyLen0);


			/* Invalidate Output Data Buffer */
    		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pAlignKey0, *pKeyLen0);
			pExportKeyReq->pKey[0] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignKey0));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pKey0, *pKeyLen0);


    		/* Invalidate Output Data Buffer */
    		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pKey0, *pKeyLen0);
    		pExportKeyReq->pKey[0] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKey0));
    	}
    }

    if(NULL_PTR != pKey1)
    {
    	/* Check if cached buffer allocation is required*/
    	nonSgtBuffLen = alignNonSgtBuff(pKey1, *pKeyLen1, 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
    		pAlignKey1 = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignKey1)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignKey1, *pKeyLen1);


    		/* Invalidate Output Data Buffer */
			Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pAlignKey1, *pKeyLen1);
			pExportKeyReq->pKey[1] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignKey1));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pKey1, *pKeyLen1);


    		/* Invalidate Output Data Buffer */
			Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pKey1, *pKeyLen1);
    		pExportKeyReq->pKey[1] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKey1));
    	}
    }

    if(NULL_PTR != pKey2)
    {
    	/* Check if cached buffer allocation is required*/
		nonSgtBuffLen = alignNonSgtBuff(pKey2, *pKeyLen2, 32);
		if(nonSgtBuffLen != NO_BUFF_ALLOC)
		{
			pAlignKey2 = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignKey2)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA,FALSE, (uint32_t)pAlignKey2, *pKeyLen2);

			/* Invalidate Output Data Buffer */
			Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pAlignKey2, *pKeyLen2);
			pExportKeyReq->pKey[2] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignKey2));
			nonSgtBuffLen = 0;
		}
		else
		{
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pKey2, *pKeyLen2);

			/* Invalidate Output Data Buffer */
			Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pKey2, *pKeyLen2);
			pExportKeyReq->pKey[2] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKey2));
		}
    }

	if(NULL_PTR != pKeyLen0)
	{
		/* Copy input key len to un-cached memory */
		pAlignKeyLen0[0] = *pKeyLen0;
		pExportKeyReq->pKeyLen[0]  = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignKeyLen0));
	}

	if(NULL_PTR != pKeyLen1)
	{
		/* Copy input key len to un-cached memory */
		pAlignKeyLen1[0] = *pKeyLen1;
		pExportKeyReq->pKeyLen[1] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignKeyLen1));
	}

	if(NULL_PTR != pKeyLen2)
	{
		/* Copy input key len to un-cached memory */
		pAlignKeyLen2[0] = *pKeyLen2;
		pExportKeyReq->pKeyLen[2] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignKeyLen2));
	}

#endif
#if defined (S32N55)
	pHseSrvDesc->srvId              =  HSE_SRV_ID_KEY_EXPORT;
#else
    pHseSrvDesc->srvId              = HSE_SRV_ID_EXPORT_KEY;
#endif
    pExportKeyReq->targetKeyHandle  = targetKeyHandle;
    pExportKeyReq->pKeyInfo         = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKeyInfo));

#if !defined (D_CACHE_ENABLE_MBEDTLS)
    pExportKeyReq->pKey[0]          = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKey0));
    pExportKeyReq->pKeyLen[0]       = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKeyLen0));
    pExportKeyReq->pKey[1]          = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKey1));
    pExportKeyReq->pKeyLen[1]       = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKeyLen1));
    pExportKeyReq->pKey[2]          = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKey2));
    pExportKeyReq->pKeyLen[2]       = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKeyLen2));
#endif

    /* Key imported in plain - not encrypted => cipherKeyHandle = HSE_INVALID_KEY_HANDLE */
    pExportKeyReq->cipher.cipherKeyHandle   = HSE_INVALID_KEY_HANDLE;
    /* Key imported without authentication - not signed => authKeyHandle = HSE_INVALID_KEY_HANDLE */
    pExportKeyReq->keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;

	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

    /* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

#if defined(D_CACHE_ENABLE_MBEDTLS)
    if(srvResponse == HSE_SRV_RSP_OK)
    {
		if(0 != pAlignKeyLen0[0])
		{
			memcpy(pKeyLen0, pAlignKeyLen0, sizeof(uint32_t));
		}

		if(0 != pAlignKeyLen1[0])
		{
			memcpy(pKeyLen1, pAlignKeyLen1, sizeof(uint32_t));
		}

		if(0 != pAlignKeyLen2[0])
		{
			memcpy(pKeyLen2, pAlignKeyLen2, sizeof(uint32_t));
		}

		if(NULL_PTR != pAlignKey0)
		{
			memcpy(pKey0, pAlignKey0, *pKeyLen0);
		}

		if(NULL_PTR != pAlignKey1)
		{
			memcpy(pKey1, pAlignKey1, *pKeyLen1);
		}

		if(NULL_PTR != pAlignKey2)
		{
			memcpy(pKey2, pAlignKey2, *pKeyLen2);
		}
    }
   #endif
exit:

#if defined(D_CACHE_ENABLE_MBEDTLS)
    /* Free allocated memory */
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
* Description:  Exports a key given the key handle
************************************************************************************************/
hseSrvResponse_t HSE_ExportEncKey
(
    hseKeyHandle_t targetKeyHandle,
    hseKeyInfo_t *pKeyInfo,
	cipher_t *cipherParam,
	keyContainer_t *keyContainerParam,
    uint8_t *pKey0, uint32_t *pKeyLen0,
    uint8_t *pKey1, uint32_t *pKeyLen1,
    uint8_t *pKey2, uint32_t *pKeyLen2
)
{
    uint8_t u8MuChannel;
    hseSrvDescriptor_t *pHseSrvDesc;
    hseExportKeySrv_t *pExportKeyReq;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

    /* Get a free channel on MU0 */
    u8MuChannel = Hse_Ip_GetFreeChannel(APP_MU_INSTANCE_U8);
    if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
    {
    	goto exit;
    }

    /* Complete the service descriptor placed in shared memory */
    pHseSrvDesc = &MbedTLS_aSrvDescriptor[u8MuChannel];
    memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));
    pExportKeyReq = &(pHseSrvDesc->hseSrv.exportKeyReq);

#if defined (D_CACHE_ENABLE_MBEDTLS)
	uint8_t *pAlignKey0			= NULL;
	uint8_t *pAlignKey1			= NULL;
	uint8_t *pAlignKey2			= NULL;
	uint16_t nonSgtBuffLen		= 0;

	/* Get the decrypted key size */
    hseKeyInfo_t keyInfo;
    uint32_t outEncLen;
    srvResponse = HSE_GetKeyInfo(targetKeyHandle, &keyInfo);
    if(HSE_SRV_RSP_OK == srvResponse)
    {
    	outEncLen = HSE_BITS_TO_BYTES(keyInfo.keyBitLen);
    }
    else
    {
		goto exit;
    }

	if(NULL_PTR != pKeyInfo)
	{
		/* Invalidate output data buffer */

		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pKeyInfo, sizeof(hseKeyInfo_t));

		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pKeyInfo, sizeof(hseKeyInfo_t));
	}

    if(NULL_PTR != pKey0)
    {
    	/* Check if cached buffer allocation is required*/
    	nonSgtBuffLen = alignNonSgtBuff(pKey0, *pKeyLen0, 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
    		pAlignKey0 = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignKey0)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE,(uint32_t)pAlignKey0, *pKeyLen0);

			/* Invalidate Output Data Buffer */
    		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pAlignKey0, *pKeyLen0);
			pExportKeyReq->pKey[0] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignKey0));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pKey0, *pKeyLen0);

    		/* Invalidate Output Data Buffer */
    		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pKey0, *pKeyLen0);
    		pExportKeyReq->pKey[0] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKey0));
    	}
    }

    if(NULL_PTR != pKey1)
    {
    	/* Check if cached buffer allocation is required*/
    	nonSgtBuffLen = alignNonSgtBuff(pKey1, *pKeyLen1, 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
    		pAlignKey1 = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignKey1)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignKey1, *pKeyLen1);


    		/* Invalidate Output Data Buffer */
			Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pAlignKey1, *pKeyLen1);
			pExportKeyReq->pKey[1] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignKey1));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pKey1, *pKeyLen1);

    		/* Invalidate Output Data Buffer */
			Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pKey1, *pKeyLen1);
    		pExportKeyReq->pKey[1] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKey1));
    	}
    }

    if(NULL_PTR != pKey2)
    {
    	/* Check if cached buffer allocation is required*/
		nonSgtBuffLen = alignNonSgtBuff(pKey2, outEncLen, 32);
		if(nonSgtBuffLen != NO_BUFF_ALLOC)
		{
			pAlignKey2 = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignKey2)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignKey2, outEncLen);


			/* Invalidate Output Data Buffer */
			Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pAlignKey2, outEncLen);
			pExportKeyReq->pKey[2] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignKey2));
			nonSgtBuffLen = 0;
		}
		else
		{
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pKey2, outEncLen);

			/* Invalidate Output Data Buffer */
			Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pKey2, outEncLen);
			pExportKeyReq->pKey[2] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKey2));
		}
    }

	if(NULL_PTR != pKeyLen0)
	{
		/* Copy input key len to un-cached memory */
		pAlignKeyLen0[0] = *pKeyLen0;
		pExportKeyReq->pKeyLen[0]  = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignKeyLen0));
	}

	if(NULL_PTR != pKeyLen1)
	{
		/* Copy input key len to un-cached memory */
		pAlignKeyLen1[0] = *pKeyLen1;
		pExportKeyReq->pKeyLen[1] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignKeyLen1));
	}

	if(NULL_PTR != pKeyLen2)
	{
		/* Copy input key len to un-cached memory */
		pAlignKeyLen2[0] = *pKeyLen2;
		pExportKeyReq->pKeyLen[2] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignKeyLen2));
	}

#else /* ! D_CACHE_ENABLE_MBEDTLS */
    pExportKeyReq->pKey[0]          = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKey0));
    pExportKeyReq->pKeyLen[0]       = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKeyLen0));
    pExportKeyReq->pKey[1]          = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKey1));
    pExportKeyReq->pKeyLen[1]       = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKeyLen1));
    pExportKeyReq->pKey[2]          = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKey2));
    pExportKeyReq->pKeyLen[2]       = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKeyLen2));
#endif /* D_CACHE_ENABLE_MBEDTLS */

#if defined (S32N55)
	pHseSrvDesc->srvId              =  HSE_SRV_ID_KEY_EXPORT;
#else
    pHseSrvDesc->srvId              = HSE_SRV_ID_EXPORT_KEY;
#endif
    pExportKeyReq->targetKeyHandle  = targetKeyHandle;
    pExportKeyReq->pKeyInfo         = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pKeyInfo));

    if(NULL_PTR != cipherParam)
    {
    	pExportKeyReq->cipher.cipherKeyHandle = cipherParam->cipherKeyHandle;
    	pExportKeyReq->cipher.cipherScheme = cipherParam->cipherScheme;
    }
    else
    {
    	/* Key imported in plain - not encrypted => cipherKeyHandle = HSE_INVALID_KEY_HANDLE */
    	pExportKeyReq->cipher.cipherKeyHandle = HSE_INVALID_KEY_HANDLE;
    }

    if(NULL_PTR != keyContainerParam)
    {
    	pExportKeyReq->keyContainer.authKeyHandle = keyContainerParam->authKeyHandle;
    	pExportKeyReq->keyContainer.authScheme = keyContainerParam->authScheme;
    }
    else
    {
    	 /* Key imported without authentication - not signed => authKeyHandle = HSE_INVALID_KEY_HANDLE */
    	pExportKeyReq->keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;
    }

	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

    /* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

exit:

#if defined(D_CACHE_ENABLE_MBEDTLS)

    if(srvResponse == HSE_SRV_RSP_OK)
    {
    	if(0 != pAlignKeyLen0[0])
    	{
    		memcpy(pKeyLen0, pAlignKeyLen0, sizeof(uint32_t));
    	}

    	if(0 != pAlignKeyLen1[0])
    	{
    		memcpy(pKeyLen1, pAlignKeyLen1, sizeof(uint32_t));
    	}

    	if(0 != pAlignKeyLen2[0])
    	{
    		memcpy(pKeyLen2, pAlignKeyLen2, sizeof(uint32_t));
    	}

    	if(NULL_PTR != pAlignKey0)
    	{
    		memcpy(pKey0, pAlignKey0, *pKeyLen0);
    	}

    	if(NULL_PTR != pAlignKey1)
    	{
    		memcpy(pKey1, pAlignKey1, *pKeyLen1);
    	}

    	if(NULL_PTR != pAlignKey2)
    	{
    		memcpy(pKey2, pAlignKey2, *pKeyLen2);
    	}
    }

    /* Free allocated memory */
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
* Description: Encrypt and export pre-master secret
************************************************************************************************/
hseSrvResponse_t HSE_EncryptPms
(
	hseKeyHandle_t targetKeyHandle,
	cipher_t *cipherParam,
	uint8_t *pOutEncPms, uint32_t *encPmsLen
)
{
	keyContainer_t keyContainerParam = {0};

	/* Input parameters sanity check */
	if ((NULL == cipherParam) || (NULL == pOutEncPms) || (NULL == encPmsLen))
	{
		return HSE_SRV_RSP_INVALID_PARAM;
	}

    /* Key imported without authentication - not signed => authKeyHandle = HSE_INVALID_KEY_HANDLE */
    keyContainerParam.authKeyHandle = HSE_INVALID_KEY_HANDLE;

    return HSE_ExportEncKey(targetKeyHandle, NULL,
    						cipherParam, &keyContainerParam,
							NULL, 0U, NULL, 0U,
    						pOutEncPms, encPmsLen);
}

/*************************************************************************************************
* Description:  Exports an ECC Public Key using Private key handle
************************************************************************************************/
hseSrvResponse_t HSE_ExportEccPubKey
(
    hseKeyHandle_t handle,
    hseEccCurveId_t eccCurveId,
	uint16_t keyBitLen,
    uint8_t* pPubKey
)
{
    /* Get the public key length */
    uint32_t pubKeyLen = 0U;

	/* Input parameters sanity check */
	if (NULL == pPubKey)
	{
		return HSE_SRV_RSP_INVALID_PARAM;
	}

	if(eccCurveId == HSE_EC_USER_CURVE1)
	{
	    /* Get the public key length */
	    pubKeyLen = (BITS_TO_BYTES(keyBitLen))*2U;
	}
	else
	{
	    /* Get the public key length */
	    pubKeyLen = GetPubKeyLen(eccCurveId);
	}

    return HSE_ExportKey(handle, NULL, pPubKey, &pubKeyLen, NULL, 0UL, NULL, 0U);
}

#ifdef __cplusplus
}
#endif
