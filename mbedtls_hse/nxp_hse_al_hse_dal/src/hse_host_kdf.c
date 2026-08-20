/**
 *   @file    	hse_host_kdf.c
 *
 *   @brief   	This file contains wrappers for KDF services
 *   @details
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
#if defined(D_CACHE_ENABLE_MBEDTLS)
#include "Cache_Ip.h"
#include "alignment.h"
#endif /* D_CACHE_ENABLE */

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

/*==================================================================================================
 *                                       LOCAL FUNCTIONS
 ==================================================================================================*/

/*==================================================================================================
 *                                       GLOBAL FUNCTIONS
 ==================================================================================================*/

/*******************************************************************************
 * Description: Copy a symmetric key (AES/HMAC) from a
 * SHARED_SECRET slot (output of KDF)
 ******************************************************************************/
hseSrvResponse_t HSE_KeyDeriveCopyKey
(
    hseKeyHandle_t      keyHandle,
    uint16_t            startOffset,
    hseKeyHandle_t      targetKeyHandle,
    hseKeyInfo_t        keyInfo
)
{
    uint8_t u8MuChannel;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

    /* Get a free channel on u8MuInstance */
    u8MuChannel = Hse_Ip_GetFreeChannel(APP_MU_INSTANCE_U8);
    if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
    {
    	goto exit;
    }

	/*note: which MU channel need to specify?*/
    hseSrvDescriptor_t *pHseSrvDesc = &MbedTLS_aSrvDescriptor[MU_CH1];

    hseKeyDeriveCopyKeySrv_t *pExtractKeySrv = &(pHseSrvDesc->hseSrv.keyDeriveCopyKeyReq);

    memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));
    pHseSrvDesc->srvId = HSE_SRV_ID_KEY_DERIVE_COPY;

    pExtractKeySrv->keyHandle = keyHandle;
    pExtractKeySrv->startOffset = startOffset;
    pExtractKeySrv->targetKeyHandle = targetKeyHandle;
    pExtractKeySrv->keyInfo = keyInfo;

	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

    /*note: which MU channel need to specify?*/
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, MU_CH1, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

exit:
    return srvResponse;
}

hseSrvResponse_t HSE_Tls12Prf
(
    hseKdfTLS12PrfScheme_t *pKdfScheme
)
{
    uint8_t u8MuChannel;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;
#if defined(D_CACHE_ENABLE_MBEDTLS)
	uint8_t *pAlignSeed = NULL;
	uint8_t *pAlignLabel = NULL ;
	uint8_t *pAlignOut = NULL ;
	uint16_t nonSgtBuffLen = 0;
#endif /* defined(D_CACHE_ENABLE) */

    /* Get a free channel on u8MuInstance */
    u8MuChannel = Hse_Ip_GetFreeChannel(APP_MU_INSTANCE_U8);
    if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
    {
    	goto exit;
    }

	hseSrvDescriptor_t *pHseSrvDesc = &MbedTLS_aSrvDescriptor[u8MuChannel];
    hseKeyDeriveSrv_t* pDeriveKeySrv = &(pHseSrvDesc->hseSrv.keyDeriveReq);
    memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));

#if defined (D_CACHE_ENABLE_MBEDTLS)
    if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(pKdfScheme->pSeed))
    {
    	nonSgtBuffLen = alignNonSgtBuff(NXP_HSE_HOST_ADDR_TO_PTR(pKdfScheme->pSeed), pKdfScheme->seedLength, 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
			/* Flush Input Data Buffer to memory */
    		pAlignSeed = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignSeed)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		memcpy(pAlignSeed, NXP_HSE_HOST_ADDR_TO_PTR(pKdfScheme->pSeed), pKdfScheme->seedLength);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignSeed, pKdfScheme->seedLength);
			pDeriveKeySrv->sch.TLS12Prf.pSeed = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignSeed));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
			/* Flush Input Data Buffer to memory */
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pKdfScheme->pSeed, pKdfScheme->seedLength);
			pDeriveKeySrv->sch.TLS12Prf.pSeed = pKdfScheme->pSeed;
    	}
    }

    if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(pKdfScheme->pLabel))
    {
    	nonSgtBuffLen = alignNonSgtBuff(NXP_HSE_HOST_ADDR_TO_PTR(pKdfScheme->pLabel), pKdfScheme->labelLength, 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
			/* Flush Input Data Buffer to memory */
    		pAlignLabel = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignLabel)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		memcpy(pAlignLabel, NXP_HSE_HOST_ADDR_TO_PTR(pKdfScheme->pLabel), pKdfScheme->labelLength);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignLabel, pKdfScheme->labelLength);
			pDeriveKeySrv->sch.TLS12Prf.pLabel = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignLabel));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
			/* Flush Input Data Buffer to memory */
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pKdfScheme->pLabel, pKdfScheme->labelLength);
			pDeriveKeySrv->sch.TLS12Prf.pLabel = pKdfScheme->pLabel;
    	}
    }

    if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(pKdfScheme->pOutput))
    {
    	nonSgtBuffLen = alignNonSgtBuff(NXP_HSE_HOST_ADDR_TO_PTR(pKdfScheme->pOutput), pKdfScheme->outputLength, 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
			/* Flush Input Data Buffer to memory */
    		pAlignOut = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignOut)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignOut, pKdfScheme->outputLength);

			Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pAlignOut, pKdfScheme->outputLength);
			pDeriveKeySrv->sch.TLS12Prf.pOutput = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignOut));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{

    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pKdfScheme->pOutput, pKdfScheme->outputLength);

			/* Flush Input Data Buffer to memory */
			Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pKdfScheme->pOutput, pKdfScheme->outputLength);
			pDeriveKeySrv->sch.TLS12Prf.pOutput = pKdfScheme->pOutput;
    	}
    }
#endif
    /* Prepare Descriptor */
    pHseSrvDesc->srvId 							= HSE_SRV_ID_KEY_DERIVE;
    pDeriveKeySrv->kdfAlgo 						= HSE_KDF_ALGO_TLS12PRF;
    pDeriveKeySrv->sch.TLS12Prf.srcKeyHandle 	= pKdfScheme->srcKeyHandle;
    pDeriveKeySrv->sch.TLS12Prf.targetKeyHandle = pKdfScheme->targetKeyHandle;
    pDeriveKeySrv->sch.TLS12Prf.keyMatLength 	= pKdfScheme->keyMatLength;
    pDeriveKeySrv->sch.TLS12Prf.seedLength 		= pKdfScheme->seedLength;
    pDeriveKeySrv->sch.TLS12Prf.labelLength 	= pKdfScheme->labelLength;
    pDeriveKeySrv->sch.TLS12Prf.hmacHash 		= pKdfScheme->hmacHash;
    pDeriveKeySrv->sch.TLS12Prf.outputLength 	= pKdfScheme->outputLength;
    pDeriveKeySrv->sch.TLS12Prf.pskKeyHandle	= pKdfScheme->pskKeyHandle;
    pDeriveKeySrv->sch.TLS12Prf.tlsPskUsage		= pKdfScheme->tlsPskUsage;

#if !defined (D_CACHE_ENABLE_MBEDTLS)
    pDeriveKeySrv->sch.TLS12Prf.pSeed 			= pKdfScheme->pSeed;
    pDeriveKeySrv->sch.TLS12Prf.pLabel 			= pKdfScheme->pLabel;
    pDeriveKeySrv->sch.TLS12Prf.pOutput 		= pKdfScheme->pOutput;
#endif

	/* Build the request to be sent to Hse Ip layer */
	MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
	MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

	/* Send request to HSE */
	srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, MU_CH1, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

#if defined(D_CACHE_ENABLE_MBEDTLS)
    if(srvResponse == HSE_SRV_RSP_OK)
    {
    	if(NULL_PTR != pAlignOut)
    	{
    		/* Copy data back to application buffer */
    		(void)memcpy(NXP_HSE_HOST_ADDR_TO_PTR(pKdfScheme->pOutput), pAlignOut, pKdfScheme->outputLength);
    	}
    }
#endif

exit:
#if defined(D_CACHE_ENABLE_MBEDTLS)
    if(NULL_PTR != pAlignSeed)
    {
    	nxp_hse_freeH(pAlignSeed);
    	pAlignSeed = NULL;
    }

    if(NULL_PTR != pAlignLabel)
    {
    	nxp_hse_freeH(pAlignLabel);
    	pAlignLabel = NULL;
    }

    if(NULL_PTR != pAlignOut)
    {
    	nxp_hse_freeH(pAlignOut);
    	pAlignOut = NULL;
    }
#endif

    return srvResponse;
}

#ifdef __cplusplus
}
#endif
