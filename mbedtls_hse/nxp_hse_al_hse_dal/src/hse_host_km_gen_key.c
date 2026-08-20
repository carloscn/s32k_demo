/**
*   @file    	hse_host_gen_key.c
*
*   @brief   	This file implements wrappers for key generation service (AES/ECC/RSA) and ECDH.
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
#include "hse_host_km_gen_key.h"
#if defined(D_CACHE_ENABLE_MBEDTLS)
#include "Cache_Ip.h"
#include "alignment.h"
#endif /* D_CACHE_ENABLE */

#ifdef HSE_SPT_KEY_GEN
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

static hseSrvResponse_t ValidateEccCurve_Info(hseEccCurveId_t eccCurveId);

/*==================================================================================================
 *                                       LOCAL FUNCTIONS
 ==================================================================================================*/

/**
 * 	@brief		Validate the Input ECC Curve type
 *
 * 	@param[in]	eccCurveId
 *				ECC Curve ID
 *
 *  @return     HSE_SRV_RSP_NOT_SUPPORTED if curve is not supported
 *  			0 if curve is supported
 *
 */
static hseSrvResponse_t ValidateEccCurve_Info(hseEccCurveId_t eccCurveId)
{
	/* Check for the Input ECC Curve type */
	switch (eccCurveId)
	{
		case HSE_EC_SEC_SECP256R1 :
		case HSE_EC_SEC_SECP384R1 :
		case HSE_EC_SEC_SECP521R1 :
		case HSE_EC_BRAINPOOL_BRAINPOOLP256R1 :
		case HSE_EC_BRAINPOOL_BRAINPOOLP320R1 :
		case HSE_EC_BRAINPOOL_BRAINPOOLP384R1 :
		case HSE_EC_BRAINPOOL_BRAINPOOLP512R1 :
		case HSE_EC_25519_ED25519 :
		case HSE_EC_25519_CURVE25519 :
#ifdef HSE_SPT_EC_448_CURVE448
		case HSE_EC_448_CURVE448:
#endif /* HSE_SPT_EC_448_CURVE448 */

#ifdef HSE_SPT_EC_448_ED448
		case HSE_EC_448_ED448:
#endif /* HSE_SPT_EC_448_ED448 */
		case HSE_EC_USER_CURVE1 :
		case HSE_EC_USER_CURVE2 :
		case HSE_EC_USER_CURVE3 :
		break;
		case HSE_EC_CURVE_NONE:
		default:
			return( HSE_SRV_RSP_NOT_SUPPORTED );
	}
	return 0U;
}

/*==================================================================================================
 *                                       GLOBAL FUNCTIONS
 ==================================================================================================*/

#if defined(HSE_SPT_ECDH) || defined(HSE_SPT_CLASSIC_DH)
/*************************************************************************************************
* Description:  Generate a ECDH/DH Shared Secret
************************************************************************************************/
hseSrvResponse_t HSE_GenerateDhSharedSecret
(
    hseKeyHandle_t privKeyHandle,
    hseKeyHandle_t pubKeyHandle,
    hseKeyHandle_t targetKeyHandle
)
{
    uint8_t u8MuChannel;
    hseSrvDescriptor_t *pHseSrvDesc;
    hseDHComputeSharedSecretSrv_t *pDhSrv;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

    /* Get a free channel on MU0 */
    u8MuChannel = Hse_Ip_GetFreeChannel(APP_MU_INSTANCE_U8);
    if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
    {
    	goto exit;
    }

    /* Alloc free descriptor */
    pHseSrvDesc = &MbedTLS_aSrvDescriptor[u8MuChannel];

    pDhSrv = &(pHseSrvDesc->hseSrv.dhComputeSecretReq);
    memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));

    /* Complete service parameters */
    pHseSrvDesc->srvId 			= HSE_SRV_ID_DH_COMPUTE_SHARED_SECRET;
    pDhSrv->privKeyHandle 		= privKeyHandle;
    pDhSrv->peerPubKeyHandle 	= pubKeyHandle;
    pDhSrv->targetKeyHandle 	= targetKeyHandle;

	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

    /* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

exit:
    return srvResponse; 
}
#endif /* HSE_SPT_ECDH || HSE_SPT_CLASSIC_DH */

#ifdef HSE_SPT_ECC
/*************************************************************************************************
* Description:  Load User Defined Curve
************************************************************************************************/
hseSrvResponse_t Hse_LoadEccUserCurve
(
	hseEccCurveId_t eccCurveId,
	hseKeyBits_t pBitLen,
	hseKeyBits_t nBitLen,
	const uint8_t    *pA,
	const uint8_t    *pB,
	const uint8_t    *pP,
	const uint8_t    *pN,
	const uint8_t    *pG
)
{
    uint8_t u8MuChannel;
    hseLoadEccCurveSrv_t *pLoadEccCurveSrv;
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
    pLoadEccCurveSrv = &(pHseSrvDesc->hseSrv.loadEccCurveReq);
    memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));

#if defined (D_CACHE_ENABLE_MBEDTLS)
	uint8_t *pAlign_A = NULL, *pAlign_B = NULL, *pAlign_P = NULL,\
			*pAlign_N = NULL, *pAlign_G = NULL;
	uint16_t nonSgtBuffLen = 0U;
	/* The HSE expects an array of size 2 * #HSE_BITS_TO_BYTES(#pBitLen) in G */
	uint32_t G_len = (2U * BITS_TO_BYTES(pBitLen));

	if(NULL_PTR != pA)
	{
		nonSgtBuffLen = alignNonSgtBuff(pA, pBitLen, 32);
		if(nonSgtBuffLen != NO_BUFF_ALLOC)
		{
			/* Flush Input Data Buffer to memory */
			pAlign_A = nxp_hse_callocH(nonSgtBuffLen, 32);
			if(NULL_PTR == pAlign_A)
			{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
			}

			memcpy(pAlign_A, pA, pBitLen);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlign_A, pBitLen);
			pLoadEccCurveSrv->pA 		 = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlign_A));
			nonSgtBuffLen = 0;
		}
		else
		{
			/* Flush Input Data Buffer to memory */
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pA, pBitLen);
			pLoadEccCurveSrv->pA 		 = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pA));
		}
	}

	if(NULL_PTR != pB)
	{
		nonSgtBuffLen = alignNonSgtBuff(pB, pBitLen, 32);
		if(nonSgtBuffLen != NO_BUFF_ALLOC)
		{
			/* Flush Input Data Buffer to memory */
			pAlign_B = nxp_hse_callocH(nonSgtBuffLen, 32);
			if(NULL_PTR == pAlign_B)
			{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
			}

			memcpy(pAlign_B, pB, pBitLen);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlign_B, pBitLen);
			pLoadEccCurveSrv->pB 		 = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlign_B));
			nonSgtBuffLen = 0;
		}
		else
		{
			/* Flush Input Data Buffer to memory */
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pB, pBitLen);
			pLoadEccCurveSrv->pB 		 = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pB));
		}
	}

	if(NULL_PTR != pP)
	{
		nonSgtBuffLen = alignNonSgtBuff(pP, pBitLen, 32);
		if(nonSgtBuffLen != NO_BUFF_ALLOC)
		{
			/* Flush Input Data Buffer to memory */
			pAlign_P = nxp_hse_callocH(nonSgtBuffLen, 32);
			if(NULL_PTR == pAlign_P)
			{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
			}

			memcpy(pAlign_P, pP, pBitLen);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlign_P, pBitLen);
			pLoadEccCurveSrv->pP 		 = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlign_P));
			nonSgtBuffLen = 0;
		}
		else
		{
			/* Flush Input Data Buffer to memory */
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pP, pBitLen);
			pLoadEccCurveSrv->pP 		 = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pP));
		}
	}

	if(NULL_PTR != pN)
	{
		nonSgtBuffLen = alignNonSgtBuff(pN, nBitLen, 32);
		if(nonSgtBuffLen != NO_BUFF_ALLOC)
		{
			/* Flush Input Data Buffer to memory */
			pAlign_N = nxp_hse_callocH(nonSgtBuffLen, 32);
			if(NULL_PTR == pAlign_N)
			{
				return HSE_SRV_RSP_MEMORY_FAILURE;
			}

			memcpy(pAlign_N, pN, nBitLen);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlign_N, nBitLen);
			pLoadEccCurveSrv->pN 		 = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlign_N));
			nonSgtBuffLen = 0;
		}
		else
		{
			/* Flush Input Data Buffer to memory */
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pN, nBitLen);
			pLoadEccCurveSrv->pN 		 = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pN));
		}
	}

	if(NULL_PTR != pG)
	{
		nonSgtBuffLen = alignNonSgtBuff(pG, G_len, 32);
		if(nonSgtBuffLen != NO_BUFF_ALLOC)
		{
			/* Flush Input Data Buffer to memory */
			pAlign_G = nxp_hse_callocH(nonSgtBuffLen, 32);
			if(NULL_PTR == pAlign_G)
			{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
			}

			memcpy(pAlign_G, pG, G_len);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlign_G, G_len);
			pLoadEccCurveSrv->pG 		 = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlign_G));
			nonSgtBuffLen = 0;
		}
		else
		{
			/* Flush Input Data Buffer to memory */
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pG, G_len);
			pLoadEccCurveSrv->pG 		 = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pG));
		}
	}

#endif /* D_CACHE_ENABLE */

    /* Complete service parameters */
	pHseSrvDesc->srvId 			 = HSE_SRV_ID_LOAD_ECC_CURVE;
	pLoadEccCurveSrv->eccCurveId = eccCurveId;
	pLoadEccCurveSrv->pBitLen 	 = pBitLen;
	pLoadEccCurveSrv->nBitLen 	 = nBitLen;
#if !defined(D_CACHE_ENABLE_MBEDTLS)
	pLoadEccCurveSrv->pA 		 = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pA));
	pLoadEccCurveSrv->pB 		 = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pB));
	pLoadEccCurveSrv->pP 		 = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pP));
	pLoadEccCurveSrv->pN 		 = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pN));
	pLoadEccCurveSrv->pG 		 = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pG));
#endif

	/* Build the request to be sent to Hse Ip layer */
	MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
	MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

	/* Send the request synchronously */
	srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

exit:

#if defined(D_CACHE_ENABLE_MBEDTLS)
	/* Free memory */
	if(NULL_PTR != pAlign_A)
	{
		nxp_hse_freeH(pAlign_A);
		pAlign_A = NULL;
	}
	if(NULL_PTR != pAlign_B)
	{
		nxp_hse_freeH(pAlign_B);
		pAlign_B = NULL;
	}
	if(NULL_PTR != pAlign_P)
	{
		nxp_hse_freeH(pAlign_P);
		pAlign_P = NULL;
	}
	if(NULL_PTR != pAlign_N)
	{
		nxp_hse_freeH(pAlign_N);
		pAlign_N = NULL;
	}
	if(NULL_PTR != pAlign_G)
	{
		nxp_hse_freeH(pAlign_G);
		pAlign_G = NULL;
	}
#endif

	return srvResponse;
}
#endif /* HSE_SPT_ECC */
#ifdef HSE_SPT_SYM_RND_KEY_GEN
/*************************************************************************************************
* Description:  Generate a symmetric random key
************************************************************************************************/
hseSrvResponse_t HSE_GenerateSymKey
(
    hseKeyHandle_t keyHandle,
    hseKeyInfo_t keyInfo
)
{
    uint8_t u8MuChannel;
    hseSrvDescriptor_t *pHseSrvDesc;
    hseKeyGenerateSrv_t* pKeyGenSrv;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

    /* Get a free channel on MU0 */
    u8MuChannel = Hse_Ip_GetFreeChannel(APP_MU_INSTANCE_U8);
    if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
    {
    	goto exit;
    }

    /* Alloc free descriptor */
    pHseSrvDesc = &MbedTLS_aSrvDescriptor[u8MuChannel];

    pKeyGenSrv = &(pHseSrvDesc->hseSrv.keyGenReq);
    memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));

    /* Complete service parameters */
    pHseSrvDesc->srvId 			= HSE_SRV_ID_KEY_GENERATE;
    pKeyGenSrv->keyGenScheme 	= HSE_KEY_GEN_SYM_RANDOM_KEY;
    pKeyGenSrv->targetKeyHandle = keyHandle;
#if defined(S32N55)
    pKeyGenSrv->pKeyInfo 		= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(&keyInfo));
#else
    pKeyGenSrv->keyInfo 		= keyInfo;
#endif
	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

    /* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

exit:
    return srvResponse;    
}
#endif /* HSE_SPT_SYM_RND_KEY_GEN */

#ifdef HSE_SPT_ECC_KEY_PAIR_GEN
/*************************************************************************************************
* Description:  Generate an ECC key pair on the curve specified by key info
************************************************************************************************/
hseSrvResponse_t HSE_GenerateEccKey
(
    hseKeyHandle_t keyHandle,
    hseKeyInfo_t keyInfo,
    uint8_t *pGeneratedPub
)
{
    uint8_t u8MuChannel;
    hseSrvDescriptor_t *pHseSrvDesc;
    hseKeyGenerateSrv_t* pKeyGenSrv;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

    /* Validate the Input ECC Curve type */
    srvResponse = ValidateEccCurve_Info(keyInfo.specific.eccCurveId);
    if(srvResponse == HSE_SRV_RSP_NOT_SUPPORTED)
    {
    	goto exit;
    }

    /* Get a free channel on u8MuInstance */
    u8MuChannel = Hse_Ip_GetFreeChannel(APP_MU_INSTANCE_U8);
    if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
    {
    	goto exit;
    }

    /* Complete the service descriptor placed in shared memory */
    pHseSrvDesc = &MbedTLS_aSrvDescriptor[u8MuChannel];

    pKeyGenSrv = &(pHseSrvDesc->hseSrv.keyGenReq);
    memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));

#if defined(D_CACHE_ENABLE_MBEDTLS)

    uint8_t *pAlignPubKey = NULL ;
	uint16_t nonSgtBuffLen = 0;
	uint16_t pubKeyLen;

    if(NULL_PTR != pGeneratedPub)
    {
    	if((keyInfo.specific.eccCurveId == HSE_EC_25519_CURVE25519)
#ifdef HSE_SPT_EC_448_CURVE448
    			||(keyInfo.specific.eccCurveId == HSE_EC_448_CURVE448)
#endif /* HSE_SPT_EC_448_CURVE448 */
    	)
    	{
    		pubKeyLen = BITS_TO_BYTES(keyInfo.keyBitLen);
    	}
    	else if ((keyInfo.specific.eccCurveId == HSE_EC_25519_ED25519)
#ifdef HSE_SPT_EC_448_ED448
    			||(keyInfo.specific.eccCurveId == HSE_EC_448_ED448)
#endif /* HSE_SPT_EC_448_ED448 */
				)
    	{
    		pubKeyLen = (2 * BITS_TO_BYTES(keyInfo.keyBitLen) );
    	}
    	else
    	{
    		pubKeyLen = (2 * BITS_TO_BYTES(keyInfo.keyBitLen) )+ 1;
    	}

    	nonSgtBuffLen = alignNonSgtBuff(pGeneratedPub, pubKeyLen, 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
    		pAlignPubKey = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignPubKey)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32)pAlignPubKey, pubKeyLen);

    		/* Invalidate Output Data Buffer */
    		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32)pAlignPubKey, pubKeyLen);
    		pKeyGenSrv->sch.eccKey.pPubKey = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignPubKey));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32)pGeneratedPub, pubKeyLen);


    		/* Invalidate Output Data Buffer */
        	Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32)pGeneratedPub, pubKeyLen);
        	pKeyGenSrv->sch.eccKey.pPubKey = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pGeneratedPub));
    	}
    }

#endif /* D_CACHE_ENABLE */

    pHseSrvDesc->srvId 			= HSE_SRV_ID_KEY_GENERATE;
    pKeyGenSrv->keyGenScheme 	= HSE_KEY_GEN_ECC_KEY_PAIR;
    pKeyGenSrv->targetKeyHandle = keyHandle;
#if defined(S32N55)
    pKeyGenSrv->pKeyInfo 		= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(&keyInfo));
#else
    pKeyGenSrv->keyInfo 		= keyInfo;
#endif
#if !defined (D_CACHE_ENABLE_MBEDTLS)
    /* ECC public key can be returned into an output buffer (optional) */
    pKeyGenSrv->sch.eccKey.pPubKey = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pGeneratedPub));
#endif

	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

    /* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

#if defined (D_CACHE_ENABLE_MBEDTLS)
    if(HSE_SRV_RSP_OK == srvResponse)
    {
        if(NULL_PTR != pAlignPubKey)
        {
        	memcpy(pGeneratedPub, pAlignPubKey, pubKeyLen);
        }
    }
#endif

exit:

#if defined (D_CACHE_ENABLE_MBEDTLS)
    if(NULL_PTR != pAlignPubKey)
    {
    	nxp_hse_freeH(pAlignPubKey);
    	pAlignPubKey = NULL;
    }

#endif

    return srvResponse;
}
#endif /* HSE_SPT_ECC_KEY_PAIR_GEN */

#ifdef HSE_SPT_RSA_KEY_PAIR_GEN
/*************************************************************************************************
* Description:  Generate a RSA key pair with the given public exponent e
************************************************************************************************/
hseSrvResponse_t HSE_GenerateRsaKey
(
    hseKeyHandle_t keyHandle,
    hseKeyInfo_t keyInfo,
    uint32_t eLen,
    uint8_t *pE,
    uint8_t *pN,
	Hse_Ip_pfResponseCallbackType pfnCallback,
	void* pCallbackParam
)
{
    uint8_t u8MuChannel;
    hseSrvDescriptor_t *pHseSrvDesc;
    hseKeyGenerateSrv_t* pKeyGenSrv;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

    /* Get a free channel on MU0 */
    u8MuChannel = Hse_Ip_GetFreeChannel(APP_MU_INSTANCE_U8);
    if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
    {
    	goto exit;
    }

    /* Alloc free descriptor */
    pHseSrvDesc = &MbedTLS_aSrvDescriptor[u8MuChannel];
    pKeyGenSrv = &(pHseSrvDesc->hseSrv.keyGenReq);
    memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));

#if defined (D_CACHE_ENABLE_MBEDTLS)

	uint8_t *pAlignE = NULL ;
	uint8_t *pAlignN = NULL ;
	uint16_t nonSgtBuffLen = 0;

    if(NULL_PTR != pE)
    {
    	nonSgtBuffLen = alignNonSgtBuff(pE, eLen, 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
			/* Flush Input Data Buffer to memory */
    		pAlignE = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignE)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		memcpy(pAlignE, pE, eLen);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignE, eLen);
			pKeyGenSrv->sch.rsaKey.pPubExp = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignE));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
			/* Flush Input Data Buffer to memory */
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pE, eLen);
			pKeyGenSrv->sch.rsaKey.pPubExp = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pE));
    	}
    }

    if(NULL_PTR != pN)
    {
    	nonSgtBuffLen = alignNonSgtBuff(pN, (keyInfo.keyBitLen / 8), 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
    		pAlignN = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignN)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32)pAlignN, (keyInfo.keyBitLen / 8));

    		/* Invalidate Output Data Buffer */
    		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32)pAlignN, (keyInfo.keyBitLen / 8));
			pKeyGenSrv->sch.rsaKey.pModulus = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignN));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32)pN, (keyInfo.keyBitLen / 8));


    		/* Invalidate Output Data Buffer */
        	Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32)pN, (keyInfo.keyBitLen / 8));
			pKeyGenSrv->sch.rsaKey.pModulus = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pN));
    	}
    }

#endif /* D_CACHE_ENABLE */

    /* Complete service parameters */
    pHseSrvDesc->srvId 					= HSE_SRV_ID_KEY_GENERATE;
    pKeyGenSrv->keyGenScheme			= HSE_KEY_GEN_RSA_KEY_PAIR;
    pKeyGenSrv->targetKeyHandle 		= keyHandle;
#if defined (S32N55)
    pKeyGenSrv->pKeyInfo 	= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(&keyInfo));
#else
    pKeyGenSrv->keyInfo 				= keyInfo;
#endif
    /* Public exponent e must be provided */
    pKeyGenSrv->sch.rsaKey.pubExpLength = eLen;

#if !defined (D_CACHE_ENABLE_MBEDTLS)
    pKeyGenSrv->sch.rsaKey.pPubExp 		= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pE));
    /* RSA modulus can be returned into an output buffer (optional) */
    pKeyGenSrv->sch.rsaKey.pModulus 	= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pN));
#endif

	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].pfCallback = pfnCallback;
    MbedTLS_aRequest[u8MuChannel].pCallbackParam = pCallbackParam;

    /* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

#if defined (D_CACHE_ENABLE_MBEDTLS)
    if(HSE_SRV_RSP_OK == srvResponse)
    {
        if(NULL_PTR != pAlignN)
        {
        	memcpy(pN, pAlignN, (keyInfo.keyBitLen / 8));
        }
    }
#endif

exit:

#if defined (D_CACHE_ENABLE_MBEDTLS)
    if(NULL_PTR != pAlignN)
    {
    	nxp_hse_freeH(pAlignN);
    	pAlignN = NULL;
    }

    if(NULL_PTR != pAlignE)
    {
    	nxp_hse_freeH(pAlignE);
    	pAlignE = NULL;
    }
#endif
    return srvResponse;    
}
#endif /* HSE_SPT_RSA_KEY_PAIR_GEN */

#ifdef HSE_SPT_TLS12_RSA_PRE_MASTER_SECRET_GEN
/*************************************************************************************************
* Description:  Generate Shared Secret
************************************************************************************************/
hseSrvResponse_t HSE_GenSharedSecret
(
    hseKeyHandle_t keyHandle,
	uint8_t protocolVersion[TLS12_PROTOCOL_VERSION_LENGTH],
    hseKeyInfo_t keyInfo
)
{
    uint8_t u8MuChannel;
    hseSrvDescriptor_t *pHseSrvDesc;
    hseKeyGenerateSrv_t* pKeyGenSrv;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

    /* Get a free channel on MU0 */
    u8MuChannel = Hse_Ip_GetFreeChannel(APP_MU_INSTANCE_U8);
    if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
    {
    	goto exit;
    }

    /* Alloc free descriptor */
    pHseSrvDesc = &MbedTLS_aSrvDescriptor[u8MuChannel];
    pKeyGenSrv = &(pHseSrvDesc->hseSrv.keyGenReq);
    memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));

    /* Complete service parameters */
    pHseSrvDesc->srvId				= HSE_SRV_ID_KEY_GENERATE;
    pKeyGenSrv->keyGenScheme		= HSE_TLS12_RSA_PRE_MASTER_SECRET_GEN;
    pKeyGenSrv->targetKeyHandle		= keyHandle;
#if defined(S32N55)
    pKeyGenSrv->pKeyInfo		    = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(&keyInfo));
#else
    pKeyGenSrv->keyInfo				= keyInfo;
#endif
    memcpy(pKeyGenSrv->sch.rsaPreMaster.protocolVersion, protocolVersion, TLS12_PROTOCOL_VERSION_LENGTH);

	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

    /* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

exit:
    return srvResponse;
}
#endif /* HSE_SPT_TLS12_RSA_PRE_MASTER_SECRET_GEN */

#ifdef HSE_SPT_CLASSIC_DH_KEY_PAIR_GEN
/*************************************************************************************************
* Description:  Generate DH Key Pair
************************************************************************************************/
hseSrvResponse_t HSE_GenerateDhKeyPair
(
	hseKeyHandle_t keyHandle,
	hseKeyInfo_t keyInfo,
	const uint8_t *pG,
	uint32_t gLen,
	const uint8_t *pMod,
	uint32_t modLen,
	uint8_t *pPub
)
{
    uint8_t u8MuChannel;
    hseSrvDescriptor_t *pHseSrvDesc;
    hseKeyGenerateSrv_t* pKeyGenSrv;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

    /* Get a free channel on MU0 */
    u8MuChannel = Hse_Ip_GetFreeChannel(APP_MU_INSTANCE_U8);
    if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
    {
    	goto exit;
    }

    /* Alloc free descriptor */
    pHseSrvDesc = &MbedTLS_aSrvDescriptor[u8MuChannel];
    pKeyGenSrv = &(pHseSrvDesc->hseSrv.keyGenReq);
    memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));

#if defined (D_CACHE_ENABLE_MBEDTLS)
	uint8_t *pAlignBaseG = NULL;
	uint8_t *pAlignModulus = NULL ;
	uint8_t *pAlignPubKey = NULL ;
	uint16_t nonSgtBuffLen = 0;

    if(NULL_PTR != pG)
    {
    	nonSgtBuffLen = alignNonSgtBuff(pG, gLen, 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
			/* Flush Input Data Buffer to memory */
    		pAlignBaseG = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignBaseG)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		memcpy(pAlignBaseG, pG, gLen);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignBaseG, gLen);
			pKeyGenSrv->sch.classicDhKey.pBaseG = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignBaseG));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
    		/* Flush Input Data Buffer to memory */
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pG, gLen);
    		pKeyGenSrv->sch.classicDhKey.pBaseG = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pG));
    	}
    }
    else
    {
		srvResponse = HSE_SRV_RSP_INVALID_PARAM;
		goto exit;
    }

    if(NULL_PTR != pMod)
    {
    	nonSgtBuffLen = alignNonSgtBuff(pMod, modLen, 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
			/* Flush Input Data Buffer to memory */
    		pAlignModulus = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignModulus)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		memcpy(pAlignModulus, pMod, modLen);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignModulus, modLen);
			pKeyGenSrv->sch.classicDhKey.pModulus = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignModulus));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
    		/* Flush Input Data Buffer to memory */
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pMod, modLen);
    		pKeyGenSrv->sch.classicDhKey.pModulus = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pMod));
    	}
    }
    else
    {
		srvResponse = HSE_SRV_RSP_INVALID_PARAM;
		goto exit;
    }

    if(NULL_PTR != pPub)
    {
    	/* Check if cached buffer allocation is required*/
		nonSgtBuffLen = alignNonSgtBuff(pPub, modLen, 32);
		if(nonSgtBuffLen != NO_BUFF_ALLOC)
		{
			pAlignPubKey = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignPubKey)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignPubKey, modLen);


			/* Invalidate Output Data Buffer */
			Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pAlignPubKey, modLen);
			pKeyGenSrv->sch.classicDhKey.pPubKey = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignPubKey));
			nonSgtBuffLen = 0;
		}
		else
		{

			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pPub, modLen);


			/* Invalidate Output Data Buffer */
			Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pPub, modLen);
			pKeyGenSrv->sch.classicDhKey.pPubKey = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pPub));
		}
    }
    else
    {
		srvResponse = HSE_SRV_RSP_INVALID_PARAM;
		goto exit;
    }
#else  /* ! D_CACHE_ENABLE */
    pKeyGenSrv->sch.classicDhKey.pBaseG				= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pG));
	pKeyGenSrv->sch.classicDhKey.pModulus			= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pMod));
	pKeyGenSrv->sch.classicDhKey.pPubKey			= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pPub));
#endif /* D_CACHE_ENABLE */

    /* Complete service parameters */
    pHseSrvDesc->srvId								= HSE_SRV_ID_KEY_GENERATE;
    pKeyGenSrv->keyGenScheme						= HSE_KEY_GEN_CLASSIC_DH_KEY_PAIR;
    pKeyGenSrv->targetKeyHandle						= keyHandle;
#if defined(S32N55)
    pKeyGenSrv->pKeyInfo		    = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(&keyInfo));
#else
    pKeyGenSrv->keyInfo				= keyInfo;
#endif
	pKeyGenSrv->sch.classicDhKey.baseGLength		= gLen;
	pKeyGenSrv->sch.classicDhKey.modulusLength		= modLen;

	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

    /* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

exit:
#if defined(D_CACHE_ENABLE_MBEDTLS)

	if(srvResponse == HSE_SRV_RSP_OK)
	{
    	if(NULL_PTR != pAlignPubKey)
    	{
    		memcpy(pPub, pAlignPubKey, modLen);
    	}
	}

    /* Free allocated memory */
	if(NULL_PTR != pAlignBaseG)
	{
		nxp_hse_freeH(pAlignBaseG);
		pAlignBaseG = NULL;
	}

	if(NULL_PTR != pAlignModulus)
	{
		nxp_hse_freeH(pAlignModulus);
		pAlignModulus = NULL;
	}

	if(NULL_PTR != pAlignPubKey)
	{
		nxp_hse_freeH(pAlignPubKey);
		pAlignPubKey = NULL;
	}

#endif

    return srvResponse;

}
#endif /* HSE_SPT_CLASSIC_DH_KEY_PAIR_GEN */
#endif /* HSE_SPT_KEY_GEN */

#ifdef __cplusplus
}
#endif
