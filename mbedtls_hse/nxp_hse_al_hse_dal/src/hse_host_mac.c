/**
 *   @file    		hse_host_mac.c
 *
 *   @brief   		This file use verify MAC operation
 *   @details 		This file will generate & verify CMAC & GMAC.
 *
 *   @addtogroup 	[HSE_DAL]
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
#else
/* D_CACHE_ENABLE (chip) is on; D_CACHE_ENABLE_MBEDTLS (SGT path) is off.
 * Descriptor + pointed-to buffers live in cacheable SRAM — clean before HSE
 * reads, invalidate after HSE writes. Raw SCB ops match provision/easy_boot. */
#include "S32K312_SCB.h"
#include "Mcal.h"
#define HSE_HOST_DCACHE_LINE (32U)
static void hse_host_dcache_clean(const void *addr, uint32_t len)
{
    uintptr_t a, end;
    if ((NULL == addr) || (0U == len)) {
        return;
    }
    a = (uintptr_t)addr & ~(uintptr_t)(HSE_HOST_DCACHE_LINE - 1U);
    end = ((uintptr_t)addr + len + (HSE_HOST_DCACHE_LINE - 1U))
          & ~(uintptr_t)(HSE_HOST_DCACHE_LINE - 1U);
    for (; a < end; a += HSE_HOST_DCACHE_LINE) {
        S32_SCB->DCCMVAC = (uint32_t)a;
    }
    __asm volatile ("dsb 0xF" ::: "memory");
    __asm volatile ("isb 0xF" ::: "memory");
}
static void hse_host_dcache_invalidate(const void *addr, uint32_t len)
{
    uintptr_t a, end;
    if ((NULL == addr) || (0U == len)) {
        return;
    }
    a = (uintptr_t)addr & ~(uintptr_t)(HSE_HOST_DCACHE_LINE - 1U);
    end = ((uintptr_t)addr + len + (HSE_HOST_DCACHE_LINE - 1U))
          & ~(uintptr_t)(HSE_HOST_DCACHE_LINE - 1U);
    for (; a < end; a += HSE_HOST_DCACHE_LINE) {
        S32_SCB->DCIMVAC = (uint32_t)a;
    }
    __asm volatile ("dsb 0xF" ::: "memory");
    __asm volatile ("isb 0xF" ::: "memory");
}
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
 * 	@brief		Process MAC request
 *
 * 	@param[in]	accessMode
 *				Specifies the access mode: ONE-PASS, START, UPDATE, FINISH
 *
 * 	@param[in]	streamId
 *				Specifies the stream to use for START, UPDATE, FINISH access modes. Each interface supports
*               a limited number of streams per interface, up to #HSE_STREAM_COUNT
 *
 *	@param[in]	macScheme
 *				Specifies the MAC scheme
 *
 *	@param[in]	authDir
 *				Specifies the direction: generate/verify
 *
 *	@param[in]	inputSgtType
 *				HSE_SGT_OPTION_NONE
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation.
 *
 *	@param[in]	pInput
 *				 Used in all steps, but ignored when #inputLength is zero
 *
 * 	@param[in]	inputLen
 * 				STREAMING USAGE: Used in all steps.
 *            - START: Must be a multiple of block length (for HMAC-hash or AES), or zero. Cannot be zero for HMAC.
 *            - UPDATE: Must be a multiple of block length (for HMAC-hash or AES). Cannot be zero.
 *                  Refrain from issuing the service request, instead of passing zero.
 *            - FINISH: Can be any value (For CMAC & XCBC-MAC, zero length is invalid).
 *
 *           Algorithm block lengths (for STREAMING USAGE):
 *            - CMAC, GMAC, XCBC-MAC: 16
 *            - HMAC, depends on underlying hash:
 *                - MD5, SHA1, SHA2_224, SHA2_256: 64
 *                - SHA2_512_224, SHA2_512_256, SHA2_384, SHA2_512: 128
 *                - SHA3: not supported for HMAC
 *
 *	@param[in/out]	pTag
 *				The output tag for "generate"; the input tag for "verify"
 *
 *	@param[in/out]	pTagLen
 *				Holds the address to a memory location (an uint32_t variable) in which the tag length in bytes is stored
 *				GENERATE:
 *              - On calling service (input), this parameter shall contain the size of the buffer provided by #pTag.
 *              - For GMAC, valid tag lengths are 4, 8, 12, 13, 14, 15 and 16. Tag-lengths greater than 16 will be truncated to 16.
 *              - For HMAC, valid tag lengths are [1, hash-length]. Tag-lengths greater than hash-length will be truncated to hash-length.
 *              - For CMAC & XCBC-MAC, valid tag lengths are [4, cipher-block-length]. Tag-lengths greater than cipher-block-length will be
 *                truncated to cipher-block-length.
 *              - When the request has finished (output), the actual length of the returned value shall be stored.
 *              - VERIFY:
 *              - On calling service (input), this parameter shall contain the tag-length to be verified.
 *              - For GMAC, valid tag lengths are 4, 8, 12, 13, 14, 15 and 16.
 *              - For HMAC, valid tag lengths are [1, hash-length].
 *              - For CMAC & XCBC-MAC, valid tag lengths are [4, cipher block-length].
 *
 *              STREAMING USAGE: Used in FINISH.
 *
 *  @return     The HSE Service response
 *
 */
static hseSrvResponse_t HSE_MacReq
(
    const hseAccessMode_t accessMode,
    const hseStreamId_t streamId,
    const hseMacScheme_t macScheme,
    const hseAuthDir_t authDir,
    const hseSGTOption_t inputSgtType,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLen,
    uint8_t *pTag,
    uint32_t *pTagLen
);

/*==================================================================================================
 *                                       LOCAL FUNCTIONS
 ==================================================================================================*/

/*************************************************************************************************
* Description: Process MAC request
************************************************************************************************/
static hseSrvResponse_t HSE_MacReq
(
    const hseAccessMode_t accessMode,
    const hseStreamId_t streamId,
    const hseMacScheme_t macScheme,
    const hseAuthDir_t authDir,
    const hseSGTOption_t inputSgtType,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLen,
    uint8_t *pTag,
    uint32_t *pTagLen
)
{
    uint8_t u8MuChannel;
    hseMacSrv_t* pMacSrv;
    hseSrvDescriptor_t *pHseSrvDesc;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

    uint32_t pAlignTagLen_32ByteAlignedAddr;
    uint32_t pAlignTag_32ByteAlignedAddr;

    (void)inputSgtType;

    /* Get a free channel on MU0 */
    u8MuChannel = Hse_Ip_GetFreeChannel(APP_MU_INSTANCE_U8);
    if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
    {
    	goto exit;
    }

    /* Alloc free descriptor */
    pHseSrvDesc = &MbedTLS_aSrvDescriptor[u8MuChannel];
    pMacSrv = &(pHseSrvDesc->hseSrv.macReq);
    memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));

#if defined (D_CACHE_ENABLE_MBEDTLS)

	hseSrvSGTNode_t inputSgtTbl;
	uint8_t *pAlignTag = NULL ;
	uint8_t *pAlignTagLen = NULL;
	uint16_t nonSgtBuffLen = 0;

	memset(&inputSgtTbl, 0, sizeof(hseSrvSGTNode_t));

    if(NULL_PTR != pInput)
    {
        if(checkAlignmentReq(pInput, inputLen, 32, &inputSgtTbl) != NO_BUFF_ALLOC)
        {
        	alignInBuff((uint8_t*)pInput, &inputSgtTbl);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)inputSgtTbl.hseSrvSgtList,
					3*sizeof(hseScatterList_t));
        }
        else
        {
    		/* Flush Input Data Buffer to memory */
        	Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, false, (uint32_t)pInput, inputLen);
        	storeAlignBufptr((uint8_t*)pInput, inputLen, &inputSgtTbl );
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)inputSgtTbl.hseSrvSgtList,
					sizeof(hseScatterList_t));
        }
    }

    if(NULL_PTR != pTagLen)
    {
		nonSgtBuffLen = alignNonSgtBuff((uint8_t *)pTagLen, sizeof(uint32_t), 32);
		if(nonSgtBuffLen != NO_BUFF_ALLOC)
		{
			pAlignTagLen = nxp_hse_callocH(nonSgtBuffLen, 32);

    		if(NULL_PTR == pAlignTagLen)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}
			memcpy(pAlignTagLen, pTagLen, sizeof(uint32_t));
			/* Flush Input Data Buffer to memory*/
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, TRUE, (uint32_t)pAlignTagLen, sizeof(uint32_t));
            #if defined(S32N55)
			pMacSrv->tagLength 	= *pAlignTagLen;
            #else
			pMacSrv->pTagLength = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignTagLen));
            #endif
	    	nonSgtBuffLen = 0;
		}
    	else
    	{
			/* Flush Input Data Buffer to memory*/
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, TRUE, (uint32_t)pTagLen, sizeof(uint32_t));
            #if defined(S32N55)
    	    if (pTagLen==NULL)
    	    pMacSrv->tagLength =0;
    	    else
    		pMacSrv->tagLength 	= *pTagLen;
            #else
    	    pMacSrv->pTagLength = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pTagLen));
            #endif
    	}
    }

    if(NULL_PTR != pTag)
    {
    	if(HSE_AUTH_DIR_GENERATE == authDir)
    	{
    		nonSgtBuffLen = alignNonSgtBuff(pTag, *pTagLen, 32);
    		if(nonSgtBuffLen != NO_BUFF_ALLOC)
    		{
    			pAlignTag = nxp_hse_callocH(nonSgtBuffLen, 32);

        		if(NULL_PTR == pAlignTag)
        		{
        			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
        			goto exit;
        		}

        		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignTag, *pTagLen);


    			/* Flush Input Data Buffer to memory*/
        		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pAlignTag, *pTagLen);
    			pMacSrv->pTag = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignTag));
    	    	nonSgtBuffLen = 0;
    		}
        	else
        	{
        		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pTag, *pTagLen);


    			/* Flush Input Data Buffer to memory*/
        		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pTag, *pTagLen);
        	    pMacSrv->pTag = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pTag));
        	}
    	}
    	else
    	{
    		nonSgtBuffLen = alignNonSgtBuff(pTag, *pTagLen, 32);
    		if(nonSgtBuffLen != NO_BUFF_ALLOC)
    		{
    			pAlignTag = nxp_hse_callocH(nonSgtBuffLen, 32);
        		if(NULL_PTR == pAlignTag)
        		{
        			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
        			goto exit;
        		}

    			memcpy(pAlignTag, pTag, *pTagLen);
				 /*Flush Input Data Buffer to memory*/
				Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignTag, *pTagLen);
				pMacSrv->pTag = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignTag));
    	    	nonSgtBuffLen = 0;
    		}
        	else
        	{
    			 /*Flush Input Data Buffer to memory*/
        		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pTag, *pTagLen);
        	    pMacSrv->pTag = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pTag));
        	}
    	}
    }

#endif /* D_CACHE_ENABLE_MBEDTLS */

    /* Fill descriptor */
    pMacSrv = &(pHseSrvDesc->hseSrv.macReq);

    pHseSrvDesc->srvId 		= HSE_SRV_ID_MAC;
    pMacSrv->accessMode 	= accessMode;
    pMacSrv->streamId 		= streamId;
    pMacSrv->macScheme 		= macScheme;
    pMacSrv->authDir 		= authDir;
    pMacSrv->keyHandle 		= keyHandle;
    pMacSrv->inputLength 	= inputLen;

#if defined(D_CACHE_ENABLE_MBEDTLS)
    pMacSrv->pInput 		= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(inputSgtTbl.hseSrvSgtList));
    pMacSrv->sgtOption 		= HSE_SGT_OPTION_INPUT;
#else
    pMacSrv->pInput 		= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pInput));
    pMacSrv->pTag 			= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pTag));
#if defined(S32N55)
    if (pTagLen==NULL)
    pMacSrv->tagLength =0;
    else
    pMacSrv->tagLength 	= *pTagLen;

#else
    pMacSrv->pTagLength 	= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pTagLen));
#endif
    pMacSrv->sgtOption 		= HSE_SGT_OPTION_NONE;
#endif


	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

#if !defined(D_CACHE_ENABLE_MBEDTLS)
    /* Descriptor always; every buffer HSE reads via pointer fields. */
    hse_host_dcache_clean(pHseSrvDesc, sizeof(hseSrvDescriptor_t));
    if (NULL_PTR != pInput) {
        hse_host_dcache_clean(pInput, inputLen);
    }
    if (NULL_PTR != pTagLen) {
        hse_host_dcache_clean(pTagLen, sizeof(uint32_t));
    }
    if ((NULL_PTR != pTag) && (NULL_PTR != pTagLen)) {
        hse_host_dcache_clean(pTag, *pTagLen);
    }
#endif

	/* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

#if defined(D_CACHE_ENABLE_MBEDTLS)
    if(srvResponse == HSE_SRV_RSP_OK)
    {
    	if(NULL_PTR != pAlignTagLen)
    	{
    		memcpy(pTagLen, pAlignTagLen, sizeof(uint32_t));
    	}

    	if(HSE_AUTH_DIR_GENERATE == authDir)
    	{
    		if(NULL_PTR != pAlignTag)
    		{
        		memcpy(pTag, pAlignTag, *pTagLen);
    		}
    	}
    }
#else
    if ((HSE_SRV_RSP_OK == srvResponse) && (HSE_AUTH_DIR_GENERATE == authDir)) {
        if (NULL_PTR != pTagLen) {
            hse_host_dcache_invalidate(pTagLen, sizeof(uint32_t));
        }
        if ((NULL_PTR != pTag) && (NULL_PTR != pTagLen)) {
            hse_host_dcache_invalidate(pTag, *pTagLen);
        }
    }
#endif

exit:

#if defined(D_CACHE_ENABLE_MBEDTLS)
    if(NULL_PTR != pAlignTagLen)
	{
    	nxp_hse_freeH(pAlignTagLen);
    	pAlignTagLen = NULL;
	}

    if(HSE_AUTH_DIR_GENERATE == authDir)
	{
    	nxp_hse_freeH(pAlignTag);
    	pAlignTag = NULL;
	}

    alignDataFree(inputSgtTbl.buffAllocFlag, &inputSgtTbl);
#endif

    return srvResponse;
}

/*==================================================================================================
 *                                       GLOBAL FUNCTIONS
 ==================================================================================================*/

/*************************************************************************************************
* Description: Process CMAC request in one shot
************************************************************************************************/
hseSrvResponse_t HSE_Cmac
(
    const hseAuthDir_t authDir,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLen,
    uint8_t *pTag,
    uint32_t *pTagLen
)
{

#if defined(D_CACHE_ENABLE_MBEDTLS)
#if defined(S32N55)
	hseMacScheme_t macScheme __attribute__((aligned (32))) = {
	        .macAlgo 				= HSE_MAC_ALGO_CMAC,
	    };
#else
    hseMacScheme_t macScheme __attribute__((aligned (32))) = {
        .macAlgo 				= HSE_MAC_ALGO_CMAC,
        .sch.cmac.cipherAlgo 	= HSE_CIPHER_ALGO_AES
    };
#endif
#elif defined(S32N55)
    hseMacScheme_t macScheme = {
        .macAlgo 				= HSE_MAC_ALGO_CMAC,
        .sch.cmac           	= HSE_CIPHER_ALGO_AES
    };
#else
    hseMacScheme_t macScheme = {
        .macAlgo 				= HSE_MAC_ALGO_CMAC,
        .sch.cmac.cipherAlgo 	= HSE_CIPHER_ALGO_AES
    };
#endif

    return HSE_MacReq(HSE_ACCESS_MODE_ONE_PASS, 0U, macScheme, authDir, HSE_SGT_OPTION_NONE,
        keyHandle, pInput, inputLen, pTag, pTagLen);
}

/*************************************************************************************************
* Description: Process CMAC stream start request
************************************************************************************************/
hseSrvResponse_t HSE_CmacStart
(
	const hseStreamId_t streamId,
    const hseAuthDir_t authDir,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLen
)
{

#if defined(D_CACHE_ENABLE_MBEDTLS)
#if defined(S32N55)
	 hseMacScheme_t macScheme __attribute__((aligned (32))) = {
	        .macAlgo 				= HSE_MAC_ALGO_CMAC
	    };
#else
    hseMacScheme_t macScheme __attribute__((aligned (32))) = {
        .macAlgo 				= HSE_MAC_ALGO_CMAC,
        .sch.cmac.cipherAlgo 	= HSE_CIPHER_ALGO_AES
    };
#endif
#elif defined(S32N55)
    hseMacScheme_t macScheme = {
        .macAlgo 				= HSE_MAC_ALGO_CMAC,
        .sch.cmac           	= HSE_CIPHER_ALGO_AES
    };
#else
    hseMacScheme_t macScheme = {
        .macAlgo 				= HSE_MAC_ALGO_CMAC,
        .sch.cmac.cipherAlgo 	= HSE_CIPHER_ALGO_AES
    };
#endif

    return HSE_MacReq(HSE_ACCESS_MODE_START, streamId, macScheme, authDir, HSE_SGT_OPTION_NONE,
        keyHandle, pInput, inputLen, NULL, 0U);
}

/*************************************************************************************************
* Description: Process CMAC stream update request
************************************************************************************************/
hseSrvResponse_t HSE_CmacUpdate
(
	const hseStreamId_t streamId,
    const hseAuthDir_t authDir,
    const uint8_t *pInput,
    const uint32_t inputLen
)
{

#if defined(D_CACHE_ENABLE_MBEDTLS)
#if defined(S32N55)
    hseMacScheme_t macScheme __attribute__((aligned (32))) = {
        .macAlgo 				= HSE_MAC_ALGO_CMAC,
    };
#else
    hseMacScheme_t macScheme __attribute__((aligned (32))) = {
        .macAlgo 				= HSE_MAC_ALGO_CMAC,
        .sch.cmac.cipherAlgo 	= HSE_CIPHER_ALGO_AES
    };
#endif
#elif defined(S32N55)
    hseMacScheme_t macScheme = {
        .macAlgo 				= HSE_MAC_ALGO_CMAC,
        .sch.cmac           	= HSE_CIPHER_ALGO_AES
    };
#else
    hseMacScheme_t macScheme = {
        .macAlgo 				= HSE_MAC_ALGO_CMAC,
        .sch.cmac.cipherAlgo 	= HSE_CIPHER_ALGO_AES
    };
#endif

    return HSE_MacReq(HSE_ACCESS_MODE_UPDATE, streamId, macScheme, authDir, HSE_SGT_OPTION_NONE,
        0U, pInput, inputLen, NULL, 0U);
}

/*************************************************************************************************
* Description: Process CMAC stream finish request
************************************************************************************************/
hseSrvResponse_t HSE_CmacFinish
(
	const hseStreamId_t streamId,
    const hseAuthDir_t authDir,
    const uint8_t *pInput,
    const uint32_t inputLen,
    uint8_t *pTag,
    uint32_t *pTagLen
)
{

#if defined(D_CACHE_ENABLE_MBEDTLS)
#if defined(S32N55)
	hseMacScheme_t macScheme __attribute__((aligned (32))) = {
	        .macAlgo 				= HSE_MAC_ALGO_CMAC,
	    };
#else
    hseMacScheme_t macScheme __attribute__((aligned (32))) = {
        .macAlgo 				= HSE_MAC_ALGO_CMAC,
        .sch.cmac.cipherAlgo 	= HSE_CIPHER_ALGO_AES
    };
#endif
#elif defined(S32N55)
    hseMacScheme_t macScheme = {
        .macAlgo 				= HSE_MAC_ALGO_CMAC,
        .sch.cmac           	= HSE_CIPHER_ALGO_AES
    };
#else
    hseMacScheme_t macScheme = {
        .macAlgo 				= HSE_MAC_ALGO_CMAC,
        .sch.cmac.cipherAlgo 	= HSE_CIPHER_ALGO_AES
    };
#endif
    return HSE_MacReq(HSE_ACCESS_MODE_FINISH, streamId, macScheme, authDir, HSE_SGT_OPTION_NONE,
        0U, pInput, inputLen, pTag, pTagLen);
}

/*************************************************************************************************
* Description: Process GMAC one shot request
************************************************************************************************/
hseSrvResponse_t HSE_Gmac
(
    const hseAuthDir_t authDir,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLen,
    const uint8_t *pIv,
    const uint32_t ivLen,
    uint8_t *pTag,
    uint32_t *pTagLen
)
{

#if defined(D_CACHE_ENABLE_MBEDTLS)
    hseMacScheme_t macScheme __attribute__((aligned (32))) = {
        .macAlgo 			= HSE_MAC_ALGO_GMAC,
        .sch.gmac.pIV 		= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pIv)),
        .sch.gmac.ivLength 	= ivLen,
    };
#else
    hseMacScheme_t macScheme = {
        .macAlgo 			= HSE_MAC_ALGO_GMAC,
        .sch.gmac.pIV 		= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pIv)),
        .sch.gmac.ivLength 	= ivLen,
    };
#endif

    return HSE_MacReq(HSE_ACCESS_MODE_ONE_PASS, 0U, macScheme, authDir, HSE_SGT_OPTION_NONE,
        keyHandle, pInput, inputLen, pTag, pTagLen);
}

/*************************************************************************************************
* Description: Process HMAC stream start request
************************************************************************************************/
hseSrvResponse_t HSE_HmacStart
(
	const hseStreamId_t streamId,
    const hseAuthDir_t authDir,
    const hseHashAlgo_t hashAlgo,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLen,
    uint8_t *pTag,
    uint32_t *pTagLen
)
{

#if defined(D_CACHE_ENABLE_MBEDTLS)
    hseMacScheme_t macScheme __attribute__((aligned (32))) = {
        .macAlgo 			= HSE_MAC_ALGO_HMAC,
        .sch.hmac.hashAlgo 	= hashAlgo,
    };
#else
    hseMacScheme_t macScheme = {
        .macAlgo 			= HSE_MAC_ALGO_HMAC,
        .sch.hmac.hashAlgo 	= hashAlgo,
    };
#endif

    return HSE_MacReq(HSE_ACCESS_MODE_START, streamId, macScheme, authDir, HSE_SGT_OPTION_NONE,
        keyHandle, pInput, inputLen, pTag, pTagLen);
}

/*************************************************************************************************
* Description: Process HMAC stream update request
************************************************************************************************/
hseSrvResponse_t HSE_HmacUpdate
(
	const hseStreamId_t streamId,
	const hseAuthDir_t authDir,
    const hseHashAlgo_t hashAlgo,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLen,
    uint8_t *pTag,
    uint32_t *pTagLen
)
{

#if defined(D_CACHE_ENABLE_MBEDTLS)
    hseMacScheme_t macScheme __attribute__((aligned (32))) = {
        .macAlgo 			= HSE_MAC_ALGO_HMAC,
        .sch.hmac.hashAlgo 	= hashAlgo,
    };
#else
    hseMacScheme_t macScheme = {
        .macAlgo 			= HSE_MAC_ALGO_HMAC,
        .sch.hmac.hashAlgo 	= hashAlgo,
    };
#endif

    return HSE_MacReq(HSE_ACCESS_MODE_UPDATE, streamId, macScheme, authDir, HSE_SGT_OPTION_NONE,
        keyHandle, pInput, inputLen, pTag, pTagLen);
}

/*************************************************************************************************
* Description: Process HMAC stream finish request
************************************************************************************************/
hseSrvResponse_t HSE_HmacFinish
(
	const hseStreamId_t streamId,
	const hseAuthDir_t authDir,
    const hseHashAlgo_t hashAlgo,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLen,
    uint8_t *pTag,
    uint32_t *pTagLen
)
{

#if defined(D_CACHE_ENABLE_MBEDTLS)
    hseMacScheme_t macScheme __attribute__((aligned (32))) = {
        .macAlgo 			= HSE_MAC_ALGO_HMAC,
        .sch.hmac.hashAlgo 	= hashAlgo,
    };
#else
    hseMacScheme_t macScheme = {
        .macAlgo 			= HSE_MAC_ALGO_HMAC,
        .sch.hmac.hashAlgo 	= hashAlgo,
    };
#endif

    return HSE_MacReq(HSE_ACCESS_MODE_FINISH, streamId, macScheme, authDir, HSE_SGT_OPTION_NONE,
        keyHandle, pInput, inputLen, pTag, pTagLen);
}

/*************************************************************************************************
* Description: Process HMAC one shot request
************************************************************************************************/
hseSrvResponse_t HSE_Hmac
(
    const hseAuthDir_t authDir,
    const hseHashAlgo_t hashAlgo,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLen,
    uint8_t *pTag,
    uint32_t *pTagLen
)
{

#if defined(D_CACHE_ENABLE_MBEDTLS)
    hseMacScheme_t macScheme __attribute__((aligned (32))) = {
        .macAlgo 			= HSE_MAC_ALGO_HMAC,
        .sch.hmac.hashAlgo 	= hashAlgo,
    };
#else
    hseMacScheme_t macScheme = {
        .macAlgo 			= HSE_MAC_ALGO_HMAC,
        .sch.hmac.hashAlgo 	= hashAlgo,
    };
#endif

    return HSE_MacReq(HSE_ACCESS_MODE_ONE_PASS, 0U, macScheme, authDir, HSE_SGT_OPTION_NONE,
        keyHandle, pInput, inputLen, pTag, pTagLen);
}

#ifdef __cplusplus
}
#endif
