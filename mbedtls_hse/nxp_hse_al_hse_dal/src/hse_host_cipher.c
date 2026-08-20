/**
*   @file    	hse_host_cipher.c
*
*   @brief   	This file contains cipher services.
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
 * 	@brief		AES Cipher request
 *
 * 	@param[in]	accessMode
 *				Specifies the access mode: ONE-PASS, START, UPDATE, FINISH.
 *              STREAMING USAGE: Used in all steps
 *
 * 	@param[in]	streamId
 *				Specifies the stream to use for START, UPDATE, FINISH access modes. Each interface supports
 *          	a limited number of streams per interface, up to #HSE_STREAM_COUNT.
 *              STREAMING USAGE: Used in all steps
 *
 *	@param[in]	cipherBlockMode
 *				Specifies the cipher mode.
 *              STREAMING USAGE: Used in START
 *
 *	@param[in]	cipherDir
 *				Specifies the cipher direction: encryption/decryption.
 *              STREAMING USAGE: Used in START.
 *
 *	@param[in]	inputSgtType
 *				none
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation.
 *              STREAMING USAGE: Used in START step.
 *
 *	@param[in]	pIV
 *				Initialization Vector/Nonce. Ignored for NULL & ECB cipher block modes.
 *              IV length is 16 bytes. (AES cipher block size).
 *              STREAMING USAGE: Used in START.
 *
 * 	@param[in]	ivLength
 *				none
 *
 *  @param[in]	pInput
 *				The plaintext for encryption or the ciphertext for decryption.
 *              STREAMING USAGE: Used in START, UPDATE and FINISH. Ignored in START if #inputLength is zero
 *
 *	@param[in]	inputLen
 *				The plaintext and ciphertext length. For ECB, CBC & CFB cipher block modes,
 *              must be a multiple of block length. Cannot be zero.
 *           	STREAMING USAGE: MANDATORY for all steps.
 *              - START: Must be a multiple of block length. Can be zero.
 *              - UPDATE: Must be a multiple of block length. Cannot be zero. Refrain from issuing the service request, instead of passing zero.
 *              - FINISH: For ECB, CBC & CFB cipher block modes, must be a multiple of block length. Cannot be zero.
 *              For remaining cipher block modes, can be any value except zero.
 *              AES block lengths: 16
 *
 *	@param[out]	pOutput
 *				The plaintext for decryption or ciphertext for encryption.
 *              STREAMING USAGE: Used in START, UPDATE and FINISH. Ignored in START if #inputLength is zero.
 *
 *  @return     The HSE Service response
 *
 */
static hseSrvResponse_t HSE_AesCipherReq
(
    hseAccessMode_t accessMode,
    hseStreamId_t streamId,
    hseCipherBlockMode_t cipherBlockMode,
    hseCipherDir_t cipherDir,
    hseSGTOption_t inputSgtType,
    hseKeyHandle_t keyHandle,
    const uint8_t *pIV,
    uint32_t ivLength,
    const uint8_t *pInput,
    uint32_t inputLength,
    uint8_t *pOutput
);

/*==================================================================================================
*                                       LOCAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
* Description:  AES Cipher request
************************************************************************************************/
static hseSrvResponse_t HSE_AesCipherReq
(
    hseAccessMode_t accessMode,
    hseStreamId_t streamId,
    hseCipherBlockMode_t cipherBlockMode,
    hseCipherDir_t cipherDir,
    hseSGTOption_t inputSgtType,
    hseKeyHandle_t keyHandle,
    const uint8_t *pIV,
    uint32_t ivLength,
    const uint8_t *pInput,
    uint32_t inputLength,
    uint8_t *pOutput
)
{
    uint8_t u8MuChannel;
    hseSrvDescriptor_t *pHseSrvDesc;
    hseSymCipherSrv_t* pSymCipherReq;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;
    
    /* Get a free channel on MU0 */
    u8MuChannel = Hse_Ip_GetFreeChannel(APP_MU_INSTANCE_U8);
    if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
    {
    	goto exit;
    }

    /* Alloc free descriptor */
    pHseSrvDesc = &MbedTLS_aSrvDescriptor[u8MuChannel];
    pSymCipherReq = &(pHseSrvDesc->hseSrv.symCipherReq);
    memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));

#if defined (D_CACHE_ENABLE_MBEDTLS)

	hseSrvSGTNode_t inputSgtTbl, outSgtTbl;
	uint8_t *pAlignIv = NULL;
	uint16_t nonSgtBuffLen = 0;

	memset(&inputSgtTbl, 0, sizeof(hseSrvSGTNode_t));
	memset(&outSgtTbl, 0, sizeof(hseSrvSGTNode_t));

    if(NULL_PTR != pIV)
    {
    	nonSgtBuffLen = alignNonSgtBuff(pIV, ivLength, 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
			/* Flush Input Data Buffer to memory */
    		pAlignIv = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignIv)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		memcpy(pAlignIv, pIV, ivLength);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignIv, ivLength);
			pSymCipherReq->pIV = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignIv));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
			/* Flush Input Data Buffer to memory */
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pIV, ivLength);
			pSymCipherReq->pIV = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pIV));
    	}
    }

    if(NULL_PTR != pInput)
    {
        if(checkAlignmentReq(pInput, inputLength, 32, &inputSgtTbl) != NO_BUFF_ALLOC)
        {
        	alignInBuff((uint8_t*)pInput, &inputSgtTbl);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)inputSgtTbl.hseSrvSgtList,
					3*sizeof(hseScatterList_t));
        }
        else
        {
    		/* Flush Input Data Buffer to memory */
        	Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, false, (uint32_t)pInput, inputLength);
        	storeAlignBufptr((uint8_t*)pInput, inputLength, &inputSgtTbl );
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)inputSgtTbl.hseSrvSgtList,
					sizeof(hseScatterList_t));
        }
    }

    if(NULL_PTR != pOutput)
    {
        if(checkAlignmentReq(pOutput, inputLength, 32, &outSgtTbl) != NO_BUFF_ALLOC)
        {
        	alignOutBuff((uint8_t*)pOutput, &outSgtTbl);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)outSgtTbl.hseSrvSgtList,
					3*sizeof(hseScatterList_t));
        }
        else
        {

    		Cache_Ip_CleanByAddr( CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pOutput, (inputLength));

    		/* Flush Input Data Buffer to memory */
        	Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA,  (uint32_t)pOutput, inputLength);
        	storeAlignBufptr((uint8_t*)pOutput, inputLength, &outSgtTbl );
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)outSgtTbl.hseSrvSgtList,
					sizeof(hseScatterList_t));
        }
    }
#else
    (void)ivLength;
#endif /* D_CACHE_ENABLE_MBEDTLS */

    pHseSrvDesc->srvId              = HSE_SRV_ID_SYM_CIPHER;
    pSymCipherReq->accessMode       = accessMode;
    pSymCipherReq->cipherAlgo       = HSE_CIPHER_ALGO_AES;
    pSymCipherReq->cipherBlockMode  = cipherBlockMode;
    pSymCipherReq->cipherDir        = cipherDir;
    pSymCipherReq->streamId         = streamId;
    pSymCipherReq->keyHandle        = keyHandle;
    pSymCipherReq->inputLength      = inputLength;

#if defined(D_CACHE_ENABLE_MBEDTLS)
    pSymCipherReq->pInput 		= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(inputSgtTbl.hseSrvSgtList));
    pSymCipherReq->pOutput  	= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(outSgtTbl.hseSrvSgtList));
    inputSgtType 				= HSE_SGT_OPTION_INPUT_OUTPUT_MASK;
    pSymCipherReq->sgtOption	= inputSgtType;
#else
    pSymCipherReq->pIV			= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pIV));
    pSymCipherReq->pInput   	= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pInput));
    pSymCipherReq->pOutput  	= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pOutput));
    inputSgtType 				= HSE_SGT_OPTION_NONE;
    pSymCipherReq->sgtOption	= inputSgtType;
#endif

	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

    /* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

#if defined(D_CACHE_ENABLE_MBEDTLS)
    if(srvResponse == HSE_SRV_RSP_OK)
    {
    	//pOutput = (pOutput);
    	copySgtDataToLocalBuff(&outSgtTbl, pOutput);
    	pOutput = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pOutput));
    }
#endif

exit:
#if defined(D_CACHE_ENABLE_MBEDTLS)

	if(NULL_PTR != pAlignIv)
	{
		nxp_hse_freeH(pAlignIv);
		pAlignIv = NULL;
	}

    alignDataFree(inputSgtTbl.buffAllocFlag, &inputSgtTbl);
    alignDataFree(outSgtTbl.buffAllocFlag, &outSgtTbl);
#endif

    return srvResponse;
}

/*==================================================================================================
*                                       GLOBAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
* Description:  AES Encryption request
************************************************************************************************/
hseSrvResponse_t HSE_AesEncrypt
(
    hseCipherBlockMode_t cipherBlockMode,
    hseKeyHandle_t keyHandle,
    const uint8_t *pIV,
    uint32_t ivLength,
    const uint8_t* pInput,
    uint32_t inputLength,
    uint8_t* pOutput
)
{
    return HSE_AesCipherReq(
        HSE_ACCESS_MODE_ONE_PASS, 0U, cipherBlockMode, HSE_CIPHER_DIR_ENCRYPT, HSE_SGT_OPTION_NONE,
        keyHandle, pIV, ivLength, pInput, inputLength, pOutput
    );
}

/*************************************************************************************************
* Description:  AES Decryption request
************************************************************************************************/
hseSrvResponse_t HSE_AesDecrypt
(
    hseCipherBlockMode_t cipherBlockMode,
    hseKeyHandle_t keyHandle,
    const uint8_t *pIV,
    uint32_t ivLength,
    const uint8_t* pInput,
    uint32_t inputLength,
    uint8_t* pOutput
)
{
    return HSE_AesCipherReq(
        HSE_ACCESS_MODE_ONE_PASS, 0U, cipherBlockMode, HSE_CIPHER_DIR_DECRYPT, HSE_SGT_OPTION_NONE,
        keyHandle, pIV, ivLength, pInput, inputLength, pOutput
    );
}

#ifdef HSE_SPT_XTS_AES
/*************************************************************************************************
* Description:  AES XTS request
************************************************************************************************/
hseSrvResponse_t HSE_AesXTS
(
	hseCipherDir_t   cipherDir,
	hseKeyHandle_t   cipherKeyHandle,
	hseKeyHandle_t   tweakKeyHandle,
	uint64_t         sectorNumber,
	uint16_t         sectorSize,
	uint32_t         inputLength,
	const uint8_t	 *pInput,
	uint8_t		     *pOutput
)
{
    uint8_t u8MuChannel;
    hseSrvDescriptor_t *pHseSrvDesc;
    hseXtsAesCipherSrv_t* pXtsAesCipherReq;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

    /* Get a free channel on MU0 */
    u8MuChannel = Hse_Ip_GetFreeChannel(APP_MU_INSTANCE_U8);
    if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
    {
    	goto exit;
    }

    /* Alloc free descriptor */
    pHseSrvDesc = &MbedTLS_aSrvDescriptor[u8MuChannel];
    pXtsAesCipherReq = &(pHseSrvDesc->hseSrv.xtsAesCipherReq);
    memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));

#if defined (D_CACHE_ENABLE_MBEDTLS)
	uint8_t *pAlignInput = NULL, *pAlignOutput = NULL;
	uint16_t nonSgtBuffLen = 0;

	if(NULL_PTR != pInput)
	{
		nonSgtBuffLen = alignNonSgtBuff(pInput, inputLength, 32);
		if(nonSgtBuffLen != NO_BUFF_ALLOC)
		{
			/* Flush Input Data Buffer to memory */
			pAlignInput = nxp_hse_callocH(nonSgtBuffLen, 32);
			if(NULL_PTR == pAlignInput)
			{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
			}

			memcpy(pAlignInput, pInput, inputLength);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignInput, inputLength);
			pXtsAesCipherReq->pInput = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignInput));
			nonSgtBuffLen = 0;
		}
		else
		{
			/* Flush Input Data Buffer to memory */
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pInput, inputLength);
			pXtsAesCipherReq->pInput = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pInput));
		}
	}

	if(NULL_PTR != pOutput)
	{
		nonSgtBuffLen = alignNonSgtBuff(pOutput, inputLength, 32);
		if(nonSgtBuffLen != NO_BUFF_ALLOC)
		{
			pAlignOutput = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignOutput)
    		{
    			return HSE_SRV_RSP_MEMORY_FAILURE;
    		}

    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignOutput, inputLength);


			/* Flush Input Data Buffer to memory*/
    		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pAlignOutput, inputLength);
    		pXtsAesCipherReq->pOutput = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignOutput));
	    	nonSgtBuffLen = 0;
		}
    	else
    	{
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pOutput, inputLength);


			/* Flush Input Data Buffer to memory*/
    		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pOutput, inputLength);
    		pXtsAesCipherReq->pOutput = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pOutput));
    	}
	}
#endif /* D_CACHE_ENABLE_MBEDTLS */

    pHseSrvDesc->srvId              	= HSE_SRV_ID_XTS_AES_CIPHER;
    pXtsAesCipherReq->cipherDir       	= cipherDir;
    pXtsAesCipherReq->cipherKeyHandle  	= cipherKeyHandle;
    pXtsAesCipherReq->tweakKeyHandle    = tweakKeyHandle;
    pXtsAesCipherReq->sectorNumber      = sectorNumber;
    pXtsAesCipherReq->sectorSize        = sectorSize;
    pXtsAesCipherReq->inputLength    	= inputLength;

#if !defined(D_CACHE_ENABLE_MBEDTLS)
    pXtsAesCipherReq->pInput   			= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pInput));
    pXtsAesCipherReq->pOutput  			= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pOutput));
#endif

	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

    /* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

#if defined(D_CACHE_ENABLE_MBEDTLS)

	if(HSE_SRV_RSP_OK == srvResponse)
	{
		if(NULL_PTR != pAlignOutput)
		{
			memcpy(pOutput, pAlignOutput, inputLength);
		}
	}
#endif

exit:

#if defined(D_CACHE_ENABLE_MBEDTLS)
	if(NULL_PTR != pAlignInput)
	{
		nxp_hse_freeH(pAlignInput);
		pAlignInput = NULL;
	}

	if(NULL_PTR != pAlignOutput)
	{
		nxp_hse_freeH(pAlignOutput);
		pAlignOutput = NULL;
	}
#endif
    return srvResponse;
}
#endif /* HSE_SPT_XTS_AES */

#ifdef __cplusplus
}
#endif
