/**
*   @file    	hse_host_aead.c
*
*   @brief   	This file contains AEAD services: CCM, GCM.
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
 * 	@brief		AEAD Operation in one shot
 *
 * 	@param[in]	mode
 *				Specifies the access mode: ONE-PASS
 *
 * 	@param[in]	cipherDir
 *				Specifies the cipher direction: encryption/decryption
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation
 *
 *	@param[in]	pIv
 *				Initialization Vector/Nonce
 *
 *	@param[in]	ivLen
 *				The length of the IV/Nonce (in bytes).
 *              - CCM valid IV sizes 7, 8, 9, 10, 11, 12, 13 bytes
 *              - GCM: 1<= ivLength <= 2^32-1. Recommended 12 bytes or greater.
 *
 *	@param[in]	pAad
 *				The AAD Header data. Ignored if aadLength is zero
 *
 *	@param[in]	aadLen
 *				The length of AAD Header data (in bytes). Can be zero.
 *              - CCM: Restricted to lengths less than or equal to (2^16 - 2^8) bytes.
 *
 * 	@param[in]	pInput
 *				The plaintext for "authenticated encryption"; the ciphertext for "authenticated decryption"
 *
 *	@param[in]	inputLen
 *				The length of the plaintext and ciphertext (in bytes).
 *              Can be zero (compute/verify the tag without input message)
 *
 *	@param[in]	tagLen
 *				The length of tag (in bytes).
 *              - CCM valid Tag sizes 4, 6, 8, 10, 12, 14, 16 bytes
 *              - GCM valid Tag sizes 4, 8, 12, 13, 14, 15, 16 bytes
 *
 *	@param[out/in]	pTag
 *				The output tag for "authenticated encryption" or
 *              the input tag for "authenticated decryption".
 *
 *	@param[out]	pOutput
 *				The ciphertext for "authenticated encryption"; the plaintext for "authenticated decryption".
 *
 *  @return     The HSE Service response
 *
 */
static hseSrvResponse_t HSE_AeadReq_OneShot
(
    const hseAuthCipherMode_t mode,
    const hseCipherDir_t cipherDir,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pIv,
    const uint32_t ivLen,
    const uint8_t *pAad,
    const uint32_t aadLen,
    const uint8_t *pInput,
    const uint32_t inputLen,
    const uint32_t tagLen,
    uint8_t *pTag,
    uint8_t *pOutput
);

/**
 * 	@brief		AEAD Operation in streaming mode
 *
 * 	@param[in]	accessMode
 *				Specifies the access mode: START, UPDATE, FINISH
 *
 * 	@param[in]	mode
 *				Specifies the authenticated cipher mode
 *
 * 	@param[in]	cipherDir
 *				Specifies the cipher direction: encryption/decryption
 *
 *  @param[in]	streamId
 *				Specifies the cipher direction: encryption/decryption
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation
 *
 *	@param[in]	pIv
 *				Initialization Vector/Nonce. STREAMING USAGE: Used in START
 *
 *	@param[in]	ivLen
 *				The length of the IV/Nonce (in bytes).
 *              - CCM valid IV sizes 7, 8, 9, 10, 11, 12, 13 bytes
 *              - GCM: 1<= ivLength <= 2^32-1. Recommended 12 bytes or greater.
 *              STREAMING USAGE: Used in START
 *
 *	@param[in]	pAad
 *				The AAD Header data. Ignored if aadLength is zero. STREAMING USAGE: Used in START
 *
 *	@param[in]	aadLen
 *				The length of AAD Header data (in bytes). Can be zero.
 *              - CCM: Restricted to lengths less than or equal to (2^16 - 2^8) bytes.
 *              STREAMING USAGE: Used in START
 *
 * 	@param[in]	pInput
 *				The plaintext for "authenticated encryption"; the ciphertext for "authenticated decryption"
 *
 *	@param[in]	inputLen
 *				The length of the plaintext and ciphertext (in bytes).
 *              Can be zero (compute/verify the tag without input message)
 *              STREAMING USAGE:
 *             - START:  The input length is ignored.
 *             - UPDATE: Must be a multiple of block length. Cannot be zero. Refrain from issuing the service request,
 *                      instead of passing zero.
 *             - FINISH: All lengths are allowed.
 *
 *	@param[in]	tagLen
 *				The length of tag (in bytes).
 *              - CCM valid Tag sizes 4, 6, 8, 10, 12, 14, 16 bytes
 *              - GCM valid Tag sizes 4, 8, 12, 13, 14, 15, 16 bytes
 *              STREAMING USAGE: Used in FINISH step.
 *
 *	@param[out/in]	pTag
 *				The output tag for "authenticated encryption" or
 *              the input tag for "authenticated decryption".
 *				STREAMING USAGE: Used in FINISH step.
 *
 *	@param[out]	pOutput
 *				The ciphertext for "authenticated encryption"; the plaintext for "authenticated decryption".
 *				STREAMING USAGE: Used in UPDATE and FINISH step.
 *
 *  @return     The HSE Service response
 *
 */
static hseSrvResponse_t HSE_AeadReq_Stream
(
	const hseAccessMode_t accessMode,
    const hseAuthCipherMode_t mode,
    const hseCipherDir_t cipherDir,
	const hseStreamId_t streamId,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pIv,
    const uint32_t ivLen,
    const uint8_t *pAad,
    const uint32_t aadLen,
    const uint8_t *pInput,
    const uint32_t inputLen,
    const uint32_t tagLen,
    uint8_t *pTag,
    uint8_t *pOutput
);

/*==================================================================================================
 *                                       LOCAL FUNCTIONS
 ==================================================================================================*/

/*************************************************************************************************
* Description:  AEAD Operation in one shot
************************************************************************************************/
static hseSrvResponse_t HSE_AeadReq_OneShot
(
    const hseAuthCipherMode_t mode,
    const hseCipherDir_t cipherDir,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pIv,
    const uint32_t ivLen,
    const uint8_t *pAad,
    const uint32_t aadLen,
    const uint8_t *pInput,
    const uint32_t inputLen,
    const uint32_t tagLen,
    uint8_t *pTag,
    uint8_t *pOutput
)
{
    uint8_t u8MuChannel;
    hseAeadSrv_t *pAeadSrv;
    hseSrvDescriptor_t *pHseSrvDesc;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

    /* Get a free channel on MU0 */
    u8MuChannel = Hse_Ip_GetFreeChannel(APP_MU_INSTANCE_U8);
    if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
    {
    	goto exit;
    }

    /* Clear the service descriptor placed in shared memory */
    pHseSrvDesc = &MbedTLS_aSrvDescriptor[u8MuChannel];
    pAeadSrv = &(pHseSrvDesc->hseSrv.aeadReq);
    memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));

#if defined (D_CACHE_ENABLE_MBEDTLS)

	hseSrvSGTNode_t inputSgtTbl, outSgtTbl;
	uint8_t *pAlignIv = NULL;
	uint8_t *pAlignAad = NULL ;
	uint8_t *pAlignTag = NULL ;
	uint16_t nonSgtBuffLen = 0;

	memset(&inputSgtTbl, 0, sizeof(hseSrvSGTNode_t));
	memset(&outSgtTbl, 0, sizeof(hseSrvSGTNode_t));

    if(NULL_PTR != pIv)
    {
    	nonSgtBuffLen = alignNonSgtBuff(pIv, ivLen, 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
			/* Flush Input Data Buffer to memory */
    		pAlignIv = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignIv)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		memcpy(pAlignIv, pIv, ivLen);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignIv, ivLen);
			pAeadSrv->pIV = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignIv));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
			/* Flush Input Data Buffer to memory */
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pIv, ivLen);
			pAeadSrv->pIV = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pIv));
    	}
    }

    if(NULL_PTR != pAad)
    {
    	nonSgtBuffLen = alignNonSgtBuff(pAad, aadLen, 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
			/* Flush Input Data Buffer to memory */
    		pAlignAad = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignAad)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		memcpy(pAlignAad, pAad, aadLen);
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignAad, aadLen);
			pAeadSrv->pAAD = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignAad));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
			/* Flush Input Data Buffer to memory*/
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAad, aadLen);
    	    pAeadSrv->pAAD = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAad));
    	}
    }

    if(NULL_PTR != pTag)
    {
    	if(HSE_CIPHER_DIR_ENCRYPT == cipherDir)
    	{
    		nonSgtBuffLen = alignNonSgtBuff(pTag, tagLen, 32);
    		if(nonSgtBuffLen != NO_BUFF_ALLOC)
    		{
    			pAlignTag = nxp_hse_callocH(nonSgtBuffLen, 32);
        		if(NULL_PTR == pAlignTag)
        		{
        			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
        			goto exit;
        		}

        		Cache_Ip_CleanByAddr( CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignTag, (tagLen));


    			/* Flush Input Data Buffer to memory*/
        		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pAlignTag, tagLen);
    			pAeadSrv->pTag = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignTag));
    	    	nonSgtBuffLen = 0;
    		}
        	else
        	{
        		Cache_Ip_CleanByAddr( CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pTag, (tagLen));

    			/* Flush Input Data Buffer to memory*/
        		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pTag, tagLen);
        	    pAeadSrv->pTag = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pTag));
        	}
    	}
    	else
    	{
    		nonSgtBuffLen = alignNonSgtBuff(pTag, tagLen, 32);
    		if(nonSgtBuffLen != NO_BUFF_ALLOC)
    		{
    			pAlignTag = nxp_hse_callocH(nonSgtBuffLen, 32);
        		if(NULL_PTR == pAlignTag)
        		{
        			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
        			goto exit;
        		}

    			memcpy(pAlignTag, pTag, tagLen);
				 /*Flush Input Data Buffer to memory*/
				Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignTag, tagLen);
				pAeadSrv->pTag = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignTag));
    	    	nonSgtBuffLen = 0;
    		}
        	else
        	{
    			 /*Flush Input Data Buffer to memory*/
        		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pTag, tagLen);
        	    pAeadSrv->pTag = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pTag));
        	}
    	}
    }

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

    if(NULL_PTR != pOutput)
    {
        if(checkAlignmentReq(pOutput, inputLen, 32, &outSgtTbl) != NO_BUFF_ALLOC)
        {
        	alignOutBuff((uint8_t*)pOutput, &outSgtTbl);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)outSgtTbl.hseSrvSgtList,
					3*sizeof(hseScatterList_t));
        }
        else
        {

    		Cache_Ip_CleanByAddr( CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pOutput, (inputLen));


    		/* Flush Input Data Buffer to memory */
        	Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA,  (uint32_t)pOutput, inputLen);
        	storeAlignBufptr((uint8_t*)pOutput, inputLen, &outSgtTbl );
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)outSgtTbl.hseSrvSgtList,
					sizeof(hseScatterList_t));
        }
    }

#endif /* NXP_D_CACHE_ENABLE */

    /* Fill the service descriptor */
    pHseSrvDesc->srvId 			= HSE_SRV_ID_AEAD;
    pAeadSrv->accessMode 		= HSE_ACCESS_MODE_ONE_PASS;
    pAeadSrv->authCipherMode 	= mode;
    pAeadSrv->cipherDir 		= cipherDir;
    pAeadSrv->keyHandle 		= keyHandle;
    pAeadSrv->ivLength 			= ivLen;
    pAeadSrv->aadLength 		= aadLen;
    pAeadSrv->inputLength 		= inputLen;
    pAeadSrv->tagLength 		= tagLen;

#if defined(D_CACHE_ENABLE_MBEDTLS)
    pAeadSrv->pInput 			= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(inputSgtTbl.hseSrvSgtList));
    pAeadSrv->pOutput 			= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(outSgtTbl.hseSrvSgtList));
    pAeadSrv->sgtOption			= HSE_SGT_OPTION_INPUT_OUTPUT_MASK;
#else
    pAeadSrv->pAAD 				= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAad));
    pAeadSrv->pIV 				= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pIv));
    pAeadSrv->pTag 				= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pTag));
    pAeadSrv->pInput 			= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pInput));
    pAeadSrv->pOutput 			= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pOutput));
    pAeadSrv->sgtOption			= HSE_SGT_OPTION_NONE;
#endif

	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

    /* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

#if defined(D_CACHE_ENABLE_MBEDTLS)
    if(srvResponse == HSE_SRV_RSP_OK)
    {
    	copySgtDataToLocalBuff(&outSgtTbl, pOutput);

    	if(HSE_CIPHER_DIR_ENCRYPT == cipherDir)
    	{
    		if(NULL_PTR != pAlignTag)
    		{
    			memcpy(pTag, pAlignTag, tagLen);
    		}
    	}
    }
#endif

exit:
#if defined(D_CACHE_ENABLE_MBEDTLS)
	if(NULL_PTR != pAlignTag)
	{
		nxp_hse_freeH(pAlignTag);
		pAlignTag = NULL;
	}

	if(NULL_PTR != pAlignIv)
	{
		nxp_hse_freeH(pAlignIv);
		pAlignIv = NULL;
	}

	if(NULL_PTR != pAlignAad)
	{
		nxp_hse_freeH(pAlignAad);
		pAlignAad = NULL;
	}

    alignDataFree(inputSgtTbl.buffAllocFlag, &inputSgtTbl);
    alignDataFree(outSgtTbl.buffAllocFlag, &outSgtTbl);
#endif

    return srvResponse;
}

/*************************************************************************************************
* Description:  AEAD Operation in streaming mode
************************************************************************************************/
static hseSrvResponse_t HSE_AeadReq_Stream
(
	const hseAccessMode_t accessMode,
    const hseAuthCipherMode_t mode,
    const hseCipherDir_t cipherDir,
	const hseStreamId_t streamId,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pIv,
    const uint32_t ivLen,
    const uint8_t *pAad,
    const uint32_t aadLen,
    const uint8_t *pInput,
    const uint32_t inputLen,
    const uint32_t tagLen,
    uint8_t *pTag,
    uint8_t *pOutput
)
{
    uint8_t u8MuChannel;
    hseAeadSrv_t *pAeadSrv;
    hseSrvDescriptor_t *pHseSrvDesc;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

    /* Get a free channel on MU0 */
    u8MuChannel = Hse_Ip_GetFreeChannel(APP_MU_INSTANCE_U8);
    if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
    {
    	goto exit;
    }

    /* Clear the service descriptor placed in shared memory */
    pHseSrvDesc = &MbedTLS_aSrvDescriptor[u8MuChannel];
    pAeadSrv = &(pHseSrvDesc->hseSrv.aeadReq);
    memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));

#if defined (D_CACHE_ENABLE_MBEDTLS)

	hseSrvSGTNode_t inputSgtTbl, outSgtTbl;
	uint8_t *pAlignIv = NULL;
	uint8_t *pAlignAad = NULL ;
	uint8_t *pAlignTag = NULL ;
	uint16_t nonSgtBuffLen = 0;

	memset(&inputSgtTbl, 0, sizeof(hseSrvSGTNode_t));
	memset(&outSgtTbl, 0, sizeof(hseSrvSGTNode_t));

    if(NULL_PTR != pIv)
    {
    	nonSgtBuffLen = alignNonSgtBuff(pIv, ivLen, 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
			/* Flush Input Data Buffer to memory */
    		pAlignIv = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignIv)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		memcpy(pAlignIv, pIv, ivLen);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignIv, ivLen);
			pAeadSrv->pIV = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignIv));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
			/* Flush Input Data Buffer to memory */
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pIv, ivLen);
			pAeadSrv->pIV = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pIv));
    	}
    }

    if(NULL_PTR != pAad)
    {
    	nonSgtBuffLen = alignNonSgtBuff(pAad, aadLen, 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
			/* Flush Input Data Buffer to memory */
    		pAlignAad = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignAad)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		memcpy(pAlignAad, pAad, aadLen);
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignAad, aadLen);
			pAeadSrv->pAAD = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignAad));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
			/* Flush Input Data Buffer to memory*/
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAad, aadLen);
    	    pAeadSrv->pAAD = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAad));
    	}
    }

    if(NULL_PTR != pTag)
    {
    	if(HSE_CIPHER_DIR_ENCRYPT == cipherDir)
    	{
    		nonSgtBuffLen = alignNonSgtBuff(pTag, tagLen, 32);
    		if(nonSgtBuffLen != NO_BUFF_ALLOC)
    		{
    			pAlignTag = nxp_hse_callocH(nonSgtBuffLen, 32);
        		if(NULL_PTR == pAlignTag)
        		{
        			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
        			goto exit;
        		}

        		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignTag, tagLen);


    			/* Flush Input Data Buffer to memory*/
        		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pAlignTag, tagLen);
    			pAeadSrv->pTag = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignTag));
    	    	nonSgtBuffLen = 0;
    		}
        	else
        	{
        		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA,FALSE,  (uint32_t)pTag, tagLen);


        		/* Flush Input Data Buffer to memory*/
        		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pTag, tagLen);
        	    pAeadSrv->pTag = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pTag));
        	}
    	}
    	else
    	{
    		nonSgtBuffLen = alignNonSgtBuff(pTag, tagLen, 32);
    		if(nonSgtBuffLen != NO_BUFF_ALLOC)
    		{
    			pAlignTag = nxp_hse_callocH(nonSgtBuffLen, 32);


        		if(NULL_PTR == pAlignTag)
        		{
        			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
        			goto exit;
        		}

    			memcpy(pAlignTag, pTag, tagLen);
				 /*Flush Input Data Buffer to memory*/
				Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignTag, tagLen);
				pAeadSrv->pTag = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignTag));
    	    	nonSgtBuffLen = 0;
    		}
        	else
        	{
    			 /*Flush Input Data Buffer to memory*/
        		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pTag, tagLen);
        	    pAeadSrv->pTag = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pTag));
        	}
    	}
    }

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

    if(NULL_PTR != pOutput)
    {
        if(checkAlignmentReq(pOutput, inputLen, 32, &outSgtTbl) != NO_BUFF_ALLOC)
        {
        	alignOutBuff((uint8_t*)pOutput, &outSgtTbl);
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)outSgtTbl.hseSrvSgtList,
					3*sizeof(hseScatterList_t));
        }
        else
        {
        	Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pOutput, inputLen);


    		/* Flush Input Data Buffer to memory */
        	Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA,  (uint32_t)pOutput, inputLen);
        	storeAlignBufptr((uint8_t*)pOutput, inputLen, &outSgtTbl );
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)outSgtTbl.hseSrvSgtList,
					sizeof(hseScatterList_t));
        }
    }

#endif /* D_CACHE_ENABLE */

    /* Fill the service descriptor */
    pHseSrvDesc->srvId 			= HSE_SRV_ID_AEAD;
    pAeadSrv->accessMode 		= accessMode;
    pAeadSrv->authCipherMode 	= mode;
    pAeadSrv->cipherDir 		= cipherDir;
    pAeadSrv->streamId 			= streamId;
    pAeadSrv->keyHandle 		= keyHandle;
    pAeadSrv->ivLength 			= ivLen;
    pAeadSrv->aadLength 		= aadLen;
    pAeadSrv->inputLength 		= inputLen;
    pAeadSrv->tagLength 		= tagLen;

#if defined(D_CACHE_ENABLE_MBEDTLS)
    pAeadSrv->pInput 			= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(inputSgtTbl.hseSrvSgtList));
    pAeadSrv->pOutput 			= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(outSgtTbl.hseSrvSgtList));
    pAeadSrv->sgtOption			= HSE_SGT_OPTION_INPUT_OUTPUT_MASK;
#else
    pAeadSrv->pAAD 				= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAad));
    pAeadSrv->pIV 				= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pIv));
    pAeadSrv->pInput 			= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pInput));
    pAeadSrv->pTag 				= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pTag));
    pAeadSrv->pOutput 			= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pOutput));
    pAeadSrv->sgtOption			= HSE_SGT_OPTION_NONE;
#endif

	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

    /* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

#if defined(D_CACHE_ENABLE_MBEDTLS)
    if(srvResponse == HSE_SRV_RSP_OK)
    {
    	copySgtDataToLocalBuff(&outSgtTbl, pOutput);

    	if(HSE_CIPHER_DIR_ENCRYPT == cipherDir)
    	{
    		if(NULL_PTR != pAlignTag)
    		{
    			memcpy(pTag, pAlignTag, tagLen);
    		}
    	}
    }
#endif

exit:
#if defined(D_CACHE_ENABLE_MBEDTLS)
	if(NULL_PTR != pAlignTag)
	{
		nxp_hse_freeH(pAlignTag);
		pAlignTag = NULL;
	}

	if(NULL_PTR != pAlignIv)
	{
		nxp_hse_freeH(pAlignIv);
		pAlignIv = NULL;
	}

	if(NULL_PTR != pAlignAad)
	{
		nxp_hse_freeH(pAlignAad);
		pAlignAad = NULL;
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
* Description:  AEAD GCM Encrypt One Shot
************************************************************************************************/
hseSrvResponse_t HSE_AeadGcmEncrypt
(
    const hseKeyHandle_t keyHandle,
    const uint8_t *pIv,
    const uint32_t ivLen,
    const uint8_t *pAad,
    const uint32_t aadLen,
    const uint8_t *pInput,
    const uint32_t inputLen,
    const uint32_t tagLen,
    uint8_t *pTag,
    uint8_t *pOutput
)
{
    return HSE_AeadReq_OneShot(HSE_AUTH_CIPHER_MODE_GCM, HSE_CIPHER_DIR_ENCRYPT, keyHandle,
        pIv, ivLen, pAad, aadLen, pInput, inputLen, tagLen, pTag, pOutput);
}

/*************************************************************************************************
* Description:  AEAD GCM Decrypt One Shot
************************************************************************************************/
hseSrvResponse_t HSE_AeadGcmDecrypt
(
    const hseKeyHandle_t keyHandle,
    const uint8_t *pIv,
    const uint32_t ivLen,
    const uint8_t *pAad,
    const uint32_t aadLen,
    const uint8_t *pInput,
    const uint32_t inputLen,
    const uint32_t tagLen,
    uint8_t *pTag,
    uint8_t *pOutput
)
{
    return HSE_AeadReq_OneShot(HSE_AUTH_CIPHER_MODE_GCM, HSE_CIPHER_DIR_DECRYPT, keyHandle,
        pIv, ivLen, pAad, aadLen, pInput, inputLen, tagLen, pTag, pOutput);
}

/*************************************************************************************************
* Description:  AEAD GCM Encrypt/Decrypt Stream Start
************************************************************************************************/
hseSrvResponse_t HSE_AeadGcmStreamStart
(
	const hseStreamId_t streamId,
	const hseCipherDir_t cipherDir,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pIv,
    const uint32_t ivLen,
    const uint8_t *pAad,
    const uint32_t aadLen
)
{
    return HSE_AeadReq_Stream(HSE_ACCESS_MODE_START, HSE_AUTH_CIPHER_MODE_GCM, cipherDir, streamId,
    		keyHandle, pIv, ivLen, pAad, aadLen, NULL, 0U, 0U, NULL, NULL);
}

/*************************************************************************************************
* Description:  AEAD GCM Encrypt/Decrypt Stream Update
************************************************************************************************/
hseSrvResponse_t HSE_AeadGcmStreamUpdate
(
	const hseStreamId_t streamId,
	const hseCipherDir_t cipherDir,
    const uint8_t *pInput,
    const uint32_t inputLen,
    uint8_t *pOutput
)
{
	return HSE_AeadReq_Stream(HSE_ACCESS_MODE_UPDATE, HSE_AUTH_CIPHER_MODE_GCM, cipherDir, streamId,
	    	0U, NULL, 0U, NULL, 0U, pInput, inputLen, 0U, NULL, pOutput);
}

/*************************************************************************************************
* Description:  AEAD GCM Encrypt/Decrypt Stream Finish
************************************************************************************************/
hseSrvResponse_t HSE_AeadGcmStreamFinish
(
	const hseStreamId_t streamId,
	const hseCipherDir_t cipherDir,
    const uint8_t *pInput,
    const uint32_t inputLen,
    const uint32_t tagLen,
    uint8_t *pTag,
	uint8_t *pOutput
)
{
	return HSE_AeadReq_Stream(HSE_ACCESS_MODE_FINISH, HSE_AUTH_CIPHER_MODE_GCM, cipherDir, streamId,
	    	0U, NULL, 0U, NULL, 0U, pInput, inputLen, tagLen, pTag, pOutput);
}

/*************************************************************************************************
* Description:  AEAD CCM Encrypt One Shot
************************************************************************************************/
hseSrvResponse_t HSE_AeadCcmEncrypt
(
    const hseKeyHandle_t keyHandle,
    const uint8_t *pIv,
    const uint32_t ivLen,
    const uint8_t *pAad,
    const uint32_t aadLen,
    const uint8_t *pInput,
    const uint32_t inputLen,
    const uint32_t tagLen,
    uint8_t *pTag,
    uint8_t *pOutput
)
{
    return HSE_AeadReq_OneShot(HSE_AUTH_CIPHER_MODE_CCM, HSE_CIPHER_DIR_ENCRYPT, keyHandle,
        pIv, ivLen, pAad, aadLen, pInput, inputLen, tagLen, pTag, pOutput);
}

/*************************************************************************************************
* Description:  AEAD CCM Decrypt One Shot
************************************************************************************************/
hseSrvResponse_t HSE_AeadCcmDecrypt
(
    const hseKeyHandle_t keyHandle,
    const uint8_t *pIv,
    const uint32_t ivLen,
    const uint8_t *pAad,
    const uint32_t aadLen,
    const uint8_t *pInput,
    const uint32_t inputLen,
    const uint32_t tagLen,
    uint8_t *pTag,
    uint8_t *pOutput
)
{
    return HSE_AeadReq_OneShot(HSE_AUTH_CIPHER_MODE_CCM, HSE_CIPHER_DIR_DECRYPT, keyHandle,
        pIv, ivLen, pAad, aadLen, pInput, inputLen, tagLen, pTag, pOutput);
}

#ifdef __cplusplus
}
#endif
