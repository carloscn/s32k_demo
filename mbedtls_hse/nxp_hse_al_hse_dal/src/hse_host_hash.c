/**
*   @file    	hse_host_hash.c
*
*   @details 	This file contains hashing services
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
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
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

/* Argument for the async hash callback function */
typedef struct
{
    uint8_t u8MuInstance;
    uint8_t u8MuChannel;
} hashCallbackParams_t;


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
 * 	@brief		Blocking hash request
 *
 * 	@param[in]	accessMode
 *				Specifies the access mode: START, UPDATE, FINISH
 *
 *  @param[in]	streamId
 *				Specifies the stream to use for START, UPDATE, FINISH access modes
 *
 *	@param[in]	hashAlgo
 *				Specifies the hash algorithm
 *
 * 	@param[in]	pInput
 *				Address of the input message
 *				STREAMING USAGE: Used in all steps (except if inputLength is zero)
 *
 *	@param[in]	inputLen
 *				MD5, SHA1, SHA2_224, SHA2_256: 64
 *              - SHA2_384, SHA2_512, SHA2_512_224, SHA2_512_256: 128
 *              - SHA3: no limitation (can be any size)
 *
 *	@param[out]	pHash
 *			    The address of the output buffer where the resulting hash will be stored. <br>
 *              STREAMING USAGE: MANDATORY for FINISH
 *
 *	@param[out/in]	pHashLength
 *				Pointer to a uint32_t location in which the hash length in bytes is stored
 *
 *  @return     The HSE Service response
 *
 */
static hseSrvResponse_t HSE_HashData
(
    hseAccessMode_t accessMode,
    uint32_t streamId,
    hseHashAlgo_t hashAlgo,
    const uint8_t *pInput,
    uint32_t inputLength,
    uint8_t *pHash,
    uint32_t *pHashLength
);

/*==================================================================================================
*                                       LOCAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
* Description:  Blocking hash request
************************************************************************************************/
static hseSrvResponse_t HSE_HashData
(
    hseAccessMode_t accessMode,
    uint32_t streamId,
    hseHashAlgo_t hashAlgo,
    const uint8_t *pInput,
    uint32_t inputLength,
    uint8_t *pHash,
    uint32_t *pHashLength
)
{
    uint8_t u8MuChannel;
    hseSrvDescriptor_t *pHseSrvDesc;
    hseHashSrv_t *pHashSrv;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

    /* Get a free channel on u8MuInstance */
    u8MuChannel = Hse_Ip_GetFreeChannel(APP_MU_INSTANCE_U8);
    if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
    {
    	goto exit;
    }

    /* Complete the service descriptor placed in shared memory */
    pHseSrvDesc = &MbedTLS_aSrvDescriptor[u8MuChannel];
    memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));
    pHashSrv = &(pHseSrvDesc->hseSrv.hashReq);

#if defined (D_CACHE_ENABLE_MBEDTLS)

	hseSrvSGTNode_t inputSgtTbl;
	uint8_t *pAlignInput = NULL;
	uint8_t *pAlignHash = NULL ;
	uint8_t *pAlignHashLen = NULL;
	uint16_t nonSgtBuffLen = 0;

	memset(&inputSgtTbl, 0, sizeof(hseSrvSGTNode_t));

    if(NULL_PTR != pInput)
    {
#if defined (S32N55)
    	if(hashAlgo == HSE_HASH_ALGO_SHA3_224 || hashAlgo == HSE_HASH_ALGO_SHA3_256
    	    			|| hashAlgo == HSE_HASH_ALGO_SHA3_384 || hashAlgo == HSE_HASH_ALGO_SHA3_512
    					)
#else
    	if(hashAlgo == HSE_HASH_ALGO_SHA3_224 || hashAlgo == HSE_HASH_ALGO_SHA3_256
    			|| hashAlgo == HSE_HASH_ALGO_SHA3_384 || hashAlgo == HSE_HASH_ALGO_SHA3_512
				|| hashAlgo == HSE_HASH_ALGO_MP)
#endif
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
                pHashSrv->pInput = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignInput));
    	    	nonSgtBuffLen = 0;
        	}
        	else
        	{
    			/* Flush Input Data Buffer to memory*/
        		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pInput, inputLength);
        		 pHashSrv->pInput = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pInput));
        	}

            pHashSrv->sgtOption	= HSE_SGT_OPTION_NONE;
    	}
    	else
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
            	Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pInput, inputLength);
            	storeAlignBufptr((uint8_t*)pInput, inputLength, &inputSgtTbl );
    			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)inputSgtTbl.hseSrvSgtList,
    					sizeof(hseScatterList_t));
            }

            pHashSrv->pInput = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(inputSgtTbl.hseSrvSgtList));
            pHashSrv->sgtOption = HSE_SGT_OPTION_INPUT;
    	}
    }

    if(NULL_PTR != pHashLength)
    {
		nonSgtBuffLen = alignNonSgtBuff((uint8_t *)pHashLength, sizeof(uint32_t), 32);
		if(nonSgtBuffLen != NO_BUFF_ALLOC)
		{
			pAlignHashLen = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignHashLen)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

			memcpy(pAlignHashLen, pHashLength, sizeof(uint32_t));

			/* Flush Input Data Buffer to memory*/
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, TRUE, (uint32_t)pAlignHashLen, sizeof(uint32_t));
           #if defined(S32N55)
            pHashSrv->hashLength =*pAlignHashLen;
           #else
			pHashSrv->pHashLength = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignHashLen));
           #endif
	    	nonSgtBuffLen = 0;
		}
    	else
    	{
			/* Flush Input Data Buffer to memory*/
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, TRUE, (uint32_t)pHashLength, sizeof(uint32_t));
            #if defined S32N55
               if (pHashLength==NULL)
                  pHashSrv->hashLength    =0;
               else
                 pHashSrv->hashLength    =*pHashLength;
            #else
    		pHashSrv->pHashLength = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pHashLength));
           #endif
    	}
    }

    if(NULL_PTR != pHash)
    {
		nonSgtBuffLen = alignNonSgtBuff(pHash, *pHashLength, 32);
		if(nonSgtBuffLen != NO_BUFF_ALLOC)
		{
			pAlignHash = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignHash)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}
    		Cache_Ip_CleanByAddr( CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignHash, (*pHashLength));

			/* Flush Input Data Buffer to memory*/
			Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pAlignHash, *pHashLength);
			pHashSrv->pHash = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignHash));
			nonSgtBuffLen = 0;
		}
		else
		{
    		Cache_Ip_CleanByAddr( CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pHash, (*pHashLength));

			/* Flush Input Data Buffer to memory*/
			Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pHash, *pHashLength);
			pHashSrv->pHash = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pHash));
		}
    }

#endif /* D_CACHE_ENABLE_MBEDTLS */

    pHseSrvDesc->srvId      = HSE_SRV_ID_HASH;
    pHashSrv->accessMode    = accessMode;
    pHashSrv->streamId      = streamId;
    pHashSrv->hashAlgo      = hashAlgo;
    pHashSrv->inputLength   = inputLength;

#if !defined (D_CACHE_ENABLE_MBEDTLS)
    pHashSrv->pInput        = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pInput));
    pHashSrv->pHash         = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pHash));
#if defined S32N55
    if (pHashLength==NULL)
    pHashSrv->hashLength    =0;
    else
    pHashSrv->hashLength    =*pHashLength;
#else
    pHashSrv->pHashLength   = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pHashLength));
#endif
    pHashSrv->sgtOption		= HSE_SGT_OPTION_NONE;
#endif

	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

    /* Send the request asynchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

#if defined(D_CACHE_ENABLE_MBEDTLS)
    if(srvResponse == HSE_SRV_RSP_OK)
    {
    	if(NULL_PTR != pAlignHashLen)
    	{
    		memcpy(pHashLength, pAlignHashLen, sizeof(uint32_t));
    	}

		if(NULL_PTR != pAlignHash)
		{
			memcpy(pHash, pAlignHash, *pHashLength);
		}
    }
#endif

exit:
#if defined(D_CACHE_ENABLE_MBEDTLS)
    if(NULL_PTR != pAlignHashLen)
    {
    	nxp_hse_freeH(pAlignHashLen);
    	pAlignHashLen = NULL;
    }

    if(NULL_PTR != pAlignHash)
    {
    	nxp_hse_freeH(pAlignHash);
    	pAlignHash = NULL;
    }
#if defined(S32N55)
    if(hashAlgo == HSE_HASH_ALGO_SHA3_224 || hashAlgo == HSE_HASH_ALGO_SHA3_256
    			|| hashAlgo == HSE_HASH_ALGO_SHA3_384 || hashAlgo == HSE_HASH_ALGO_SHA3_512)
#else
	if(hashAlgo == HSE_HASH_ALGO_SHA3_224 || hashAlgo == HSE_HASH_ALGO_SHA3_256
			|| hashAlgo == HSE_HASH_ALGO_SHA3_384 || hashAlgo == HSE_HASH_ALGO_SHA3_512
			|| hashAlgo == HSE_HASH_ALGO_MP)
#endif
	{
		if(NULL_PTR != pAlignInput)
		{
			nxp_hse_freeH(pAlignInput);
			pAlignInput = NULL;
		}
	}
	else
	{
	    alignDataFree(inputSgtTbl.buffAllocFlag, &inputSgtTbl);
	}

#endif

    return srvResponse;
}

/*==================================================================================================
*                                       GLOBAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
* Description:  Blocking hash request
************************************************************************************************/
hseSrvResponse_t HSE_Hash
(
    hseHashAlgo_t hashAlgo,
    const uint8_t *pInput,
    uint32_t inputLength,
    uint8_t *pHash,
    uint32_t *pHashLength
)
{
	return HSE_HashData(HSE_ACCESS_MODE_ONE_PASS, 0U, hashAlgo,pInput, inputLength,	\
		pHash, pHashLength);
}

/*************************************************************************************************
* Description:  Blocking hash stream start request
************************************************************************************************/
hseSrvResponse_t HSE_HashStreamStart
(
    uint32_t streamId,
    hseHashAlgo_t hashAlgo,
    const uint8_t *pInput,
    uint32_t inputLength,
    uint8_t *pHash,
    uint32_t *pHashLength
)
{
	return HSE_HashData(HSE_ACCESS_MODE_START, streamId, hashAlgo,pInput, inputLength,	\
		pHash, pHashLength);
}

/*************************************************************************************************
* Description:  Blocking hash stream update request
************************************************************************************************/
hseSrvResponse_t HSE_HashStreamUpdate
(
    uint32_t streamId,
    hseHashAlgo_t hashAlgo,
    const uint8_t *pInput,
    uint32_t inputLength,
    uint8_t *pHash,
    uint32_t *pHashLength
)
{
	return HSE_HashData(HSE_ACCESS_MODE_UPDATE, streamId, hashAlgo,pInput, inputLength,	\
		pHash, pHashLength);
}

/*************************************************************************************************
* Description:  Blocking hash stream finish request
************************************************************************************************/
hseSrvResponse_t HSE_HashStreamFinish
(
    uint32_t streamId,
    hseHashAlgo_t hashAlgo,
    const uint8_t *pInput,
    uint32_t inputLength,
    uint8_t *pHash,
    uint32_t *pHashLength
)
{
	return HSE_HashData(HSE_ACCESS_MODE_FINISH, streamId, hashAlgo,pInput, inputLength,	\
		pHash, pHashLength);
}

#ifdef __cplusplus
}
#endif
