/**
*   @file    	hse_host_rng.c
*
*   @brief   	This file implements services for random number generator.
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
 * 	@brief		Random Number Generator service
 *
 * 	@param[in]	rngClass
 *				The RNG class
 *
 *	@param[out]	pOutput
 *				The address where the random number will be stored
 *
 *	@param[in]	outputLength
 *				Length on the random number in bytes. It should not be more than 2048
 *              bytes, otherwise an error will be returned by HSE FW
 *
 *  @return     The HSE Service response
 *
 */
static hseSrvResponse_t HSE_RngReq
(
    hseRngClass_t rngClass,
    uint8_t *pOutput,
    uint32_t outputLength
);

/*==================================================================================================
*                                       LOCAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
* Description:  Random Number Generator service
************************************************************************************************/
static hseSrvResponse_t HSE_RngReq
(
    hseRngClass_t rngClass,
    uint8_t *pOutput,
    uint32_t outputLength
)
{
	uint8_t u8MuChannel;
	hseGetRandomNumSrv_t *pRngSrv;
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
	pRngSrv = &(pHseSrvDesc->hseSrv.getRandomNumReq);
	memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));

#if defined(D_CACHE_ENABLE_MBEDTLS)

	uint8_t *pAlignOut = NULL ;
	uint16_t nonSgtBuffLen = 0;

    if(NULL_PTR != pOutput)
    {
    	nonSgtBuffLen = alignNonSgtBuff(pOutput, outputLength, 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
    		pAlignOut = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignOut)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignOut, outputLength);


    		/* Invalidate Output Data Buffer */
    		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pAlignOut, outputLength);
    		pRngSrv->pRandomNum = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignOut));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pOutput, outputLength);


    		/* Invalidate Output Data Buffer */
        	Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pOutput, outputLength);
        	pRngSrv->pRandomNum = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pOutput));
    	}
    }

#endif /* D_CACHE_ENABLE_MBEDTLS */

	/* Fill the service descriptor */
	pHseSrvDesc->srvId 			= HSE_SRV_ID_GET_RANDOM_NUM;
	pRngSrv->rngClass 			= rngClass;
	pRngSrv->randomNumLength 	= outputLength;

#if !defined(D_CACHE_ENABLE_MBEDTLS)
	pRngSrv->pRandomNum 		= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pOutput));
#endif

	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

	/* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

#if defined(D_CACHE_ENABLE_MBEDTLS)
    if(srvResponse == HSE_SRV_RSP_OK)
    {
    	if(NULL_PTR != pAlignOut)
    	{
        	memcpy(pOutput, pAlignOut, outputLength);
    	}
    }
#endif

exit:

#if defined(D_CACHE_ENABLE_MBEDTLS)
	if(NULL_PTR != pAlignOut)
	{
		nxp_hse_freeH(pAlignOut);
		pAlignOut = NULL;
	}
#endif

	return srvResponse;
}

/*==================================================================================================
*                                       GLOBAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
* Description:  Random Number Generator service for class DRG3
************************************************************************************************/
#if !defined(S32N55)
hseSrvResponse_t HSE_RngDRG3
(
   uint8_t *pOutput,
   uint32_t outputLength
)
{
   return HSE_RngReq(HSE_RNG_CLASS_DRG3, pOutput, outputLength);
}

/*************************************************************************************************
* Description:  Random Number Generator service for class DRG4
************************************************************************************************/
hseSrvResponse_t HSE_RngDRG4
(
   uint8_t *pOutput,
   uint32_t outputLength
)
{
   return HSE_RngReq(HSE_RNG_CLASS_DRG4, pOutput, outputLength);
}
#endif

/*************************************************************************************************
* Description:  Random Number Generator service for class PTG3
************************************************************************************************/
hseSrvResponse_t HSE_RngPTG3
(
    uint8_t *pOutput,
    uint32_t outputLength
)
{
    return HSE_RngReq(HSE_RNG_CLASS_PTG3, pOutput, outputLength);
}

#ifdef __cplusplus
}
#endif
