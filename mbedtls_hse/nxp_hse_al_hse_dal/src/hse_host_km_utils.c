/**
*   @file    	hse_host_km_utils.c
*
*   @brief   	This file implements wrappers for key mgmt utils services
*   			(i.e. get key info, erase key, etc.).
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

/*==================================================================================================
 *                                       LOCAL FUNCTIONS
 ==================================================================================================*/

/*==================================================================================================
 *                                       GLOBAL FUNCTIONS
 ==================================================================================================*/

/*************************************************************************************************
* Description:  Retrieve the key info
************************************************************************************************/
hseSrvResponse_t HSE_GetKeyInfo
(
    hseKeyHandle_t keyHandle,
    hseKeyInfo_t* reqKeyInfo
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

    hseKeyInfo_t *pAlignReqKeyInfo = NULL ;
	uint16_t nonSgtBuffLen = 0;

    if(NULL_PTR != reqKeyInfo)
    {
    	nonSgtBuffLen = alignNonSgtBuff((uint8_t*)reqKeyInfo, sizeof(hseKeyInfo_t), 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
    		pAlignReqKeyInfo = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignReqKeyInfo)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		/* Invalidate Output Data Buffer */
    		Cache_Ip_CleanByAddr( CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignReqKeyInfo, sizeof(hseKeyInfo_t));

    		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pAlignReqKeyInfo, sizeof(hseKeyInfo_t));
    		memcpy(pAlignReqKeyInfo, reqKeyInfo, sizeof(*reqKeyInfo));
    		pHseSrvDesc->hseSrv.getKeyInfoReq.pKeyInfo 	= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignReqKeyInfo));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE,(uint32_t)reqKeyInfo, sizeof(hseKeyInfo_t));


        	/* Invalidate Output Data Buffer */
        	Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)reqKeyInfo, sizeof(hseKeyInfo_t));
            pHseSrvDesc->hseSrv.getKeyInfoReq.pKeyInfo 	= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(reqKeyInfo));
    	}
    }

#endif /* D_CACHE_ENABLE_MBEDTLS */

    /* Complete service parameters */
#if defined (S32N55)
    pHseSrvDesc->srvId 							= HSE_SRV_ID_KEY_GET_INFO;
#else
    pHseSrvDesc->srvId 							= HSE_SRV_ID_GET_KEY_INFO;
#endif
    pHseSrvDesc->hseSrv.getKeyInfoReq.keyHandle = keyHandle;

#if !defined(D_CACHE_ENABLE_MBEDTLS)
    pHseSrvDesc->hseSrv.getKeyInfoReq.pKeyInfo 	= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(reqKeyInfo));
#endif

  /* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

	/* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

#if defined(D_CACHE_ENABLE_MBEDTLS)
    if(HSE_SRV_RSP_OK == srvResponse)
    {
    	if(NULL_PTR != pAlignReqKeyInfo)
    	{
    		memcpy(reqKeyInfo, pAlignReqKeyInfo, sizeof(hseKeyInfo_t));
    	}
    }
#endif

exit:

#if defined(D_CACHE_ENABLE_MBEDTLS)
	if(NULL_PTR != pAlignReqKeyInfo)
	{
		nxp_hse_freeH(pAlignReqKeyInfo);
		pAlignReqKeyInfo = NULL;
	}
#endif

    return srvResponse;
}

/*************************************************************************************************
* Description:  Erase one key by handle / more keys by option (sym / asym / all RAM/NVM)
*   NOTE:       Use keyHandle = HSE_INVALID_KEY_HANDLE to delete more then one key
************************************************************************************************/
hseSrvResponse_t HSE_EraseKey
(
    hseKeyHandle_t        keyHandle,
    hseEraseKeyOptions_t  eraseKeyOptions
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

    /* Complete service parameters */
#if defined(S32N55)
    pHseSrvDesc->srvId 								= HSE_SRV_ID_KEY_ERASE;
#else
    pHseSrvDesc->srvId 								= HSE_SRV_ID_ERASE_KEY;
#endif
    pHseSrvDesc->hseSrv.eraseKeyReq.keyHandle 		= keyHandle;
    pHseSrvDesc->hseSrv.eraseKeyReq.eraseKeyOptions = eraseKeyOptions;

	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

    /* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

exit:
    return srvResponse;
}

#ifdef __cplusplus
}
#endif
