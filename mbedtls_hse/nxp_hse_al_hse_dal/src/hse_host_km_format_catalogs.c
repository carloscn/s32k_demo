/**
*   @file    	hse_host_km_format_catalogs.c
*
*   @brief   	This file implements wrappers for key catalogs format HSE service.
*
*   @addtogroup [HSE_DAL]
*   @{
*/
/*==================================================================================================
*
*   (c) Copyright 2022, 2024 NXP.
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
#if defined(S32N55)
uint8_t oid[] =
{
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};


uint8_t odk[] =
{
    0x02,0x05,0xA3,0xB4,0x07,0x92,0x53,0x61,0x15,0x29,0x76,0x29,0x83,0x17,0x38,0x42,
    0x05,0x56,0x92,0x63,0x57,0x25,0x39,0x82,0x44,0x73,0x11,0x03,0x28,0x32,0x66,0x15
};


uint8_t oct[] =
{
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x92,0x53,0x61,0x15,0x02,0x99,0x35,0x55,0x18,0x54,0x87,0x20,0x14,0x21,0x99,0xA4,
    0x83,0x17,0x38,0x42,0x07,0xA3,0xB4,0x07,0x92,0xB4,0x07,0x92,0x53,0x25,0x40,0x22,
};
#endif
/*==================================================================================================
 *                                   LOCAL FUNCTION PROTOTYPES
 ==================================================================================================*/

/*==================================================================================================
 *                                       LOCAL FUNCTIONS
 ==================================================================================================*/

/*==================================================================================================
 *                                       GLOBAL FUNCTIONS
 ==================================================================================================*/
#if defined(S32N55)
hseSheCatalogFormat_t mHseSheCatalogCfg =
{
    .n = 3,
    .reserved = {0x00, 0x00, 0x00},
    .entries =
    {
        {HSE_ALL_MU_MASK, 13U, {0U}},
        {HSE_ALL_MU_MASK, 13U, {0U}},
        {HSE_ALL_MU_MASK, 13U, {0U}}
    }
};
#endif
/*************************************************************************************************
* Description:  Formats the key catalogs (first step in configuring the key catalogs).
************************************************************************************************/

#if defined(S32N55)
hseSrvResponse_t HSE_FormatKeyCatalogs(void)
{
	hseStdKeyCatalogFormat_t mHseRamCatalogCfg =
	{
#if defined (TEST_SUITE1) || defined(TEST_SUITE2) ||defined(BENCHMARK) ||defined(S32N55)
			.n=9,
#elif defined(TEST_SUITE3)
			.n=8,
#else
			.n=5,
#endif
			.reserved = {0x00,0x00,0x00},
			.entries =
			{
					HSE_RAM_KEY_CATALOG_CFG
			}
	};
	hseStdKeyCatalogFormat_t mHseNvmCatalogCfg =
	{
#if defined (TEST_SUITE1) || defined(TEST_SUITE2) ||defined(BENCHMARK)||defined(S32N55)
			.n=6,
#elif defined(TEST_SUITE3)
			.n=4,
#else
			.n=2,
#endif
			.reserved = {0x00,0x00,0x00},
			.entries =
			{
					HSE_NVM_KEY_CATALOG_CFG
			}
	};

	uint8_t u8MuChannel;
    hseSrvDescriptor_t *pHseSrvDesc;
    hseOwnerInstallSrv_t *pFormatKeyCatalogsReq;
    hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

    /* Get a free channel on MU0 */
    u8MuChannel = Hse_Ip_GetFreeChannel(APP_MU_INSTANCE_U8);
    if(HSE_IP_INVALID_MU_CHANNEL_U8 == u8MuChannel)
    {
    	srvResponse = HSE_SRV_RSP_GENERAL_ERROR;
    }


    /* Complete the service descriptor placed in shared memory */
    pHseSrvDesc = &MbedTLS_aSrvDescriptor[u8MuChannel];
    memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));
    pFormatKeyCatalogsReq = &(pHseSrvDesc->hseSrv.ownerInstallReq);
    /* Use the default catalog configurations to format the NVM and RAM catalogs */
    pHseSrvDesc->srvId = HSE_SRV_ID_OWNER_INSTALL;
    pFormatKeyCatalogsReq->pOid                 = (HOST_ADDR)oid;
	pFormatKeyCatalogsReq->pOdk                 = (HOST_ADDR)odk;
	pFormatKeyCatalogsReq->pOct                 = (HOST_ADDR)oct;
	pFormatKeyCatalogsReq->pNvmCatalogFormat 	= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(&mHseNvmCatalogCfg));
    pFormatKeyCatalogsReq->pRamCatalogFormat 	= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(&mHseRamCatalogCfg));
    pFormatKeyCatalogsReq->pSheConfig           = (HOST_ADDR)&mHseSheCatalogCfg;

	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

    /* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

exit:

    return srvResponse;
}
#else
    hseSrvResponse_t HSE_FormatKeyCatalogs
    (
    	const hseKeyGroupCfgEntry_t* ram_key_catalog,
    	const hseKeyGroupCfgEntry_t* nvm_key_catalog
    )
    {
        uint8_t u8MuChannel;
        hseSrvDescriptor_t *pHseSrvDesc;
        hseFormatKeyCatalogsSrv_t *pFormatKeyCatalogsReq;
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
        pFormatKeyCatalogsReq = &pHseSrvDesc->hseSrv.formatKeyCatalogsReq;

        /* Use the default catalog configurations to format the NVM and RAM catalogs */
        pHseSrvDesc->srvId  						= HSE_SRV_ID_FORMAT_KEY_CATALOGS;
        pFormatKeyCatalogsReq->pNvmKeyCatalogCfg 	= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(nvm_key_catalog));
        pFormatKeyCatalogsReq->pRamKeyCatalogCfg 	= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(ram_key_catalog));

    	/* Build the request to be sent to Hse Ip layer */
        MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
        MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

        /* Send the request synchronously */
        srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

    exit:

        return srvResponse;
    }
#endif

#ifdef __cplusplus
}
#endif
