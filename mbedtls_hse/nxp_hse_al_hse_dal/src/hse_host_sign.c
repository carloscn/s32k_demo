/**
 *   @file    		hse_host_sign.c
 *
 *   @brief   		This file use verify signature operation
 *   @details 		This file will generate & verify signatures.
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
#include "mbedtls/platform.h"
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

uint32_t pAlignSignLen0[1];
uint32_t pAlignSignLen1[1];
uint32_t pAlignCipherLen[1];

#define CRYPTO_43_HSE_STOP_SEC_VAR_CLEARED_UNSPECIFIED_NO_CACHEABLE
#include "Crypto_43_HSE_MemMap.h"
#else
#define CRYPTO_START_SEC_VAR_CLEARED_UNSPECIFIED_NO_CACHEABLE
#include "Crypto_MemMap.h"

uint32_t pAlignSignLen0[1];
uint32_t pAlignSignLen1[1];
uint32_t pAlignCipherLen[1];

#define CRYPTO_STOP_SEC_VAR_CLEARED_UNSPECIFIED_NO_CACHEABLE
#include "Crypto_MemMap.h"
#endif

#endif

/*==================================================================================================
 *                                   LOCAL FUNCTION PROTOTYPES
 ==================================================================================================*/

/**
 * 	@brief		Generic Signature generation/verification HSE request
 *
 * 	@param[in]	authDir
 *				Specifies the direction: generate/verify. STREAMING USAGE: Used in FINISH
 *
 * 	@param[in]	accessMode
 *				Specifies the access mode: ONE-PASS, START, UPDATE, FINISH
 *
 *	@param[in]	signScheme
 *				Scheme for selected Signature algo.
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation
 *
 *	@param[in]	pInput
 *				The address of the message to be signed/verify.
 *
 *	@param[in]	inputLength
 *				Input length
 *
 *  @param[in]	bInputIsHashed
 *				Specifies that the input is already hashed with the algorithm in specified in the sign scheme
 *
 *	@param[out]	pSign[1]
 *				Where the signature components must be stored.  It is output for "generate" and input for "verify
 *
 *	@param[in/out]	pSignLen[1]
 *				An array of two addresses of two uint32_t values containing signature lengths. It is input/output for "generate" and input for
 *				"verify".On calling "generate" service, these parameter shall contain the size of the signature buffers provided by the
 *				application. When the request has finished, the actual lengths of the signature components.
 *
 *  @return     The HSE Service response
 *
 */

static hseSrvResponse_t HSE_SignReq
(
    const hseAuthDir_t authDir,
    const hseAccessMode_t accessMode,
    const hseSignScheme_t signScheme,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLength,
    const bool_t bInputIsHashed,
    uint8_t *pSign0,
    uint8_t *pSign1,
    uint32_t *pSignLen0,
    uint32_t *pSignLen1
);

/**
 * 	@brief		Generic RSA ENC/DEC HSE request
 *
 * 	@param[in]	rsaScheme
 *				The RSA cipher scheme
 *
 * 	@param[in]	cipherDir
 *				Specifies the cipher direction: encryption/decryption
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation
 *
 *  @param[in]	inputLength
 *				The input length (plaintext or ciphertext)
 *
 *	@param[in]	pInput
 *				The plaintext for encryption or the ciphertext for decryption
 *
 *	@param[in/out]	pOutputLength
 *				Holds the address to a location (an uint32_t variable) in which the output length in bytes is stored
 *
 *	@param[out]	pOutput
 *				The address of the Output. The plaintext for decryption or ciphertext for encryption
 *
 *  @return     The HSE Service response
 *
 */
static hseSrvResponse_t HSE_RsaCipherReq
(
	const hseRsaCipherScheme_t rsaScheme,
	const hseCipherDir_t cipherDir,
	const hseKeyHandle_t keyHandle,
	const uint32_t inputLength,
	const uint8_t *pInput,
	uint32_t *pOutputLength,
	uint8_t *pOutput
);

/*==================================================================================================
 *                                       LOCAL FUNCTIONS
 ==================================================================================================*/

/*************************************************************************************************
* Description:  Generic Signature generation/verification HSE request
************************************************************************************************/

static hseSrvResponse_t HSE_SignReq
(
    const hseAuthDir_t authDir,
    const hseAccessMode_t accessMode,
    const hseSignScheme_t signScheme,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLength,
    const bool_t bInputIsHashed,
    uint8_t *pSign0,
    uint8_t *pSign1,
    uint32_t *pSignLen0,
    uint32_t *pSignLen1
)
{
    uint8_t u8MuChannel;
    hseSignSrv_t* pSignSrv;
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
    pSignSrv = &(pHseSrvDesc->hseSrv.signReq);
    memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));

#if defined (D_CACHE_ENABLE_MBEDTLS)

	hseSrvSGTNode_t inputSgtTbl;
	uint8_t *pAlignInput = NULL;
	uint8_t *pAlignSign0 = NULL ;
	uint8_t *pAlignSign1 = NULL ;
	uint16_t nonSgtBuffLen = 0;

	memset(&inputSgtTbl, 0, sizeof(hseSrvSGTNode_t));

    if(NULL_PTR != pInput)
    {
    	if(bInputIsHashed)
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
        		pSignSrv->pInput = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignInput));
    	    	nonSgtBuffLen = 0;
        	}
        	else
        	{
        		if(inputLength != 0)
        		{
        			/* Flush Input Data Buffer to memory*/
            		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pInput, inputLength);
            		pSignSrv->pInput = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pInput));
        		}
        		else
        		{
        			pSignSrv->pInput = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pInput));
        		}
        	}

        	pSignSrv->sgtOption	= HSE_SGT_OPTION_NONE;
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
            	Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, false, (uint32_t)pInput, inputLength);
            	storeAlignBufptr((uint8_t*)pInput, inputLength, &inputSgtTbl );
    			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)inputSgtTbl.hseSrvSgtList,
    					sizeof(hseScatterList_t));
            }

            pSignSrv->pInput = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(inputSgtTbl.hseSrvSgtList));
            pSignSrv->sgtOption = HSE_SGT_OPTION_INPUT;
    	}
    }
#if defined(S32N55)
    uint32_t l1 = 0;
	uint32_t l2 = 0;
	if( pSignLen0 != NULL)
	{
		l1 = *pSignLen0;
	}
	if( pSignLen1 != NULL)
	{
		l2 = *pSignLen1;
	}
	uint32_t Total = l1 + l2;
	uint8_t *pConcat = NULL;
	pConcat = mbedtls_calloc(1,Total);

	pSignSrv->signLen = Total;



	if(NULL_PTR != pSign0)
		{
			if(HSE_AUTH_DIR_GENERATE == authDir)
			{
	    		nonSgtBuffLen = alignNonSgtBuff(pSign0, *pSignLen0, 32);
	    		if(nonSgtBuffLen != NO_BUFF_ALLOC)
	    		{
	    			pAlignSign0 = nxp_hse_callocH(nonSgtBuffLen, 32);
	        		if(NULL_PTR == pAlignSign0)
	        		{
	        			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
	        			goto exit;
	        		}

	        		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignSign0, *pSignLen0);

	    			/* Flush Input Data Buffer to memory*/
	        		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pAlignSign0, *pSignLen0);
#if defined(S32N55)
	        		memcpy(pConcat, pAlignSign0, l1);
#else
	        		pSignSrv->pSignature[0] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignSign0));
#endif
	        		memcpy(pConcat, pAlignSign0, l1);
	    	    	nonSgtBuffLen = 0;
	    		}
	        	else
	        	{
	        		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA,FALSE, (uint32_t)pSign0, *pSignLen0);

	        		/* Flush Input Data Buffer to memory*/
	        		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pSign0, *pSignLen0);
#if defined(S32N55)
	        		memcpy(pConcat, pSign0, l1);
#else
	        		pSignSrv->pSignature[0] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pSign0));
#endif
	        	}
			}
			else
			{
	    		nonSgtBuffLen = alignNonSgtBuff(pSign0, *pSignLen0, 32);
	    		if(nonSgtBuffLen != NO_BUFF_ALLOC)
	    		{
	    			pAlignSign0 = nxp_hse_callocH(nonSgtBuffLen, 32);
	        		if(NULL_PTR == pAlignSign0)
	        		{
	        			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
	        			goto exit;
	        		}

	    			memcpy(pAlignSign0, pSign0, *pSignLen0);

	    			/* Flush Input Data Buffer to memory*/
	    			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignSign0, *pSignLen0);
#if defined(S32N55)
	    			memcpy(pConcat, pAlignSign0, l1);
#else
	        		pSignSrv->pSignature[0] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignSign0));
#endif
	    	    	nonSgtBuffLen = 0;
	    		}
	        	else
	        	{
	    			/* Flush Input Data Buffer to memory*/
	        		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pSign0, *pSignLen0);
#if defined(S32N55)
	        		memcpy(pConcat, pSign0, l1);
#else
	        		pSignSrv->pSignature[0] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pSign0));
#endif
	        	}
			}
		}

		if(NULL_PTR != pSign1)
		{
			if(HSE_AUTH_DIR_GENERATE == authDir)
			{
	    		nonSgtBuffLen = alignNonSgtBuff(pSign1, *pSignLen1, 32);
	    		if(nonSgtBuffLen != NO_BUFF_ALLOC)
	    		{
	    			pAlignSign1 = nxp_hse_callocH(nonSgtBuffLen, 32);
	        		if(NULL_PTR == pAlignSign1)
	        		{
	        			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
	        			goto exit;
	        		}

	        		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignSign1, *pSignLen1);


	    			/* Flush Input Data Buffer to memory*/
	        		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pAlignSign1, *pSignLen1);
#if defined(S32N55)
	        		memcpy(pConcat + l1, pAlignSign1, l2);
#else
	        		pSignSrv->pSignature[1] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignSign1));
#endif
	    	    	nonSgtBuffLen = 0;
	    		}
	        	else
	        	{
	        		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pSign1, *pSignLen1);


	    			/* Flush Input Data Buffer to memory*/
	        		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pSign1, *pSignLen1);
#if defined(S32N55)
	        		memcpy(pConcat + l1, pSign1, l2);
#else
	        		pSignSrv->pSignature[1] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pSign1));
#endif
	        	}
			}
			else
			{
	    		nonSgtBuffLen = alignNonSgtBuff(pSign1, *pSignLen1, 32);
	    		if(nonSgtBuffLen != NO_BUFF_ALLOC)
	    		{
	    			pAlignSign1 = nxp_hse_callocH(nonSgtBuffLen, 32);
	        		if(NULL_PTR == pAlignSign1)
	        		{
	        			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
	        			goto exit;
	        		}

	    			memcpy(pAlignSign1, pSign1, *pSignLen1);

	    			/* Flush Input Data Buffer to memory*/
	    			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignSign1, *pSignLen1);
#if defined(S32N55)
	        		memcpy(pConcat + l1, pAlignSign1, l2);
#else
	        		pSignSrv->pSignature[1] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignSign1));
#endif
	    	    	nonSgtBuffLen = 0;
	    		}
	        	else
	        	{
	    			/* Flush Input Data Buffer to memory*/
	        		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pSign1, *pSignLen1);
#if defined(S32N55)
	        		memcpy(pConcat + l1, pSign1, l2);
#else
	        		pSignSrv->pSignature[1] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pSign1));
#endif
	        	}
			}
		}

		pSignSrv->pSignature = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pConcat));
#else
	if(NULL_PTR != pSignLen0)
	{
		pAlignSignLen0[0] = *pSignLen0;
	    pSignSrv->pSignatureLength[0] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignSignLen0));
	}
	else
	{
		pSignSrv->pSignatureLength[0] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pSignLen0));
	}

	if(NULL_PTR != pSignLen1)
	{
		pAlignSignLen1[0] = *pSignLen1;
		pSignSrv->pSignatureLength[1] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignSignLen1));
	}
	else
	{
		pSignSrv->pSignatureLength[1] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pSignLen1));
	}

	if(NULL_PTR != pSign0)
	{
		if(HSE_AUTH_DIR_GENERATE == authDir)
		{
    		nonSgtBuffLen = alignNonSgtBuff(pSign0, *pSignLen0, 32);
    		if(nonSgtBuffLen != NO_BUFF_ALLOC)
    		{
    			pAlignSign0 = nxp_hse_callocH(nonSgtBuffLen, 32);
        		if(NULL_PTR == pAlignSign0)
        		{
        			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
        			goto exit;
        		}

        		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignSign0, *pSignLen0);

    			/* Flush Input Data Buffer to memory*/
        		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pAlignSign0, *pSignLen0);
        		pSignSrv->pSignature[0] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignSign0));
    	    	nonSgtBuffLen = 0;
    		}
        	else
        	{
        		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA,FALSE, (uint32_t)pSign0, *pSignLen0);

        		/* Flush Input Data Buffer to memory*/
        		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pSign0, *pSignLen0);
        		pSignSrv->pSignature[0] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pSign0));
        	}
		}
		else
		{
    		nonSgtBuffLen = alignNonSgtBuff(pSign0, *pSignLen0, 32);
    		if(nonSgtBuffLen != NO_BUFF_ALLOC)
    		{
    			pAlignSign0 = nxp_hse_callocH(nonSgtBuffLen, 32);
        		if(NULL_PTR == pAlignSign0)
        		{
        			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
        			goto exit;
        		}

    			memcpy(pAlignSign0, pSign0, *pSignLen0);

    			/* Flush Input Data Buffer to memory*/
    			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignSign0, *pSignLen0);
        		pSignSrv->pSignature[0] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignSign0));
    	    	nonSgtBuffLen = 0;
    		}
        	else
        	{
    			/* Flush Input Data Buffer to memory*/
        		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pSign0, *pSignLen0);
        		pSignSrv->pSignature[0] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pSign0));
        	}
		}
	}

	if(NULL_PTR != pSign1)
	{
		if(HSE_AUTH_DIR_GENERATE == authDir)
		{
    		nonSgtBuffLen = alignNonSgtBuff(pSign1, *pSignLen1, 32);
    		if(nonSgtBuffLen != NO_BUFF_ALLOC)
    		{
    			pAlignSign1 = nxp_hse_callocH(nonSgtBuffLen, 32);
        		if(NULL_PTR == pAlignSign1)
        		{
        			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
        			goto exit;
        		}

        		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignSign1, *pSignLen1);


    			/* Flush Input Data Buffer to memory*/
        		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pAlignSign1, *pSignLen1);
        		pSignSrv->pSignature[1] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignSign1));
    	    	nonSgtBuffLen = 0;
    		}
        	else
        	{
        		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pSign1, *pSignLen1);


    			/* Flush Input Data Buffer to memory*/
        		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pSign1, *pSignLen1);
        		pSignSrv->pSignature[1] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pSign1));
        	}
		}
		else
		{
    		nonSgtBuffLen = alignNonSgtBuff(pSign1, *pSignLen1, 32);
    		if(nonSgtBuffLen != NO_BUFF_ALLOC)
    		{
    			pAlignSign1 = nxp_hse_callocH(nonSgtBuffLen, 32);
        		if(NULL_PTR == pAlignSign1)
        		{
        			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
        			goto exit;
        		}

    			memcpy(pAlignSign1, pSign1, *pSignLen1);

    			/* Flush Input Data Buffer to memory*/
    			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignSign1, *pSignLen1);
        		pSignSrv->pSignature[1] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignSign1));
    	    	nonSgtBuffLen = 0;
    		}
        	else
        	{
    			/* Flush Input Data Buffer to memory*/
        		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pSign1, *pSignLen1);
        		pSignSrv->pSignature[1] = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pSign1));
        	}
		}
	}
#endif
#endif/* D_CACHE_ENABLE_MBEDTLS */

    /* Complete service parameters */
    pHseSrvDesc->srvId 				= HSE_SRV_ID_SIGN;
    pSignSrv->authDir 				= authDir;
    pSignSrv->accessMode 			= accessMode;
    pSignSrv->signScheme 			= signScheme;
    pSignSrv->keyHandle 			= keyHandle;
    pSignSrv->inputLength 			= inputLength;
    pSignSrv->bInputIsHashed 		= bInputIsHashed;

#if defined(D_CACHE_ENABLE_MBEDTLS)
#if defined(S32N55)
    pSignSrv->signLen     = Total;
#else
    pSignSrv->pSignatureLength[0] 	= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignSignLen0));
    pSignSrv->pSignatureLength[1] 	= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignSignLen1));
#endif

#endif
#if defined(S32N55)

    uint32_t L1 = 0;
        uint32_t L2 = 0;
        if( pSignLen0 != NULL)
        {
        	L1 = *pSignLen0;
        }
        if( pSignLen1 != NULL)
    	{
    		L2 = *pSignLen1;
    	}
        uint32_t total = L1 + L2;
    	uint8_t *pconcat = NULL;
    	pconcat = mbedtls_calloc(1,total);
    	if(pconcat != NULL)
    	{
    	memcpy(pconcat, pSign0, L1);
    	if(pSign1!=NULL)
    	{
    		memcpy(pconcat + L1, pSign1, L2);
    	}
    	}
    pSignSrv->pInput 				= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pInput));
    pSignSrv->pSignature 		    = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pconcat));
    pSignSrv->signLen               = total;
    pSignSrv->sgtOption				= HSE_SGT_OPTION_NONE;
#else
    pSignSrv->pInput 				= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pInput));
    pSignSrv->pSignature[0] 		= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pSign0));
    pSignSrv->pSignature[1] 		= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pSign1));
    pSignSrv->pSignatureLength[0] 	= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pSignLen0));
    pSignSrv->pSignatureLength[1] 	= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pSignLen1));
    pSignSrv->sgtOption				= HSE_SGT_OPTION_NONE;
#endif
	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

    /* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);
#if defined(S32N55)
    memcpy(pSign0,pconcat,L1);

    memcpy(pSign1,pconcat+L1,L2);
    mbedtls_free(pconcat);
#endif
#if defined(D_CACHE_ENABLE_MBEDTLS) && defined(S32N55)
    memcpy(pAlignSign0,pConcat,l1);
	memcpy(pAlignSign1,pConcat+l1,l2);
	mbedtls_free(pconcat);
#endif
#if defined(D_CACHE_ENABLE_MBEDTLS)
    if(srvResponse == HSE_SRV_RSP_OK)
    {
    	if(NULL_PTR != pSignLen0)
    	{
    		memcpy(pSignLen0, pAlignSignLen0, sizeof(uint32_t));
    	}

    	if(NULL_PTR != pSignLen1)
    	{
    		memcpy(pSignLen1, pAlignSignLen1, sizeof(uint32_t));
    	}

    	if(HSE_AUTH_DIR_GENERATE == authDir)
    	{
    		if(NULL_PTR != pAlignSign0)
    		{
        		memcpy(pSign0, pAlignSign0, *pSignLen0);
    		}

    		if(NULL_PTR != pAlignSign1)
    		{
        		memcpy(pSign1, pAlignSign1, *pSignLen1);
    		}
    	}
    }
#endif

exit:

#if defined(D_CACHE_ENABLE_MBEDTLS)
	if(NULL_PTR != pAlignSign0)
	{
		nxp_hse_freeH(pAlignSign0);
		pAlignSign0 = NULL;
	}

	if(NULL_PTR != pAlignSign1)
	{
		nxp_hse_freeH(pAlignSign1);
		pAlignSign1 = NULL;
	}

    if(bInputIsHashed)
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

/*************************************************************************************************
* Description:  Generic RSA ENC/DEC HSE request
************************************************************************************************/
static hseSrvResponse_t HSE_RsaCipherReq
(
	const hseRsaCipherScheme_t rsaScheme,
	const hseCipherDir_t cipherDir,
	const hseKeyHandle_t keyHandle,
	const uint32_t inputLength,
	const uint8_t *pInput,
	uint32_t *pOutputLength,
	uint8_t *pOutput
)
{
	uint8_t u8MuChannel;
	hseRsaCipherSrv_t *pRsaSrv;
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
	pRsaSrv = &(pHseSrvDesc->hseSrv.rsaCipherReq);
	memset(pHseSrvDesc, 0, sizeof(hseSrvDescriptor_t));
	pHseSrvDesc->srvId = HSE_SRV_ID_RSA_CIPHER;

#if defined (D_CACHE_ENABLE_MBEDTLS)

	uint8_t *pAlignInput = NULL;
	uint8_t *pAlignOutput = NULL ;
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
    		pRsaSrv->pInput = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignInput));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
			/* Flush Input Data Buffer to memory*/
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pInput, inputLength);
    		pRsaSrv->pInput = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pInput));
    	}
    }

    if(NULL_PTR != pOutput)
    {
    	nonSgtBuffLen = alignNonSgtBuff(pOutput, *pOutputLength, 32);
    	if(nonSgtBuffLen != NO_BUFF_ALLOC)
    	{
			/* Flush Input Data Buffer to memory */
    		pAlignOutput = nxp_hse_callocH(nonSgtBuffLen, 32);
    		if(NULL_PTR == pAlignOutput)
    		{
    			srvResponse = HSE_SRV_RSP_MEMORY_FAILURE;
    			goto exit;
    		}

    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, (uint32_t)pAlignOutput, *pOutputLength);


    		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pAlignOutput, *pOutputLength);
    		pRsaSrv->pOutput = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignOutput));
	    	nonSgtBuffLen = 0;
    	}
    	else
    	{
    		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE,(uint32_t)pOutput, *pOutputLength);


			/* Flush Input Data Buffer to memory*/
    		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, (uint32_t)pOutput, *pOutputLength);
    		pRsaSrv->pOutput = Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pOutput));
    	}
    }

	if(NULL_PTR != pOutputLength)
	{
		memcpy(pAlignCipherLen, pOutputLength, sizeof(uint32_t));
	}

#endif

	pRsaSrv->rsaScheme 		= rsaScheme;
	pRsaSrv->cipherDir 		= cipherDir;
	pRsaSrv->keyHandle 		= keyHandle;
	pRsaSrv->inputLength 	= inputLength;


#if defined(D_CACHE_ENABLE_MBEDTLS)
	pRsaSrv->pOutputLength 	= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pAlignCipherLen));
#else
	pRsaSrv->pOutput 		= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pOutput));
	pRsaSrv->pInput 		= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pInput));
	pRsaSrv->pOutputLength 	= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pOutputLength));
#endif

	/* Build the request to be sent to Hse Ip layer */
    MbedTLS_aRequest[u8MuChannel].eReqType   = HSE_IP_REQTYPE_SYNC;
    MbedTLS_aRequest[u8MuChannel].u32Timeout = TIMEOUT_TICKS_U32;

    /* Send the request synchronously */
    srvResponse = Hse_Ip_ServiceRequest(APP_MU_INSTANCE_U8, u8MuChannel, &MbedTLS_aRequest[u8MuChannel], pHseSrvDesc);

#if defined(D_CACHE_ENABLE_MBEDTLS)
    if(HSE_SRV_RSP_OK ==  srvResponse)
    {
    	if(NULL_PTR != pOutputLength)
    	{
    		memcpy(pOutputLength, pAlignCipherLen, sizeof(uint32_t));
    	}

		if(NULL_PTR != pAlignOutput)
		{
			memcpy(pOutput, pAlignOutput, *pOutputLength);
		}
    }
#endif

exit:

#if defined(D_CACHE_ENABLE_MBEDTLS)
	if(NULL_PTR != pAlignOutput)
	{
		nxp_hse_freeH(pAlignOutput);
		pAlignOutput = NULL;
	}

	if(NULL_PTR != pAlignInput)
	{
		nxp_hse_freeH(pAlignInput);
		pAlignInput = NULL;
	}
#endif

	return srvResponse;
}

/*==================================================================================================
 *                                       GLOBAL FUNCTIONS
 ==================================================================================================*/

/*************************************************************************************************
* Description:  ECDSA GEN/VER with hash done in ONE_SHOT
* (or not at all, depending on bInputIsHashed - pre-hashed)
************************************************************************************************/

hseSrvResponse_t HSE_Ecdsa
(
    const hseAuthDir_t authDir,
    const hseHashAlgo_t hashAlgo,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLength,
    const bool_t bInputIsHashed,
    uint8_t *pR,
    uint8_t *pS,
    uint32_t *pRLen,
    uint32_t *pSLen
)
{
    /* Declare the sign scheme for ECDSA */
#if defined(D_CACHE_ENABLE_MBEDTLS)
    hseSignScheme_t signScheme __attribute__((aligned (32))) = {
        .signSch 			= HSE_SIGN_ECDSA,
        .sch.ecdsa.hashAlgo = hashAlgo
    };
#else
    hseSignScheme_t signScheme = {
        .signSch 			= HSE_SIGN_ECDSA,
        .sch.ecdsa.hashAlgo = hashAlgo
    };
#endif

    /* Send the request */
    return HSE_SignReq(authDir, HSE_ACCESS_MODE_ONE_PASS, signScheme,
        keyHandle, pInput, inputLength, bInputIsHashed, pR, pS, pRLen, pSLen);
}

/*************************************************************************************************
* Description:  RSA PSS GEN/VER with hash done
* in ONE_SHOT (or not at all, depending on bInputIsHashed - pre-hashed)
************************************************************************************************/
hseSrvResponse_t HSE_RsaSaPss
(
    const hseAuthDir_t authDir,
    const hseHashAlgo_t hashAlgo,
    const uint32_t saltLength,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLength,
    const bool_t bInputIsHashed,
    uint8_t *pSignature,
    uint32_t *pSignLen
)
{
    /* Declare the sign scheme for RSA PSS */
#if defined(D_CACHE_ENABLE_MBEDTLS)
    hseSignScheme_t signScheme __attribute__((aligned (32))) = {
        .signSch 				= HSE_SIGN_RSASSA_PSS,
        .sch.rsaPss.hashAlgo 	= hashAlgo,
        .sch.rsaPss.saltLength 	= saltLength
    };
#else
    hseSignScheme_t signScheme = {
        .signSch 				= HSE_SIGN_RSASSA_PSS,
        .sch.rsaPss.hashAlgo 	= hashAlgo,
        .sch.rsaPss.saltLength 	= saltLength
    };
#endif

    /* Send the request */
    return HSE_SignReq(authDir, HSE_ACCESS_MODE_ONE_PASS, signScheme,
        keyHandle, pInput, inputLength, bInputIsHashed, pSignature, NULL, pSignLen, NULL);
}

/*************************************************************************************************
* Description:  RSA PKCS 1V15 GEN/VER with hash
* done in ONE_SHOT (or not at all, depending on bInputIsHashed - pre-hashed)
************************************************************************************************/
hseSrvResponse_t HSE_RsaSaPkcs_v1_5
(
    const hseAuthDir_t authDir,
    const hseHashAlgo_t hashAlgo,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLength,
    const bool_t bInputIsHashed,
    uint8_t *pSignature,
    uint32_t *pSignLen
)
{
    /* Declare the sign scheme for RSA PKCS 1v15 */
#if defined(D_CACHE_ENABLE_MBEDTLS)
    hseSignScheme_t signScheme __attribute__((aligned (32))) = {
        .signSch 					= HSE_SIGN_RSASSA_PKCS1_V15,
		.sch.rsaPkcs1v15.hashAlgo 	= hashAlgo,
    };
#else
    hseSignScheme_t signScheme = {
        .signSch 					= HSE_SIGN_RSASSA_PKCS1_V15,
		.sch.rsaPkcs1v15.hashAlgo 	= hashAlgo,
    };
#endif

    /* Send the request */
    return HSE_SignReq(authDir, HSE_ACCESS_MODE_ONE_PASS, signScheme,
        keyHandle, pInput, inputLength, bInputIsHashed, pSignature, NULL, pSignLen, NULL);
}


/*************************************************************************************************
* Description:  RSA RSAES- ENC/DEC in
* ONE_SHOT (or not at all, depending on bInputIsHashed - pre-hashed)
************************************************************************************************/
hseSrvResponse_t HSE_RsaEsNoPadding
(
	const hseCipherDir_t cipherDir,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLength,
    uint8_t *pOutput,
    uint32_t *pOutputLength
)
{
    /* Declare the cipher scheme for RSA RSAES-PKCS1-v1_5 */
#if defined(D_CACHE_ENABLE_MBEDTLS)
	hseRsaCipherScheme_t rsaScheme __attribute__((aligned (32))) = {
		.rsaAlgo = HSE_RSA_ALGO_NO_PADDING,
    };
#else
	hseRsaCipherScheme_t rsaScheme = {
		.rsaAlgo = HSE_RSA_ALGO_NO_PADDING,
    };
#endif


    /* Send the request */
    return HSE_RsaCipherReq(rsaScheme, cipherDir, keyHandle, inputLength, pInput, pOutputLength, pOutput);
}
/*************************************************************************************************
* Description:  RSA RSAES-PKCS1-v1_5 ENC/DEC
* in ONE_SHOT (or not at all, depending on bInputIsHashed - pre-hashed)
************************************************************************************************/
hseSrvResponse_t HSE_RsaEsPkcs_v1_5
(
	const hseCipherDir_t cipherDir,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLength,
    uint8_t *pOutput,
    uint32_t *pOutputLength
)
{
    /* Declare the cipher scheme for RSA RSAES-PKCS1-v1_5 */
#if defined(D_CACHE_ENABLE_MBEDTLS)
	hseRsaCipherScheme_t rsaScheme __attribute__((aligned (32))) = {
		.rsaAlgo = HSE_RSA_ALGO_RSAES_PKCS1_V15,
    };
#else
	hseRsaCipherScheme_t rsaScheme = {
		.rsaAlgo = HSE_RSA_ALGO_RSAES_PKCS1_V15,
    };
#endif

    /* Send the request */
    return HSE_RsaCipherReq(rsaScheme, cipherDir, keyHandle, inputLength, pInput, pOutputLength, pOutput);
}

/*************************************************************************************************
* Description:  RSA RSAES-OAEP ENC/DEC
* in ONE_SHOT (or not at all, depending on bInputIsHashed - pre-hashed)
************************************************************************************************/
hseSrvResponse_t HSE_RsaEsOaep
(
	const hseHashAlgo_t hashAlgo,
	const hseCipherDir_t cipherDir,
	const hseKeyHandle_t keyHandle,
	const uint8_t *pLabel,
	const uint32_t labelLength,
	const uint8_t *pInput,
	const uint32_t inputLength,
	uint8_t *pOutput,
	uint32_t *pOutputLength
)
{
	/* Declare the cipher scheme for RSA RSAES-PKCS1-v1_5 */
#if defined(D_CACHE_ENABLE_MBEDTLS)
	hseRsaCipherScheme_t rsaScheme __attribute__((aligned (32))) = {
		.rsaAlgo 					= HSE_RSA_ALGO_RSAES_OAEP,
		.sch.rsaOAEP.hashAlgo 		= hashAlgo,
		.sch.rsaOAEP.labelLength 	= labelLength,
		.sch.rsaOAEP.pLabel 		= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pLabel))
	};
#else
	hseRsaCipherScheme_t rsaScheme = {
		.rsaAlgo 					= HSE_RSA_ALGO_RSAES_OAEP,
		.sch.rsaOAEP.hashAlgo 		= hashAlgo,
		.sch.rsaOAEP.labelLength 	= labelLength,
		.sch.rsaOAEP.pLabel 		= Hse_Ip_ToAHBAddress(HSE_PTR_TO_HOST_ADDR(pLabel))
	};
#endif

	/* Send the request */
	return HSE_RsaCipherReq(rsaScheme, cipherDir, keyHandle, inputLength, pInput, pOutputLength, pOutput);
}

#ifdef __cplusplus
}
#endif
