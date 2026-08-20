/**
*   @file    	hse_host_km_utils.h
*
*   @brief   	This file implements wrappers for key mgmt utils services
*   			(i.e. get key info, erase key, etc.).
*
*   @addtogroup [HSE_DAL]
*   @{
*/
/*==================================================================================================
*
*   Copyright 2022 NXP.
*
*   This software is owned or controlled by NXP and may only be used strictly in accordance with 
*   the applicable license terms. By expressly accepting such terms or by downloading, installing, 
*   activating and/or otherwise using the software, you are agreeing that you have read, and that 
*   you agree to comply with and are bound by, such license terms. If you do not agree to 
*   be bound by the applicable license terms, then you may not retain, install, activate or 
*   otherwise use the software.
==================================================================================================*/

#ifndef HSE_HOST_KM_UTILS_H
#define HSE_HOST_KM_UTILS_H

#ifdef __cplusplus
extern "C"{
#endif

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/

#include "hse_interface.h"

/*==================================================================================================
*                              SOURCE FILE VERSION INFORMATION
==================================================================================================*/

/*==================================================================================================
*                                     FILE VERSION CHECKS
==================================================================================================*/

/*==================================================================================================
*                                          CONSTANTS
==================================================================================================*/

/*==================================================================================================
*                                      DEFINES AND MACROS
==================================================================================================*/

/*==================================================================================================
*                                             ENUMS
==================================================================================================*/

/*==================================================================================================
                                 STRUCTURES AND OTHER TYPEDEFS
==================================================================================================*/

/*==================================================================================================
                                 GLOBAL VARIABLE DECLARATIONS
==================================================================================================*/

/*==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================*/

/**
 * 	@brief		Retrieve the key info
 *
 * 	@param[in]	keyHandle
 *				The key handle
 *
 *	@param[out]	reqKeyInfo
 *				Address where to store hseKeyInfo_t (Specifies usage flags, restriction access, key bit length etc )
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_GetKeyInfo
(
    hseKeyHandle_t keyHandle,
    hseKeyInfo_t* reqKeyInfo
);

/**
 * 	@brief		Erase one key by handle / more keys by option (sym / asym / all RAM/NVM).
 * 				Use keyHandle = HSE_INVALID_KEY_HANDLE to delete more then one key
 *
 * 	@param[in]	keyHandle
 *				The key handle
 *
 *	@param[in]	eraseKeyOptions
 *				Options to erase keys.
 *				The erase key options are used only if the provided key handle is set to #HSE_INVALID_KEY_HANDLE
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_EraseKey
(
    hseKeyHandle_t        keyHandle,
    hseEraseKeyOptions_t  eraseKeyOptions
);

#ifdef __cplusplus
}
#endif

#endif /* HSE_HOST_KM_UTILS_H */
