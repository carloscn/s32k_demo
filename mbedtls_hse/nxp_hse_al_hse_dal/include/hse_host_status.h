/**
*   @file    	hse_host_status.h
*
*   @brief   	This file implements hse host status.
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

#ifndef HSE_HOST_STATUS_H
#define HSE_HOST_STATUS_H

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
 * 	@brief		Returns True if CUST_SUPER_USER
 *
 * 	@param[in]	void
 *
 *  @return     access
 *
 */
uint8_t HSE_IsCustSU(void);

/**
 * 	@brief		Returns True if OEM_SUPER_USER
 *
 * 	@param[in]	void
 *
 *  @return     access
 *
 */
uint8_t HSE_IsOemSU(void);

/**
 * 	@brief		Returns True if IN_FIELD_USER
 *
 * 	@param[in]	void
 *
 *  @return     access
 *
 */
uint8_t HSE_IsUser(void);

#ifdef __cplusplus
}
#endif

#endif /* HSE_HOST_STATUS_H */
