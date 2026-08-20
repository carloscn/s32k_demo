/**
*   @file    	hse_host_status.c
*
*   @brief   	This file implements hse host status.
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
#include "string.h"

/*==================================================================================================
*                                       LOCAL MACROS
==================================================================================================*/
#if defined(S32N55)
#define CUST_SUPER_USER_MODE(hseStatus) \
		(HSE_STATUS_SUPER_USER == (hseStatus & (HSE_STATUS_SUPER_USER)))
	
#define OEM_SUPER_USER_MODE(hseStatus) \
		(HSE_STATUS_SUPER_USER == (hseStatus & (HSE_STATUS_SUPER_USER)))

#define IN_FIELD_USER_MODE(hseStatus) \
		(0UL == (hseStatus & (HSE_STATUS_SUPER_USER)))
#else
#define CUST_SUPER_USER_MODE(hseStatus) \
		(HSE_STATUS_CUST_SUPER_USER == (hseStatus & (HSE_STATUS_CUST_SUPER_USER|HSE_STATUS_OEM_SUPER_USER)))
	
#define OEM_SUPER_USER_MODE(hseStatus) \
		(HSE_STATUS_OEM_SUPER_USER == (hseStatus & (HSE_STATUS_CUST_SUPER_USER|HSE_STATUS_OEM_SUPER_USER)))
	
#define IN_FIELD_USER_MODE(hseStatus) \
		(0UL == (hseStatus & (HSE_STATUS_CUST_SUPER_USER|HSE_STATUS_OEM_SUPER_USER)))
#endif
/*==================================================================================================
*                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
==================================================================================================*/

/*==================================================================================================
*                                      LOCAL CONSTANTS
==================================================================================================*/

/*==================================================================================================
*                                      LOCAL VARIABLES
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

/*******************************************************************************
 * Description: Returns True if CUST_SUPER_USER
 ******************************************************************************/
uint8_t HSE_IsCustSU(void)
{
	uint16_t hsestatus;
	uint8_t access = (uint8_t)FALSE;
	/* Read MU Status */
	hsestatus = Hse_Ip_GetHseStatus(0U);

	if(CUST_SUPER_USER_MODE(hsestatus))
	{
		access = (uint8_t)TRUE;
	}
	return access;
}

/*******************************************************************************
 * Description: Returns True if OEM_SUPER_USER
 ******************************************************************************/
uint8_t HSE_IsOemSU(void)
{
	uint16_t hsestatus;
	uint8_t access = (uint8_t)FALSE;
	/* Read MU Status */
	hsestatus = Hse_Ip_GetHseStatus(0U);

	if(OEM_SUPER_USER_MODE(hsestatus))
	{
		access = (uint8_t)TRUE;
	}
	return access;
}

/*******************************************************************************
 * Description: Returns True if IN_FIELD_USER
 ******************************************************************************/
uint8_t HSE_IsUser(void)
{
	uint16_t hsestatus;
	uint8_t access = (uint8_t)FALSE;
	/* Read MU Status */
	hsestatus = Hse_Ip_GetHseStatus(0U);

	if(IN_FIELD_USER_MODE(hsestatus))
	{
		access = (uint8_t)TRUE;
	}
	return access;
}

#ifdef __cplusplus
}
#endif
