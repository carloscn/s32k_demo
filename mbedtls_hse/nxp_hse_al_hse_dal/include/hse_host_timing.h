/**
*   @file    	hse_host_timing.h
*
*   @brief   	This file implements the wrappers for timer.
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

#ifndef HSE_HOST_TIMING_H
#define HSE_HOST_TIMING_H

#ifdef __cplusplus
extern "C"{
#endif

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/

//#include "hse_interface.h"

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

/**
* @internal
* @brief    Callback type for timer
* @details  nxp_hse_timing_CallbackType
*
*/
typedef void (*nxp_hse_timing_callbackType)(uint8_t callbackParam);

typedef struct
{
	uint32_t init;						  /* !< Timer initialize flag */
	uint32_t lifetimecounter;			  /* !< Lifetime counter count value */
	uint32_t alarmStart;				  /* !< Alarm start count */
	uint32_t alarmEnd;					  /* !< Alarm end count */
	nxp_hse_timing_callbackType callback; /* !< Timer callback function */
	uint8_t callbackparam;				  /* !< Timer callback parameter */
}nxp_hse_timer_t;

/*==================================================================================================
                                 GLOBAL VARIABLE DECLARATIONS
==================================================================================================*/

extern nxp_hse_timer_t timer; /*!< nxp_hse_timer_t variable */

/*==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================*/

/*************************************************************************************************
* Description:  Initialize Real time clock timer
************************************************************************************************/
void nxp_hse_timer_init(void);

/*************************************************************************************************
* Description:  Get Epoch time in seconds
************************************************************************************************/
extern unsigned long nxp_hse_timing_get_timer_count(void);

/*************************************************************************************************
* Description:  Get timer count in milliseconds
************************************************************************************************/
extern uint32_t nxp_hse_timing_get_timer( void );

/*************************************************************************************************
* Description:  Set Alarm in seconds with callback
************************************************************************************************/
extern void nxp_hse_set_alarm( int seconds,  nxp_hse_timing_callbackType callback, uint8_t callbackparam );

/*************************************************************************************************
* Description:  Get high resolution lifecycle timer count
************************************************************************************************/
extern uint64_t nxp_hse_timing_get_hres_tick(void);

/*************************************************************************************************
* Description:  Initialize lifecycle timer
************************************************************************************************/
extern void nxp_hse_config_lifecycle_timer(void);

#ifdef __cplusplus
}
#endif

#endif /* HSE_HOST_TIMING_H */
