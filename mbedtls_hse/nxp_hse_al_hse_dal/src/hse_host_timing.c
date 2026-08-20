/**
*   @file    	hse_host_timing.c
*
*   @brief   	This file implements the wrappers for timer.
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

#include "mbedtls/timing.h"
#include "hse_host_timing.h"
#if !defined(S32N55)
#include "nvic.h"
#endif
#include "device.h"

#if defined(BENCHMARK) || defined(TEST_SUITE)
#include "Pit_Ip.h"
#include "IntCtrl_Ip.h"
#endif
#if defined (RTC_ENABLED)
#include "Rtc_Ip.h"
#include "IntCtrl_Ip.h"
#endif

/*==================================================================================================
 *                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
 ==================================================================================================*/

/*==================================================================================================
 *                                       LOCAL MACROS
 ==================================================================================================*/

#define CH_0                ((uint8)0U)

#if defined(S32N55)
#define PIT_0_HW_INST		(11U)
#else
#define PIT_0_HW_INST		(0U)
#endif
#define RTC_0_HW_INST		(0U)

#if defined(RTC_ENABLED)
	#if defined(CPU_S32K344) || defined(CPU_S32K342) || defined(CPU_S32K396) || defined(CPU_S32K358) || defined(CPU_S32K388) || defined(CPU_S32K389)
		#define RTC_IRQ 			RTC_IRQn
	#else
		#define RTC_IRQ 			RTC_SYS_CONT_IRQn
	#endif

#endif
/*==================================================================================================
 *                                      LOCAL CONSTANTS
 ==================================================================================================*/

/*==================================================================================================
 *                                      LOCAL VARIABLES
 ==================================================================================================*/

nxp_hse_timer_t timer; /*!< nxp_hse_timer_t variable */

/*==================================================================================================
 *                                      GLOBAL CONSTANTS
 ==================================================================================================*/

/*==================================================================================================
 *                                      GLOBAL VARIABLES
 ==================================================================================================*/

extern ISR(RTC_0_Ch_0_ISR);

/*==================================================================================================
 *                                   LOCAL FUNCTION PROTOTYPES
 ==================================================================================================*/

/*==================================================================================================
 *                                       LOCAL FUNCTIONS
 ==================================================================================================*/

/**
 * 	@brief		RTC notification callback function
 *
 * 	@param[in]	void
 *
 *  @return     void
 *
 */
void rtc_notification(void)
{
	/* Increment Millisecond Counter */
	timer.lifetimecounter++;
	if(timer.alarmStart < timer.alarmEnd)
	{
		if(timer.lifetimecounter >= timer.alarmEnd)
		{
			/* call application callback */
			if(NULL != timer.callback)
			{
				timer.callback(timer.callbackparam);
			}

			/* Reset the internal data structure */
			timer.alarmStart = 0U;
			timer.alarmEnd = 0U;
			timer.callback = NULL;
			timer.callbackparam = (uint8_t)0U;
		}
	}
	else if(timer.alarmStart > timer.alarmEnd)
	{
		/* Start Timer is greater than end timer case of Roll-over */
		if(timer.lifetimecounter <= timer.alarmEnd)
		{
			/* call application callback */
			if(NULL != timer.callback)
			{
				timer.callback(timer.callbackparam);
			}

			/* Reset the internal data structure */
			timer.alarmStart = 0U;
			timer.alarmEnd = 0U;
			timer.callback = NULL;
			timer.callbackparam = (uint8_t)0U;
		}
	}
}

#if (defined(SAF8544) || defined(CPU_S32R47))
void PitNotification(void)
{
	/* Increment Millisecond Counter */
	timer.lifetimecounter++;
	if(timer.alarmStart < timer.alarmEnd)
	{
		if(timer.lifetimecounter >= timer.alarmEnd)
		{
			/* call application callback */
			if(NULL != timer.callback)
			{
				timer.callback(timer.callbackparam);
			}

			/* Reset the internal data structure */
			timer.alarmStart = 0U;
			timer.alarmEnd = 0U;
			timer.callback = NULL;
			timer.callbackparam = (uint8_t)0U;
		}
	}
	else if(timer.alarmStart > timer.alarmEnd)
	{
		/* Start Timer is greater than end timer case of Roll-over */
		if(timer.lifetimecounter <= timer.alarmEnd)
		{
			/* call application callback */
			if(NULL != timer.callback)
			{
				timer.callback(timer.callbackparam);
			}

			/* Reset the internal data structure */
			timer.alarmStart = 0U;
			timer.alarmEnd = 0U;
			timer.callback = NULL;
			timer.callbackparam = (uint8_t)0U;
		}
	}
}
#endif

/*==================================================================================================
 *                                       GLOBAL FUNCTIONS
 ==================================================================================================*/

/*************************************************************************************************
* Description:  Initialize RTC timer
************************************************************************************************/
void nxp_hse_timer_init(void)
{
    if(FALSE == timer.init)
    {
    	timer.lifetimecounter = 0U;
#if defined(RTC_ENABLED)
#if defined(S32K342)
    	/* Initialize RTC Driver */
    	Rtc_Ip_Init(RTC_0_HW_INST, &RTC_0_InitConfig_PB_BOARD_InitPeripherals);
    	/* Setup RTC base Time */
    	Rtc_Ip_SetTimeDate(RTC_0_HW_INST, &Rtc_DateTimeCfg_0_BOARD_InitPeripherals);
#elif defined(S32K396) || defined(CPU_S32K389)
    	/* Initialize RTC Driver */
    	Rtc_Ip_Init(RTC_0_HW_INST, &RTC_0_InitConfig_PB_VS_0);
    	/* Setup RTC base Time */
    	//Rtc_Ip_SetTimeDate(RTC_0_HW_INST, &Rtc_DateTimeCfg_0_VS_0);
#elif defined(CPU_S32K388)
    	/* Initialize RTC Driver */
#if defined(LWIP_APP)
    	Rtc_Ip_Init(RTC_0_HW_INST, &Rtc_DateTimeCfg_0_VS_0);
    	Rtc_Ip_SetTimeDate(RTC_0_HW_INST, &Rtc_DateTimeCfg_0_VS_0);
#else
    	Rtc_Ip_Init(RTC_0_HW_INST, &Rtc_DateTimeCfg_0);
    	/* Setup RTC base Time */
    	Rtc_Ip_SetTimeDate(RTC_0_HW_INST, &Rtc_DateTimeCfg_0);
#endif

#elif defined(S32K358)
#if defined(LWIP_APP)

    	Rtc_Ip_Init(RTC_0_HW_INST, &RTC_0_InitConfig_PB_VS_0);
    	    /* Setup RTC base Time */
    	Rtc_Ip_SetTimeDate(RTC_0_HW_INST, &Rtc_DateTimeCfg_0_VS_0);
#else
   	/* Initialize RTC Driver */
    	Rtc_Ip_Init(RTC_0_HW_INST, &RTC_0_InitConfig_PB);
    	/* Setup RTC base Time */
    	Rtc_Ip_SetTimeDate(RTC_0_HW_INST, &Rtc_DateTimeCfg_0);
#endif
#endif
    	/* Configure Periodic Interrupt of 1ms */
    	Rtc_Ip_ConfigurePeriodicInterrupt(RTC_0_HW_INST, 1, 1);
    	/* Setup RTC Interrupt Handler */
    	IntCtrl_Ip_InstallHandler(RTC_IRQ, RTC_0_Ch_0_ISR, NULL_PTR);

		/* Enable RTC Interrupt */
    	IntCtrl_Ip_EnableIrq(RTC_IRQ);

		/* Start RTC Counter */
		Rtc_Ip_StartCounter(RTC_0_HW_INST);

#endif

		timer.init = TRUE;
    }

    return;
}

/*************************************************************************************************
* Description:  Get RTC Timer count
************************************************************************************************/
unsigned long nxp_hse_timing_get_timer_count(void)
{
    uint32_t count = 0;
#if defined(RTC_ENABLED)
	Rtc_Ip_TimedateType timeDate;

	Rtc_Ip_GetTimeDate(RTC_0_HW_INST, &timeDate);
	Rtc_Ip_ConvertTimeDateToSeconds(&timeDate, &count);
#endif
    return (unsigned long)count;
}

/*************************************************************************************************
* Description:  Get RTC timer count in milliseconds
************************************************************************************************/
uint32_t nxp_hse_timing_get_timer( void )
{
    return ( timer.lifetimecounter );
}

/*************************************************************************************************
* Description:  Set Alarm in seconds with callback
************************************************************************************************/
void nxp_hse_set_alarm( int seconds,  nxp_hse_timing_callbackType callback, uint8_t callbackparam)
{
	if(0 == seconds)
	{
		return;
	}
	/* Register timer callback */
	timer.callback = callback;
	timer.callbackparam = callbackparam;
	timer.alarmStart = timer.lifetimecounter;
	timer.alarmEnd = timer.lifetimecounter + 1000*seconds;

	return;
}

/*************************************************************************************************
* Description:  Get PIT 0 lifecycle timer count
************************************************************************************************/
#if defined(BENCHMARK) || defined(TEST_SUITE)
uint64_t nxp_hse_timing_get_hres_tick(void)
{
	uint64_t hres_tick;

	hres_tick = Pit_Ip_GetLifetimeTimer(PIT_0_HW_INST);

	return ~(hres_tick);
}
#endif
/*************************************************************************************************
* Description:  Configure and start PIT 0 in lifecycle timer mode
************************************************************************************************/
#if defined(BENCHMARK) || defined(TEST_SUITE)
void nxp_hse_config_lifecycle_timer(void)
{
#if defined(CPU_SAF8544)

#if defined(LWIP_APP)
    /* Initialize PIT driver and start the timer */
    Pit_Ip_Init(PIT_0_HW_INST, &PIT_0_InitConfig_PB_BOARD_InitPeripherals);
#else
    /* Set PIT_0 configuration Mode */
    Pit_Ip_Init(PIT_0_HW_INST, &PIT_0_InitConfig_PB);
#endif /* LWIP_APP */

#else
	/* Set PIT_0 configuration Mode */
	/* Set PIT_0 configuration Mode */
	#if defined (S32K396) || defined(S32K389)
    	Pit_Ip_Init(PIT_0_HW_INST, &PIT_0_InitConfig_PB_VS_0);
    #elif defined (CPU_S32K388) || defined(CPU_S32R47)
    	Pit_Ip_Init(PIT_0_HW_INST, &PIT_0_InitConfig_PB);
	#elif defined(S32K358)
#if defined(LWIP_APP)
    	Pit_Ip_Init(PIT_0_HW_INST, &PIT_0_InitConfig_PB_VS_0);
#else
    	Pit_Ip_Init(PIT_0_HW_INST, &PIT_0_InitConfig_PB);
#endif
   #endif
#endif /* CPU_SAF8544 */
	Pit_Ip_SetLifetimeTimer(PIT_0_HW_INST);
}
#endif
#ifdef __cplusplus
}
#endif
