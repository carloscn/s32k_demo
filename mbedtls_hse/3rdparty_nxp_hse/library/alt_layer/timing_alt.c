/*==================================================================================================
*
*   Copyright 2022, 2024 NXP.
*
*   This software is owned or controlled by NXP and may only be used strictly in accordance with
*   the applicable license terms. By expressly accepting such terms or by downloading, installing,
*   activating and/or otherwise using the software, you are agreeing that you have read, and that
*   you agree to comply with and are bound by, such license terms. If you do not agree to
*   be bound by the applicable license terms, then you may not retain, install, activate or
*   otherwise use the software.
==================================================================================================*/

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_TIMING_ALT)
#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#endif

#if defined(MBEDTLS_TIMING_ALT)
#include "mbedtls/timing.h"
#include "Osif.h"
#endif /* !MBEDTLS_TIMING_ALT */

/*==================================================================================================
*                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
==================================================================================================*/

struct mbedtls_timing_hr_time mbedtls_timer; /*!< Timer variable */

/*==================================================================================================
*                                       LOCAL MACROS
==================================================================================================*/

/*==================================================================================================
*                                      LOCAL CONSTANTS
==================================================================================================*/

/*==================================================================================================
*                                      LOCAL VARIABLES
==================================================================================================*/

volatile int mbedtls_timing_alarmed = 0;	/*!< Alarm generation flag */

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
 * 	@brief		alarm notification callback
 *
 * 	@param[in]	param
 * 				input callback parameter
 *
 *  @return		void.
 *
 */
static void alarm_notification(uint8_t param);

/*==================================================================================================
*                                       LOCAL FUNCTIONS
==================================================================================================*/
static void alarm_notification(uint8_t param)
{
	(void)param;
	mbedtls_timing_alarmed = 1UL;
}

/*==================================================================================================
*                                       GLOBAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
* Description: Return the CPU cycle counter value
************************************************************************************************/
unsigned long mbedtls_timing_hardclock(void)
{
	/* Return CPU cycles from System */
    return (unsigned long)OsIf_GetCounter(OSIF_COUNTER_DUMMY);

}

/*************************************************************************************************
* Description: Return the elapsed time in milliseconds
************************************************************************************************/
unsigned long mbedtls_timing_get_timer( struct mbedtls_timing_hr_time *val, int reset )
{
    struct mbedtls_timing_hr_time *ctx = (struct mbedtls_timing_hr_time *)val;
    uint32_t elapsedtime;

    if (0 != reset)
    {
    	/* Get the current RTC time */
    	ctx->start = nxp_hse_timing_get_timer();
    	return (0);
    }

    /* calculate time elapsed from start */
    elapsedtime = nxp_hse_timing_get_timer() - ctx->start;

    return (unsigned long)elapsedtime;
}

/*************************************************************************************************
* Description: Setup an alarm clock
************************************************************************************************/
void mbedtls_set_alarm( int seconds )
{
	/* Reset mbedtls_timing_alarmed */
    mbedtls_timing_alarmed = 0;
    if( seconds == 0 )
    {
        /* alarm(0) cancelled any previous pending alarm, but the
           handler won't fire, so raise the flag straight away. */
        mbedtls_timing_alarmed = 1;
    }
    /* Configure Alarm */
    nxp_hse_set_alarm(seconds, alarm_notification, (uint8)0U);

    return;
}

/*************************************************************************************************
* Description: Set a pair of delays to watch
************************************************************************************************/
void mbedtls_timing_set_delay( void *data, uint32_t int_ms, uint32_t fin_ms )
{
	mbedtls_timing_delay_context *ctx = (mbedtls_timing_delay_context *) data;

	ctx->int_ms = int_ms;
	ctx->fin_ms = fin_ms;

	if( fin_ms != 0 )
	{
		(void) mbedtls_timing_get_timer( &ctx->timer, 1 );
	}
}

/*************************************************************************************************
* Description:  Get the status of delays
************************************************************************************************/
int mbedtls_timing_get_delay( void *data )
{
    mbedtls_timing_delay_context *ctx = (mbedtls_timing_delay_context *) data;
    unsigned long elapsed_ms;

    if( ctx->fin_ms == 0 )
    {
    	return( -1 );
    }

    elapsed_ms = mbedtls_timing_get_timer( &ctx->timer, 0 );

    if( elapsed_ms >= ctx->fin_ms )
    {
    	return( 2 );
    }

    if( elapsed_ms >= ctx->int_ms )
    {
    	return( 1 );
    }

    return( 0 );
}

#endif /* MBEDTLS_TIMING_ALT */
