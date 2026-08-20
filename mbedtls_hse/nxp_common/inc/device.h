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

#ifndef DEVICE_H
#define DEVICE_H

#ifdef __cplusplus
extern "C"{
#endif

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/
#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif /*MBEDTLS_CONFIG_FILE*/


#include "OsIf.h"
#if defined (MBEDTLS_USE_NXP_HSE_CRYTPO)
#include "hse_target.h"
#if (HSE_PLATFORM == HSE_S32G2XX)
#include "S32G274A.h"
#elif (HSE_PLATFORM == HSE_S32R45X)
#include "S32R45X.h"
#elif (HSE_PLATFORM == HSE_S32S2XX)
#include "S32S247TV.h"
#elif (HSE_PLATFORM == HSE_S32K3X4)
#include "S32K344.h"
#elif (HSE_PLATFORM == HSE_S32G3XX)
#include "S32G399A.h"
#elif (HSE_PLATFORM == HSE_SAF85XX)
#include "SAF85XX.h"
#elif (HSE_PLATFORM == HSE_S32N5XX)
#include "S32NZ55.h"
#elif (HSE_PLATFORM == HSE_S32K389)
#include "S32K389.h"
#endif
#include "printf.h"
#include <stdint.h>
#endif
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
/* Define uart driver is supported or not */
#define UART_SUPPORT

/**< @brief Add blocking loops for debug */
#define DEBUG

#define NO_ERROR 						((uint32_t)(0x00UL))

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

/*!
 * @brief 		Initialize peripherals clock, pins, OSIF, UART
 *
 * @return 		void
 */
void Init_Peripherals(void);

#if defined(USING_OS_FREERTOS)

void vAssertCalled(uint32_t ulLine, const char * const pcFileName);

#endif /* defined(USING_OS_FREERTOS) */

#ifdef __cplusplus
}
#endif

#endif /* DEVICE_H */
