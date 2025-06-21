/*==================================================================================================
* Project : RTD AUTOSAR 4.7
* Platform : CORTEXM
* Peripheral : S32K3XX
* Dependencies : none
*
* Autosar Version : 4.7.0
* Autosar Revision : ASR_REL_4_7_REV_0000
* Autosar Conf.Variant :
* SW Version : 4.0.0
* Build Version : S32K3_RTD_4_0_0_P24_D2405_ASR_REL_4_7_REV_0000_20240515
*
* Copyright 2020 - 2024 NXP
*
* NXP Confidential. This software is owned or controlled by NXP and may only be
* used strictly in accordance with the applicable license terms. By expressly
* accepting such terms or by downloading, installing, activating and/or otherwise
* using the software, you are agreeing that you have read, and that you agree to
* comply with and are bound by, such license terms. If you do not agree to be
* bound by the applicable license terms, then you may not retain, install,
* activate or otherwise use the software.
==================================================================================================*/

/**
*   @file main.c
*
*   @addtogroup main_module main module documentation
*   @{
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "Siul2_Port_Ip.h"
#include "Siul2_Dio_Ip.h"
#include "Lpuart_Uart_Ip.h"
#include "Lpuart_Uart_Ip_Irq.h"
#include "Clock_Ip.h"
#include "IntCtrl_Ip.h"
#include "Pit_Ip.h"
#include "osal_log.h"
#include "osal_utils.h"
#include "test_cmac.h"
#include "test_led.h"

#define APP_METADATA_MAGIC 0xAABBCCDDU
#define APP_NAME_MAX_LEN 16U
#define APP_VERSION_MAX_LEN 12U

// Application metadata structure
typedef struct {
    uint32_t magic;                         // 0x00: Identifier
    char     app_name[APP_NAME_MAX_LEN];    // 0x04: Null-terminated app name
    char     version[APP_VERSION_MAX_LEN];  // 0x14: Null-terminated version
    char    *build_timestamp;               // 0x24: Null-terminated build date and time string
    uint32_t flash_start_addr;              // 0x28: App binary flash base address
    uint32_t image_size;                    // 0x2C: Size in bytes for CRC coverage
    uint32_t crc32;                         // 0x30: CRC32 over image (excluding metadata)
} app_metadata_t;

// Static string for build timestamp
static const char build_timestamp[] = __DATE__ " " __TIME__;

// Metadata instance, placed in .app_metadata section
const app_metadata_t app_metadata __attribute__((section(".app_metadata"))) =
{
    .magic = APP_METADATA_MAGIC,
    .app_name = "MainApp",
    .version = "v1.2.3",
    .build_timestamp = (char *)build_timestamp, // Reference to static timestamp string
    .flash_start_addr = 0x00440000U,  // Example Flash base address
    .image_size = 0x00190000U,        // Example image size
    .crc32 = 0U                       // To be filled by post-build script
};
// Buffer for log messages
volatile int exit_code = 0;

// Constants
#define WELCOME_MSG "Hello, this message is sent via UART!\r\n"
#define BUFFER_SIZE 50

#define PIT_INST_0 0U
#define CH_0 0U
// PIT time-out period - equivalent to 1s
#define PIT_PERIOD 40000000

// Global buffers
uint8_t rxBuffer[BUFFER_SIZE];
uint8_t txBuffer[BUFFER_SIZE];
volatile uint8_t toggleLed = 0U;

// Pit notification called by the configured channel periodically
void pit0_callback_handler(void)
{
	toggleLed = 1U;
}

void board_level_init(void)
{
    // 1. Initialize clock
    Clock_Ip_Init(&Clock_Ip_aClockConfig[0]);

    // 2. Initialize ports
    Siul2_Port_Ip_Init(NUM_OF_CONFIGURED_PINS_PortContainer_0_BOARD_InitPeripherals,
                       g_pin_mux_InitConfigArr_PortContainer_0_BOARD_InitPeripherals);
    OsIf_Init(NULL);
    // 3. Initialize interrupt controller
    IntCtrl_Ip_Init(&IntCtrlConfig_0);

    // 4. Initialize LPUART6
    Lpuart_Uart_Ip_Init(LPUART_INSTANCE, &Lpuart_Uart_Ip_xHwConfigPB_6);

    // 5. Initialize PIT
    Pit_Ip_Init(PIT_INST_0, &PIT_0_InitConfig_PB);
    Pit_Ip_InitChannel(PIT_INST_0, PIT_0_CH_0);
    Pit_Ip_EnableChannelInterrupt(PIT_INST_0, CH_0);
    Pit_Ip_StartChannel(PIT_INST_0, CH_0, PIT_PERIOD);
}

int main(void)
{

	board_level_init();

    // Send welcome message
	osal_log_info((const char *)WELCOME_MSG);

    test_mbedtls_cmac();
    // Wait for transmission to complete
    uint32_t bytesRemaining;
    while (Lpuart_Uart_Ip_GetTransmitStatus(LPUART_INSTANCE, &bytesRemaining) == LPUART_UART_IP_STATUS_BUSY);

    // Start asynchronous receive
    Lpuart_Uart_Ip_AsyncReceive(LPUART_INSTANCE, rxBuffer, BUFFER_SIZE);


    // Main loop
    while (1)
    {
        // Check receive status
        Lpuart_Uart_Ip_StatusType rxStatus = Lpuart_Uart_Ip_GetReceiveStatus(LPUART_INSTANCE, &bytesRemaining);

        if (rxStatus == LPUART_UART_IP_STATUS_SUCCESS)
        {
            // Echo received data
            memcpy(txBuffer, rxBuffer, bytesRemaining);
            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, txBuffer, bytesRemaining, 5000);

            // Wait for echo transmission to complete
            while (Lpuart_Uart_Ip_GetTransmitStatus(LPUART_INSTANCE, &bytesRemaining) == LPUART_UART_IP_STATUS_BUSY);

            // Restart receive
            Lpuart_Uart_Ip_AsyncReceive(LPUART_INSTANCE, rxBuffer, BUFFER_SIZE);
        }
        else if (rxStatus != LPUART_UART_IP_STATUS_BUSY)
        {
            // Handle errors (e.g., overrun, framing error)
            Lpuart_Uart_Ip_AbortReceivingData(LPUART_INSTANCE);
            Lpuart_Uart_Ip_AsyncReceive(LPUART_INSTANCE, rxBuffer, BUFFER_SIZE);
        }

        // Toggle the Red LED when the pit notification is called
        if (toggleLed == 1U) {
        	Siul2_Dio_Ip_TogglePins(LED_RED_PORT, (1 << LED_RED_PIN));
        	toggleLed = 0U;
        }

        // Blink LEDs to indicate running state
        test_led();
    }

    return exit_code;
}

/** @} */
