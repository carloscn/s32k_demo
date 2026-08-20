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
#include "Clock_Ip.h"
#include "IntCtrl_Ip.h"
#include "Pit_Ip.h"
#include "osal_log.h"
#include "osal_utils.h"
#include "hal_uart.h"
#include "hal_error.h"
#include "build_magic.h"
#include "test_cmac.h"
#include "test_led.h"
#include "Hse_Ip.h"

#define APP_METADATA_MAGIC 0xAABBCCDDU
#define APP_NAME_MAX_LEN 16U
#define APP_VERSION_MAX_LEN 12U

typedef struct {
    uint32_t magic;
    char     app_name[APP_NAME_MAX_LEN];
    char     version[APP_VERSION_MAX_LEN];
    char    *build_timestamp;
    uint32_t flash_start_addr;
    uint32_t image_size;
    uint32_t crc32;
} app_metadata_t;

static const char build_timestamp[] = __DATE__ " " __TIME__;

const app_metadata_t app_metadata __attribute__((section(".app_metadata"))) =
{
    .magic = APP_METADATA_MAGIC,
    .app_name = "MainApp",
    .version = "v1.2.3",
    .build_timestamp = (char *)build_timestamp,
    .flash_start_addr = 0x00440000U,
    .image_size = 0x00190000U,
    .crc32 = 0U
};

volatile int exit_code = 0;

#define WELCOME_MSG "Hello, this message is sent via UART!\r\n"
#define BUFFER_SIZE 50

#define PIT_INST_0 0U
#define CH_0 0U
#define PIT_PERIOD 40000000

HAL_UART lpuart6;

uint8_t rxBuffer[BUFFER_SIZE];
uint8_t txBuffer[BUFFER_SIZE];
volatile uint8_t toggleLed = 0U;

void pit0_callback_handler(void)
{
    toggleLed = 1U;
}

void board_level_init(void)
{
    static Hse_Ip_MuStateType s_hse_mu_state;

    Clock_Ip_Init(&Clock_Ip_aClockConfig[0]);

    Siul2_Port_Ip_Init(NUM_OF_CONFIGURED_PINS_PortContainer_0_BOARD_InitPeripherals,
                       g_pin_mux_InitConfigArr_PortContainer_0_BOARD_InitPeripherals);
    OsIf_Init(NULL);
    IntCtrl_Ip_Init(&IntCtrlConfig_0);

    lpuart6.num = LPUART_UART_IP_INSTANCE_USING_6;
    lpuart6.irq = LPUART6_IRQn;
    (void)hal_uart_init(&lpuart6);

    Pit_Ip_Init(PIT_INST_0, &PIT_0_InitConfig_PB);
    Pit_Ip_InitChannel(PIT_INST_0, PIT_0_CH_0);
    Pit_Ip_EnableChannelInterrupt(PIT_INST_0, CH_0);
    Pit_Ip_StartChannel(PIT_INST_0, CH_0, PIT_PERIOD);

    /* HSE host driver for THIS binary (easy_boot's Hse_Ip_Init does not
     * carry across the jump). Required once before any HSE-backed mbedTLS. */
    (void)Hse_Ip_Init(0U, &s_hse_mu_state);
}

int main(void)
{
    size_t bytes_remaining;

    board_level_init();

    osal_log_info("[build-magic] " APP_BUILD_MAGIC_STR " (" APP_BUILD_MAGIC_TIME ")\n");
    osal_log_info((const char *)WELCOME_MSG);

    test_mbedtls_cmac();

    (void)hal_uart_receive_it(&lpuart6, rxBuffer, BUFFER_SIZE);

    while (1)
    {
        int32_t rx_status = hal_uart_get_receive_status(&lpuart6, &bytes_remaining);

        if (rx_status == HAL_ERR_SUCCESS)
        {
            /* Driver reports remaining count; bytes received = request - rem. */
            size_t n = BUFFER_SIZE - bytes_remaining;
            if (n > BUFFER_SIZE) {
                n = BUFFER_SIZE;
            }
            if (n > 0U) {
                memcpy(txBuffer, rxBuffer, n);
                (void)hal_uart_transmit_it(&lpuart6, txBuffer, n);
            }
            (void)hal_uart_receive_it(&lpuart6, rxBuffer, BUFFER_SIZE);
        }
        else if (rx_status != HAL_ERR_RESOURCE_BUSY)
        {
            hal_uart_abort_receive(&lpuart6);
            (void)hal_uart_receive_it(&lpuart6, rxBuffer, BUFFER_SIZE);
        }

        if (toggleLed == 1U) {
            Siul2_Dio_Ip_TogglePins(LED_RED_PORT, (1 << LED_RED_PIN));
            toggleLed = 0U;
        }

        test_led();
    }

    return exit_code;
}

/** @} */
