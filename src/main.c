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

#include "Siul2_Port_Ip.h"
#include "Siul2_Dio_Ip.h"
#include "stdint.h"
#include "Lpuart_Uart_Ip.h"
#include "Lpuart_Uart_Ip_Irq.h"
#include "Clock_Ip.h"
#include "IntCtrl_Ip.h"
#include "Pit_Ip.h"
#include "string.h"

volatile int exit_code = 0;

// Constants
#define LPUART_INSTANCE LPUART_UART_IP_INSTANCE_USING_6
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

// Simple delay function
void test_delay(uint32_t delay)
{
    static volatile uint32_t delay_timer = 0;
    while (delay_timer < delay) {
        delay_timer++;
    }
    delay_timer = 0;
}

// LED blinking function
void test_led(void)
{
    uint8_t count = 0;

    while (count++ < 10)
    {
        Siul2_Dio_Ip_WritePin(LED_GREEN_PORT, LED_GREEN_PIN, 1U);
        test_delay(4800000);
        Siul2_Dio_Ip_WritePin(LED_BLUE_PORT, LED_BLUE_PIN, 1U);
        test_delay(4800000);
        Siul2_Dio_Ip_WritePin(LED_GREEN_PORT, LED_GREEN_PIN, 0U);
        test_delay(4800000);
        Siul2_Dio_Ip_WritePin(LED_BLUE_PORT, LED_BLUE_PIN, 0U);
        test_delay(4800000);
    }
}


void board_level_init(void)
{
    // 1. Initialize clock
    Clock_Ip_Init(&Clock_Ip_aClockConfig[0]);

    // 2. Initialize ports
    Siul2_Port_Ip_Init(NUM_OF_CONFIGURED_PINS_PortContainer_0_BOARD_InitPeripherals,
                       g_pin_mux_InitConfigArr_PortContainer_0_BOARD_InitPeripherals);

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
    Lpuart_Uart_Ip_AsyncSend(LPUART_INSTANCE, (const uint8_t *)WELCOME_MSG, strlen(WELCOME_MSG));

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
            Lpuart_Uart_Ip_AsyncSend(LPUART_INSTANCE, txBuffer, bytesRemaining);

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
