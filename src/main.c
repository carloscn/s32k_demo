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
#include "Siul2_Port_Ip.h"
#include "Siul2_Dio_Ip.h"
#include "stdint.h"
#include "Lpuart_Uart_Ip.h"
#include "Lpuart_Uart_Ip_Irq.h"
#include "Clock_Ip.h"
#include "IntCtrl_Ip.h"
#include "Pit_Ip.h"
#include "string.h"
#include "mbedtls/cmac.h"

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

int test_cmac(void)
{
    // Key (16 bytes)
    unsigned char key[16] = {
        0xFA, 0x7B, 0x0B, 0xCA, 0x18, 0x32, 0x95, 0xE4,
        0xA3, 0x27, 0xB8, 0xC7, 0x2A, 0x1A, 0x4D, 0xFF
    };

    // Input data (SecOC structure: SecOCDataId + Payload + Freshness)
    unsigned char secoc_data_id[] = {0x03, 0x09}; // 2 bytes
    unsigned char payload[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // 12 bytes
    unsigned char freshness[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // 8 bytes
    unsigned char data_to_auth[2 + 12 + 8]; // Total length: 22 bytes
    const unsigned char received_mac[3] = {0x6A, 0x0E, 0x6D}; // Truncated MAC (3 bytes)
    unsigned char mac[16]; // Full CMAC-128 output
    unsigned char truncated_mac[3]; // Truncated to 24 bits (3 bytes)

    // Construct DataToAuthenticator
    size_t offset = 0;
    memcpy(data_to_auth + offset, secoc_data_id, sizeof(secoc_data_id));
    offset += sizeof(secoc_data_id);
    memcpy(data_to_auth + offset, payload, sizeof(payload));
    offset += sizeof(payload);
    memcpy(data_to_auth + offset, freshness, sizeof(freshness));

    // Initialize LPUART message buffer (e.g., 64 bytes should be sufficient)
    uint8_t uart_buffer[64];
    size_t uart_len;

    // Log start of CMAC computation
    const char *start_msg = "Starting CMAC computation...\n";
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (const uint8_t *)start_msg, strlen(start_msg), 50000);

    // Initialize cipher context
    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_init(&ctx);

    // Get AES-128-ECB cipher info
    const mbedtls_cipher_info_t *cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    if (cipher_info == NULL) {
        // Error: AES-128-ECB not supported
        const char *error_msg = "Error: AES-128-ECB not supported\n";
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (const uint8_t *)error_msg, strlen(error_msg), 5000);
        mbedtls_cipher_free(&ctx);
        return -1;
    }

    // Setup cipher context
    int ret = mbedtls_cipher_setup(&ctx, cipher_info);
    if (ret != 0) {
        // Error: Cipher setup failed
        uart_len = snprintf((char *)uart_buffer, sizeof(uart_buffer), "Error: Cipher setup failed, ret=%d\n", ret);
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, uart_buffer, uart_len, 5000);
        mbedtls_cipher_free(&ctx);
        return -2;
    }

    // Start CMAC computation
    ret = mbedtls_cipher_cmac_starts(&ctx, key, 16 * 8); // Key length in bits (16 bytes * 8)
    if (ret != 0) {
        // Error: CMAC start failed
        uart_len = snprintf((char *)uart_buffer, sizeof(uart_buffer), "Error: CMAC start failed, ret=%d\n", ret);
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, uart_buffer, uart_len, 5000);
        mbedtls_cipher_free(&ctx);
        return -3;
    }

    // Update CMAC with input data
    ret = mbedtls_cipher_cmac_update(&ctx, data_to_auth, sizeof(data_to_auth));
    if (ret != 0) {
        // Error: CMAC update failed
        uart_len = snprintf((char *)uart_buffer, sizeof(uart_buffer), "Error: CMAC update failed, ret=%d\n", ret);
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, uart_buffer, uart_len, 5000);
        mbedtls_cipher_free(&ctx);
        return -4;
    }

    // Finish CMAC computation
    ret = mbedtls_cipher_cmac_finish(&ctx, mac);
    if (ret != 0) {
        // Error: CMAC finish failed
        uart_len = snprintf((char *)uart_buffer, sizeof(uart_buffer), "Error: CMAC finish failed, ret=%d\n", ret);
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, uart_buffer, uart_len, 5000);
        mbedtls_cipher_free(&ctx);
        return -5;
    }

    // Free cipher context
    mbedtls_cipher_free(&ctx);

    // Truncate MAC to 3 bytes
    memcpy(truncated_mac, mac, 3);

    // Log full calculated MAC
    uart_len = snprintf((char *)uart_buffer, sizeof(uart_buffer), "Calculated MAC (full 16 bytes): ");
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, uart_buffer, uart_len, 5000);
    for (int i = 0; i < 16; i++) {
        uart_len = snprintf((char *)uart_buffer, sizeof(uart_buffer), "%02X ", mac[i]);
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, uart_buffer, uart_len, 5000);
    }
    const char *newline = "\n";
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (const uint8_t *)newline, strlen(newline), 5000);

    // Log truncated calculated MAC
    uart_len = snprintf((char *)uart_buffer, sizeof(uart_buffer), "Calculated MAC (truncated 3 bytes): ");
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, uart_buffer, uart_len, 5000);
    for (int i = 0; i < 3; i++) {
        uart_len = snprintf((char *)uart_buffer, sizeof(uart_buffer), "%02X ", truncated_mac[i]);
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, uart_buffer, uart_len, 5000);
    }
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (const uint8_t *)newline, strlen(newline), 5000);

    // Verify against received MAC
    if (memcmp(truncated_mac, received_mac, 3) != 0) {
        // Error: Calculated MAC does not match received MAC
        uart_len = snprintf((char *)uart_buffer, sizeof(uart_buffer), "MAC verification failed. Calculated: ");
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, uart_buffer, uart_len, 5000);
        for (int i = 0; i < 3; i++) {
            uart_len = snprintf((char *)uart_buffer, sizeof(uart_buffer), "%02X ", truncated_mac[i]);
            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, uart_buffer, uart_len, 5000);
        }
        uart_len = snprintf((char *)uart_buffer, sizeof(uart_buffer), "Received: 6A 0E 6D\n");
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, uart_buffer, uart_len, 5000);
        return -6;
    }

    // Success
    uart_len = snprintf((char *)uart_buffer, sizeof(uart_buffer), "CMAC test passed. Calculated MAC: ");
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, uart_buffer, uart_len, 5000);
    for (int i = 0; i < 3; i++) {
        uart_len = snprintf((char *)uart_buffer, sizeof(uart_buffer), "%02X ", truncated_mac[i]);
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, uart_buffer, uart_len, 5000);
    }
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (const uint8_t *)newline, strlen(newline), 5000);
    return 0;
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
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (const uint8_t *)WELCOME_MSG, strlen(WELCOME_MSG), 5000);

    test_cmac();
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
