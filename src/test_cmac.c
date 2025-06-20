#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "osal_log.h"
#include "osal_utils.h"
#include "mbedtls/cmac.h"
#include "test_cmac.h"

int32_t test_mbedtls_cmac(void)
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
    char log_buffer[LOG_BUFFER_SIZE];
    char hex_buffer[64]; // Enough for 16 bytes * 3 chars + null

    // Construct DataToAuthenticator
    size_t offset = 0;
    memcpy(data_to_auth + offset, secoc_data_id, sizeof(secoc_data_id));
    offset += sizeof(secoc_data_id);
    memcpy(data_to_auth + offset, payload, sizeof(payload));
    offset += sizeof(payload);
    memcpy(data_to_auth + offset, freshness, sizeof(freshness));

    // Log start of CMAC computation
    osal_log_info("Starting CMAC computation...\n");

    // Initialize cipher context
    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_init(&ctx);

    // Get AES-128-ECB cipher info
    const mbedtls_cipher_info_t *cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    if (cipher_info == NULL) {
        osal_log_info("Error: AES-128-ECB not supported\n");
        mbedtls_cipher_free(&ctx);
        return -1;
    }

    // Setup cipher context
    int ret = mbedtls_cipher_setup(&ctx, cipher_info);
    if (ret != 0) {
        snprintf(log_buffer, LOG_BUFFER_SIZE, "Error: Cipher setup failed, ret=%d\n", ret);
        osal_log_info(log_buffer);
        mbedtls_cipher_free(&ctx);
        return -2;
    }

    // Start CMAC computation
    ret = mbedtls_cipher_cmac_starts(&ctx, key, 16 * 8); // Key length in bits (16 bytes * 8)
    if (ret != 0) {
        snprintf(log_buffer, LOG_BUFFER_SIZE, "Error: CMAC start failed, ret=%d\n", ret);
        osal_log_info(log_buffer);
        mbedtls_cipher_free(&ctx);
        return -3;
    }

    // Update CMAC with input data
    ret = mbedtls_cipher_cmac_update(&ctx, data_to_auth, sizeof(data_to_auth));
    if (ret != 0) {
        snprintf(log_buffer, LOG_BUFFER_SIZE, "Error: CMAC update failed, ret=%d\n", ret);
        osal_log_info(log_buffer);
        mbedtls_cipher_free(&ctx);
        return -4;
    }

    // Finish CMAC computation
    ret = mbedtls_cipher_cmac_finish(&ctx, mac);
    if (ret != 0) {
        snprintf(log_buffer, LOG_BUFFER_SIZE, "Error: CMAC finish failed, ret=%d\n", ret);
        osal_log_info(log_buffer);
        mbedtls_cipher_free(&ctx);
        return -5;
    }

    // Free cipher context
    mbedtls_cipher_free(&ctx);

    // Truncate MAC to 3 bytes
    memcpy(truncated_mac, mac, 3);

    // Log full calculated MAC
    if (osal_utils_uint8_array_to_hex(mac, 16, hex_buffer, sizeof(hex_buffer))) {
        snprintf(log_buffer, LOG_BUFFER_SIZE, "Calculated MAC (full 16 bytes): %s\n", hex_buffer);
        osal_log_info(log_buffer);
    } else {
        osal_log_info("Error: Failed to format full MAC\n");
    }

    // Log truncated calculated MAC
    if (osal_utils_uint8_array_to_hex(truncated_mac, 3, hex_buffer, sizeof(hex_buffer))) {
        snprintf(log_buffer, LOG_BUFFER_SIZE, "Calculated MAC (truncated 3 bytes): %s\n", hex_buffer);
        osal_log_info(log_buffer);
    } else {
        osal_log_info("Error: Failed to format truncated MAC\n");
    }

    // Verify against received MAC
    if (memcmp(truncated_mac, received_mac, 3) != 0) {
        if (osal_utils_uint8_array_to_hex(truncated_mac, 3, hex_buffer, sizeof(hex_buffer))) {
            snprintf(log_buffer, LOG_BUFFER_SIZE, "MAC verification failed. Calculated: %s Received: 6A 0E 6D\n", hex_buffer);
            osal_log_info(log_buffer);
        } else {
            osal_log_info("MAC verification failed. Error formatting calculated MAC\n");
        }
        return -6;
    }

    // Success
    if (osal_utils_uint8_array_to_hex(truncated_mac, 3, hex_buffer, sizeof(hex_buffer))) {
        snprintf(log_buffer, LOG_BUFFER_SIZE, "CMAC test passed. Calculated MAC: %s\n", hex_buffer);
        osal_log_info(log_buffer);
    } else {
        osal_log_info("Error: Failed to format success MAC\n");
    }

    return 0;
}
