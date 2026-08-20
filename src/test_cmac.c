/**
 * @file test_cmac.c
 * @brief CMAC smoke test via mbedTLS API only (HSE under NXP ALT).
 *
 * App crypto use:
 *   mbedtls_cipher_cmac(..., handle_bytes, 128 | KEYLOADED_FLAG, ...)
 * Hse_Ip_Init lives in board_level_init() — not here.
 * Same vector/key as s32k_easy_boot hse_cmac_demo.c.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "osal_log.h"
#include "osal_utils.h"
#include "mbedtls/cmac.h"
#include "keystore_mgmt.h"
#include "test_cmac.h"

/* Must match s32k312_provision / easy_boot NVM CUST AES-128 g0s0. */
#define PROVISIONED_SECOC_KEY_HANDLE \
    GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 0U, 0U)

/* HSE-visible I/O: file-scope .bss in cacheable SRAM, not DTCM stack. */
static unsigned char s_data_to_auth[2 + 12 + 8];
static unsigned char s_mac[16];
static unsigned char s_truncated_mac[3];
static unsigned char s_key_handle_bytes[4];

int32_t test_mbedtls_cmac(void)
{
    char log_buffer[LOG_BUFFER_SIZE];
    char hex_buffer[64];

    unsigned char secoc_data_id[] = {0x03, 0x09};
    unsigned char payload[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char freshness[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const unsigned char received_mac[3] = {0x6A, 0x0E, 0x6D};

    size_t offset = 0;
    memcpy(s_data_to_auth + offset, secoc_data_id, sizeof(secoc_data_id));
    offset += sizeof(secoc_data_id);
    memcpy(s_data_to_auth + offset, payload, sizeof(payload));
    offset += sizeof(payload);
    memcpy(s_data_to_auth + offset, freshness, sizeof(freshness));

    osal_log_info("[build] test_cmac.c compiled " __DATE__ " " __TIME__ "\n");
    osal_log_info("Starting CMAC computation (provisioned NVM key via mbedTLS)...\n");

    const hseKeyHandle_t keyHandle = PROVISIONED_SECOC_KEY_HANDLE;
    snprintf(log_buffer, LOG_BUFFER_SIZE, "Using provisioned NVM key handle=0x%08lX\n",
             (unsigned long)keyHandle);
    osal_log_info(log_buffer);

    s_key_handle_bytes[0] = (unsigned char)(keyHandle & 0xFFU);
    s_key_handle_bytes[1] = (unsigned char)((keyHandle >> 8) & 0xFFU);
    s_key_handle_bytes[2] = (unsigned char)((keyHandle >> 16) & 0xFFU);
    s_key_handle_bytes[3] = (unsigned char)((keyHandle >> 24) & 0xFFU);

    const mbedtls_cipher_info_t *cipher_info =
        mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    if (cipher_info == NULL) {
        osal_log_info("Error: AES-128-ECB not supported\n");
        return -4;
    }

    int ret = mbedtls_cipher_cmac(cipher_info, s_key_handle_bytes, 128U | KEYLOADED_FLAG,
                                   s_data_to_auth, sizeof(s_data_to_auth), s_mac);
    if (ret != 0) {
        snprintf(log_buffer, LOG_BUFFER_SIZE, "Error: CMAC computation failed, ret=%d\n", ret);
        osal_log_info(log_buffer);
        return -6;
    }

    memcpy(s_truncated_mac, s_mac, 3);

    if (osal_utils_uint8_array_to_hex(s_mac, 16, hex_buffer, sizeof(hex_buffer))) {
        snprintf(log_buffer, LOG_BUFFER_SIZE, "Calculated MAC (full 16 bytes): %s\n", hex_buffer);
        osal_log_info(log_buffer);
    }

    if (osal_utils_uint8_array_to_hex(s_truncated_mac, 3, hex_buffer, sizeof(hex_buffer))) {
        snprintf(log_buffer, LOG_BUFFER_SIZE, "Calculated MAC (truncated 3 bytes): %s\n", hex_buffer);
        osal_log_info(log_buffer);
    }

    if (memcmp(s_truncated_mac, received_mac, 3) != 0) {
        osal_log_info("MAC verification FAILED against provisioned-key reference (6A 0E 6D)\n");
        return -9;
    }

    osal_log_info("CMAC test passed via mbedTLS using the provisioned NVM key.\n");
    return 0;
}
