#ifndef TEST_CMAC_H_
#define TEST_CMAC_H_

#include <stdint.h>

/**
 * Test CMAC computation using mbedTLS for S32K312.
 * Uses the SecOC data structure from the provided Linux example.
 * Logs progress and results via osal_log_info.
 * Returns 0 on success, negative value on failure.
 */
int32_t test_mbedtls_cmac(void);

#endif /* TEST_CMAC_H_ */
