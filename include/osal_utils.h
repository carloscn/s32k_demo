
#ifndef OSAL_UTILS_H_
#define OSAL_UTILS_H_

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>

/**
 * Convert a uint8_t array to a hexadecimal string.
 * Each byte is formatted as two uppercase hex digits with a space after each.
 * The output string is null-terminated and does not include a trailing space.
 * @param data: Input byte array.
 * @param length: Length of the input array.
 * @param output: Buffer to store the hex string.
 * @param output_size: Size of the output buffer.
 * @return: Number of bytes written to output (excluding null terminator), or 0 if buffer is too small.
 */
size_t osal_utils_uint8_array_to_hex(const uint8_t *data, size_t length, char *output, size_t output_size);

/**
 * Delay for a specified number of microseconds using a loop.
 * Tuned for S32K312 with a 120 MHz core clock (120 cycles per microsecond).
 * Uses inline assembly for predictable cycle counts.
 * @param us: Number of microseconds to delay.
 */
void osal_utils_delay_us(size_t us);

/**
 * Delay for a specified number of milliseconds by calling osal_delay_us.
 * @param ms: Number of milliseconds to delay.
 */
void osal_utils_delay_ms(size_t ms);

#endif /* OSAL_UTILS_H_ */
