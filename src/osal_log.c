#include "osal_log.h"
#include "hal_uart.h"
#include <string.h>
#include <stdio.h>

extern HAL_UART lpuart6;

#if OSAL_LOG_TIMESTAMP_ENABLE
static uint32_t s_osal_log_seq = 0U;
#endif

void osal_log_info(const char *msg)
{
    if (msg == NULL || msg[0] == '\0') {
        return;
    }

#if OSAL_LOG_TIMESTAMP_ENABLE
    /* Static: avoids stack pressure; same pattern as provision TX path. */
    static char s_prefixed[LOG_BUFFER_SIZE + 16];
    snprintf(s_prefixed, sizeof(s_prefixed), "[%04lu] %s",
             (unsigned long)(s_osal_log_seq++), msg);
    (void)hal_uart_transmit_it(&lpuart6, (uint8_t *)s_prefixed, strlen(s_prefixed));
#else
    (void)hal_uart_transmit_it(&lpuart6, (uint8_t *)msg, strlen(msg));
#endif
}
