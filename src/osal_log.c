#include "osal_log.h"
#include "Lpuart_Uart_Ip.h"
#include "Lpuart_Uart_Ip_Irq.h"
#include <string.h>

void osal_log_info(const char *msg)
{
    uint32_t bytes_remaining;
    Lpuart_Uart_Ip_AsyncSend(LPUART_INSTANCE, (const uint8_t *)msg, strlen(msg));
    // Poll until transmission completes
    while (Lpuart_Uart_Ip_GetTransmitStatus(LPUART_INSTANCE, &bytes_remaining) == LPUART_UART_IP_STATUS_BUSY) {
        ; // Wait for completion
    }
    if (Lpuart_Uart_Ip_GetTransmitStatus(LPUART_INSTANCE, &bytes_remaining) != LPUART_UART_IP_STATUS_SUCCESS) {
        // Handle error (optional)
    }
}
