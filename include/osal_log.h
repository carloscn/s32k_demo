
#ifndef OSAL_LOG_H_
#define OSAL_LOG_H_

#define LPUART_INSTANCE LPUART_UART_IP_INSTANCE_USING_6
#define LOG_BUFFER_SIZE 256u
/**
 * Log a message via LPUART.
 * Polls transmission status to ensure completion.
 * @param msg: Null-terminated message to log.
 */
void osal_log_info(const char *msg);

#endif /* OSAL_LOG_H_ */
