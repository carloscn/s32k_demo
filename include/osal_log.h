
#ifndef OSAL_LOG_H_
#define OSAL_LOG_H_

#define LOG_BUFFER_SIZE 256u

/* Prefixes every osal_log_info() line with an incrementing sequence number
 * ("[0007] ..."), so any UART capture/terminal scrollback can be told apart
 * from a fresh boot at a glance - a new boot always restarts at [0000],
 * so stale content is immediately obvious instead of ambiguous. Override
 * with -DOSAL_LOG_TIMESTAMP_ENABLE=0 to disable. */
#ifndef OSAL_LOG_TIMESTAMP_ENABLE
#define OSAL_LOG_TIMESTAMP_ENABLE 1
#endif
/**
 * Log a message via HAL UART (hal_uart_transmit_it).
 * @param msg: Null-terminated message to log.
 */
void osal_log_info(const char *msg);

#endif /* OSAL_LOG_H_ */
