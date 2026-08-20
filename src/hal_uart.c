/*******************************************************************************
 * user include
 ******************************************************************************/
#include "hal_uart.h"
#include "hal_error.h"
#include "Lpuart_Uart_Ip.h"
#include "Lpuart_Uart_Ip_Irq.h"
#include "IntCtrl_Ip.h"
#include "osal_utils.h"
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*******************************************************************************
 * definitions
 ******************************************************************************/
#define lpuart_instance 6u
/*******************************************************************************
 * variables
 ******************************************************************************/
static volatile bool tx_busy = false;
static volatile bool rx_busy = false;
static uint8_t *rx_buffer = NULL;
static size_t rx_size = 0;
static size_t rx_count = 0;
static HAL_UART *current_huart = NULL;


/*function**********************************************************************
 *
 * function name : lpuart6_irq_handler
 * description   : interrupt handler for lpuart6 transmission and reception.
 *
 * implements : lpuart6_irq_handler_activity
 *end**************************************************************************/
void lpuart6_irq_handler(void)
{
    uint32_t bytes_remaining;
    Lpuart_Uart_Ip_StatusType status;

    /* check transmission status */
    status = Lpuart_Uart_Ip_GetTransmitStatus(lpuart_instance, &bytes_remaining);
    if (status == LPUART_UART_IP_STATUS_SUCCESS && tx_busy) {
        tx_busy = false;
//        if (current_huart != NULL && current_huart->send_handler != NULL) {
//            ((void (*)(HAL_UART *))current_huart->send_handler)(current_huart);
//        }
        hal_uart_tx_cplt_callback(current_huart);
    }

    /* check reception status */
    status = Lpuart_Uart_Ip_GetReceiveStatus(lpuart_instance, &bytes_remaining);
    if (rx_busy && rx_buffer != NULL) {
        if (status == LPUART_UART_IP_STATUS_SUCCESS || bytes_remaining == 0) {
            rx_count = rx_size - bytes_remaining;
            rx_busy = false;
//            if (current_huart != NULL && current_huart->recv_handler != NULL) {
//                ((void (*)(HAL_UART *))current_huart->recv_handler)(current_huart);
//            }
            hal_uart_rx_cplt_callback(current_huart);
        } else if (status == LPUART_UART_IP_STATUS_RX_OVERRUN) {
            rx_busy = false;
            rx_buffer = NULL;
            rx_size = 0;
            rx_count = 0;
            // note: hal_uart_rx_cplt_callback could be called with error status if needed
        }
    }
}

/*function**********************************************************************
 *
 * function name : hal_uart_init
 * description   : initializes the specified uart peripheral.
 *
 * implements : hal_uart_init_activity
 *end**************************************************************************/
int32_t hal_uart_init(HAL_UART *huart)
{
    if (huart == NULL || huart->num != HAL_UART_6) {
        return HAL_ERR_INVALID_PARAM;
    }

    /* initialize lpuart6 */
    Lpuart_Uart_Ip_Init(huart->num, &Lpuart_Uart_Ip_xHwConfigPB_6);
    /* configure interrupts */
//    IntCtrl_Ip_EnableIrq(huart->irq);
//    IntCtrl_Ip_InstallHandler(huart->irq, lpuart6_irq_handler, NULL);

    current_huart = huart;
    tx_busy = false;
    rx_busy = false;

    return HAL_ERR_SUCCESS;
}

/*function**********************************************************************
 *
 * function name : hal_uart_deinit
 * description   : deinitializes the specified uart peripheral.
 *
 * implements : hal_uart_deinit_activity
 *end**************************************************************************/
void hal_uart_deinit(HAL_UART *huart)
{
    if (huart == NULL) {
        return;
    }

    /* deinitialize lpuart6 */
    Lpuart_Uart_Ip_Deinit(lpuart_instance);

    /* disable interrupts */
    IntCtrl_Ip_DisableIrq(huart->irq);

    current_huart = NULL;
    tx_busy = false;
    rx_busy = false;
    rx_buffer = NULL;
    rx_size = 0;
    rx_count = 0;
}

/*function**********************************************************************
 *
 * function name : hal_uart_transmit
 * description   : transmits data over uart with polling.
 *
 * implements : hal_uart_transmit_activity
 *end**************************************************************************/
int32_t hal_uart_transmit(HAL_UART *huart, uint8_t *data, size_t size, size_t timeout_ms)
{
	Lpuart_Uart_Ip_StatusType status;
    if (huart == NULL || data == NULL || size == 0) {
        return HAL_ERR_INVALID_PARAM;
    }

    if (tx_busy) {
        return HAL_ERR_RESOURCE_BUSY;
    }

    tx_busy = true;
    current_huart = huart;

    /* start asynchronous transmission */
    status = Lpuart_Uart_Ip_SyncSend(huart->num, data, size, timeout_ms);
    tx_busy = false;
    if (status != LPUART_UART_IP_STATUS_SUCCESS) {
        return HAL_ERR_UART_XFER_FAILED;
    }

    return HAL_ERR_SUCCESS;
}

/*function**********************************************************************
 *
 * function name : hal_uart_transmit_it
 * description   : transmits data over uart using interrupt.
 *
 * implements : hal_uart_transmit_it_activity
 *end**************************************************************************/
int32_t hal_uart_transmit_it(HAL_UART *huart, uint8_t *data, size_t size)
{
	Lpuart_Uart_Ip_StatusType status;

    if (huart == NULL || data == NULL || size == 0) {
        return HAL_ERR_INVALID_PARAM;
    }

    if (tx_busy) {
        return HAL_ERR_RESOURCE_BUSY;
    }

    tx_busy = true;
    current_huart = huart;

    uint32_t bytes_remaining;
    /* start asynchronous transmission */
    status = Lpuart_Uart_Ip_AsyncSend(huart->num, data, size);
    if (status != LPUART_UART_IP_STATUS_SUCCESS) {
        tx_busy = false;
        return HAL_ERR_UART_XFER_FAILED;
    }

    /* poll until transmission completes or timeout */
    do {
    	tx_busy = false;
    } while ((status = Lpuart_Uart_Ip_GetTransmitStatus(huart->num, &bytes_remaining)) == LPUART_UART_IP_STATUS_BUSY);

    if (status != LPUART_UART_IP_STATUS_SUCCESS) {
        tx_busy = false;
        return HAL_ERR_UART_XFER_FAILED;
    }

    tx_busy = false;

    return HAL_ERR_SUCCESS;
}


/*function**********************************************************************
 *
 * function name : hal_uart_receive
 * description   : receives data over uart with polling.
 *
 * implements : hal_uart_receive_activity
 *end**************************************************************************/
int32_t hal_uart_receive(HAL_UART *huart, uint8_t *data, size_t size, size_t timeout_ms)
{
    if (huart == NULL || data == NULL || size == 0) {
        return HAL_ERR_INVALID_PARAM;
    }

    if (rx_busy) {
        return HAL_ERR_RESOURCE_BUSY;
    }

    rx_busy = true;
    current_huart = huart;
    rx_buffer = data;
    rx_size = size;
    rx_count = 0;

    uint32_t bytes_remaining;

    /* start asynchronous reception */
    if (Lpuart_Uart_Ip_AsyncReceive(huart->num, data, size) != LPUART_UART_IP_STATUS_SUCCESS) {
        rx_busy = false;
        rx_buffer = NULL;
        rx_size = 0;
        return HAL_ERR_UART_XFER_FAILED;
    }

    /* Poll in ~1 ms quanta using osal_utils_delay_ms's already-calibrated
     * busy-wait (same one that produces the visually-correct boot LED
     * timing), so timeout_ms means real milliseconds instead of an
     * uncalibrated loop-iteration count. */
    size_t elapsed_ms = 0;
    while (Lpuart_Uart_Ip_GetReceiveStatus(huart->num, &bytes_remaining) == LPUART_UART_IP_STATUS_BUSY) {
        if (elapsed_ms >= timeout_ms) {
            rx_busy = false;
            rx_buffer = NULL;
            rx_size = 0;
            return HAL_ERR_TIMEOUT;
        }
        osal_utils_delay_ms(1);
        elapsed_ms++;
    }

    if (Lpuart_Uart_Ip_GetReceiveStatus(huart->num, &bytes_remaining) == LPUART_UART_IP_STATUS_RX_OVERRUN) {
        rx_busy = false;
        rx_buffer = NULL;
        rx_size = 0;
        return HAL_ERR_UART_BUFFER_OVERFLOW;
    }

    if (Lpuart_Uart_Ip_GetReceiveStatus(huart->num, &bytes_remaining) != LPUART_UART_IP_STATUS_SUCCESS) {
        rx_busy = false;
        rx_buffer = NULL;
        rx_size = 0;
        return HAL_ERR_UART_XFER_FAILED;
    }

    rx_count = size - bytes_remaining;
    rx_busy = false;
    rx_buffer = NULL;
    rx_size = 0;

    return HAL_ERR_SUCCESS;
}

/*function**********************************************************************
 *
 * function name : hal_uart_read_line
 * description   : reads a line of human-typed input with local echo,
 *                 backspace support, terminated by CR or LF. Reads one byte
 *                 at a time via hal_uart_receive(); idle_timeout_ms is the
 *                 gap allowed between bytes, not a total-line timeout.
 *
 * implements : hal_uart_read_line_activity
 *end**************************************************************************/
int32_t hal_uart_read_line(HAL_UART *huart, char *buf, size_t buf_size, size_t idle_timeout_ms, size_t *out_len)
{
    if (huart == NULL || buf == NULL || buf_size < 2 || out_len == NULL) {
        return HAL_ERR_INVALID_PARAM;
    }

    size_t len = 0;
    for (;;) {
        uint8_t ch = 0;
        int32_t status = hal_uart_receive(huart, &ch, 1, idle_timeout_ms);
        if (status != HAL_ERR_SUCCESS) {
            return status;
        }

        /* Echo via hal_uart_transmit_it (AsyncSend + poll GetTransmitStatus) -
         * the same TX path osal_log_info uses, proven reliable on hardware.
         * hal_uart_transmit (SyncSend) hung after the first call when mixed
         * with an in-flight AsyncReceive - do not use it here. */
        if (ch == '\r' || ch == '\n') {
            (void)hal_uart_transmit_it(huart, (uint8_t *)"\r\n", 2);
            break;
        } else if (ch == 0x08 || ch == 0x7F) { /* backspace / DEL */
            if (len > 0) {
                len--;
                (void)hal_uart_transmit_it(huart, (uint8_t *)"\b \b", 3);
            }
        } else if (ch >= 0x20 && ch < 0x7F) { /* printable */
            if (len < (buf_size - 1)) {
                buf[len++] = (char)ch;
                (void)hal_uart_transmit_it(huart, &ch, 1);
            }
            /* else: buffer full, silently ignore further characters */
        }
        /* other control characters are ignored */
    }

    buf[len] = '\0';
    *out_len = len;
    return HAL_ERR_SUCCESS;
}

/*function**********************************************************************
 *
 * function name : hal_uart_receive_it
 * description   : receives data over uart using interrupt.
 *
 * implements : hal_uart_receive_it_activity
 *end**************************************************************************/
int32_t hal_uart_receive_it(HAL_UART *huart, uint8_t *data, size_t size)
{
    if (huart == NULL || data == NULL || size == 0) {
        return HAL_ERR_INVALID_PARAM;
    }

    if (rx_busy) {
        return HAL_ERR_RESOURCE_BUSY;
    }

    rx_busy = true;
    current_huart = huart;
    rx_buffer = data;
    rx_size = size;
    rx_count = 0;

    /* start asynchronous reception */
    if (Lpuart_Uart_Ip_AsyncReceive(huart->num, data, size) != LPUART_UART_IP_STATUS_SUCCESS) {
        rx_busy = false;
        rx_buffer = NULL;
        rx_size = 0;
        return HAL_ERR_UART_XFER_FAILED;
    }

    return HAL_ERR_SUCCESS;
}

/*function**********************************************************************
 *
 * function name : hal_uart_get_receive_status
 * description   : polls an in-flight AsyncReceive from hal_uart_receive_it().
 *
 * implements : hal_uart_get_receive_status_activity
 *end**************************************************************************/
int32_t hal_uart_get_receive_status(HAL_UART *huart, size_t *bytes_remaining)
{
    uint32_t rem = 0U;
    Lpuart_Uart_Ip_StatusType status;

    if (huart == NULL || bytes_remaining == NULL) {
        return HAL_ERR_INVALID_PARAM;
    }

    status = Lpuart_Uart_Ip_GetReceiveStatus(huart->num, &rem);
    *bytes_remaining = (size_t)rem;

    if (status == LPUART_UART_IP_STATUS_BUSY) {
        return HAL_ERR_RESOURCE_BUSY;
    }

    if (status == LPUART_UART_IP_STATUS_SUCCESS) {
        rx_count = (rx_size > rem) ? (rx_size - rem) : 0U;
        rx_busy = false;
        rx_buffer = NULL;
        rx_size = 0;
        return HAL_ERR_SUCCESS;
    }

    if (status == LPUART_UART_IP_STATUS_RX_OVERRUN) {
        rx_busy = false;
        rx_buffer = NULL;
        rx_size = 0;
        rx_count = 0;
        return HAL_ERR_UART_BUFFER_OVERFLOW;
    }

    rx_busy = false;
    rx_buffer = NULL;
    rx_size = 0;
    rx_count = 0;
    return HAL_ERR_UART_XFER_FAILED;
}

/*function**********************************************************************
 *
 * function name : hal_uart_abort_receive
 * description   : aborts an in-flight receive and clears HAL RX state.
 *
 * implements : hal_uart_abort_receive_activity
 *end**************************************************************************/
void hal_uart_abort_receive(HAL_UART *huart)
{
    if (huart == NULL) {
        return;
    }

    (void)Lpuart_Uart_Ip_AbortReceivingData(huart->num);
    rx_busy = false;
    rx_buffer = NULL;
    rx_size = 0;
    rx_count = 0;
}

/*function**********************************************************************
 *
 * function name : hal_uart_tx_cplt_callback
 * description   : callback for uart transmission completion.
 *
 * implements : hal_uart_tx_cplt_callback_activity
 *end**************************************************************************/
__attribute__((weak)) void hal_uart_tx_cplt_callback(HAL_UART *huart)
{
    /* weak implementation; override in application code */
}

/*function**********************************************************************
 *
 * function name : hal_uart_rx_cplt_callback
 * description   : callback for uart reception completion.
 *
 * implements : hal_uart_rx_cplt_callback_activity
 *end**************************************************************************/
__attribute__((weak)) void hal_uart_rx_cplt_callback(HAL_UART *huart)
{
    /* weak implementation; override in application code */
}

#if HAL_UNIT_TEST
/*function**********************************************************************
 *
 * function name : hal_uart_unit_test
 * description   : unit test for uart hal module.
 *
 * implements : hal_uart_unit_test_activity
 *end**************************************************************************/
void hal_uart_unit_test(void)
{
    /* todo: implement unit test */
}
#endif /* HAL_UNIT_TEST */

/******************************************************************************
 * eof
 *****************************************************************************/
