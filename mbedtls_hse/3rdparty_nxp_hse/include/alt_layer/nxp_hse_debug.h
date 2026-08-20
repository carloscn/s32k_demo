/*==================================================================================================
*
*   Copyright 2022, 2024 NXP.
*
*   This software is owned or controlled by NXP and may only be used strictly in accordance with
*   the applicable license terms. By expressly accepting such terms or by downloading, installing,
*   activating and/or otherwise using the software, you are agreeing that you have read, and that
*   you agree to comply with and are bound by, such license terms. If you do not agree to
*   be bound by the applicable license terms, then you may not retain, install, activate or
*   otherwise use the software.
==================================================================================================*/

#ifndef NXP_HSE_DEBUG_H_
#define NXP_HSE_DEBUG_H_

#ifdef __cplusplus
extern "C"{
#endif

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

/*==================================================================================================
*                              SOURCE FILE VERSION INFORMATION
==================================================================================================*/

/*==================================================================================================
*                                     FILE VERSION CHECKS
==================================================================================================*/

/*==================================================================================================
*                                          CONSTANTS
==================================================================================================*/

/*==================================================================================================
*                                      DEFINES AND MACROS
==================================================================================================*/
#if defined(MBEDTLS_DEBUG_C)

#define MBEDTLS_DEBUG_STRIP_PARENS( ... )   __VA_ARGS__

#define NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( level, args )                    \
    mbedtls_debug_print_msg( ssl, level, __FILE__, __LINE__,    \
                             MBEDTLS_DEBUG_STRIP_PARENS args )

#define NXP_HSE_MBEDTLS_SSL_DEBUG_RET( level, text, ret )                \
    mbedtls_debug_print_ret( ssl, level, __FILE__, __LINE__, text, ret )

#define NXP_HSE_MBEDTLS_SSL_DEBUG_BUF( level, text, buf, len )           \
    mbedtls_debug_print_buf( ssl, level, __FILE__, __LINE__, text, buf, len )

#if defined(MBEDTLS_BIGNUM_C)
#define NXP_HSE_MBEDTLS_SSL_DEBUG_MPI( level, text, X )                  \
    mbedtls_debug_print_mpi( ssl, level, __FILE__, __LINE__, text, X )
#endif

#if defined(MBEDTLS_ECP_C)
#define NXP_HSE_MBEDTLS_SSL_DEBUG_ECP( level, text, X )                  \
    mbedtls_debug_print_ecp( ssl, level, __FILE__, __LINE__, text, X )
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
#define NXP_HSE_MBEDTLS_SSL_DEBUG_CRT( level, text, crt )                \
    mbedtls_debug_print_crt( ssl, level, __FILE__, __LINE__, text, crt )
#endif

#if defined(MBEDTLS_ECDH_C)
#define NXP_HSE_MBEDTLS_SSL_DEBUG_ECDH( level, ecdh, attr )               \
    mbedtls_debug_printf_ecdh( ssl, level, __FILE__, __LINE__, ecdh, attr )
#endif

#else /* MBEDTLS_DEBUG_C */

#define NXP_HSE_MBEDTLS_SSL_DEBUG_MSG( level, args )            do { } while( 0 )
#define NXP_HSE_MBEDTLS_SSL_DEBUG_RET( level, text, ret )       do { } while( 0 )
#define NXP_HSE_MBEDTLS_SSL_DEBUG_BUF( level, text, buf, len )  do { } while( 0 )
#define NXP_HSE_MBEDTLS_SSL_DEBUG_MPI( level, text, X )         do { } while( 0 )
#define NXP_HSE_MBEDTLS_SSL_DEBUG_ECP( level, text, X )         do { } while( 0 )
#define NXP_HSE_MBEDTLS_SSL_DEBUG_CRT( level, text, crt )       do { } while( 0 )
#define NXP_HSE_MBEDTLS_SSL_DEBUG_ECDH( level, ecdh, attr )     do { } while( 0 )

#endif /* MBEDTLS_DEBUG_C */
/*==================================================================================================
*                                             ENUMS
==================================================================================================*/

/*==================================================================================================
                                 STRUCTURES AND OTHER TYPEDEFS
==================================================================================================*/

/*==================================================================================================
                                 GLOBAL VARIABLE DECLARATIONS
==================================================================================================*/

/*==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================*/
/**
 * @brief				nxp_hse_debug_prints
 * @details				Callback function used to prints the debug message along with other information
 *
 * @param[in]			ctx
 *						ssl context
 *
 * @param[in]			level
 * 						level of debug prints
 *
 * @param[in]			file
 * 						pointer to the file where debug function is called
 *
 * @param[in]			line
 * 						line number where debug function is called
 *
 * @param[in]			str
 * 						message to be printed
 *
 * 	@return				return type		: void
 *
 */
 #if !defined(S32N55)
static void nxp_hse_debug_prints( void *ctx, int level,
                     const char *file, int line,
                     const char *str );
#endif
#ifdef __cplusplus
}
#endif

#endif /* NXP_HSE_DEBUG_H_ */
