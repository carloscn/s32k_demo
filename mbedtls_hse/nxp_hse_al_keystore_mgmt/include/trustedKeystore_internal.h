/*==================================================================================================
*
*   Copyright 2022 NXP.
*
*   This software is owned or controlled by NXP and may only be used strictly in accordance with
*   the applicable license terms. By expressly accepting such terms or by downloading, installing,
*   activating and/or otherwise using the software, you are agreeing that you have read, and that
*   you agree to comply with and are bound by, such license terms. If you do not agree to
*   be bound by the applicable license terms, then you may not retain, install, activate or
*   otherwise use the software.
==================================================================================================*/

#ifndef TRUSTED_KEYSTORE_INTERNAL_H
#define TRUSTED_KEYSTORE_INTERNAL_H

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
#include "mbedtls/x509.h"
#if defined(MBEDTLS_USE_NXP_HSE_TRUSTED_KEYSTORE)
#include "trustedkeystore_interface.h"
#ifdef __cplusplus
extern "C" {
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

/*==================================================================================================
*                                             ENUMS
==================================================================================================*/

/*==================================================================================================
                                 STRUCTURES AND OTHER TYPEDEFS
==================================================================================================*/
typedef struct trusted_keystore_element_s
{
	key_type_t keytype;			/**< Key Type */
    unsigned int keyhandle;			/**< HSE-NVM Key Handle */
	unsigned int key_flags;
	key_param_t key_param;
	struct trusted_keystore_element_s *prev;
	struct trusted_keystore_element_s *next;
} trusted_keystore_element_t;

typedef struct
{
	trusted_keystore_element_t *element_head;
	trusted_keystore_element_t *element_tail;
	unsigned int numkeys;
}trusted_keystore_t;

/*==================================================================================================
                                 GLOBAL VARIABLE DECLARATIONS
==================================================================================================*/

/*==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================*/

#ifdef __cplusplus
}
#endif
#endif /* MBEDTLS_USE_NXP_HSE_TRUSTED_KEYSTORE */
#endif /* TRUSTED_KEYSTORE_INTERNAL_H */
