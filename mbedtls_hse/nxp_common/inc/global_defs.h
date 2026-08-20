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

#ifndef GLOBAL_DEFS_H
#define GLOBAL_DEFS_H

#ifdef __cplusplus
extern "C"{
#endif

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/
#include "device.h"
#include "global_types.h"
//#if defined(MBEDTLS_USE_NXP_HSE_CRYPTO)
#include "hse_interface.h"
#include "hse_target.h"
//#endif
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

#if !defined(BITS_TO_BYTES)
    #define BITS_TO_BYTES(bitLen)               ((uint16_t)(((bitLen) + 7U) / 8U))
#endif
#if !defined(BYTES_TO_BITS)
    #define BYTES_TO_BITS(byteLen)              ((byteLen) * 8U)
#endif

#define ASSERT(condition)   \
    do {                    \
        if(!(condition))    \
            while(1);       \
    } while(0)

#define _FLASH_PAGE_SIZE        (1024U * 4U)
#define MAX_KEY_FILE_SIZE       HSE_MAX_NVM_STORE_SIZE
#define MAX_SYS_IMG_SIZE        (_FLASH_PAGE_SIZE    	 /* Data-set 1 (SYS-IMG header) */ + \
                                 _FLASH_PAGE_SIZE    	 /* Data-set 2 (SMR/CR/NVM config tables) */ + \
                                 HSE_MAX_NVM_STORE_SIZE  /* Data-set 3 (Key file) */)
#define MAX_HSE_FW_IMG_SIZE   	(0x40000UL)
#define BUFFER_SIZE           	MAX(MAX_HSE_FW_IMG_SIZE, MAX_SYS_IMG_SIZE)

#define MU0                     (0U)
#define MU1                     (1U)
#define MU2                     (2U)
#define MU3                     (3U)

#if defined(CPU_S32G274A)

/** @brief HSE key catalog configuration.
 *            - Each catalog entry represent a key group of the same key type.
 *            - Each group is identified by its index within the catalog.
 *            Note that a key group can contain keys that have keybitLen <= maxKeyBitLen.
 *            For example, the group of key type "HSE_KEY_TYPE_AES" of 256bits can contain AES128, AES192 and AES256 keys.
 *            If there are not enough slots for an AES128 key in an AES128 group, the key can be store in an AES256 slot.
 *            The catalog is ending with a zero filled entry.
 */

#if (HSE_FWTYPE == 1)   /* HSE FW PREMIUM key catalogs configuration */

/** @brief    HSE NVM key catalog configuration*/
#define  HSE_NVM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)      Reserved  */  \
/* CUST keys */    \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           10U,        HSE_KEY128_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           10U,        HSE_KEY256_BITS, {0U} }, \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_HMAC,          5U,         HSE_KEY1024_BITS, {0U} }, \
        /* ECC keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PAIR,      2U,         HSE_KEY521_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PUB,       4U,         HSE_KEY521_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PUB_EXT,   2U,         HSE_KEY521_BITS, {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PAIR,      3U,         HSE_KEY4096_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB,       4U,         HSE_KEY4096_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB_EXT,   2U,         HSE_KEY4096_BITS, {0U} }, \
/* OEM keys */    \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_AES,            10U,        HSE_KEY128_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_AES,            10U,        HSE_KEY256_BITS, {0U} }, \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_HMAC,           10U,        HSE_KEY1024_BITS, {0U} }, \
        /* ECC keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_ECC_PAIR,       2U,         HSE_KEY521_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_ECC_PUB,        3U,         HSE_KEY521_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_ECC_PUB_EXT,    5U,         HSE_KEY521_BITS, {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_RSA_PAIR,       2U,         HSE_KEY4096_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_RSA_PUB,        3U,         HSE_KEY4096_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_RSA_PUB_EXT,    5U,         HSE_KEY4096_BITS, {0U} }, \
        { HSE_MU0_MASK,    HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_ECC_PUB,        1U,         HSE_KEY521_BITS,  {0U} }, \
        { 0U,              0U,                0U,                          0U,         0U, {0U}  }

/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)  */  \
        /* Symmetric key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            20U,        HSE_KEY128_BITS, {0U} }, \
        /* Usable only on MU0 */ \
        { HSE_MU0_MASK,    HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            20U,        HSE_KEY256_BITS, {0U} }, \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_HMAC,           10U,        HSE_KEY1024_BITS, {0U} }, \
        /* ECC keys*/\
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PAIR,       2U,         HSE_KEY521_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PUB,        6U,         HSE_KEY521_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PUB_EXT,    1U,         HSE_KEY521_BITS, {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_RSA_PUB,        6U,         HSE_KEY4096_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_RSA_PUB_EXT,    1U,         HSE_KEY4096_BITS, {0U} }, \
        /* Temporary secrets */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  5U,         HSE_KEY638_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  5U,         HSE_KEY4096_BITS, {0U} }, \
        { 0U,              0U,                 0U,                           0U,         0U, {0U}  }

#define NVM_RSA2048_PAIR_DEV_KEY_HANDLE			GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 6, 2)
#define NVM_RSA2048_PUB_ROOT_CERT_HANDLE		GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 7, 2)
#define NVM_RSA2048_PUB_CLI_CERT_HANDLE			GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 7, 3)

#elif (HSE_FWTYPE == 0) /* HSE FW STANDARD key catalogs configuration */

/** @brief    HSE NVM key catalog configuration*/
#define  HSE_NVM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)      Reserved  */  \
/* CUST keys */    \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           3U,         HSE_KEY128_BITS, {0U} }, \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_HMAC,          1U,         HSE_KEY512_BITS, {0U} }, \
        /* ECC keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PAIR,      1U,         HSE_KEY256_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PUB,       1U,         HSE_KEY256_BITS, {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PAIR,      3U,         HSE_KEY2048_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB,       4U,         HSE_KEY2048_BITS, {0U} }, \
        { 0U,              0U,                0U,                          0U,         0U, {0U}  }

/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)  */  \
        /* Symmetric key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            4U,        HSE_KEY128_BITS, {0U} }, \
        /* Usable only on MU0 */ \
        { HSE_MU0_MASK,    HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            4U,        HSE_KEY256_BITS, {0U} }, \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_HMAC,           4U,        HSE_KEY512_BITS, {0U} }, \
        /* ECC keys*/\
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PAIR,       2U,        HSE_KEY256_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PUB,        2U,        HSE_KEY256_BITS, {0U} }, \
        /* Temporary secrets */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  4U,        HSE_KEY638_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  4U,        HSE_KEY4096_BITS, {0U} }, \
		/* RSA keys */ \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,	HSE_KEY_TYPE_RSA_PUB,		 6U,		 HSE_KEY2048_BITS, {0U} }, \
		/*{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,	HSE_KEY_TYPE_RSA_PUB_EXT,	 10U,		 HSE_KEY2048_BITS, {0U} },*/ \
		{ 0U,              0U,                 0U,                           0U,        0U, {0U}  }

#define NVM_RSA2048_PAIR_DEV_KEY_HANDLE			GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 4, 2)
#define NVM_RSA2048_PUB_ROOT_CERT_HANDLE		GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 5, 2)
#define NVM_RSA2048_PUB_CLI_CERT_HANDLE			GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 5, 3)

#else
#error "Unkown HSE FW type"
#endif

#endif /* CPU_S32G274A */

#if defined(CPU_S32G399A)
/** @brief HSE key catalog configuration.
 *            - Each catalog entry represent a key group of the same key type.
 *            - Each group is identified by its index within the catalog.
 *            Note that a key group can contain keys that have keybitLen <= maxKeyBitLen.
 *            For example, the group of key type "HSE_KEY_TYPE_AES" of 256bits can contain AES128, AES192 and AES256 keys.
 *            If there are not enough slots for an AES128 key in an AES128 group, the key can be store in an AES256 slot.
 *            The catalog is ending with a zero filled entry.
 */

#if (HSE_FWTYPE == 1)   /* HSE FW PREMIUM key catalogs configuration */

/** @brief    HSE NVM key catalog configuration*/
#define  HSE_NVM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)      Reserved  */  \
/* CUST keys */    \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           10U,        HSE_KEY128_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           10U,        HSE_KEY256_BITS, {0U} }, \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_HMAC,          5U,         HSE_KEY1024_BITS, {0U} }, \
        /* ECC keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PAIR,      2U,         HSE_KEY521_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PUB,       4U,         HSE_KEY521_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PUB_EXT,   2U,         HSE_KEY521_BITS, {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PAIR,      3U,         HSE_KEY4096_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB,       4U,         HSE_KEY4096_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB_EXT,   2U,         HSE_KEY4096_BITS, {0U} }, \
		/* DH Keys */ \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_DH_PAIR,	   2U,		   HSE_KEY4096_BITS, {0U} },\
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_DH_PUB,	   	   2U,		   HSE_KEY4096_BITS, {0U} },\
/* OEM keys */    \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_AES,            10U,        HSE_KEY128_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_AES,            10U,        HSE_KEY256_BITS, {0U} }, \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_HMAC,           10U,        HSE_KEY1024_BITS, {0U} }, \
        /* ECC keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_ECC_PAIR,       2U,         HSE_KEY521_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_ECC_PUB,        3U,         HSE_KEY521_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_ECC_PUB_EXT,    5U,         HSE_KEY521_BITS, {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_RSA_PAIR,       2U,         HSE_KEY4096_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_RSA_PUB,        3U,         HSE_KEY4096_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_RSA_PUB_EXT,    5U,         HSE_KEY4096_BITS, {0U} }, \
        { HSE_MU0_MASK,    HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_ECC_PUB,        1U,         HSE_KEY521_BITS,  {0U} }, \
		/* DH Keys */ \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_DH_PAIR,	   	   2U,		   HSE_KEY4096_BITS, {0U} },\
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_OEM, HSE_KEY_TYPE_DH_PUB,	   	   2U,		   HSE_KEY4096_BITS, {0U} },\
        { 0U,              0U,                0U,                          0U,         0U, {0U}  }

/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)  */  \
        /* Symmetric key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            20U,        HSE_KEY128_BITS, {0U} }, \
        /* Usable only on MU0 */ \
        { HSE_MU0_MASK,    HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            20U,        HSE_KEY256_BITS, {0U} }, \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_HMAC,           10U,        HSE_KEY1024_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_HMAC,            2U,         HSE_KEY256_BITS, {0U} }, \
        /* ECC keys*/\
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PAIR,       2U,         HSE_KEY521_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PUB,        6U,         HSE_KEY521_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PUB_EXT,    1U,         HSE_KEY521_BITS, {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_RSA_PUB,        6U,         HSE_KEY4096_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_RSA_PUB_EXT,    1U,         HSE_KEY4096_BITS, {0U} }, \
        /* Temporary secrets */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  5U,         HSE_KEY638_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  5U,         HSE_KEY4096_BITS, {0U} }, \
		/* DH Keys */ \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY, 	HSE_KEY_TYPE_DH_PAIR,	     2U,		 HSE_KEY4096_BITS, {0U} },\
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY, 	HSE_KEY_TYPE_DH_PUB,	   	 2U,		 HSE_KEY4096_BITS, {0U} },\
        { 0U,              0U,                 0U,                           0U,         0U, {0U}  }

#define NVM_RSA2048_PAIR_DEV_KEY_HANDLE			GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 6, 2)
#define NVM_RSA2048_PUB_ROOT_CERT_HANDLE		GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 7, 2)
#define NVM_RSA2048_PUB_CLI_CERT_HANDLE			GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 7, 3)

#elif (HSE_FWTYPE == 0) /* HSE FW STANDARD key catalogs configuration */

/** @brief    HSE NVM key catalog configuration*/
#define  HSE_NVM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)      Reserved  */  \
/* CUST keys */    \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           3U,         HSE_KEY128_BITS, {0U} }, \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_HMAC,          1U,         HSE_KEY512_BITS, {0U} }, \
        /* ECC keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PAIR,      1U,         HSE_KEY256_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PUB,       1U,         HSE_KEY256_BITS, {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PAIR,      3U,         HSE_KEY2048_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB,       4U,         HSE_KEY2048_BITS, {0U} }, \
        { 0U,              0U,                0U,                          0U,         0U, {0U}  }

/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)  */  \
        /* Symmetric key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            4U,        HSE_KEY128_BITS, {0U} }, \
        /* Usable only on MU0 */ \
        { HSE_MU0_MASK,    HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            4U,        HSE_KEY256_BITS, {0U} }, \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_HMAC,           4U,        HSE_KEY512_BITS, {0U} }, \
        /* ECC keys*/\
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PAIR,       2U,        HSE_KEY256_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PUB,        2U,        HSE_KEY256_BITS, {0U} }, \
        /* Temporary secrets */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  4U,        HSE_KEY638_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  4U,        HSE_KEY4096_BITS, {0U} }, \
		/* RSA keys */ \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,	HSE_KEY_TYPE_RSA_PUB,		 6U,		 HSE_KEY2048_BITS, {0U} }, \
		/*{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,	HSE_KEY_TYPE_RSA_PUB_EXT,	 10U,		 HSE_KEY2048_BITS, {0U} },*/ \
		{ 0U,              0U,                 0U,                           0U,        0U, {0U}  }

#define NVM_RSA2048_PAIR_DEV_KEY_HANDLE			GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 4, 2)
#define NVM_RSA2048_PUB_ROOT_CERT_HANDLE		GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 5, 2)
#define NVM_RSA2048_PUB_CLI_CERT_HANDLE			GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 5, 3)

#else
#error "Unkown HSE FW type"
#endif
#endif /* CPU_S32G399A */
#if defined (S32N55)
#if (HSE_FWTYPE ==1 )  /* HSE FW PREMIUM key catalogs configuration */

#if defined(TEST_SUITE1)||defined(TEST_SUITE2)|| defined(LWIP_APP)||defined(BENCHMARK)

#define  HSE_NVM_KEY_CATALOG_CFG \
		 /* Group MU Mask   Group Owner             Group Key Type       Maximum slot size (in bits)   Number of Slots     Reserved  */ \
		/* CUST keys */    \
		{ HSE_ALL_MU_MASK,  HSE_KEY_OWNER_CLI0,   HSE_KEY_TYPE_AES,         HSE_KEY256_BITS,               3U,                {0U} }, \
		 /* HMAC key */ \
        { HSE_ALL_MU_MASK,  HSE_KEY_OWNER_CLI0,   HSE_KEY_TYPE_HMAC,         HSE_KEY512_BITS,               1U,                {0U} },\
	 /* ECC keys */ \
        { HSE_ALL_MU_MASK,  HSE_KEY_OWNER_CLI0,   HSE_KEY_TYPE_ECC_PAIR,     HSE_KEY256_BITS,               1U,                {0U} }, \
        { HSE_ALL_MU_MASK,  HSE_KEY_OWNER_CLI0,   HSE_KEY_TYPE_ECC_PUB,      HSE_KEY256_BITS,               1U,                {0U} }, \
		/* RSA keys */ \
		{ HSE_ALL_MU_MASK,  HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_RSA_PAIR,     HSE_KEY4096_BITS,              3U,                {0U} }, \
		{ HSE_ALL_MU_MASK,  HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_RSA_PUB,      HSE_KEY4096_BITS,              4U,                {0U} }, \
	    { 0U,              0U,                0U,                          0U,                           0U,                {0U}  }

		/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
	    /* Group MU Mask   Group Owner         Group Key Type           Maximum slot size (in bits)           Number of Slots  */  \
		        /* Symmetric key */ \
		        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,                 HSE_KEY128_BITS,              6U,    {0U} }, \
		        /* Usable only on MU0 */ \
		        { HSE_MU0_MASK,    HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,                 HSE_KEY256_BITS,              6U,    {0U} }, \
		        /* HMAC key */ \
		        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_HMAC,                HSE_KEY1024_BITS,             6U,    {0U} }, \
		        /* ECC keys*/\
		        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PAIR,            HSE_KEY521_BITS,              2U,     {0U} }, \
		        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PUB,             HSE_KEY521_BITS,              6U,     {0U} }, \
		        /* Temporary secrets */ \
		        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,       HSE_KEY638_BITS,              1U,     {0U} }, \
		        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,       HSE_KEY2048_BITS,             2U,     {0U} }, \
		        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,       HSE_KEY4096_BITS,             2U,     {0U} }, \
		        /* RSA keys */ \
		        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB,            HSE_KEY4096_BITS,              3U,    {0U} }, \
		        /*{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB_EXT,     10U,         HSE_KEY2048_BITS, {0U} },*/ \
		        { 0U,              0U,                 0U,                           0U,        0U,             {0U}  }
#endif //TEST_SUITE1 || TEST_SUITE2

#if defined(TEST_SUITE3)
#define  HSE_NVM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type          Maximum key bit length   Number of Slots      Reserved  */  \
/* CUST keys */    \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CLI0, HSE_KEY_TYPE_AES,              HSE_KEY128_BITS,          4U,     {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CLI0, HSE_KEY_TYPE_AES,               HSE_KEY256_BITS,         2U,      {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CLI0, HSE_KEY_TYPE_RSA_PAIR,        HSE_KEY2048_BITS,          2U,     {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CLI0, HSE_KEY_TYPE_RSA_PUB,          HSE_KEY4096_BITS,         1U,    {0U} }, \
        { 0U,              0U,                0U,                              0U,                      0U,     {0U}  }
		/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
		        /* Group MU Mask   Group Owner         Group Key Type                Maximum key bit length   Number of Slots   Reserved */  \
		        /* Symmetric key */ \
		       { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,                 HSE_KEY256_BITS,          10U,              {0U} }, \
		        /* Usable only on MU0 */ \
		        /* HMAC key */ \
		        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_HMAC,             HSE_KEY1024_BITS,          2U,                  {0U} }, \
		        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_HMAC,             HSE_KEY256_BITS,          10U,                 {0U} }, \
		        /* Temporary secrets */ \
		        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,      HSE_KEY4096_BITS,         2U,                   {0U} },\
		        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,      HSE_KEY638_BITS,           4U,                   {0U} },\
		        /* RSA keys */ \
		        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB,           HSE_KEY2048_BITS,         2U,                   {0U} }, \
		        /* DH Keys */ \
		        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_DH_PAIR,          HSE_KEY2048_BITS,         2U,                   {0U} },\
		        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_DH_PUB,           HSE_KEY2048_BITS,         1U,     {0U} },\
		        /*{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB_EXT,     10U,         HSE_KEY2048_BITS, {0U} },*/ \
		        { 0U,              0U,                 0U,                           0U,        0U, {0U}  }
#endif //TEST_SUITE3

#if defined(TEST_SUITE4)
/** @brief    HSE NVM key catalog configuration*/
#define  HSE_NVM_KEY_CATALOG_CFG  \
		/* Group MU Mask   Group Owner         Group Key Type         Maximum key bit length   Number of Slots     Reserved  */  \
/* CUST keys */    \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CLI0, HSE_KEY_TYPE_AES,                  HSE_KEY128_BITS, 4U,  {0U} }, \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CLI0, HSE_KEY_TYPE_AES,                HSE_KEY256_BITS,   2U,  {0U} }, \
		{ 0U,              0U,                0U,                          0U,         0U, {0U}  }

/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
		/* Group MU Mask   Group Owner         Group Key Type           Maximum key bit length         Number of Slots */         \
		/* Symmetric key */ \
	   { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,             HSE_KEY256_BITS,               1U,            {0U} }, \
		/* Usable only on MU0 */ \
		/* HMAC key */ \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_HMAC,         HSE_KEY1024_BITS,               1U,            {0U} }, \
		/* Temporary secrets */ \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  HSE_KEY4096_BITS,               2U,         {0U} },\
		/* DH Keys */ \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_DH_PAIR,      HSE_KEY4096_BITS,               2U,        {0U} },\
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_DH_PUB,       HSE_KEY4096_BITS,               1U,          {0U} },\
		/*{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB_EXT,     10U,         HSE_KEY2048_BITS, {0U} },*/ \
		{ 0U,              0U,                 0U,                           0U,        0U, {0U}  }
#endif //TEST_SUITE4
#define NVM_RSA2048_PAIR_DEV_KEY_HANDLE			GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 6, 2)
#define NVM_RSA2048_PUB_ROOT_CERT_HANDLE		GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 7, 2)
#define NVM_RSA2048_PUB_CLI_CERT_HANDLE			GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 7, 3)

#elif (HSE_FWTYPE == 0) /* HSE FW STANDARD key catalogs configuration */

#if defined(TEST_SUITE1)|| defined(TEST_SUITE2)
/** @brief    HSE NVM key catalog configuration*/
#define  HSE_NVM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type         Maximum key bit length  Number of Slots     Reserved  */  \
/* CUST keys */    \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CLI0, HSE_KEY_TYPE_AES,       HSE_KEY256_BITS,                 3U, {0U} }, \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CLI0, HSE_KEY_TYPE_HMAC,      HSE_KEY512_BITS,                 1U, {0U} }, \
        /* ECC keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CLI0, HSE_KEY_TYPE_ECC_PAIR,  HSE_KEY256_BITS,                 1U, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CLI0, HSE_KEY_TYPE_ECC_PUB,   HSE_KEY256_BITS,                 1U, {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CLI0, HSE_KEY_TYPE_RSA_PAIR,  HSE_KEY4096_BITS,                3U, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CLI0, HSE_KEY_TYPE_RSA_PUB,       HSE_KEY4096_BITS,            4U, {0U} }, \
        { 0U,              0U,                0U,                          0U,         0U, {0U}  }
/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type         Maximum key bit length  Number of Slots */  \
        /* Symmetric key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,           HSE_KEY128_BITS,        6U,          {0U} }, \
        /* Usable only on MU0 */ \
        { HSE_MU0_MASK,    HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,           HSE_KEY256_BITS,      6U,    {0U} }, \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_HMAC,         HSE_KEY1024_BITS,      6U,     {0U} }, \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_HMAC,          HSE_KEY256_BITS,       2U,   {0U} }, \
        /* ECC keys*/\
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PAIR,      HSE_KEY521_BITS,     2U,     {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PUB,         HSE_KEY521_BITS,   6U,     {0U} }, \
        /* Temporary secrets */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,   HSE_KEY638_BITS,  1U,      {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,   HSE_KEY2048_BITS,  2U,      {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,    HSE_KEY4096_BITS,  2U,     {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB,         HSE_KEY4096_BITS,      3U,    {0U} }, \
        /*{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB_EXT,     10U,         HSE_KEY2048_BITS, {0U} },*/ \
        { 0U,              0U,                 0U,                           0U,        0U, {0U}  }
#endif //TEST_SUITE1 || TEST_SUITE2

#if defined(TEST_SUITE3)




#define  HSE_NVM_KEY_CATALOG_CFG  \
       /* Group MU Mask   Group Owner         Group Key Type        Maixmum key bit length    Number of Slots   Reserved  */  \
/* CUST keys */    \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CLI0, HSE_KEY_TYPE_AES,            HSE_KEY128_BITS,        4U, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CLI0, HSE_KEY_TYPE_AES,            HSE_KEY256_BITS,        2U,    {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CLI0, HSE_KEY_TYPE_RSA_PAIR,      HSE_KEY2048_BITS,        2U,   {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CLI0, HSE_KEY_TYPE_RSA_PUB,       HSE_KEY4096_BITS,        1U,     {0U} }, \
        { 0U,              0U,                0U,                          0U,         0U, {0U}  }

/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Maximum key bit length  Number of Slots  */  \
        /* Symmetric key */ \
       { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,                HSE_KEY256_BITS,          10U,    {0U} }, \
        /* Usable only on MU0 */ \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_HMAC,            HSE_KEY1024_BITS,          2U,          {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_HMAC,            HSE_KEY256_BITS,           10U,     {0U} }, \
        /* Temporary secrets */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,     HSE_KEY4096_BITS,        2U,     {0U} },\
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,     HSE_KEY638_BITS,   4U,  {0U} },\
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB,          HSE_KEY2048_BITS,     2U,     {0U} }, \
        /* DH Keys */ \
		/*{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB_EXT,     10U,         HSE_KEY2048_BITS, {0U} },*/ \
        { 0U,              0U,                 0U,                           0U,        0U, {0U}  }


 #endif //TEST_SUITE3

#if defined(TEST_SUITE4)
/** @brief    HSE NVM key catalog configuration*/

#define  HSE_NVM_KEY_CATALOG_CFG  \
		/* Group MU Mask   Group Owner         Group Key Type        Maximum key bit length   Number of Slots    Reserved  */  \
/* CUST keys */    \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CLI0, HSE_KEY_TYPE_AES,             HSE_KEY128_BITS,     4U,            {0U} }, \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CLI0, HSE_KEY_TYPE_AES,           HSE_KEY256_BITS,       2U,            {0U} }, \
		{ 0U,              0U,                0U,                          0U,                    0U,            {0U}  }

/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
		/* Group MU Mask   Group Owner         Group Key Type              Maximum key bit length        Number of Slots*/  \
		/* Symmetric key */ \
	   { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,              HSE_KEY256_BITS,         1U,   {0U} }, \
		/* Usable only on MU0 */ \
		/* HMAC key */ \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_HMAC,          HSE_KEY1024_BITS,    1U,    {0U} }, \
		/* Temporary secrets */ \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,   HSE_KEY4096_BITS,     2U,     {0U} },\
		/*{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB_EXT,     10U,         HSE_KEY2048_BITS, {0U} },*/ \
		{ 0U,              0U,                 0U,                           0U,        0U, {0U}  }
#endif //TEST_SUITE4
#define NVM_RSA2048_PAIR_DEV_KEY_HANDLE			GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 4, 2)
#define NVM_RSA2048_PUB_ROOT_CERT_HANDLE		GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 5, 2)
#define NVM_RSA2048_PUB_CLI_CERT_HANDLE			GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 5, 3)
#else
#error "Unkown HSE FW type"
#endif /* CPU_S32K344  CPU_S32K342*/
#endif

#if defined (CPU_S32K344) ||defined(CPU_S32K342)
 /** @brief HSE key catalog configuration.
 *            - Each catalog entry represent a key group of the same key type.
 *            - Each group is identified by its index within the catalog.
 *            Note that a key group can contain keys that have keybitLen <= maxKeyBitLen.
 *            For example, the group of key type "HSE_KEY_TYPE_AES" of 256bits can contain AES128, AES192 and AES256 keys.
 *            If there are not enough slots for an AES128 key in an AES128 group, the key can be store in an AES256 slot.
 *            The catalog is ending with a zero filled entry.
 */

#if (HSE_FWTYPE == 1)   /* HSE FW PREMIUM key catalogs configuration */

#if defined(TEST_SUITE1)|| defined(TEST_SUITE2) || defined(LWIP_APP) || defined(BENCHMARK)
/** @brief    HSE NVM key catalog configuration*/
#define  HSE_NVM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)      Reserved  */  \
/* CUST keys */    \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           3U,         HSE_KEY256_BITS, {0U} }, \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_HMAC,          1U,         HSE_KEY512_BITS, {0U} }, \
        /* ECC keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PAIR,      1U,         HSE_KEY256_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PUB,       1U,         HSE_KEY256_BITS, {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PAIR,      3U,         HSE_KEY4096_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB,       4U,         HSE_KEY4096_BITS, {0U} }, \
        { 0U,              0U,                0U,                          0U,         0U, {0U}  }



/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)  */  \
        /* Symmetric key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            6U,        HSE_KEY128_BITS, {0U} }, \
        /* Usable only on MU0 */ \
        { HSE_MU0_MASK,    HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            6U,        HSE_KEY256_BITS, {0U} }, \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_HMAC,           6U,        HSE_KEY1024_BITS, {0U} }, \
        /* ECC keys*/\
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PAIR,       2U,        HSE_KEY521_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PUB,        6U,        HSE_KEY521_BITS, {0U} }, \
        /* Temporary secrets */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  1U,        HSE_KEY638_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  2U,        HSE_KEY2048_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  2U,        HSE_KEY4096_BITS, {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB,         3U,         HSE_KEY4096_BITS, {0U} }, \
        /*{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB_EXT,     10U,         HSE_KEY2048_BITS, {0U} },*/ \
        { 0U,              0U,                 0U,                           0U,        0U, {0U}  }
#endif //TEST_SUITE1 || TEST_SUITE2

#if defined(TEST_SUITE3)
#define  HSE_NVM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)      Reserved  */  \
/* CUST keys */    \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           4U,         HSE_KEY128_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           2U,         HSE_KEY256_BITS, {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PAIR,      2U,         HSE_KEY2048_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB,       1U,         HSE_KEY4096_BITS, {0U} }, \
        { 0U,              0U,                0U,                          0U,         0U, {0U}  }

/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)  */  \
        /* Symmetric key */ \
       { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            10U,        HSE_KEY256_BITS, {0U} }, \
        /* Usable only on MU0 */ \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_HMAC,           2U,        HSE_KEY1024_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_HMAC,           10U,        HSE_KEY256_BITS, {0U} }, \
        /* Temporary secrets */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  2U,        HSE_KEY4096_BITS, {0U} },\
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  4U,        HSE_KEY638_BITS, {0U} },\
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB,         2U,         HSE_KEY2048_BITS, {0U} }, \
        /* DH Keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_DH_PAIR,      2U,         HSE_KEY2048_BITS, {0U} },\
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_DH_PUB,       1U,         HSE_KEY2048_BITS, {0U} },\
        /*{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB_EXT,     10U,         HSE_KEY2048_BITS, {0U} },*/ \
        { 0U,              0U,                 0U,                           0U,        0U, {0U}  }
 #endif //TEST_SUITE3

#if defined(TEST_SUITE4)
/** @brief    HSE NVM key catalog configuration*/
#define  HSE_NVM_KEY_CATALOG_CFG  \
		/* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)      Reserved  */  \
/* CUST keys */    \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           4U,         HSE_KEY128_BITS, {0U} }, \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           2U,         HSE_KEY256_BITS, {0U} }, \
		{ 0U,              0U,                0U,                          0U,         0U, {0U}  }

/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
		/* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)  */  \
		/* Symmetric key */ \
	   { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            1U,        HSE_KEY256_BITS, {0U} }, \
		/* Usable only on MU0 */ \
		/* HMAC key */ \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_HMAC,           1U,        HSE_KEY1024_BITS, {0U} }, \
		/* Temporary secrets */ \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  2U,        HSE_KEY4096_BITS, {0U} },\
		/* DH Keys */ \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_DH_PAIR,      2U,         HSE_KEY4096_BITS, {0U} },\
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_DH_PUB,       1U,         HSE_KEY4096_BITS, {0U} },\
		/*{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB_EXT,     10U,         HSE_KEY2048_BITS, {0U} },*/ \
		{ 0U,              0U,                 0U,                           0U,        0U, {0U}  }
#endif //TEST_SUITE4


#define NVM_RSA2048_PAIR_DEV_KEY_HANDLE			GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 6, 2)
#define NVM_RSA2048_PUB_ROOT_CERT_HANDLE		GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 7, 2)
#define NVM_RSA2048_PUB_CLI_CERT_HANDLE			GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 7, 3)

#elif (HSE_FWTYPE == 0) /* HSE FW STANDARD key catalogs configuration */

#if defined(TEST_SUITE1)|| defined(TEST_SUITE2) || defined(LWIP_APP) || defined(BENCHMARK)
/** @brief    HSE NVM key catalog configuration*/
#define  HSE_NVM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)      Reserved  */  \
/* CUST keys */    \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           3U,         HSE_KEY256_BITS, {0U} }, \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_HMAC,          1U,         HSE_KEY512_BITS, {0U} }, \
        /* ECC keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PAIR,      1U,         HSE_KEY256_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PUB,       1U,         HSE_KEY256_BITS, {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PAIR,      3U,         HSE_KEY4096_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB,       4U,         HSE_KEY4096_BITS, {0U} }, \
        { 0U,              0U,                0U,                          0U,         0U, {0U}  }



/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)  */  \
        /* Symmetric key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            6U,        HSE_KEY128_BITS, {0U} }, \
        /* Usable only on MU0 */ \
        { HSE_MU0_MASK,    HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            6U,        HSE_KEY256_BITS, {0U} }, \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_HMAC,           6U,        HSE_KEY1024_BITS, {0U} }, \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_HMAC,           2U,        HSE_KEY256_BITS, {0U} }, \
        /* ECC keys*/\
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PAIR,       2U,        HSE_KEY521_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PUB,        6U,        HSE_KEY521_BITS, {0U} }, \
        /* Temporary secrets */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  1U,        HSE_KEY638_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  2U,        HSE_KEY2048_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  2U,        HSE_KEY4096_BITS, {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB,         3U,         HSE_KEY4096_BITS, {0U} }, \
        /*{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB_EXT,     10U,         HSE_KEY2048_BITS, {0U} },*/ \
        { 0U,              0U,                 0U,                           0U,        0U, {0U}  }
#endif //TEST_SUITE1 || TEST_SUITE2

#if defined(TEST_SUITE3)




#define  HSE_NVM_KEY_CATALOG_CFG  \
       /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)      Reserved  */  \
/* CUST keys */    \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           4U,         HSE_KEY128_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           2U,         HSE_KEY256_BITS, {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PAIR,      2U,         HSE_KEY2048_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB,       1U,         HSE_KEY4096_BITS, {0U} }, \
        { 0U,              0U,                0U,                          0U,         0U, {0U}  }

/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)  */  \
        /* Symmetric key */ \
       { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            10U,        HSE_KEY256_BITS, {0U} }, \
        /* Usable only on MU0 */ \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_HMAC,           2U,        HSE_KEY1024_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_HMAC,           10U,        HSE_KEY256_BITS, {0U} }, \
        /* Temporary secrets */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  2U,        HSE_KEY4096_BITS, {0U} },\
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  4U,        HSE_KEY638_BITS, {0U} },\
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB,         2U,         HSE_KEY2048_BITS, {0U} }, \
        /* DH Keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_DH_PAIR,      2U,         HSE_KEY2048_BITS, {0U} },\
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_DH_PUB,       1U,         HSE_KEY2048_BITS, {0U} },\
        /*{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB_EXT,     10U,         HSE_KEY2048_BITS, {0U} },*/ \
        { 0U,              0U,                 0U,                           0U,        0U, {0U}  }


 #endif //TEST_SUITE3

#if defined(TEST_SUITE4)
/** @brief    HSE NVM key catalog configuration*/

#define  HSE_NVM_KEY_CATALOG_CFG  \
		/* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)      Reserved  */  \
/* CUST keys */    \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           4U,         HSE_KEY128_BITS, {0U} }, \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           2U,         HSE_KEY256_BITS, {0U} }, \
		{ 0U,              0U,                0U,                          0U,         0U, {0U}  }

/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
		/* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)  */  \
		/* Symmetric key */ \
	   { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            1U,        HSE_KEY256_BITS, {0U} }, \
		/* Usable only on MU0 */ \
		/* HMAC key */ \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_HMAC,           1U,        HSE_KEY1024_BITS, {0U} }, \
		/* Temporary secrets */ \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  2U,        HSE_KEY4096_BITS, {0U} },\
		/* DH Keys */ \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_DH_PAIR,      2U,         HSE_KEY4096_BITS, {0U} },\
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_DH_PUB,       1U,         HSE_KEY4096_BITS, {0U} },\
		/*{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB_EXT,     10U,         HSE_KEY2048_BITS, {0U} },*/ \
		{ 0U,              0U,                 0U,                           0U,        0U, {0U}  }
#endif //TEST_SUITE4


#define NVM_RSA2048_PAIR_DEV_KEY_HANDLE			GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 4, 2)
#define NVM_RSA2048_PUB_ROOT_CERT_HANDLE		GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 5, 2)
#define NVM_RSA2048_PUB_CLI_CERT_HANDLE			GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 5, 3)

#else
#error "Unkown HSE FW type"
#endif /* CPU_S32K344  CPU_S32K342*/
#endif

#if defined (CPU_S32K358) || defined(CPU_S32K396) || defined(CPU_SAF8644)  || defined(CPU_SAF8544) || defined(CPU_S32K388) || defined(CPU_S32K389) || defined(CPU_S32R47)

 /** @brief HSE key catalog configuration.
 *            - Each catalog entry represent a key group of the same key type.
 *            - Each group is identified by its index within the catalog.
 *            Note that a key group can contain keys that have keybitLen <= maxKeyBitLen.
 *            For example, the group of key type "HSE_KEY_TYPE_AES" of 256bits can contain AES128, AES192 and AES256 keys.
 *            If there are not enough slots for an AES128 key in an AES128 group, the key can be store in an AES256 slot.
 *            The catalog is ending with a zero filled entry.
 */

#if (HSE_FWTYPE == 1)   /* HSE FW PREMIUM key catalogs configuration */

#if defined(TEST_SUITE1)|| defined(TEST_SUITE2) || defined(LWIP_APP) || defined(BENCHMARK)
/** @brief    HSE NVM key catalog configuration*/
#define  HSE_NVM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)      Reserved  */  \
/* CUST keys */    \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           3U,         HSE_KEY256_BITS, {0U} }, \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_HMAC,          1U,         HSE_KEY512_BITS, {0U} }, \
        /* ECC keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PAIR,      1U,         HSE_KEY256_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PUB,       1U,         HSE_KEY256_BITS, {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PAIR,      3U,         HSE_KEY4096_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB,       4U,         HSE_KEY4096_BITS, {0U} }, \
        { 0U,              0U,                0U,                          0U,         0U, {0U}  }



/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)  */  \
        /* Symmetric key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            6U,        HSE_KEY128_BITS, {0U} }, \
        /* Usable only on MU0 */ \
        { HSE_MU0_MASK,    HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            6U,        HSE_KEY256_BITS, {0U} }, \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_HMAC,           6U,        HSE_KEY1024_BITS, {0U} }, \
        /* ECC keys*/\
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PAIR,       2U,        HSE_KEY521_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PUB,        6U,        HSE_KEY521_BITS, {0U} }, \
        /* Temporary secrets */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  1U,        HSE_KEY638_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  2U,        HSE_KEY2048_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  2U,        HSE_KEY4096_BITS, {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB,         3U,         HSE_KEY4096_BITS, {0U} }, \
        /*{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB_EXT,     10U,         HSE_KEY2048_BITS, {0U} },*/ \
        { 0U,              0U,                 0U,                           0U,        0U, {0U}  }
#endif //TEST_SUITE1 || TEST_SUITE2

#if defined(TEST_SUITE3)
#define  HSE_NVM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)      Reserved  */  \
/* CUST keys */    \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           4U,         HSE_KEY128_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           2U,         HSE_KEY256_BITS, {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PAIR,      2U,         HSE_KEY2048_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB,       1U,         HSE_KEY4096_BITS, {0U} }, \
        { 0U,              0U,                0U,                          0U,         0U, {0U}  }

/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)  */  \
        /* Symmetric key */ \
       { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            10U,        HSE_KEY256_BITS, {0U} }, \
        /* Usable only on MU0 */ \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_HMAC,           2U,        HSE_KEY1024_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_HMAC,           10U,        HSE_KEY256_BITS, {0U} }, \
        /* Temporary secrets */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  2U,        HSE_KEY4096_BITS, {0U} },\
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  4U,        HSE_KEY638_BITS, {0U} },\
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB,         2U,         HSE_KEY2048_BITS, {0U} }, \
        /* DH Keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_DH_PAIR,      2U,         HSE_KEY2048_BITS, {0U} },\
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_DH_PUB,       1U,         HSE_KEY2048_BITS, {0U} },\
        /*{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB_EXT,     10U,         HSE_KEY2048_BITS, {0U} },*/ \
        { 0U,              0U,                 0U,                           0U,        0U, {0U}  }
 #endif //TEST_SUITE3

#if defined(TEST_SUITE4)
/** @brief    HSE NVM key catalog configuration*/
#define  HSE_NVM_KEY_CATALOG_CFG  \
		/* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)      Reserved  */  \
/* CUST keys */    \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           4U,         HSE_KEY128_BITS, {0U} }, \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           2U,         HSE_KEY256_BITS, {0U} }, \
		{ 0U,              0U,                0U,                          0U,         0U, {0U}  }

/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
		/* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)  */  \
		/* Symmetric key */ \
	   { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            1U,        HSE_KEY256_BITS, {0U} }, \
		/* Usable only on MU0 */ \
		/* HMAC key */ \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_HMAC,           1U,        HSE_KEY1024_BITS, {0U} }, \
		/* Temporary secrets */ \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  2U,        HSE_KEY4096_BITS, {0U} },\
		/* DH Keys */ \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_DH_PAIR,      2U,         HSE_KEY4096_BITS, {0U} },\
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_DH_PUB,       1U,         HSE_KEY4096_BITS, {0U} },\
		/*{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB_EXT,     10U,         HSE_KEY2048_BITS, {0U} },*/ \
		{ 0U,              0U,                 0U,                           0U,        0U, {0U}  }
#endif //TEST_SUITE4


#define NVM_RSA2048_PAIR_DEV_KEY_HANDLE			GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 6, 2)
#define NVM_RSA2048_PUB_ROOT_CERT_HANDLE		GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 7, 2)
#define NVM_RSA2048_PUB_CLI_CERT_HANDLE			GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 7, 3)

#elif (HSE_FWTYPE == 0) /* HSE FW STANDARD key catalogs configuration */

#define CRYPTO_43_HSE_START_SEC_VAR_INIT_UNSPECIFIED_NO_CACHEABLE
#include "Crypto_43_HSE_MemMap.h"
#if defined(TEST_SUITE1)|| defined(TEST_SUITE2) || defined(LWIP_APP) || defined(BENCHMARK)
/** @brief    HSE NVM key catalog configuration*/
#define  HSE_NVM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)      Reserved  */  \
/* CUST keys */    \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           3U,         HSE_KEY256_BITS, {0U} }, \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_HMAC,          1U,         HSE_KEY512_BITS, {0U} }, \
        /* ECC keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PAIR,      1U,         HSE_KEY256_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_ECC_PUB,       1U,         HSE_KEY256_BITS, {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PAIR,      3U,         HSE_KEY4096_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB,       4U,         HSE_KEY4096_BITS, {0U} }, \
        { 0U,              0U,                0U,                          0U,         0U, {0U}  }



/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)  */  \
        /* Symmetric key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            6U,        HSE_KEY128_BITS, {0U} }, \
        /* Usable only on MU0 */ \
        { HSE_MU0_MASK,    HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            6U,        HSE_KEY256_BITS, {0U} }, \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_HMAC,           6U,        HSE_KEY1024_BITS, {0U} }, \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_HMAC,           2U,        HSE_KEY256_BITS, {0U} }, \
        /* ECC keys*/\
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PAIR,       2U,        HSE_KEY521_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_ECC_PUB,        6U,        HSE_KEY521_BITS, {0U} }, \
        /* Temporary secrets */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  1U,        HSE_KEY638_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  2U,        HSE_KEY2048_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  2U,        HSE_KEY4096_BITS, {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB,         3U,         HSE_KEY4096_BITS, {0U} }, \
        /*{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB_EXT,     10U,         HSE_KEY2048_BITS, {0U} },*/ \
        { 0U,              0U,                 0U,                           0U,        0U, {0U}  }
#endif //TEST_SUITE1 || TEST_SUITE2

#define CRYPTO_43_HSE_STOP_SEC_VAR_INIT_UNSPECIFIED_NO_CACHEABLE
#include "Crypto_43_HSE_MemMap.h"
#if defined(TEST_SUITE3)




#define  HSE_NVM_KEY_CATALOG_CFG  \
       /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)      Reserved  */  \
/* CUST keys */    \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           4U,         HSE_KEY128_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           2U,         HSE_KEY256_BITS, {0U} }, \
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PAIR,      2U,         HSE_KEY2048_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_RSA_PUB,       1U,         HSE_KEY4096_BITS, {0U} }, \
        { 0U,              0U,                0U,                          0U,         0U, {0U}  }

/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
        /* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)  */  \
        /* Symmetric key */ \
       { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            10U,        HSE_KEY256_BITS, {0U} }, \
        /* Usable only on MU0 */ \
        /* HMAC key */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_HMAC,           2U,        HSE_KEY1024_BITS, {0U} }, \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_HMAC,           10U,        HSE_KEY256_BITS, {0U} }, \
        /* Temporary secrets */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  2U,        HSE_KEY4096_BITS, {0U} },\
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  4U,        HSE_KEY638_BITS, {0U} },\
        /* RSA keys */ \
        { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB,         2U,         HSE_KEY2048_BITS, {0U} }, \
        /* DH Keys */ \
		/*{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB_EXT,     10U,         HSE_KEY2048_BITS, {0U} },*/ \
        { 0U,              0U,                 0U,                           0U,        0U, {0U}  }


 #endif //TEST_SUITE3

#if defined(TEST_SUITE4)
/** @brief    HSE NVM key catalog configuration*/

#define  HSE_NVM_KEY_CATALOG_CFG  \
		/* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)      Reserved  */  \
/* CUST keys */    \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           4U,         HSE_KEY128_BITS, {0U} }, \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_CUST, HSE_KEY_TYPE_AES,           2U,         HSE_KEY256_BITS, {0U} }, \
		{ 0U,              0U,                0U,                          0U,         0U, {0U}  }

/** @brief    HSE RAM key catalog configuration*/
#define  HSE_RAM_KEY_CATALOG_CFG  \
		/* Group MU Mask   Group Owner         Group Key Type        Number of Slots   Maximum slot size (in bits)  */  \
		/* Symmetric key */ \
	   { HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_AES,            1U,        HSE_KEY256_BITS, {0U} }, \
		/* Usable only on MU0 */ \
		/* HMAC key */ \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,     HSE_KEY_TYPE_HMAC,           1U,        HSE_KEY1024_BITS, {0U} }, \
		/* Temporary secrets */ \
		{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,   HSE_KEY_TYPE_SHARED_SECRET,  2U,        HSE_KEY4096_BITS, {0U} },\
		/*{ HSE_ALL_MU_MASK, HSE_KEY_OWNER_ANY,    HSE_KEY_TYPE_RSA_PUB_EXT,     10U,         HSE_KEY2048_BITS, {0U} },*/ \
		{ 0U,              0U,                 0U,                           0U,        0U, {0U}  }
#endif //TEST_SUITE4


#define NVM_RSA2048_PAIR_DEV_KEY_HANDLE			GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 4, 2)
#define NVM_RSA2048_PUB_ROOT_CERT_HANDLE		GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 5, 2)
#define NVM_RSA2048_PUB_CLI_CERT_HANDLE			GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 5, 3)

#else
#error "Unknown HSE FW type"
#endif
#endif /* CPU_S32K344  CPU_S32K342*/

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

#ifdef __cplusplus
}
#endif

#endif /* GLOBAL_DEFS_H */

/** @} */
