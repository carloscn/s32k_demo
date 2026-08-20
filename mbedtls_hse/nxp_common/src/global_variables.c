/*==================================================================================================
*
*   Copyright 2022 NXP
*
*   This software is owned or controlled by NXP and may only be used strictly in accordance with
*   the applicable license terms. By expressly accepting such terms or by downloading, installing,
*   activating and/or otherwise using the software, you are agreeing that you have read, and that
*   you agree to comply with and are bound by, such license terms. If you do not agree to
*   be bound by the applicable license terms, then you may not retain, install, activate or
*   otherwise use the software.
==================================================================================================*/


#ifdef __cplusplus
extern "C"{
#endif

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/

#include "global_variables.h"

/*==================================================================================================
 *                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
 * ===============================================================================================*/

/*==================================================================================================
 *                                       LOCAL MACROS
 * ===============================================================================================*/

/*==================================================================================================
 *                                      LOCAL CONSTANTS
 * ===============================================================================================*/

/*==================================================================================================
 *                                      LOCAL VARIABLES
 * ===============================================================================================*/

/*==================================================================================================
 *                                      GLOBAL CONSTANTS
 * ===============================================================================================*/

/*==================================================================================================
 *                                      GLOBAL VARIABLES
 * ===============================================================================================*/
#if (defined (CPU_SAF8544) || defined(S32N55))
#define CRYPTO_43_HSE_START_SEC_CONST_UNSPECIFIED
#include "Crypto_43_HSE_MemMap.h"
#define CRYPTO_43_HSE_STOP_SEC_CONST_UNSPECIFIED
#include "Crypto_43_HSE_MemMap.h"
#else
#define CRYPTO_START_SEC_CONST_UNSPECIFIED
#include "Crypto_MemMap.h"
#define CRYPTO_STOP_SEC_CONST_UNSPECIFIED
#include "Crypto_MemMap.h"
#endif
#if defined (S32N55)
/**< @brief The NVM containers used to format the HSE key catalogs */
const hseStdKeyGroupCfgEntry_t gNvmCatalog[] = {HSE_NVM_KEY_CATALOG_CFG};
///**< @brief The RAM containers used to format the HSE key catalogs */
const hseStdKeyGroupCfgEntry_t gRamCatalog[] = {HSE_RAM_KEY_CATALOG_CFG};
#else
#define CRYPTO_43_HSE_START_SEC_VAR_INIT_UNSPECIFIED_NO_CACHEABLE
#include "Crypto_43_HSE_MemMap.h"
/**< @brief The NVM containers used to format the HSE key catalogs */
const hseKeyGroupCfgEntry_t gNvmCatalog[] = {HSE_NVM_KEY_CATALOG_CFG};
/**< @brief The RAM containers used to format the HSE key catalogs */
const hseKeyGroupCfgEntry_t gRamCatalog[] = {HSE_RAM_KEY_CATALOG_CFG};
#define CRYPTO_43_HSE_STOP_SEC_VAR_INIT_UNSPECIFIED_NO_CACHEABLE
#include "Crypto_43_HSE_MemMap.h"
#endif
/*==================================================================================================
 *                                   LOCAL FUNCTION PROTOTYPES
 * ===============================================================================================*/

/*==================================================================================================
 *                                       LOCAL FUNCTIONS
 * ===============================================================================================*/

/*==================================================================================================
 *                                       GLOBAL FUNCTIONS
 * ===============================================================================================*/


#ifdef __cplusplus
}
#endif

/** @} */
