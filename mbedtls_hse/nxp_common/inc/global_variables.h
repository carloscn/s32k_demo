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

#ifndef GLOBAL_VARIABLES_H
#define GLOBAL_VARIABLES_H

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
#include "global_defs.h"
#include "global_types.h"
#if defined(S32N55)
#include "hse_srv_km_config.h"
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

/*==================================================================================================
                                 GLOBAL VARIABLE DECLARATIONS
==================================================================================================*/
#if defined(S32N55)
extern const hseStdKeyGroupCfgEntry_t gNvmCatalog[];
/**< @brief The RAM containers used to format the HSE key catalogs */
extern const hseStdKeyGroupCfgEntry_t gRamCatalog[];
#else
extern const hseKeyGroupCfgEntry_t gNvmCatalog[];
/**< @brief The RAM containers used to format the HSE key catalogs */
extern const hseKeyGroupCfgEntry_t gRamCatalog[];
#endif
/*==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================*/

#ifdef __cplusplus
}
#endif

#endif /* GLOBAL_VARIABLES_H */

/** @} */
