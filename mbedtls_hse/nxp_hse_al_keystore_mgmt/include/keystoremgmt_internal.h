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

#ifndef KEYSTOREMGMT_INTERNAL_H
#define KEYSTOREMGMT_INTERNAL_H

#ifdef __cplusplus
extern "C"{
#endif

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/

#include "std_typedefs.h"
#include "keystore_cfg.h"
#include "global_defs.h"
#include "hse_interface.h"

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

#define KEYSLOT_AVAILABLE		(0U)
#define KEYSLOT_ALLOCATED		(1U)
#define KEYSLOT_INUSE			(2U)
#define KEYSLOT_NOT_AVAIL		(3U)
#define KEYSLOT_LOADED			(4U)
#define STREAM_SLOT_AVAILABLE	(0U)
#define STREAM_SLOT_INUSE		(1U)

/*==================================================================================================
*                                             ENUMS
==================================================================================================*/

/*==================================================================================================
                                 STRUCTURES AND OTHER TYPEDEFS
==================================================================================================*/

typedef struct
{
	uint8_t **keystatus;
	uint32_t numkeygrps;
	uint32_t numkeys;
}keygrp_status_t;
typedef struct
{
	keygrp_status_t ram_keygrpstatus;
	keygrp_status_t nvm_keygrpstatus;
}keycatalog_status_t;

#if defined(S32N55)
typedef struct
{
	bool_t keystore_init;
	hseMuMask_t mumask;
	const hseStdKeyGroupCfgEntry_t* ram_key_catalog;
	const hseStdKeyGroupCfgEntry_t* nvm_key_catalog;
	keycatalog_status_t key_status;
	uint8_t stream_status[HSE_STREAM_COUNT];
}KeyStoreMgmt_context_t;
#else
typedef struct
{
	bool_t keystore_init;
	hseMuMask_t mumask;
	const hseKeyGroupCfgEntry_t* ram_key_catalog;
	const hseKeyGroupCfgEntry_t* nvm_key_catalog;
	keycatalog_status_t key_status;
	uint8_t stream_status[HSE_STREAM_COUNT];
}KeyStoreMgmt_context_t;
#endif

/*==================================================================================================
                                 GLOBAL VARIABLE DECLARATIONS
==================================================================================================*/

/*==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================*/

#ifdef __cplusplus
}
#endif

#endif
