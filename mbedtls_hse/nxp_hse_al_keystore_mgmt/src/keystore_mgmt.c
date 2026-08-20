/*==================================================================================================
*
*   (c) Copyright 2022 NXP.
*
*   This software is owned or controlled by NXP and may only be used strictly in accordance with
*   the applicable license terms. By expressly accepting such terms or by downloading, installing,
*   activating and/or otherwise using the software, you are agreeing that you have read, and that
*   you agree to comply with and are bound by, such license terms. If you do not agree to
*   be bound by the applicable license terms, then you may not retain, install, activate or
*   otherwise use the software.
==================================================================================================*/

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/

#include "std_typedefs.h"
#include "global_defs.h"
#include "stdio.h"
#include "string.h"
#include "mbedtls/platform_util.h"
#include "hse_interface.h"
#include "hse_host_km_import_key.h"
#include "hse_host_km_utils.h"
#include "hse_host_km_gen_key.h"
#include "hse_host_km_format_catalogs.h"
#include "hse_host_status.h"
#include "keystore_mgmt.h"
#include "Keystoremgmt_internal.h"
#include "hse_host_global.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc     calloc
#define mbedtls_free       free
#if defined(MBEDTLS_SELF_TEST)
#include <stdio.h>
#define mbedtls_printf     printf
#endif /* MBEDTLS_SELF_TEST */
#endif /* MBEDTLS_PLATFORM_C */
#include "hse_host_km_format_catalogs.h"
#include "keystore_mgmt.h"
/*==================================================================================================
*                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL MACROS
==================================================================================================*/

/*==================================================================================================
*                                      LOCAL CONSTANTS
==================================================================================================*/

/*==================================================================================================
*                                      LOCAL VARIABLES
==================================================================================================*/
static KeyStoreMgmt_context_t gKeymgt_ctx;
static hseSrvResponse_t RsaGenKeyAsyncPoll_response;

/*==================================================================================================
*                                      GLOBAL CONSTANTS
==================================================================================================*/

/*==================================================================================================
*                                      GLOBAL VARIABLES
==================================================================================================*/

/*==================================================================================================
*                                   LOCAL FUNCTION PROTOTYPES
==================================================================================================*/
#if defined(S32N55)
static uint32_t GetKeygroupNumKeySlots(const hseStdKeyGroupCfgEntry_t *phsekeygroupentry);
#else
static uint32_t GetKeygroupNumKeySlots(const hseKeyGroupCfgEntry_t *phsekeygroupentry);
#endif
static void ParseKeyCatalog(void);
static void MarkKeySlotInUse(uint32_t keyslot);
static void MarkKeySlotAllocated(uint32_t keyslot);
static void MarkKeySlotAvailable(uint32_t keyslot);
static void MarkKeySlot(uint32_t marktype, uint32_t keyslot);
static uint32_t GetKeySlotStatus(uint32_t keyslot);
static uint32_t FindKeySlot(hseKeyCatalogId_t catalog, hseKeyType_t keytype, uint32_t keysize, hseKeyHandle_t *key_handle);
static uint32_t FindAesKeySlot(hseKeyCatalogId_t catalog, uint32_t keysize, hseKeyHandle_t *pkeyhandle);
static uint32_t FindHmacKeySlot(hseKeyCatalogId_t catalog, uint32_t keysize, hseKeyHandle_t *pkeyhandle);
/*static uint32_t FindSheKeySlot(hseKeyCatalogId_t catalog, uint32_t keysize, hseKeyHandle_t *pkeyhandle); */
static uint32_t FindSharedSecretKeySlot(hseKeyCatalogId_t catalog, uint32_t keysize, hseKeyHandle_t *pkeyhandle);
static uint32_t FindRsaPubKeySlot(hseKeyCatalogId_t catalog, uint32_t keysize, hseKeyHandle_t *pkeyhandle);
static uint32_t FindRsaNvmKeyPairSlot(hseKeyCatalogId_t catalog, uint32_t keysize, hseKeyHandle_t *pkeyhandle);
static uint32_t FindEccPubKeySlot(hseKeyCatalogId_t catalog, uint32_t keysize, hseKeyHandle_t *pkeyhandle);
static uint32_t FindEccRamKeyPairSlot(hseKeyCatalogId_t catalog, uint32_t keysize, hseKeyHandle_t *pkeyhandle);
static uint32_t FindSlot(hseKeyCatalogId_t catalog, hseKeyGroupIdx_t keygroup, hseKeySlotIdx_t keyindex);

/**
 * 	@brief		RsaGenKeyCallback
 *
 * 	@param[in]	u8MuInstance
 *				MU Instance number
 *
 * 	@param[in]	u8MuChannel
 *				MU channel number
 *
 *	@param[out]	HseResponse
 *				HSE service response
 *
 *	@param[out]	pCallbackParam
 *				Parameter used to call the asynchronous callback(can be NULL)
 *
 *  @return     void
 */
static void RsaGenKeyCallback(uint8 u8MuInstance,uint8 u8MuChannel,hseSrvResponse_t HseResponse,void* pCallbackParam);

/*==================================================================================================
*                                       LOCAL FUNCTIONS
==================================================================================================*/
static void RsaGenKeyCallback
(
	uint8 u8MuInstance,
	uint8 u8MuChannel,
	hseSrvResponse_t HseResponse,
	void* pCallbackParam
)
{
	(void)u8MuInstance;
	(void)u8MuChannel;
	(void)pCallbackParam;

	RsaGenKeyAsyncPoll_response = HseResponse;
	return;
}
#if defined(S32N55)
static uint32_t GetKeygroupNumKeySlots(const hseStdKeyGroupCfgEntry_t *phsekeygroupentry)
{
 	uint32_t total_key_slots = 0;

	while(phsekeygroupentry && (phsekeygroupentry->muMask != 0))
	{
		total_key_slots += phsekeygroupentry->numOfKeySlots;
		phsekeygroupentry++;
	}

 	return total_key_slots;
}
#else
static uint32_t GetKeygroupNumKeySlots(const hseKeyGroupCfgEntry_t *phsekeygroupentry)
{
 	uint32_t total_key_slots = 0;

	while(phsekeygroupentry && (phsekeygroupentry->muMask != 0))
	{
		total_key_slots += phsekeygroupentry->numOfKeySlots;
		phsekeygroupentry++;
	}

 	return total_key_slots;
}
#endif

#if defined(S32N55)
static void UpdateKeyGrpStatus(hseKeyCatalogId_t catalog, keygrp_status_t *pkeygrpSts, const hseStdKeyGroupCfgEntry_t *pkeygrp)
{

	const hseStdKeyGroupCfgEntry_t *phsekeygroupentry = pkeygrp;

	uint32_t grpIdx, keyslotIdx;

	for(grpIdx = 0 ; ((grpIdx < pkeygrpSts->numkeygrps) && (phsekeygroupentry->muMask != 0)); 	\
		grpIdx++, phsekeygroupentry++)
	{
		/* Check if the "muMask" supports our MU*/
		if(phsekeygroupentry->muMask & gKeymgt_ctx.mumask)
		{
			for(keyslotIdx = 0; keyslotIdx < phsekeygroupentry->numOfKeySlots; keyslotIdx++)
			{
				hseKeyInfo_t reqKeyInfo;
				hseSrvResponse_t srvResponse;

				/* Check KeySlot Status */
				srvResponse = HSE_GetKeyInfo(GET_KEY_HANDLE(catalog, grpIdx, keyslotIdx),&reqKeyInfo);
				if(srvResponse == HSE_SRV_RSP_OK)
				{
					/* Key Not Empty - mark it as Loaded */
					pkeygrpSts->keystatus[grpIdx][keyslotIdx] = KEYSLOT_LOADED;
				}
				else if (srvResponse == HSE_SRV_RSP_KEY_EMPTY)
				{
					/* Key Empty - mark it as Available */
					pkeygrpSts->keystatus[grpIdx][keyslotIdx] = KEYSLOT_AVAILABLE;
				}
			}
		}
		else
		{
			/* Mark slots as KEYSLOT_NOT_AVAIL */
			for(keyslotIdx = 0; keyslotIdx < phsekeygroupentry->numOfKeySlots; keyslotIdx++)
			{
				/* Mark Slot as Not available */
				pkeygrpSts->keystatus[grpIdx][keyslotIdx] = KEYSLOT_NOT_AVAIL;

			}
		}
	}

}
#else
static void UpdateKeyGrpStatus(hseKeyCatalogId_t catalog, keygrp_status_t *pkeygrpSts, const hseKeyGroupCfgEntry_t *pkeygrp)
{
	const hseKeyGroupCfgEntry_t *phsekeygroupentry = pkeygrp;
	uint32_t grpIdx, keyslotIdx;

	for(grpIdx = 0 ; ((grpIdx < pkeygrpSts->numkeygrps) && (phsekeygroupentry->muMask != 0)); 	\
		grpIdx++, phsekeygroupentry++)
	{
		/* Check if the "muMask" supports our MU*/
		if(phsekeygroupentry->muMask & gKeymgt_ctx.mumask)
		{
			for(keyslotIdx = 0; keyslotIdx < phsekeygroupentry->numOfKeySlots; keyslotIdx++)
			{
				hseKeyInfo_t reqKeyInfo;
				hseSrvResponse_t srvResponse;

				/* Check KeySlot Status */
				srvResponse = HSE_GetKeyInfo(GET_KEY_HANDLE(catalog, grpIdx, keyslotIdx),
					&reqKeyInfo);
				if(srvResponse == HSE_SRV_RSP_OK)
				{
					/* Key Not Empty - mark it as Loaded */
					pkeygrpSts->keystatus[grpIdx][keyslotIdx] = KEYSLOT_LOADED;
				}
				else if (srvResponse == HSE_SRV_RSP_KEY_EMPTY)
				{
					/* Key Empty - mark it as Available */
					pkeygrpSts->keystatus[grpIdx][keyslotIdx] = KEYSLOT_AVAILABLE;
				}
			}
		}
		else
		{
			/* Mark slots as KEYSLOT_NOT_AVAIL */
			for(keyslotIdx = 0; keyslotIdx < phsekeygroupentry->numOfKeySlots; keyslotIdx++)
			{
				/* Mark Slot as Not available */
				pkeygrpSts->keystatus[grpIdx][keyslotIdx] = KEYSLOT_NOT_AVAIL;

			}
		}
	}

}
#endif
static void ParseKeyCatalog(void)
{
	KeyStoreMgmt_context_t *ctx = &gKeymgt_ctx;

	/* Parse RAM Key Catalog */
	UpdateKeyGrpStatus(HSE_KEY_CATALOG_ID_RAM, &ctx->key_status.ram_keygrpstatus, ctx->ram_key_catalog);

	/* Parse NVM Key Catalog */
	UpdateKeyGrpStatus(HSE_KEY_CATALOG_ID_NVM, &ctx->key_status.nvm_keygrpstatus, ctx->nvm_key_catalog);

	return;
}

static void MarkKeySlotInUse(uint32_t keyslot)
{
	MarkKeySlot(KEYSLOT_INUSE, keyslot);
}

static void MarkKeySlotAllocated(uint32_t keyslot)
{
	MarkKeySlot(KEYSLOT_ALLOCATED, keyslot);
}

static void MarkKeySlotAvailable(uint32_t keyslot)
{
	MarkKeySlot(KEYSLOT_AVAILABLE, keyslot);
}

static void MarkKeySlot(uint32_t marktype, uint32_t keyslot)
{
	hseKeyHandle_t keyhandle = (hseKeyHandle_t)keyslot;
	hseKeyCatalogId_t catalog = GET_CATALOG_ID(keyhandle);
	hseKeyGroupIdx_t grpIdx = GET_GROUP_IDX(keyhandle);
	hseKeySlotIdx_t keyslotIdx = GET_SLOT_IDX(keyhandle);

	KeyStoreMgmt_context_t *pKeyctx = &gKeymgt_ctx;
	keygrp_status_t* pKeyslotStatus;

	if(catalog == HSE_KEY_CATALOG_ID_RAM)
	{
		pKeyslotStatus = &pKeyctx->key_status.ram_keygrpstatus;
	}
	else
	{
		pKeyslotStatus = &pKeyctx->key_status.nvm_keygrpstatus;
	}

	/* Mark the Slot */
	pKeyslotStatus->keystatus[grpIdx][keyslotIdx] = marktype;

	return;
}

static uint32_t GetKeySlotStatus(uint32_t keyslot)
{
	hseKeyHandle_t keyhandle = (hseKeyHandle_t)keyslot;
	hseKeyCatalogId_t catalog = GET_CATALOG_ID(keyhandle);
	hseKeyGroupIdx_t grpIdx = GET_GROUP_IDX(keyhandle);
	hseKeySlotIdx_t keyslotIdx = GET_SLOT_IDX(keyhandle);
	KeyStoreMgmt_context_t *pKeyctx = &gKeymgt_ctx;
	keygrp_status_t* pKeyslotStatus;

	if(catalog == HSE_KEY_CATALOG_ID_RAM)
	{
		pKeyslotStatus = &pKeyctx->key_status.ram_keygrpstatus;
	}
	else
	{
		pKeyslotStatus = &pKeyctx->key_status.nvm_keygrpstatus;
	}

	return pKeyslotStatus->keystatus[grpIdx][keyslotIdx];
}
#if defined (S32N55)
static uint8_t IsKeyGroupAccess(const hseStdKeyGroupCfgEntry_t *pKeyCatalog)
{
	uint8_t access_granted =(uint8_t)FALSE;
	switch(pKeyCatalog->groupOwner)
	{
		case HSE_KEY_OWNER_ANY:
		access_granted = (uint8_t)TRUE;
		break;
		case HSE_KEY_OWNER_CLI0:
		access_granted=HSE_IsCustSU();
		break;
		case HSE_KEY_OWNER_CLI1:
		access_granted=HSE_IsCustSU();
		break;
		case HSE_KEY_OWNER_CLI2:
		access_granted=HSE_IsCustSU();
		break;
		case HSE_KEY_OWNER_CLI3:
		access_granted=HSE_IsCustSU();
		break;

	}
	return access_granted;
}
#else
static uint8_t IsKeyGroupAccess(const hseKeyGroupCfgEntry_t *pKeyCatalog)
{
	uint8_t access_granted = (uint8_t)FALSE;

	switch(pKeyCatalog->groupOwner)
	{
		case HSE_KEY_OWNER_ANY:
			access_granted = (uint8_t)TRUE;
			break;
		case HSE_KEY_OWNER_CUST:
			access_granted = HSE_IsCustSU();
			break;
		case HSE_KEY_OWNER_OEM:
			access_granted = HSE_IsOemSU();
			break;
	}

	return access_granted;
}
#endif


static uint32_t FindKeySlot( hseKeyCatalogId_t catalog, hseKeyType_t keytype, uint32_t keysize, hseKeyHandle_t *key_handle)
{
	KeyStoreMgmt_context_t *pKeyctx = &gKeymgt_ctx;
	keygrp_status_t* pKeyslotStatus;
	uint32_t key_group = 0, key_index, slot_status = 0;
#if defined(S32N55)
	const hseStdKeyGroupCfgEntry_t *pKeyCatalog = NULL;
#else
	const hseKeyGroupCfgEntry_t *pKeyCatalog = NULL;
#endif
	hseSrvResponse_t srvResponse;

	if(catalog == HSE_KEY_CATALOG_ID_NVM)
	{
		/* Initialize the NVMKey Catalog pointer */
		pKeyCatalog = pKeyctx->nvm_key_catalog;
		pKeyslotStatus=(keygrp_status_t*)&pKeyctx->key_status.nvm_keygrpstatus;
	}
	else if (catalog == HSE_KEY_CATALOG_ID_RAM)
	{
		/* Initialize the NVMKey Catalog pointer */
		pKeyCatalog = pKeyctx->ram_key_catalog;
		pKeyslotStatus=(keygrp_status_t*)&pKeyctx->key_status.ram_keygrpstatus;
	}

	/* Iterate until Catalog terminator is found */
	while(pKeyCatalog->muMask != 0)
	{
		/* Implement check for User Rights */
		if ((catalog == HSE_KEY_CATALOG_ID_RAM) || 		\
			((catalog == HSE_KEY_CATALOG_ID_NVM) && 	\
			(IsKeyGroupAccess(pKeyCatalog) == (uint8_t)TRUE)))
		{
			/* Check for KeyType and Key Size in the key group */
			if((pKeyCatalog->keyType == keytype)&&(pKeyCatalog->maxKeyBitLen >= keysize))
			{
				/* Find available slot */
				for (key_index = 0; key_index < pKeyCatalog->numOfKeySlots; key_index++)
				{
					slot_status = pKeyslotStatus->keystatus[key_group][key_index];

					/* Check for Slot Availability */
					if(slot_status == KEYSLOT_AVAILABLE)
					{
						hseKeyHandle_t tmpkeyhandle;
						hseKeyInfo_t reqKeyInfo;
						tmpkeyhandle = GET_KEY_HANDLE(catalog, key_group, key_index);
						srvResponse = HSE_GetKeyInfo(tmpkeyhandle, &reqKeyInfo);
						if(srvResponse == HSE_SRV_RSP_KEY_EMPTY)
						{
							*key_handle = tmpkeyhandle;
							return (uint32_t)tmpkeyhandle;
						}
					}
				}

				if(slot_status == KEYSLOT_NOT_AVAIL)
				{
					*key_handle = (hseKeyHandle_t)(-1);
					break;
				}
			}
		}

		key_group++;
		pKeyCatalog++;
	}

	return (uint32_t)(-1);
}

static uint32_t FindAesKeySlot(hseKeyCatalogId_t catalog, uint32_t keysize, hseKeyHandle_t *pkeyhandle)
{
	const uint32_t AesKeysize_tbl[]={HSE_KEY128_BITS, HSE_KEY192_BITS, HSE_KEY256_BITS};
	uint32_t i, keyslot = (uint32_t)-1;

	/* Priority 1 find slot in the same keysize area*/
	for(i = 0; i < sizeof(AesKeysize_tbl)/sizeof(uint32_t); i++)
	{
		if(AesKeysize_tbl[i] < keysize)
		{
			continue;
		}

		keyslot = FindKeySlot(catalog, HSE_KEY_TYPE_AES, AesKeysize_tbl[i], pkeyhandle);

		if(keyslot != (uint32_t)-1)
		{
			break;
		}
	}

	return keyslot;
}

static uint32_t FindHmacKeySlot(hseKeyCatalogId_t catalog, uint32_t keysize, hseKeyHandle_t *pkeyhandle)
{
	const uint32_t HmacKeysize_tbl[]={							\
		HSE_KEY128_BITS, HSE_KEY160_BITS, HSE_KEY224_BITS, HSE_KEY256_BITS,		\
		HSE_KEY384_BITS, HSE_KEY512_BITS, HSE_KEY1024_BITS, HSE_MAX_HMAC_KEY_BITS_LEN	\
	};

	uint32_t i, keyslot = (uint32_t)-1;

	/* Priority 1 find slot in the same keysize area*/
	for(i = 0; i < sizeof(HmacKeysize_tbl)/sizeof(uint32_t); i++)
	{
		if(HmacKeysize_tbl[i] < keysize)
		{
			continue;
		}

		keyslot = FindKeySlot(catalog, HSE_KEY_TYPE_HMAC, HmacKeysize_tbl[i], pkeyhandle);

		if(keyslot != (uint32_t)-1)
		{
			break;
		}
	}

	return keyslot;
}
#if !defined(S32N55)
static uint32_t FindSheKeySlot(hseKeyCatalogId_t catalog, uint32_t keysize, hseKeyHandle_t *pkeyhandle)
{
	uint32_t keyslot;
	(void) keysize;

	/* Priority 1 find slot in the same keysize area*/
	keyslot = FindKeySlot(catalog, HSE_KEY_TYPE_SHE, HSE_KEY128_BITS, pkeyhandle);

	return keyslot;
}
#endif
static uint32_t FindSharedSecretKeySlot(hseKeyCatalogId_t catalog, uint32_t keysize, hseKeyHandle_t *pkeyhandle)
{
	const uint32_t SharedSecretSize_tbl[]={							\
		HSE_KEY128_BITS, HSE_KEY160_BITS, HSE_KEY224_BITS, HSE_KEY256_BITS,		\
		HSE_KEY384_BITS, HSE_KEY512_BITS, HSE_KEY1024_BITS, HSE_KEY2048_BITS,	\
		HSE_KEY3072_BITS, HSE_KEY4096_BITS	\
	};

	uint32_t i, keyslot = (uint32_t)-1;

	/* Priority 1 find slot in the same keysize area*/
	for(i = 0; i < sizeof(SharedSecretSize_tbl)/sizeof(uint32_t); i++)
	{
		if(SharedSecretSize_tbl[i] < keysize)
		{
			continue;
		}

		keyslot = FindKeySlot(catalog, HSE_KEY_TYPE_SHARED_SECRET, SharedSecretSize_tbl[i], pkeyhandle);

		if(keyslot != (uint32_t)-1)
		{
			break;
		}
	}

	return keyslot;
}

static uint32_t FindRsaPubKeySlot(hseKeyCatalogId_t catalog, uint32_t keysize, hseKeyHandle_t *pkeyhandle)
{
	const uint32_t RsaKeysize_tbl[]={							\
		HSE_KEY1024_BITS, HSE_KEY2048_BITS, HSE_KEY3072_BITS, HSE_KEY4096_BITS
	};

	uint32_t i, keyslot = (uint32_t)-1;

	/* Priority 1 find slot in the same keysize area*/
	for(i = 0; i < sizeof(RsaKeysize_tbl)/sizeof(uint32_t); i++)
	{
		if(RsaKeysize_tbl[i] < keysize)
		{
			continue;
		}

		keyslot = FindKeySlot(catalog, HSE_KEY_TYPE_RSA_PUB, RsaKeysize_tbl[i], pkeyhandle);

		if(keyslot != (uint32_t)-1)
		{
			break;
		}
	}

	return keyslot;
}

static uint32_t FindRsaNvmKeyPairSlot(hseKeyCatalogId_t catalog, uint32_t keysize, hseKeyHandle_t *pkeyhandle)
{
	const uint32_t RsaKeysize_tbl[]={							\
		HSE_KEY1024_BITS, HSE_KEY2048_BITS, HSE_KEY3072_BITS, HSE_KEY4096_BITS
	};
	uint32_t i, keyslot = (uint32_t)-1;

	/* Priority 1 find slot in the same keysize area*/
	for(i = 0; i < sizeof(RsaKeysize_tbl)/sizeof(uint32_t); i++)
	{
		if(RsaKeysize_tbl[i] < keysize)
		{
			continue;
		}

		/* Find Key Slot */
		keyslot = FindKeySlot(catalog, HSE_KEY_TYPE_RSA_PAIR, RsaKeysize_tbl[i], pkeyhandle);

		if(keyslot != (uint32_t)-1)
		{
			break;
		}
	}

	return keyslot;
}

static uint32_t FindEccPubKeySlot(hseKeyCatalogId_t catalog, uint32_t keysize, hseKeyHandle_t *pkeyhandle)
{
	const uint32_t EccKeysize_tbl[]={							\
			HSE_KEY192_BITS, HSE_KEY224_BITS, HSE_KEY240_BITS, HSE_KEY256_BITS,
			HSE_KEY320_BITS, HSE_KEY384_BITS, HSE_KEY512_BITS, HSE_KEY521_BITS
		};

	uint32_t i, keyslot = (uint32_t)-1;

	/* Priority 1 find slot in the same keysize area*/
	for(i = 0; i < sizeof(EccKeysize_tbl)/sizeof(uint32_t); i++)
	{
		if(EccKeysize_tbl[i] < keysize)
		{
			continue;
		}
		/* Find Key Slot */
		keyslot = FindKeySlot(catalog, HSE_KEY_TYPE_ECC_PUB, EccKeysize_tbl[i], pkeyhandle);

		if(keyslot != (uint32_t)-1)
		{
			break;
		}
	}

	return keyslot;
}

static uint32_t FindEccRamKeyPairSlot(hseKeyCatalogId_t catalog, uint32_t keysize, hseKeyHandle_t *pkeyhandle)
{
	const uint32_t EccKeysize_tbl[]={							\
			HSE_KEY192_BITS, HSE_KEY224_BITS, HSE_KEY240_BITS, HSE_KEY256_BITS,
			HSE_KEY320_BITS, HSE_KEY384_BITS, HSE_KEY512_BITS, HSE_KEY521_BITS
		};

	uint32_t i, keyslot = (uint32_t)-1;

	/* Priority 1 find slot in the same keysize area*/
	for(i = 0; i < sizeof(EccKeysize_tbl)/sizeof(uint32_t); i++)
	{
		if(EccKeysize_tbl[i] < keysize)
		{
			continue;
		}
		/* Find Key Slot */
		keyslot = FindKeySlot(catalog, HSE_KEY_TYPE_ECC_PAIR, EccKeysize_tbl[i], pkeyhandle);

		if(keyslot != (uint32_t)-1)
		{
			break;
		}
	}

	return keyslot;
}

#if defined(HSE_SPT_CLASSIC_DH)
static uint32_t FindDhPubKeySlot(hseKeyCatalogId_t catalog, uint32_t keysize, hseKeyHandle_t *pkeyhandle)
{
	const uint32_t DhKeysize_tbl[]={							\
			HSE_KEY1024_BITS, HSE_KEY2048_BITS, HSE_KEY3072_BITS, HSE_KEY4096_BITS
		};

	uint32_t i, keyslot = (uint32_t)-1;

	/* Priority 1 find slot in the same keysize area*/
	for(i = 0; i < sizeof(DhKeysize_tbl)/sizeof(uint32_t); i++)
	{
		if(DhKeysize_tbl[i] < keysize)
		{
			continue;
		}

		/* Find Key Slot */
		keyslot = FindKeySlot(catalog, HSE_KEY_TYPE_DH_PUB, DhKeysize_tbl[i], pkeyhandle);

		if(keyslot != (uint32_t)-1)
		{
			break;
		}
	}

	return keyslot;
}

static uint32_t FindDhKeyPairSlot(hseKeyCatalogId_t catalog, uint32_t keysize, hseKeyHandle_t *pkeyhandle)
{
	const uint32_t DhKeysize_tbl[]={							\
			HSE_KEY1024_BITS, HSE_KEY2048_BITS, HSE_KEY3072_BITS, HSE_KEY4096_BITS
		};

	uint32_t i, keyslot = (uint32_t)-1;

	/* Priority 1 find slot in the same keysize area*/
	for(i = 0; i < sizeof(DhKeysize_tbl)/sizeof(uint32_t); i++)
	{
		if(DhKeysize_tbl[i] < keysize)
		{
			continue;
		}

		/* Find Key Slot */
		keyslot = FindKeySlot(catalog, HSE_KEY_TYPE_DH_PAIR, DhKeysize_tbl[i], pkeyhandle);

		if(keyslot != (uint32_t)-1)
		{
			break;
		}
	}

	return keyslot;
}
#endif /* HSE_SPT_CLASSIC_DH */
static uint32_t FindSlot(hseKeyCatalogId_t catalog, hseKeyGroupIdx_t keygroup, hseKeySlotIdx_t keyindex)
{
	KeyStoreMgmt_context_t *ctx = &gKeymgt_ctx;
#if defined(S32N55)
	const hseStdKeyGroupCfgEntry_t *phsekeygroupentry;
#else
	const hseKeyGroupCfgEntry_t *phsekeygroupentry;
#endif
	keygrp_status_t *pkeygrpstatus;

	/* Assign the key catalog */
	if (catalog == HSE_KEY_CATALOG_ID_RAM)
	{
		/* Ram catalog */
		phsekeygroupentry = ctx->ram_key_catalog;
		pkeygrpstatus = &ctx->key_status.ram_keygrpstatus;
	}
	else if (catalog == HSE_KEY_CATALOG_ID_NVM)
	{
		/* NVM catalog */
		phsekeygroupentry = ctx->nvm_key_catalog;
		pkeygrpstatus = &ctx->key_status.nvm_keygrpstatus;
	}
	else
	{
		/* Invalid key catalog */
		return (uint32_t)-1;;
	}

	if ((keygroup >= pkeygrpstatus->numkeygrps) ||	\
		(keyindex >= phsekeygroupentry[keygroup].numOfKeySlots))
	{
		/* Invalid key catalog */
		return (uint32_t)-1;;
	}

	return (uint32_t)GET_KEY_HANDLE(catalog, keygroup, keyindex);
}
#if defined(S32N55)
static uint32_t GetNumKeygroups(const hseStdKeyGroupCfgEntry_t *phsekeygroupentry)
{
	uint32_t keygroups = 0U;
	while(phsekeygroupentry && (phsekeygroupentry->muMask != 0))
	{
		keygroups ++;
		phsekeygroupentry++;
	}
	return keygroups;
}
#else
static uint32_t GetNumKeygroups(const hseKeyGroupCfgEntry_t *phsekeygroupentry)
{
	uint32_t keygroups = 0U;
	while(phsekeygroupentry && (phsekeygroupentry->muMask != 0))
	{
		keygroups ++;
		phsekeygroupentry++;
	}
	return keygroups;
}
#endif
static void KeyStore_FreeKeyCatalogStatus(void)
{
	KeyStoreMgmt_context_t *ctx = &gKeymgt_ctx;
	uint32_t i;

	/* Release Key Status Allocation */
	if(NULL != ctx->key_status.ram_keygrpstatus.keystatus)
	{
		/* Release Ram Key Status */
		for (i = 0; i < ctx->key_status.ram_keygrpstatus.numkeygrps; i++)
		{
			mbedtls_free(ctx->key_status.ram_keygrpstatus.keystatus[i]);
			ctx->key_status.ram_keygrpstatus.keystatus[i] = (uint8_t*)NULL;
		}
	}
	if(NULL != ctx->key_status.nvm_keygrpstatus.keystatus)
	{
		/* Release Nvm Key Status */
		for (i = 0; i < ctx->key_status.nvm_keygrpstatus.numkeygrps; i++)
		{
			mbedtls_free(ctx->key_status.nvm_keygrpstatus.keystatus[i]);
			ctx->key_status.nvm_keygrpstatus.keystatus[i] = (uint8_t*)NULL;
		}
	}

	/* Release Ram Key group Status */
	mbedtls_free(ctx->key_status.ram_keygrpstatus.keystatus);
	/* Release Nvm Key group Status */
	mbedtls_free(ctx->key_status.nvm_keygrpstatus.keystatus);

	ctx->key_status.ram_keygrpstatus.keystatus = (uint8_t**)NULL;
	ctx->key_status.nvm_keygrpstatus.keystatus = (uint8_t**)NULL;

	return;
}
/*==================================================================================================
*                                       GLOBAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
* Description: Initialize KeyStore based upon user configuration.
************************************************************************************************/
KeymgmtErrCodeT KeystoreMgmt_Init(keystore_config_t *keystorecfg)
{
	KeymgmtErrCodeT err = KEYMGMT_ERR_SUCCESS;
	KeyStoreMgmt_context_t *ctx = &gKeymgt_ctx;
	uint32_t i;

	if(keystorecfg == NULL)
	{
		return KEYMGMT_ERR_INVALID_PARAM;
	}

	if(gKeymgt_ctx.keystore_init == TRUE)
	{
		/* Return Error if already initialized */
		return KEYMGMT_ERR_ALREADY_INITIALIZED;
	}

	memset((void*)&gKeymgt_ctx, 0, sizeof(gKeymgt_ctx));

    if(! (CHECK_HSE_STATUS(HSE_STATUS_INSTALL_OK)) )
    {
    	mbedtls_printf("Key Catalog Not Found");
		err = KeystoreMgmt_InstallKeyCatalog(keystorecfg);
    }

	gKeymgt_ctx.nvm_key_catalog = keystorecfg->nvm_key_catalog;
	gKeymgt_ctx.ram_key_catalog = keystorecfg->ram_key_catalog;
	gKeymgt_ctx.mumask = keystorecfg->mumask;

	ctx->key_status.ram_keygrpstatus.numkeygrps = GetNumKeygroups(gKeymgt_ctx.ram_key_catalog);
	ctx->key_status.nvm_keygrpstatus.numkeygrps = GetNumKeygroups(gKeymgt_ctx.nvm_key_catalog);

	ctx->key_status.ram_keygrpstatus.numkeys = GetKeygroupNumKeySlots(gKeymgt_ctx.ram_key_catalog);
	ctx->key_status.nvm_keygrpstatus.numkeys = GetKeygroupNumKeySlots(gKeymgt_ctx.nvm_key_catalog);

	do
	{
		ctx->key_status.ram_keygrpstatus.keystatus = (uint8_t**)mbedtls_calloc(ctx->key_status.ram_keygrpstatus.numkeygrps, sizeof(uint8_t*));
		ctx->key_status.nvm_keygrpstatus.keystatus = (uint8_t**)mbedtls_calloc(ctx->key_status.nvm_keygrpstatus.numkeygrps, sizeof(uint8_t*));

		if ((NULL == ctx->key_status.ram_keygrpstatus.keystatus) ||
			(NULL == ctx->key_status.nvm_keygrpstatus.keystatus))
		{
			err = KEYMGMT_ERR_MEMALLOC_FAILED;
			break;
		}
		/* Allocate memory for KeyStatus */
		for (i = 0; i < ctx->key_status.ram_keygrpstatus.numkeygrps; i++)
		{
			ctx->key_status.ram_keygrpstatus.keystatus[i] = (uint8_t*)mbedtls_calloc(	\
				ctx->ram_key_catalog[i].numOfKeySlots, sizeof(uint8_t));
			if(NULL == ctx->key_status.ram_keygrpstatus.keystatus[i])
			{
				err = KEYMGMT_ERR_MEMALLOC_FAILED;
				break;
			}
		}
		if(err != KEYMGMT_ERR_SUCCESS)
		{
			break;
		}

		for (i = 0; i < ctx->key_status.nvm_keygrpstatus.numkeygrps; i++)
		{
			ctx->key_status.nvm_keygrpstatus.keystatus[i] = (uint8_t*)mbedtls_calloc(	\
				ctx->nvm_key_catalog[i].numOfKeySlots, sizeof(uint8_t));
			if(NULL == ctx->key_status.nvm_keygrpstatus.keystatus[i])
			{
				err = KEYMGMT_ERR_MEMALLOC_FAILED;
				break;
			}
		}
	}while(0);

	if(KEYMGMT_ERR_SUCCESS != err)
	{
		/* Free KeyCatalog Status */
		KeyStore_FreeKeyCatalogStatus();
	}
	else
	{
		/* Parse Key Catalog and update key status */
		ParseKeyCatalog();

		gKeymgt_ctx.keystore_init=(bool_t)TRUE;
	}

	return err;
}
/*************************************************************************************************
* Description: Free all in use RAM keys
************************************************************************************************/
void KeystoreMgmt_Free(void)
{
	KeyStoreMgmt_context_t *ctx = &gKeymgt_ctx;
#if defined(S32N55)
	const hseStdKeyGroupCfgEntry_t *phsekeygroupentry = ctx->ram_key_catalog;
#else
	const hseKeyGroupCfgEntry_t *phsekeygroupentry = ctx->ram_key_catalog;
#endif
	uint32_t grpIdx, keyslotIdx;
	uint8_t **pkeystatus;

	if (ctx->keystore_init == (bool_t)FALSE)
	{
		return;
	}

	/* Iterate and erase all in_use Ram Keys */
	pkeystatus = ctx->key_status.ram_keygrpstatus.keystatus;
	for(grpIdx = 0 ; ((grpIdx < ctx->key_status.ram_keygrpstatus.numkeygrps) && (phsekeygroupentry->muMask != 0)); grpIdx++)
	{
		for(keyslotIdx = 0; keyslotIdx < phsekeygroupentry->numOfKeySlots; keyslotIdx++)
		{
			if(pkeystatus[grpIdx][keyslotIdx] == KEYSLOT_INUSE)
			{
				hseKeyHandle_t keyhandle = GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_RAM, grpIdx, keyslotIdx);
				(void)HSE_EraseKey(keyhandle, HSE_ERASE_NOT_USED);
			}
		}
		phsekeygroupentry++;
	}

	/* Free KeyCatalog Status */
	KeyStore_FreeKeyCatalogStatus();

	/* Zeroise context buffer */
	mbedtls_platform_zeroize(ctx, sizeof(ctx));
}


/* Description: Formats key catalogs based upon user configuration
************************************************************************************************/
KeymgmtErrCodeT KeystoreMgmt_InstallKeyCatalog(keystore_config_t *keystorecfg)
{
	KeymgmtErrCodeT err = KEYMGMT_ERR_SUCCESS;
	hseSrvResponse_t srvResponse;
#if defined(S32N55)
	srvResponse = HSE_FormatKeyCatalogs();
#else
	srvResponse = HSE_FormatKeyCatalogs(keystorecfg->ram_key_catalog, keystorecfg->nvm_key_catalog);
#endif
	if (HSE_SRV_RSP_OK != srvResponse)
	{
		err = KEYMGMT_ERR_INSTALL_FAILED;
	}

	return err;
}
/*************************************************************************************************
* Description: Allocates key slot if not allocated and import key to the slot
************************************************************************************************/
KeymgmtErrCodeT KeystoreMgmt_FindImportSlot(key_import_param_t *key_import_param, hseKeyHandle_t *keyhandle)
{
	KeymgmtErrCodeT err = KEYMGMT_ERR_SUCCESS;
	hseSrvResponse_t srvResponse;
	hseKeyHandle_t handle;
	uint8_t hsekeystatus;
	hseKeyInfo_t reqKeyInfo;

	/* Find and allocate Key Slot */
	err = KeystoreMgmt_FindAllocateSlot(key_import_param, &handle);
	if(err != KEYMGMT_ERR_SUCCESS)
	{
		return err;
	}
	/* Check current HSE KeyInfo, to be used for restoration of Keystore state later */
	srvResponse = HSE_GetKeyInfo(handle, &reqKeyInfo);
	if(srvResponse == HSE_SRV_RSP_KEY_EMPTY)
	{
		hsekeystatus = KEYSLOT_AVAILABLE;
	}
	else if(srvResponse == HSE_SRV_RSP_OK)
	{
		hsekeystatus = KEYSLOT_ALLOCATED;
	}
	else
	{
		/* We have received an invalid handle */
		return KEYMGMT_ERR_INVALID_PARAM;
	}

	/* Import Key to Key Slot */
	err = KeyStoreMgmt_ImportKey(handle, key_import_param);
	if(err == KEYMGMT_ERR_SUCCESS)
	{
		/* Mark the key as IN USE */
		MarkKeySlotInUse(handle);
		*keyhandle = handle;
	}
	else
	{
		/* Restore keyslot status as we are unable to import the key */
		MarkKeySlot(hsekeystatus, handle);
		err = KEYMGMT_ERR_KEY_IMPORT_FAILED;
	}

	return err;
}
/*************************************************************************************************
* Description: Allocates key slot as per the key type
************************************************************************************************/
KeymgmtErrCodeT KeystoreMgmt_FindAllocateSlot( key_import_param_t *key_import_param, hseKeyHandle_t *keyhandle)
{
	KeymgmtErrCodeT err = KEYMGMT_ERR_SUCCESS;
	hseKeyHandle_t handle;
	uint32_t keyslot = (uint32_t)-1;

	if(gKeymgt_ctx.keystore_init == FALSE)
	{
		return KEYMGMT_ERR_KEYSTORE_NOT_INITIALIZED;
	}

	if((keyhandle==NULL)||(key_import_param == NULL))
	{
		return KEYMGMT_ERR_INVALID_PARAM;
	}

	/* Protect the code from multiple thread executions */
	switch(key_import_param->key_type)
	{
		case HSE_KEY_TYPE_AES:
		{
			/* Find Key Slot */
			keyslot = FindAesKeySlot(key_import_param->key_catalog, 	\
				key_import_param->key_param.sym_key_param.size, &handle);
			break;
		}
#if !defined(S32N55)
		case HSE_KEY_TYPE_SHE:
		{
			/* Find Key Slot */
			keyslot = FindSheKeySlot(key_import_param->key_catalog, 	\
				key_import_param->key_param.sym_key_param.size, &handle);
			break;
		}
#endif
		case HSE_KEY_TYPE_HMAC:
		{
			/* Find Key Slot */
			keyslot = FindHmacKeySlot(key_import_param->key_catalog, 	\
				key_import_param->key_param.sym_key_param.size, &handle);
			break;
		}
		case HSE_KEY_TYPE_SHARED_SECRET:
		{
			/* Find Key Slot */
			keyslot = FindSharedSecretKeySlot(key_import_param->key_catalog, 	\
				key_import_param->key_param.sym_key_param.size, &handle);
			break;
		}
		case HSE_KEY_TYPE_RSA_PUB:
		{
			/* Find Key Slot */
			keyslot = FindRsaPubKeySlot(key_import_param->key_catalog, 		\
				key_import_param->key_param.rsa_keypair_param.N_len, &handle);
			break;
		}
		case HSE_KEY_TYPE_RSA_PAIR:
		{
			/* Find Key Slot */
			keyslot = FindRsaNvmKeyPairSlot(key_import_param->key_catalog, 		\
				key_import_param->key_param.rsa_keypair_param.N_len, &handle);
			break;
		}
		case HSE_KEY_TYPE_ECC_PUB:
		{
			keyslot = FindEccPubKeySlot(key_import_param->key_catalog,			\
					key_import_param->key_param.ecc_pubkey_param.size_Q, &handle);
			break;
		}
		case HSE_KEY_TYPE_ECC_PAIR:
		{
			keyslot = FindEccRamKeyPairSlot(key_import_param->key_catalog,		\
					key_import_param->key_param.ecc_keypair_param.size_Q, &handle);
			break;
		}
#if defined (HSE_SPT_CLASSIC_DH)
		case HSE_KEY_TYPE_DH_PAIR:
		{
			keyslot = FindDhKeyPairSlot(key_import_param->key_catalog,		\
					key_import_param->key_param.dh_keypair_param.pubLen, &handle);
			break;
		}
		case HSE_KEY_TYPE_DH_PUB:
		{
			keyslot = FindDhPubKeySlot(key_import_param->key_catalog,		\
					key_import_param->key_param.dh_public_param.pubLen, &handle);
			break;
		}
#endif /* HSE_SPT_CLASSIC_DH */
	}

	/* If Slot is successfully allocated */
	if(keyslot != (uint32_t)-1)
	{
		MarkKeySlotAllocated(keyslot);
		*keyhandle = handle;
	}
	else
	{
		err = KEYMGMT_ERR_SLOT_NOT_FOUND;
	}

	return err;
}

/*************************************************************************************************
* Description: Free key as per its type
************************************************************************************************/
KeymgmtErrCodeT KeyStoreMgmt_FreeKey(hseKeyHandle_t keyhandle)
{
	hseSrvResponse_t srvResponse;
	KeymgmtErrCodeT err = KEYMGMT_ERR_SUCCESS;
	hseKeyCatalogId_t catalog = GET_CATALOG_ID(keyhandle);
	hseKeyGroupIdx_t keygroup = GET_GROUP_IDX(keyhandle);
	hseKeySlotIdx_t key_index = GET_SLOT_IDX(keyhandle);

	uint32_t keyslot;

	if(gKeymgt_ctx.keystore_init == FALSE)
	{
		return KEYMGMT_ERR_KEYSTORE_NOT_INITIALIZED;
	}

	keyslot = FindSlot(catalog, keygroup, key_index);

	/* return error if keyslot is found invalid */
	if(keyslot == (uint32_t) -1)
	{
		return KEYMGMT_ERR_INVALID_PARAM;
	}

	if(catalog == HSE_KEY_CATALOG_ID_RAM)
	{
		if(GetKeySlotStatus(keyslot) != KEYSLOT_AVAILABLE)
		{
			/* Erase key from HSE */
			srvResponse = HSE_EraseKey(keyhandle, HSE_ERASE_NOT_USED);
			if(srvResponse != HSE_SRV_RSP_OK)
			{
				err = KEYMGMT_ERR_KEY_ERASE_FAIL;
			}

			/* Mark the Key Slot as available */
			MarkKeySlotAvailable(keyslot);
		}
	}
	else if (catalog == HSE_KEY_CATALOG_ID_NVM)
	{
		/* Erase key from NVM */
		err = KeyStoreMgmt_EraseNvmKey(keyhandle);
	}
	else
	{
		err = KEYMGMT_ERR_INVALID_PARAM;
	}

	return err;
}

/*************************************************************************************************
* Description: Finds if any stream slot is available
************************************************************************************************/
KeymgmtErrCodeT KeystoreMgmt_FindAllocateStreamSlot(hseStreamId_t *streamId)
{
	KeymgmtErrCodeT err = KEYMGMT_ERR_SUCCESS;
	hseStreamId_t id;
	KeyStoreMgmt_context_t *ctx = &gKeymgt_ctx;

	if(gKeymgt_ctx.keystore_init == FALSE)
	{
		return KEYMGMT_ERR_KEYSTORE_NOT_INITIALIZED;
	}

	for(id = 0; id < sizeof(ctx->stream_status)/sizeof(ctx->stream_status[0]); id++)
	{
		if(ctx->stream_status[id]== STREAM_SLOT_AVAILABLE)
		{
			break;
		}
	}

	if(id >= sizeof(ctx->stream_status)/sizeof(ctx->stream_status[0]))
	{
		err = KEYMGMT_ERR_STREAM_BUSY;
	}
	else
	{
		/* Update Slot Status */
		ctx->stream_status[id] = STREAM_SLOT_INUSE;
		*streamId = id;
	}

	return err;
}

/*************************************************************************************************
* Description: Free stream slot as per stream status
************************************************************************************************/
KeymgmtErrCodeT KeystoreMgmt_FreeStreamSlot(hseStreamId_t streamId)
{
	KeyStoreMgmt_context_t *ctx = &gKeymgt_ctx;

	if(gKeymgt_ctx.keystore_init == FALSE)
	{
		return KEYMGMT_ERR_KEYSTORE_NOT_INITIALIZED;
	}

	if(streamId >= sizeof(ctx->stream_status)/sizeof(ctx->stream_status[0]))
	{
		return KEYMGMT_ERR_INVALID_PARAM;
	}

	if(ctx->stream_status[streamId] == STREAM_SLOT_INUSE)
	{
		/* Update Slot Status */
		ctx->stream_status[streamId] = STREAM_SLOT_AVAILABLE;
	}

	return KEYMGMT_ERR_SUCCESS;
}

/*************************************************************************************************
* Description: Imports an on-going stream context
************************************************************************************************/
KeymgmtErrCodeT KeyStoreMgmt_ImportStreamCtx(hseStreamId_t streamId, void* pstream_ctx)
{
	KeymgmtErrCodeT err;
	hseSrvResponse_t srvResponse;

	srvResponse = HSE_ImportStream(streamId, pstream_ctx);
	switch(srvResponse)
	{
		case HSE_SRV_RSP_OK: err = KEYMGMT_ERR_SUCCESS; break;
		case HSE_SRV_RSP_INVALID_PARAM:
		case HSE_SRV_RSP_INVALID_ADDR:
			err = KEYMGMT_ERR_INVALID_PARAM; break;
		default:
			err = KEYMGMT_ERR_KEY_GEN_FAILED;
	}

	return err;
}

/*************************************************************************************************
* Description: Exports an on-going stream context
************************************************************************************************/
KeymgmtErrCodeT KeyStoreMgmt_ExportStreamCtx(hseStreamId_t streamId, void* pstream_ctx)
{
	KeymgmtErrCodeT err;
	hseSrvResponse_t srvResponse;

	srvResponse = HSE_ExportStream(streamId, pstream_ctx);
	switch(srvResponse)
	{
		case HSE_SRV_RSP_OK: err = KEYMGMT_ERR_SUCCESS; break;
		case HSE_SRV_RSP_INVALID_PARAM:
		case HSE_SRV_RSP_INVALID_ADDR:
			err = KEYMGMT_ERR_INVALID_PARAM; break;
		default:
			err = KEYMGMT_ERR_KEY_GEN_FAILED;
	}

	return err;
}

/*************************************************************************************************
* Description: Allocates memory upto maximum stream context  size
************************************************************************************************/
void* KeyStoreMgmt_AllocateStreamCtx(void)
{
#ifdef HSE_SPT_STREAM_CTX_IMPORT_EXPORT
	return (void*)mbedtls_calloc(1, MAX_STREAMING_CONTEXT_SIZE);
#else
    return NULL;
#endif
}

/*************************************************************************************************
* Description: Imports key to the key slot as per the key type
************************************************************************************************/
KeymgmtErrCodeT KeyStoreMgmt_ImportKey(hseKeyHandle_t keyhandle, key_import_param_t *key_import_param)
{
	KeymgmtErrCodeT err = KEYMGMT_ERR_INVALID_PARAM;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

	if(key_import_param == NULL)
	{
		return err;
	}

	switch(key_import_param->key_type)
	{
		case HSE_KEY_TYPE_AES:
		{
			if(key_import_param->key_flag == 0xFFFF)
				key_import_param->key_flag  = 0;
			/* Import Key to Key Slot */
			srvResponse = HSE_ImportSymKey(keyhandle,
				key_import_param->key_type,
				(HSE_KF_USAGE_ENCRYPT|HSE_KF_USAGE_DECRYPT|HSE_KF_USAGE_SIGN|HSE_KF_USAGE_VERIFY|((key_import_param->key_flag))),
				//(HSE_KF_USAGE_ENCRYPT|HSE_KF_USAGE_DECRYPT),
				key_import_param->key_param.sym_key_param.key,
				BITS_TO_BYTES(key_import_param->key_param.sym_key_param.size));
			break;
		}
#if !defined(S32N55)
		case HSE_KEY_TYPE_SHE:
		{
			/* Import Key to Key Slot */
			srvResponse = HSE_ImportSymKey(keyhandle,
				key_import_param->key_type,
				(HSE_KF_USAGE_ENCRYPT|HSE_KF_USAGE_DECRYPT|HSE_KF_USAGE_SIGN|HSE_KF_USAGE_VERIFY),
				key_import_param->key_param.sym_key_param.key,
				BITS_TO_BYTES(key_import_param->key_param.sym_key_param.size));
			break;
		}
#endif
		case HSE_KEY_TYPE_HMAC:
		{
			/* Import Key to Key Slot */
			srvResponse = HSE_ImportSymKey(keyhandle,
				key_import_param->key_type,
				(HSE_KF_USAGE_SIGN|HSE_KF_USAGE_VERIFY),
				key_import_param->key_param.sym_key_param.key,
				BITS_TO_BYTES(key_import_param->key_param.sym_key_param.size));
			break;
		}
		case HSE_KEY_TYPE_SHARED_SECRET:
		{
			/* Import Key to Key Slot */
			srvResponse = HSE_ImportSymKey(keyhandle,
				key_import_param->key_type,
				(HSE_KF_USAGE_SIGN|HSE_KF_USAGE_VERIFY|HSE_KF_USAGE_EXCHANGE),
				key_import_param->key_param.sym_key_param.key,
				BITS_TO_BYTES(key_import_param->key_param.sym_key_param.size));

			break;
		}
		case HSE_KEY_TYPE_RSA_PUB:
		{
			/* Import Key to Key Slot */
			srvResponse = HSE_ImportRsaKey(keyhandle,
				key_import_param->key_type,
				(HSE_KF_USAGE_ENCRYPT|HSE_KF_USAGE_VERIFY | key_import_param->key_flag ),
				key_import_param->key_param.rsa_pubkey_param.N,
				BITS_TO_BYTES(key_import_param->key_param.rsa_pubkey_param.size_N),
				key_import_param->key_param.rsa_pubkey_param.E,
				key_import_param->key_param.rsa_pubkey_param.size_E,
				NULL);
			break;
		}
		case HSE_KEY_TYPE_RSA_PAIR:
		{
			/* Import Key to Key Slot */
			srvResponse = HSE_ImportRsaKey(keyhandle,
				key_import_param->key_type,
				(HSE_KF_USAGE_ENCRYPT|HSE_KF_USAGE_DECRYPT|HSE_KF_USAGE_SIGN|HSE_KF_USAGE_VERIFY
						| HSE_KF_ACCESS_EXPORTABLE  | key_import_param->key_flag),
				key_import_param->key_param.rsa_keypair_param.N,
				(uint16_t)BITS_TO_BYTES(key_import_param->key_param.rsa_keypair_param.N_len),
				key_import_param->key_param.rsa_keypair_param.E,
				(uint16_t)key_import_param->key_param.rsa_keypair_param.E_len,
				key_import_param->key_param.rsa_keypair_param.D);
			break;
		}
		case HSE_KEY_TYPE_ECC_PUB:
		{
			hseKeyFlags_t keyFlags = 0U;
			if((key_import_param->key_param.ecc_pubkey_param.eccCurveId == HSE_EC_25519_CURVE25519)
#ifdef HSE_SPT_EC_448_CURVE448
					||(key_import_param->key_param.ecc_pubkey_param.eccCurveId == HSE_EC_448_CURVE448)
#endif /* HSE_SPT_EC_448_CURVE448 */
			)
			{
				keyFlags = (HSE_KF_USAGE_EXCHANGE | HSE_KF_ACCESS_EXPORTABLE);
			}
			else
			{
				keyFlags = (HSE_KF_USAGE_VERIFY | HSE_KF_USAGE_EXCHANGE | HSE_KF_ACCESS_EXPORTABLE);
			}
			/* Import Key to Key Slot */
			srvResponse = HSE_ImportEccKey(keyhandle,
							key_import_param->key_type,
							keyFlags,
							key_import_param->key_param.ecc_pubkey_param.size_Q,
							key_import_param->key_param.ecc_pubkey_param.eccCurveId,
							key_import_param->key_param.ecc_pubkey_param.Q,
							NULL);
			break;
		}
		case HSE_KEY_TYPE_ECC_PAIR:
		{
			hseKeyFlags_t keyFlags = 0U;
			if((key_import_param->key_param.ecc_keypair_param.eccCurveId == HSE_EC_25519_CURVE25519)
#ifdef HSE_SPT_EC_448_CURVE448
					||(key_import_param->key_param.ecc_keypair_param.eccCurveId == HSE_EC_448_CURVE448)
#endif /* HSE_SPT_EC_448_CURVE448 */
					)
			{
				keyFlags = (HSE_KF_USAGE_EXCHANGE | HSE_KF_ACCESS_EXPORTABLE);
			}
			else
			{
				keyFlags = (HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY | HSE_KF_USAGE_EXCHANGE
						 | HSE_KF_ACCESS_EXPORTABLE);
			}
			/* Import Key to Key Slot */
			srvResponse = HSE_ImportEccKey(keyhandle,
							key_import_param->key_type,
							keyFlags,
							key_import_param->key_param.ecc_keypair_param.size_Q,
							key_import_param->key_param.ecc_keypair_param.eccCurveId,
							key_import_param->key_param.ecc_keypair_param.Q,
							key_import_param->key_param.ecc_keypair_param.D);
			break;
		}
#if defined (HSE_SPT_CLASSIC_DH)
		case HSE_KEY_TYPE_DH_PUB:
		{
			/* Import DH Public Key to Key Slot */
			srvResponse = HSE_ImportDhKey(keyhandle,
										key_import_param->key_type,
										(key_import_param->key_flag | HSE_KF_USAGE_EXCHANGE | HSE_KF_ACCESS_EXPORTABLE),
										key_import_param->key_param.dh_public_param.modulusLength,
										key_import_param->key_param.dh_public_param.pModulus,
										key_import_param->key_param.dh_public_param.pPubKey,
										NULL,
										0U);

			break;
		}
		case HSE_KEY_TYPE_DH_PAIR:
		{
			/* Import DH Key pair to Key Slot */
			srvResponse = HSE_ImportDhKey(keyhandle,
										key_import_param->key_type,
										(key_import_param->key_flag | HSE_KF_USAGE_EXCHANGE | HSE_KF_ACCESS_EXPORTABLE),
										key_import_param->key_param.dh_keypair_param.modulusLength,
										key_import_param->key_param.dh_keypair_param.pModulus,
										key_import_param->key_param.dh_keypair_param.pPubKey,
										key_import_param->key_param.dh_keypair_param.pPrvKey,
										key_import_param->key_param.dh_keypair_param.prvLen);
			break;
		}
#endif /* HSE_SPT_CLASSIC_DH */
	}
	if(srvResponse == HSE_SRV_RSP_OK)
	{
		err = KEYMGMT_ERR_SUCCESS;
	}
	else
	{
		err = KEYMGMT_ERR_KEY_IMPORT_FAILED;
	}

	return err;
}

/*************************************************************************************************
* Description: Generates the key as per the key type
************************************************************************************************/
KeymgmtErrCodeT KeystoreMgmt_Genkey(hseKeyHandle_t keyhandle, key_gen_param_t *key_gen_param )
{
	KeymgmtErrCodeT err = KEYMGMT_ERR_SUCCESS;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;
	hseKeyInfo_t keyInfo;
	uint8_t hsekeystatus;
	hseKeyInfo_t reqKeyInfo;

	if(gKeymgt_ctx.keystore_init == FALSE)
	{
		return KEYMGMT_ERR_KEYSTORE_NOT_INITIALIZED;
	}

	if((keyhandle == HSE_INVALID_KEY_HANDLE) || 	\
		(keyhandle == (hseKeyHandle_t)0U) ||		\
		(key_gen_param == NULL))
	{
		return KEYMGMT_ERR_INVALID_PARAM;
	}

	/* Check current HSE KeyInfo, to be used for restoration of Keystore state later */
	srvResponse = HSE_GetKeyInfo(keyhandle, &reqKeyInfo);
	if(srvResponse == HSE_SRV_RSP_KEY_EMPTY)
	{
		hsekeystatus = KEYSLOT_AVAILABLE;
	}
	else if(srvResponse == HSE_SRV_RSP_OK)
	{
		hsekeystatus = KEYSLOT_ALLOCATED;
	}
	else
	{
		/* We have received an invalid handle */
		return KEYMGMT_ERR_INVALID_PARAM;
	}

	/* Initialize KeyInfo Data structure */
	memset(&keyInfo, 0, sizeof(keyInfo));

	switch( key_gen_param->key_type )
	{
		case HSE_KEY_TYPE_RSA_PAIR:
		{
			static uint32_t RsaGenKeyCallbackParam = 0U;
			keyInfo.keyType = HSE_KEY_TYPE_RSA_PAIR;
			keyInfo.keyFlags = (								\
				HSE_KF_USAGE_ENCRYPT | HSE_KF_USAGE_DECRYPT | 	\
				HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY | HSE_KF_ACCESS_EXPORTABLE);
			keyInfo.keyBitLen = key_gen_param->key_param.rsa_keypair_gen_param.keybitlen;
			keyInfo.specific.pubExponentSize = key_gen_param->key_param.rsa_keypair_gen_param.eLen;
			keyInfo.keyCounter = 1U;
			srvResponse = HSE_GenerateRsaKey(keyhandle,
				keyInfo, keyInfo.specific.pubExponentSize,
				(uint8_t*)key_gen_param->key_param.rsa_keypair_gen_param.pE,
				key_gen_param->key_param.rsa_keypair_gen_param.pN,
				RsaGenKeyCallback,(void*)&RsaGenKeyCallbackParam);

			/* Process the requests sent using asynchronous poll method */
//			do
//			{
//				/* Call Hse_Ip_MainFunction in case of Asynchronous Polling mode */
//				Hse_Ip_MainFunction(APP_MU_INSTANCE_U8);
//				if(0U != RsaGenKeyAsyncPoll_response)
//				{
//					/* Return the HSE response */
//					srvResponse = RsaGenKeyAsyncPoll_response;
//					/* Reset RsaGenKeyAsyncPoll_response */
//					RsaGenKeyAsyncPoll_response = 0U;
//					break;
//				}
//			}while(TRUE);

			break;
		}
		case HSE_KEY_TYPE_ECC_PAIR:
		{
			keyInfo.keyType = HSE_KEY_TYPE_ECC_PAIR;

			if((key_gen_param->key_param.ecc_keypair_gen_param.eccCurveId == HSE_EC_25519_CURVE25519)
#ifdef HSE_SPT_EC_448_CURVE448
					||(key_gen_param->key_param.ecc_keypair_gen_param.eccCurveId == HSE_EC_448_CURVE448)
#endif /* HSE_SPT_EC_448_CURVE448 */
					)
			{
				keyInfo.keyFlags = (HSE_KF_USAGE_EXCHANGE | HSE_KF_ACCESS_EXPORTABLE);
			}
			else
			{
				keyInfo.keyFlags = (HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY | HSE_KF_USAGE_EXCHANGE
													| HSE_KF_ACCESS_EXPORTABLE);
			}
			keyInfo.keyBitLen = key_gen_param->key_param.ecc_keypair_gen_param.keybitlen;
			keyInfo.specific.eccCurveId = key_gen_param->key_param.ecc_keypair_gen_param.eccCurveId;
			keyInfo.keyCounter = 1U;

			srvResponse = HSE_GenerateEccKey(keyhandle,
				keyInfo, key_gen_param->key_param.ecc_keypair_gen_param.pN);
			break;
		}
		case HSE_KEY_TYPE_AES:
#if !defined(S32N55)
		case HSE_KEY_TYPE_SHE:
#endif
		case HSE_KEY_TYPE_HMAC:
		{
			keyInfo.keyType = key_gen_param->key_type;
			keyInfo.keyBitLen = key_gen_param->key_param.sym_key_gen_param.keybitlen;
			keyInfo.keyFlags = (								\
				HSE_KF_USAGE_ENCRYPT | HSE_KF_USAGE_DECRYPT | 	\
				HSE_KF_USAGE_SIGN | HSE_KF_USAGE_VERIFY);
			srvResponse = HSE_GenerateSymKey(keyhandle,keyInfo);
			break;
		}
#ifdef HSE_SPT_TLS12_RSA_PRE_MASTER_SECRET_GEN
		case HSE_KEY_TYPE_SHARED_SECRET:
		{
			keyInfo.keyType		= key_gen_param->key_type;
			keyInfo.keyFlags	= ( HSE_KF_USAGE_DERIVE | HSE_KF_ACCESS_EXPORTABLE );
			keyInfo.keyBitLen	= key_gen_param->key_param.shared_sec_gen_param.keybitlen;

			if(key_gen_param->key_param.shared_sec_gen_param.shared_sec_type ==
					KEYMGMT_SHARED_SEC_KEY_GEN_TYPE_RSA_PMS)
			{
				srvResponse = HSE_GenSharedSecret(keyhandle,
								key_gen_param->key_param.shared_sec_gen_param.pms_param.rsa_pms_gen_param.protocolVersion,
								keyInfo);
			}

			break;
		}
#endif /* HSE_SPT_TLS12_RSA_PRE_MASTER_SECRET_GEN */

#ifdef HSE_SPT_CLASSIC_DH_KEY_PAIR_GEN
		case HSE_KEY_TYPE_DH_PAIR:
		{
			keyInfo.keyType = key_gen_param->key_type;
			keyInfo.keyFlags = (HSE_KF_USAGE_EXCHANGE | HSE_KF_ACCESS_EXPORTABLE | key_gen_param->key_flag);
			keyInfo.keyBitLen = BYTES_TO_BITS(key_gen_param->key_param.dh_keypair_gen_param.modulusLength);
			srvResponse = HSE_GenerateDhKeyPair(keyhandle,
											keyInfo,
											key_gen_param->key_param.dh_keypair_gen_param.pBaseG,
											key_gen_param->key_param.dh_keypair_gen_param.baseGLength,
											key_gen_param->key_param.dh_keypair_gen_param.pModulus,
											key_gen_param->key_param.dh_keypair_gen_param.modulusLength,
											key_gen_param->key_param.dh_keypair_gen_param.pPubKey
											);
			break;
		}
#endif /*HSE_SPT_CLASSIC_DH_KEY_PAIR_GEN*/
	}

	if(srvResponse == HSE_SRV_RSP_OK)
	{
		/* Mark the slot as in use */
		MarkKeySlotInUse(keyhandle);
	}
	else
	{
		MarkKeySlot(hsekeystatus, keyhandle);
		err = KEYMGMT_ERR_KEY_GEN_FAILED;
	}

	return err;
}

/*************************************************************************************************
* Description: Free NVM key from NVM keyslot
************************************************************************************************/
KeymgmtErrCodeT KeyStoreMgmt_EraseNvmKey(hseKeyHandle_t handle)
{
	KeymgmtErrCodeT err = KEYMGMT_ERR_SUCCESS;
	hseKeyInfo_t reqKeyInfo;
	hseSrvResponse_t srvResponse;
	uint32_t keyslot_status;
	uint32_t need_erase = (uint32_t)FALSE;

	if(gKeymgt_ctx.keystore_init == FALSE)
	{
		return KEYMGMT_ERR_KEYSTORE_NOT_INITIALIZED;
	}

	/* Check for invalid key handle  */
	if ( HSE_INVALID_KEY_HANDLE == handle )
	{
		return KEYMGMT_ERR_INVALID_PARAM;
	}

	do
	{
		/* Check if Key Handle belongs to NVM Key Catalog */
		if ( HSE_KEY_CATALOG_ID_NVM != GET_CATALOG_ID(handle))
		{
			err = KEYMGMT_ERR_INVALID_PARAM;
			break;
		}

		/* Get Key Info from HSE Firmware */
		srvResponse = HSE_GetKeyInfo(handle, &reqKeyInfo);
		if (HSE_SRV_RSP_INVALID_PARAM == srvResponse)
		{
			err = KEYMGMT_ERR_INVALID_PARAM;
			break;
		}

		if ((HSE_SRV_RSP_KEY_EMPTY != srvResponse) && \
			(HSE_SRV_RSP_OK != srvResponse))
		{
			err = KEYMGMT_ERR_INVALID_PARAM;
			break;
		}

		/* Get Key Slot Status */
		keyslot_status = GetKeySlotStatus(handle);

		if (KEYSLOT_NOT_AVAIL == keyslot_status)
		{
			/* We should not erase the key not mapped to MU */
			err = KEYMGMT_ERR_INVALID_PARAM;
			break;
		}

		if (KEYSLOT_ALLOCATED == keyslot_status)
		{
			if(HSE_SRV_RSP_OK == srvResponse)
			{
				/* Key is allocated and also loaded
					This should not be the case.
				*/
				need_erase = TRUE;//key can be loaded using HSE_DAL API's

			}
			else /* HSE_SRV_RSP_EMPTY */
			{
				/* This is the case where key is allocated to be used in future */
				err = KEYMGMT_ERR_KEY_IN_USE;
				break;
			}
		}

		if(KEYSLOT_LOADED == keyslot_status)
		{
			if(HSE_SRV_RSP_OK == srvResponse)
			{
				need_erase = TRUE;
			}
			else /* HSE_SRV_RSP_EMPTY */
			{
				MarkKeySlotAvailable(handle);
				err = KEYMGMT_ERR_SUCCESS;
				break;
			}
		}

		if(KEYSLOT_INUSE == keyslot_status)
		{
			if(HSE_SRV_RSP_OK == srvResponse)
			{
				need_erase = TRUE;
			}
			else /* HSE_SRV_RSP_EMPTY */
			{
				/* Ideally this should not be the case where key slot is in use and also empty */
				MarkKeySlotAvailable(handle);
				err = KEYMGMT_ERR_SUCCESS;
				break;
			}
		}
		if(KEYSLOT_AVAILABLE == keyslot_status)
		{
			if(HSE_SRV_RSP_OK == srvResponse)
			{
				need_erase = TRUE;
			}
			else /* HSE_SRV_RSP_EMPTY */
			{
				err = KEYMGMT_ERR_SUCCESS;
				break;
			}
		}

		if ((uint32_t)TRUE == need_erase)
		{
			const hseKeyGroupIdx_t grpIdx = GET_GROUP_IDX(handle);
#if defined(S32N55)
			const hseStdKeyGroupCfgEntry_t *pKeygrp = &gKeymgt_ctx.nvm_key_catalog[grpIdx];
#else
			const hseKeyGroupCfgEntry_t *pKeygrp = &gKeymgt_ctx.nvm_key_catalog[grpIdx];
#endif

			/* Check for Key Write Protect */
			if(0U != (reqKeyInfo.keyFlags & HSE_KF_ACCESS_WRITE_PROT))
			{
				return KEYMGMT_ERR_KEY_WRITE_PROTECTED;
			}

			/* Check ownership rights before key erase */
			if (IsKeyGroupAccess(pKeygrp) == (uint8_t)FALSE)
			{
				err = KEYMGMT_ERR_INSUFFICIENT_PERM;
				break;
			}

			/* Owner ship rights validated, Now Erase the key */
			srvResponse = HSE_EraseKey(handle, HSE_ERASE_NOT_USED) ;
			if(HSE_SRV_RSP_OK != srvResponse)
			{
				/* Fail :Return with Error Codes */
				err = KEYMGMT_ERR_KEY_ERASE_FAIL ;
				break;
			}

			/* Mark the Key Slot as Available */
			MarkKeySlotAvailable(handle);
			err = KEYMGMT_ERR_SUCCESS;
		}
	}while(0);

	return err;
}

/*************************************************************************************************
* Description: Free all NVM keys from NVM keyslot
************************************************************************************************/
KeymgmtErrCodeT KeyStoreMgmt_EraseNvmKeyStore(void)
{
	hseSrvResponse_t srvResponse;
	KeymgmtErrCodeT err = KEYMGMT_ERR_SUCCESS;

	if(gKeymgt_ctx.keystore_init == FALSE)
	{
		return KEYMGMT_ERR_KEYSTORE_NOT_INITIALIZED;
	}

	if(TRUE == HSE_IsUser())
	{
		return KEYMGMT_ERR_INSUFFICIENT_PERM;
	}

	srvResponse = HSE_EraseKey(HSE_INVALID_KEY_HANDLE, HSE_ERASE_ALL_NVM_KEYS_ON_MU_IF) ;
	if(HSE_SRV_RSP_OK != srvResponse)
	{
		/* Fail :Return with Error Codes */
		err = KEYMGMT_ERR_KEY_ERASE_FAIL ;
	}
	else
	{
		/* Once KeyStore is erased, Parse the catalog */
		ParseKeyCatalog();
		err = KEYMGMT_ERR_SUCCESS;
	}

	return (err);
}

/*************************************************************************************************
* Description: Free all RAM keys from NVM keyslot
************************************************************************************************/
KeymgmtErrCodeT KeyStoreMgmt_EraseRamKeyStore(void)
{
	hseSrvResponse_t srvResponse;
	KeymgmtErrCodeT err = KEYMGMT_ERR_SUCCESS;

	if(gKeymgt_ctx.keystore_init == FALSE)
	{
		return KEYMGMT_ERR_KEYSTORE_NOT_INITIALIZED;
	}

	if(TRUE == HSE_IsUser())
	{
		return KEYMGMT_ERR_INSUFFICIENT_PERM;
	}

	srvResponse = HSE_EraseKey(HSE_INVALID_KEY_HANDLE, HSE_ERASE_ALL_RAM_KEYS_ON_MU_IF) ;
	if(HSE_SRV_RSP_OK != srvResponse)
	{
		/* Fail :Return with Error Codes */
		err = KEYMGMT_ERR_KEY_ERASE_FAIL ;
	}
	else
	{
		/* Once KeyStore is erased, Parse the catalog */
		ParseKeyCatalog();
		err = KEYMGMT_ERR_SUCCESS;
	}

	return (err);
}

/*************************************************************************************************
* Description: Checks if the key type allocated to the input keyhandle is valid
************************************************************************************************/
KeymgmtErrCodeT KeyStoreMgmt_CheckKey(const hseKeyHandle_t keyhandle)
{
	hseKeyGroupIdx_t keygrp;
	hseKeySlotIdx_t keyslotidx;
#if defined(S32N55)
	const hseStdKeyGroupCfgEntry_t *pkeygrpcfg = NULL;

#else
	const hseKeyGroupCfgEntry_t *pkeygrpcfg = NULL;
#endif
	const keygrp_status_t *pkeygrpsts;

	/* Check if KeyStore is initialized or not */
	if (gKeymgt_ctx.keystore_init == FALSE)
	{
		return KEYMGMT_ERR_KEYSTORE_NOT_INITIALIZED;
	}

	switch(GET_CATALOG_ID(keyhandle))
	{
		case HSE_KEY_CATALOG_ID_RAM:
			pkeygrpcfg = gKeymgt_ctx.ram_key_catalog;
			pkeygrpsts = &gKeymgt_ctx.key_status.ram_keygrpstatus;
			break;
		case HSE_KEY_CATALOG_ID_NVM:
			pkeygrpcfg = gKeymgt_ctx.nvm_key_catalog;
			pkeygrpsts = &gKeymgt_ctx.key_status.nvm_keygrpstatus;
			break;
		default:
			return KEYMGMT_ERR_INVALID_PARAM;
	}

	/* Check for Key Group Index */
	keygrp = GET_GROUP_IDX(keyhandle);
	if (pkeygrpsts->numkeygrps <= keygrp )
	{
		return KEYMGMT_ERR_INVALID_PARAM;
	}

	/* Check for Key Slot index */
	keyslotidx = GET_SLOT_IDX(keyhandle);
	if (pkeygrpcfg[keygrp].numOfKeySlots <= keyslotidx )
	{
		return KEYMGMT_ERR_INVALID_PARAM;
	}

	return KEYMGMT_ERR_SUCCESS;
}

/*************************************************************************************************
* Description: Returns the key type allocated to the input keyhandle
************************************************************************************************/
hseKeyType_t KeystoreMgmt_GetKeyType(const hseKeyHandle_t keyhandle)
{
	hseKeyType_t keytype = (hseKeyType_t)0U;
	hseKeyGroupIdx_t keygrp;
	hseKeySlotIdx_t keyslotidx;
#if defined(S32N55)
	const hseStdKeyGroupCfgEntry_t *pkeygrpcfg;
#else
	const hseKeyGroupCfgEntry_t *pkeygrpcfg;
#endif
	const keygrp_status_t *pkeygrpsts;

	do
	{
		/* Check if KeyStore is initialized or not */
		if (gKeymgt_ctx.keystore_init == FALSE)
		{
			break;
		}

		switch(GET_CATALOG_ID(keyhandle))
		{
			case HSE_KEY_CATALOG_ID_RAM:
				pkeygrpcfg = gKeymgt_ctx.ram_key_catalog;
				pkeygrpsts = &gKeymgt_ctx.key_status.ram_keygrpstatus;
				break;
			case HSE_KEY_CATALOG_ID_NVM:
				pkeygrpcfg = gKeymgt_ctx.nvm_key_catalog;
				pkeygrpsts = &gKeymgt_ctx.key_status.nvm_keygrpstatus;
				break;
			default:
				return keytype;
		}

		/* Check for Key Group Index */
		keygrp = GET_GROUP_IDX(keyhandle);
		if (pkeygrpsts->numkeygrps <= keygrp )
		{
			break;
		}

		/* Check for Key Slot index */
		keyslotidx = GET_SLOT_IDX(keyhandle);
		if (pkeygrpcfg[keygrp].numOfKeySlots <= keyslotidx )
		{
			break;
		}

		/* Return Key Type */
		keytype = pkeygrpcfg[keygrp].keyType;
	}while(0);

	return keytype;
}

/*************************************************************************************************
* Description: Returns the user defined curve ID
************************************************************************************************/
hseEccCurveId_t KeystoreMgmt_UserECCGroupGetHandle(load_ecc_group_param_t *EccUserCurve)
{
	/* Assign Curve ID based on EccCurveId from load_ecc_group_param_t */
	switch(EccUserCurve->EccCurveId)
	{
		case SECP192R1 :
		case SECP224R1 :
		case SECP192K1 :
		case SECP224K1 :
		case SECP256K1 :
			EccUserCurve->hseEccCurveId = HSE_EC_USER_CURVE1;
			break;
		default:
			return INVALID_GRP_HANDLE ;
	}
	return EccUserCurve->hseEccCurveId;
}

/*************************************************************************************************
* Description: Load the user defined curve on HSE
************************************************************************************************/
KeymgmtErrCodeT KeystoreMgmt_UserECCGroupAllocate(load_ecc_group_param_t group_param)
{
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;

	/* Send the command to load ECC Curve to HSE */
	srvResponse = Hse_LoadEccUserCurve
				(group_param.ecc_load_user_curve_param.eccCurveId,\
				 group_param.ecc_load_user_curve_param.pBitLen,\
				 group_param.ecc_load_user_curve_param.nBitLen,\
				 group_param.ecc_load_user_curve_param.pA, \
				 group_param.ecc_load_user_curve_param.pB, \
				 group_param.ecc_load_user_curve_param.pP, \
				 group_param.ecc_load_user_curve_param.pN,	\
				 group_param.ecc_load_user_curve_param.pG);

	/* Check the response */
	if(HSE_SRV_RSP_OK != srvResponse)
	{
		return KEYMGMT_ERR_INVALID_PARAM;
	}
	else
	{
		return KEYMGMT_ERR_SUCCESS;
	}
}
