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

#if defined(MBEDTLS_DHM_ALT) && defined(MBEDTLS_USE_NXP_HSE_CRYPTO)

#include "nxp_hse_dhm.h"
#include "cert_table.h"

/*==================================================================================================
*                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL MACROS
==================================================================================================*/

#define NXP_HSE_DH_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_DHM_BAD_INPUT_DATA )

/*==================================================================================================
*                                      LOCAL CONSTANTS
==================================================================================================*/

/*==================================================================================================
*                                      LOCAL VARIABLES
==================================================================================================*/

/*==================================================================================================
*                                      GLOBAL CONSTANTS
==================================================================================================*/

/*==================================================================================================
*                                      GLOBAL VARIABLES
==================================================================================================*/

/*==================================================================================================
*                                   LOCAL FUNCTION PROTOTYPES
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL FUNCTIONS
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL FUNCTIONS
==================================================================================================*/

/*==================================================================================================
*                                       GLOBAL FUNCTIONS
==================================================================================================*/
/*************************************************************************************************
 * Description: This function loads DH key-pair
************************************************************************************************/
int nxp_dhm_loadkey( mbedtls_dhm_context *ctx, hseKeyHandle_t *pubKeyHandle, hseKeyHandle_t *privKeyHandle)
{
    int ret = 0;
	uint8_t *pPrv = NULL, *pMod = NULL, *pPub = NULL;
	uint32_t size_Prv = 0U, size_Mod = 0U, size_Pub = 0U;
    uint32_t size_PeerPub = 0U;
    uint8_t *pPeerPub = NULL;

    key_import_param_t key_import_param_private;
    key_import_param_t key_import_param_public;
    KeymgmtErrCodeT err;

    memset(&key_import_param_private, 0x00, sizeof(key_import_param_t));
    memset(&key_import_param_public, 0x00, sizeof(key_import_param_t));

    /* get the size of Prime modulus */
	size_Mod = ctx->len;

	if(size_Mod != 0)
	{
		/* Get Modulus */
		pMod = mbedtls_calloc(1, size_Mod);
		if( NULL == pMod )
		{
			/* Unable to allocate memory */
			ret = MBEDTLS_ERR_DHM_ALLOC_FAILED;
			goto cleanup;
		}

		ret = mbedtls_mpi_write_binary(&ctx->P, pMod, size_Mod);
		if( ret != NO_ERROR )
		{
			/* Unable to get key pair handle */
			ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
			goto cleanup;
		}
	}
	else
	{
		/* Unable to get key pair handle */
		ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
		goto cleanup;
	}

	/* Check if X contains key handle or key */
	if(mbedtls_mpi_size(&ctx->X) > sizeof(hseKeyHandle_t))
	{
		/* X contains Private key */

	    /* Get the DHM key pair key slot*/
		key_import_param_private.key_type 							= HSE_KEY_TYPE_DH_PAIR;
		key_import_param_private.key_catalog 						= HSE_KEY_CATALOG_ID_RAM;
		key_import_param_private.key_param.dh_keypair_param.pubLen	= (ctx->len * 8);
		if(KEYMGMT_ERR_SUCCESS != KeystoreMgmt_FindAllocateSlot(&key_import_param_private, privKeyHandle))
		{
			/* Unable to get key pair handle */
			ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
			goto cleanup;
		}

		/* Private key and its len */
		size_Prv = mbedtls_mpi_size( &ctx->X  );
		if(size_Prv != 0)
		{
			pPrv = mbedtls_calloc(1, size_Prv);
			if( NULL == pPrv)
			{
				/* Unable to allocate memory */
				ret = MBEDTLS_ERR_DHM_ALLOC_FAILED;
				goto cleanup;
			}

			ret = mbedtls_mpi_write_binary(&ctx->X, pPrv, size_Prv);
			if( ret != NO_ERROR )
			{
				/* Unable to get key pair handle */
				ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
				goto cleanup;
			}
		}
		else
		{
			/* Unable to get key pair handle */
			ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
			goto cleanup;
		}

		if(size_Mod != 0)
		{
			/* allocate buffer for public key */
			pPub = mbedtls_calloc(1, size_Mod);
			if( NULL == pPub)
			{
				/* Unable to allocate memory */
				ret = MBEDTLS_ERR_DHM_ALLOC_FAILED;
				goto cleanup;
			}

			ret =  mbedtls_mpi_write_binary(&ctx->GX, pPub, size_Mod);
			if( ret != NO_ERROR )
			{
				/* Unable to get key pair handle */
				ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
				goto cleanup;
			}
		}
		else
		{
			/* Unable to get key pair handle */
			ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
			goto cleanup;
		}

		/* Load own public and private key */
		key_import_param_private.key_catalog								= HSE_KEY_CATALOG_ID_RAM;
		key_import_param_private.key_type									= HSE_KEY_TYPE_DH_PAIR;
		key_import_param_private.key_param.dh_keypair_param.modulusLength	= size_Mod;
		key_import_param_private.key_param.dh_keypair_param.pModulus		= pMod;
		key_import_param_private.key_param.dh_keypair_param.pubLen			= size_Mod*8;
		key_import_param_private.key_param.dh_keypair_param.pPubKey			= pPub;
		key_import_param_private.key_param.dh_keypair_param.prvLen			= size_Prv;
		key_import_param_private.key_param.dh_keypair_param.pPrvKey			= pPrv;

		ret = KeystoreMgmt_FindImportSlot(&key_import_param_private, privKeyHandle);

		/* Immediately Zeroize Private Key irrespective of outcome. Will free memory later */
		mbedtls_platform_zeroize(pPrv, size_Prv);

		if(ret != KEYMGMT_ERR_SUCCESS)
		{
			ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
			goto cleanup;
		}
	}
	else
	{
		/* X contains Private key handle */
        /* Copy Private key handle*/
        (void)memcpy((char*)privKeyHandle, ctx->X.p, sizeof(hseKeyHandle_t));
	}

	/* Import peer public key and get key handle */
	size_PeerPub = mbedtls_mpi_size( &ctx->GY  );
	if(size_PeerPub != 0)
	{
		pPeerPub = mbedtls_calloc(1, size_PeerPub);
		if( NULL == pPeerPub)
		{
			/* Unable to allocate memory */
			ret = MBEDTLS_ERR_DHM_ALLOC_FAILED;
			goto cleanup;
		}

		ret = mbedtls_mpi_write_binary(&ctx->GY, pPeerPub, size_PeerPub);
		if( ret != NO_ERROR )
		{
			/* Unable to get key pair handle */
			ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
			goto cleanup;
		}
	}
	else
	{
		/* Unable to get key pair handle */
		ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
		goto cleanup;
	}

	key_import_param_public.key_type 								= HSE_KEY_TYPE_DH_PUB;
	key_import_param_public.key_catalog 							= HSE_KEY_CATALOG_ID_RAM;
	key_import_param_public.key_param.dh_public_param.pPubKey 		= pPeerPub;
	key_import_param_public.key_param.dh_public_param.pubLen 		= BYTES_TO_BITS(size_PeerPub);
	key_import_param_public.key_param.dh_public_param.pModulus		= pMod;
	key_import_param_public.key_param.dh_public_param.modulusLength	= size_Mod;

	err = KeystoreMgmt_FindImportSlot(&key_import_param_public, pubKeyHandle);
	if(err != KEYMGMT_ERR_SUCCESS)
	{
		ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
	}

cleanup:

	if(pPub != NULL)
	{
		mbedtls_platform_zeroize(pPub, size_Pub);
		mbedtls_free(pPub);
		pPub = NULL;
	}

	if(pPrv != NULL)
	{
		mbedtls_free(pPrv);
		pPrv = NULL;
	}

	if(pPeerPub != NULL)
	{
		mbedtls_platform_zeroize(pPeerPub, size_PeerPub);
		mbedtls_free(pPeerPub);
		pPeerPub = NULL;
	}

	return ( ret );
}

/*************************************************************************************************
 * Description: Unload DH RAM key
************************************************************************************************/
void nxp_hse_dhm_unloadkey( hseKeyHandle_t KeyHandle )
{
	if(KeyHandle == HSE_INVALID_KEY_HANDLE)
	{
		return;
	}
	else
	{
		(void)KeyStoreMgmt_FreeKey(KeyHandle);
	}
}

#endif /* MBEDTLS_DHM_ALT && MBEDTLS_USE_NXP_HSE_CRYPTO */
