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

#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT) && defined(MBEDTLS_USE_NXP_HSE_CRYPTO)
#include <string.h>
#include "global_variables.h"
#include "hse_host_km_utils.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/platform.h"
#include "hse_host_km_export_key.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "nxp_hse_pk_rsa_alt.h"
#include "mbedtls/x509_crt.h"
#include "keystore_mgmt.h"

/*==================================================================================================
*                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL MACROS
==================================================================================================*/

/* Parameter validation macros. */
#define PK_RSA_ALT_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_RSA_BAD_INPUT_DATA )

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
*                                       GLOBAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
* Description:  This function loads RSA key-pair, returns public/private key-handle in PK ctx
************************************************************************************************/
int nxp_hse_rsa_load_pkey(mbedtls_pk_context *pk, int mode)
{
	int ret = NO_ERROR;
	KeymgmtErrCodeT err;
	uint32_t size_N, size_E, size_D;
	unsigned char *N = NULL, *E = NULL, *D = NULL;
	key_import_param_t key_import_param;

    /* Get the RSA context from PK Private context */
    mbedtls_rsa_context *prsa_prv_ctx = mbedtls_pk_rsa(*pk);

	/* Check for key already loaded */
	if(prsa_prv_ctx->keyHandle != HSE_INVALID_KEY_HANDLE)
	{
		return( ret );
	}

	memset(&key_import_param, 0x00, sizeof(key_import_param_t));

	do
	{
		/* Allocate Memory Buffer for N & E */
		size_N = mbedtls_mpi_size(&prsa_prv_ctx->N);

		if(size_N < BITS_TO_BYTES(HSE_KEY1024_BITS))
		{
			return ( MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION );
		}

		size_E = mbedtls_mpi_size(&prsa_prv_ctx->E);

		N = (uint8_t*)mbedtls_calloc( 1, size_N);
		E = (uint8_t*)mbedtls_calloc( 1, size_E);
		if((N == NULL) || (E == NULL))
		{
			/* Return error */
			ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
			break;
		}

		/* Copy mpi structure to binary */
		mbedtls_mpi_write_binary(&prsa_prv_ctx->N, N, size_N);
		mbedtls_mpi_write_binary(&prsa_prv_ctx->E, E, size_E);

		/* Load the key based upon operation */
		if((mode == MBEDTLS_RSA_PUBLIC) && (prsa_prv_ctx->privkey_flag == 0))
		{
			/* Load Public Key */
			key_import_param.key_type = HSE_KEY_TYPE_RSA_PUB;
			key_import_param.key_catalog = HSE_KEY_CATALOG_ID_RAM;
			key_import_param.key_flag = HSE_KF_USAGE_KEY_PROVISION;
			key_import_param.key_param.rsa_pubkey_param.N = N;
			key_import_param.key_param.rsa_pubkey_param.E = E;
			key_import_param.key_param.rsa_pubkey_param.size_N = BYTES_TO_BITS(size_N);
			key_import_param.key_param.rsa_pubkey_param.size_E = size_E;
		}
		else if (prsa_prv_ctx->privkey_flag == 1)
		{
			/* Allocate Memory Buffer for D */
			size_D = mbedtls_mpi_size(&prsa_prv_ctx->D);

			D = (uint8_t*)mbedtls_calloc( 1, size_D);

			if (NULL == D)
			{
				/* Return error */
				ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
				break;
			}

			/* Copy mpi structure to binary */
			mbedtls_mpi_write_binary(&prsa_prv_ctx->D, D, size_D);

			/* Load Public Key */
			key_import_param.key_type = HSE_KEY_TYPE_RSA_PAIR;
			key_import_param.key_catalog = HSE_KEY_CATALOG_ID_NVM;
#if !defined(TEST_SUITE3) && !defined(TEST_SUITE4)
			key_import_param.key_flag = HSE_KF_USAGE_KEY_PROVISION;
#endif
			key_import_param.key_param.rsa_keypair_param.N = N;
			key_import_param.key_param.rsa_keypair_param.E = E;
			key_import_param.key_param.rsa_keypair_param.D = D;
			key_import_param.key_param.rsa_keypair_param.N_len = BYTES_TO_BITS(size_N);
			key_import_param.key_param.rsa_keypair_param.E_len = size_E;
		}
		else
		{
			ret = MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION;
			break;
		}

		err = KeystoreMgmt_FindImportSlot(&key_import_param, &prsa_prv_ctx->keyHandle);
		if(err != KEYMGMT_ERR_SUCCESS)
		{
			ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
			break;
		}
		else
		{
			ret = NO_ERROR;
		}
	} while(0);

	/* Free N, E and D Buffers */
	if (NULL != N)
	{
		mbedtls_platform_zeroize(N, size_N);
		mbedtls_free(N);
		N = NULL;
	}

	if (NULL != E)
	{
		mbedtls_free(E);
		E = NULL;
	}

	if (NULL != D)
	{
		mbedtls_platform_zeroize(D, size_D);
		mbedtls_free(D);
		D = NULL;
	}

	return (ret);
}
/*************************************************************************************************
* Description:  This function configures the RSA context required for PK RSA Alt support
************************************************************************************************/
int nxp_hse_pk_rsa_alt_config( mbedtls_rsa_context *ctx, uint32_t keyHandle)
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	uint8_t *pN = NULL;
	uint8_t *pE = NULL;
	uint32_t eLen = 0U;
	uint32_t nLen = 0U;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;
	hseKeyInfo_t reqKeyInfo = {0};

	/* Simple sanity check */
	PK_RSA_ALT_VALIDATE_RET( ctx != NULL );

	ctx->keyHandle = keyHandle;

	/* Get RSA key pair information */
	srvResponse = HSE_GetKeyInfo(ctx->keyHandle, &reqKeyInfo);
	if((srvResponse == HSE_SRV_RSP_OK) && (reqKeyInfo.keyType == HSE_KEY_TYPE_RSA_PAIR))
	{
		/* Get Public key len */
		ctx->len = BITS_TO_BYTES( reqKeyInfo.keyBitLen );

		/* Set Private key flag */
		ctx->privkey_flag = 1;

		ret = NO_ERROR;
	}
	else
	{
		/* return Error */
		return (MBEDTLS_ERR_PK_KEY_INVALID_FORMAT);
	}

	/* Get len of Public key N and allocate memory */
	nLen = ctx->len;
	pN = mbedtls_calloc(1, nLen);
	if(pN == NULL)
	{
		/* return Error */
		ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
		goto cleanup;
	}

	/* Set len of exponent E and allocate memory */
	eLen = 3U;
	pE = mbedtls_calloc(1, eLen);
	if(pE == NULL)
	{
		/* return Error */
		ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
		goto cleanup;
	}

	/* Check if Key is exportable, If Public key N and Exponent E
	 * are not available then export */
	if((reqKeyInfo.keyFlags & HSE_KF_ACCESS_EXPORTABLE) &&
			(ctx->N.p == NULL ) && (ctx->E.p == NULL ))
	{
		/* Export the Public Key N and Exponent E */
		srvResponse = HSE_ExportKey(ctx->keyHandle, NULL, pN, &nLen, pE, &eLen, NULL, 0);
		if(srvResponse == HSE_SRV_RSP_OK)
		{
			/* Copy Public key N to the RSA context */
			MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ctx->N, pN, nLen ) );

			/* Copy Exponent E to the RSA context */
			MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ctx->E, pE, eLen ) );

			ret = NO_ERROR;
		}
		else
		{
			/* return Error */
			ret = (MBEDTLS_ERR_PK_BAD_INPUT_DATA);
		}
	}

cleanup:

	if(pN != NULL)
	{
		/* Free Memory Buffer */
		mbedtls_free(pN);

		/* Initialize to NULL */
		pN = NULL;
	}

	if(pE != NULL)
	{
		/* Free Memory Buffer */
		mbedtls_free(pE);

		/* Initialize to NULL */
		pE = NULL;
	}

	return (ret);
}

#endif /* MBEDTLS_PK_RSA_ALT_SUPPORT && MBEDTLS_USE_NXP_HSE_CRYPTO */
