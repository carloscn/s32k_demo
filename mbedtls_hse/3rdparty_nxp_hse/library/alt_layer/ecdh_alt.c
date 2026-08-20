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

#include "mbedtls/ecdh.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "keystore_mgmt.h"
#include "nxp_hse_ecc.h"
#include "hse_host_km_gen_key.h"
#include <string.h>

/*==================================================================================================
*                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL MACROS
==================================================================================================*/

/* Parameter validation macros based on platform_util.h */
#define ECDH_ALT_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA )
#define ECDH_ALT_VALIDATE( cond )        \
    MBEDTLS_INTERNAL_VALIDATE( cond )

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
#if defined(MBEDTLS_ECDH_GEN_PUBLIC_ALT)
/*==================================================================================================
*                                       GLOBAL FUNCTIONS
==================================================================================================*/
/*************************************************************************************************
* Description: This function generates an ECDH keypair on an elliptic curve.
************************************************************************************************/
int mbedtls_ecdh_gen_public( mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
	ECDH_ALT_VALIDATE_RET( grp != NULL );
	ECDH_ALT_VALIDATE_RET( d != NULL );
	ECDH_ALT_VALIDATE_RET( Q != NULL );
	ECDH_ALT_VALIDATE_RET( f_rng != NULL );

	return (mbedtls_ecp_gen_keypair(grp, d, Q, f_rng, p_rng));
}

#endif /* MBEDTLS_ECDH_GEN_PUBLIC_ALT */

/*************************************************************************************************
* Description: This function computes the shared secret.
************************************************************************************************/
#if defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
int mbedtls_ecdh_compute_shared( mbedtls_ecp_group *grp, mbedtls_mpi *z,
								 const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
								 int (*f_rng)(void *, unsigned char *, size_t),
								 void *p_rng )
{
	int ret = 0U;
	uint8_t hseEccCurveId = 0U;
	KeymgmtErrCodeT err;
	key_import_param_t key_import_param_shared;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
	hseKeyHandle_t peerKeyhandle = HSE_INVALID_KEY_HANDLE;
	hseKeyHandle_t sharedSecretKeyHandle = HSE_INVALID_KEY_HANDLE;
	hseKeyHandle_t prvKeyhandle = HSE_INVALID_KEY_HANDLE;

	ECDH_ALT_VALIDATE_RET( grp != NULL );
	ECDH_ALT_VALIDATE_RET( Q != NULL );
	ECDH_ALT_VALIDATE_RET( d != NULL );
	ECDH_ALT_VALIDATE_RET( z != NULL );

	memset(&key_import_param_shared, 0x00, sizeof(key_import_param_t));

	/* Check if Private key is valid */
	MBEDTLS_MPI_CHK(mbedtls_ecp_check_privkey(grp, d));

	switch(	grp->id )
	{
		case MBEDTLS_ECP_DP_SECP256R1 :
			hseEccCurveId = HSE_EC_SEC_SECP256R1 ;
			break ;
		case MBEDTLS_ECP_DP_SECP384R1 :
			hseEccCurveId = HSE_EC_SEC_SECP384R1 ;
			break ;
		case MBEDTLS_ECP_DP_SECP521R1 :
			hseEccCurveId = HSE_EC_SEC_SECP521R1 ;
			break ;
		case MBEDTLS_ECP_DP_BP256R1 :
			hseEccCurveId = HSE_EC_BRAINPOOL_BRAINPOOLP256R1 ;
			break ;
		case MBEDTLS_ECP_DP_BP384R1 :
			hseEccCurveId = HSE_EC_BRAINPOOL_BRAINPOOLP384R1 ;
			break ;
		case MBEDTLS_ECP_DP_BP512R1 :
			hseEccCurveId = HSE_EC_BRAINPOOL_BRAINPOOLP512R1 ;
			break ;
		case MBEDTLS_ECP_DP_CURVE25519 :
			hseEccCurveId = HSE_EC_25519_CURVE25519 ;
			break ;
		case MBEDTLS_ECP_DP_CURVE448 :
#ifdef HSE_SPT_EC_448_CURVE448
			hseEccCurveId = HSE_EC_448_CURVE448 ;
			break ;
#endif /* HSE_SPT_EC_448_CURVE448 */
		case MBEDTLS_ECP_DP_SECP192R1 :
		case MBEDTLS_ECP_DP_SECP224R1 :
		case MBEDTLS_ECP_DP_SECP192K1 :
		case MBEDTLS_ECP_DP_SECP224K1 :
		case MBEDTLS_ECP_DP_SECP256K1 :
			ret = nxp_hse_ecc_loadusercurve(grp) ;
			if(ret < 0)
			{
				/* Goto cleanup if ret is MBEDTLS_ERR_ECP_ALLOC_FAILED \
				 * or MBEDTLS_ERR_ECP_BAD_INPUT_DATA */
				goto cleanup;
			}
			else
			{
				/* Load User Curve Id into hseEccCurveId */
				hseEccCurveId = grp->userCurveId;
			}
			break;
		default:
			return ( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
	}

	/* Load Peer Public Key and Private key */
	ret = nxp_hse_ecc_loadkey(EC_OPS_SHAREDSECRET, hseEccCurveId, grp, Q, NULL, d, &peerKeyhandle, &prvKeyhandle, f_rng, p_rng);
	if(NO_ERROR == ret)
	{
		/* Compute shared secret key */
		key_import_param_shared.key_type = HSE_KEY_TYPE_SHARED_SECRET;
		key_import_param_shared.key_catalog = HSE_KEY_CATALOG_ID_RAM;
		key_import_param_shared.key_param.sym_key_param.size = grp->nbits;

		err = KeystoreMgmt_FindAllocateSlot(&key_import_param_shared, &(sharedSecretKeyHandle ));
		if(KEYMGMT_ERR_SUCCESS == err )
		{
			/* Send the request */
			srvResponse = HSE_GenerateDhSharedSecret(prvKeyhandle, peerKeyhandle, sharedSecretKeyHandle );

			/* Check the response */
			switch(srvResponse)
			{
				case HSE_SRV_RSP_OK:
#if defined (MBEDTLS_DEBUG_C)
					mbedtls_printf("\nPrivate keyHandle 0x%02x | Peer KeyHandle : 0x%02x |"
							" Shared Secret KeyHandle 0x%02x|\n", prvKeyhandle, peerKeyhandle, sharedSecretKeyHandle );
#endif /* MBEDTLS_DEBUG_C */
					/* Copy shared secret key handle to Shared secret mpi z */
					ret = mbedtls_mpi_lset(z, (mbedtls_mpi_sint)sharedSecretKeyHandle );
					if(ret != NO_ERROR)
					{
						ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
					}

					/* Copy private key handle to grp */
					grp->keyHandle = prvKeyhandle;
					break;

				case HSE_SRV_RSP_INVALID_PARAM:
					ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
					break;

				default:
					ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
					break;
			}
		}
		else
		{
			ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
#if defined (MBEDTLS_DEBUG_C)
			mbedtls_printf("%s:%d:returned %d (-0x%04x)\n", __FILE__, __LINE__, ret, (unsigned int) -ret );
#endif /* MBEDTLS_DEBUG_C */
		}
	}
	else
	{
		ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
#if defined (MBEDTLS_DEBUG_C)
		mbedtls_printf("%s:%d:returned %d (-0x%04x)\n", __FILE__, __LINE__, ret, (unsigned int) -ret );
#endif /* MBEDTLS_DEBUG_C */
	}

	/* Unload Public key */
	nxp_hse_ecc_unloadkey(peerKeyhandle);

cleanup:

	return( ret );
}
#endif /* MBEDTLS_ECDH_COMPUTE_SHARED_ALT */
