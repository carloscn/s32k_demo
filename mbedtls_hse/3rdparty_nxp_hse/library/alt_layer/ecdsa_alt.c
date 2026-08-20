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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/ecdsa.h"
#include "mbedtls/asn1write.h"
#include "keystore_mgmt.h"
#include "nxp_hse_ecc.h"
#include "hse_host_sign.h"

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
#include "mbedtls/hmac_drbg.h"
#endif

/*==================================================================================================
*                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL MACROS
==================================================================================================*/

/* Parameter validation macros based on platform_util.h */
#define ECDSA_ALT_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA )
#define ECDSA_ALT_VALIDATE( cond )        \
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
#if defined(MBEDTLS_ECDSA_SIGN_ALT)
/**
 * @brief       This function computes the ECDSA signature of a
 *              previously-hashed message.
 *
 * 	@param[in]	grp
 *              The context for the elliptic curve to use.
 *              This must be initialized and have group parameters
 *              set, for example through mbedtls_ecp_group_load().
 *
 * 	@param[out]	r
 * 		        The MPI context in which to store the first part
 *              the signature. This must be initialized.
 *
 * 	@param[out]	s
 *              The MPI context in which to store the second part
 *              the signature. This must be initialized.
 *
 * 	@param[in]	d
 * 			    The private signing key. This must be initialized.
 *
 *  @param[in]	buf
 *              The content to be signed. This is usually the hash of
 *              the original data to be signed. This must be a readable
 *              buffer of length \p blen Bytes. It may be \c NULL if
 *              \p blen is zero.
 *
 * @param[in]	blen
 *              The length of \p buf in Bytes.
 *
 * @param[in]	f_rng
 *              The RNG function. This must not be \c NULL.
 *
 * @param[in]	p_rng
 * 			    The RNG context to be passed to \p f_rng. This may be
 *              \c NULL if \p f_rng doesn't need a context parameter.
 *
 * @return      \c 0 on success.
 *
 * @return      An \c MBEDTLS_ERR_ECP_XXX
 *              or \c MBEDTLS_MPI_XXX error code on failure.
 */
static int ecdsa_sign_restartable( mbedtls_ecp_group *grp,
                mbedtls_mpi *r, mbedtls_mpi *s,
                const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                int (*f_rng_blind)(void *, unsigned char *, size_t),
                void *p_rng_blind,
                mbedtls_ecdsa_restart_ctx *rs_ctx );

#endif /* MBEDTLS_ECDSA_SIGN_ALT */

#if defined(MBEDTLS_ECDSA_VERIFY_ALT)
/**
 * @brief        This function verifies the ECDSA signature of a
 *               previously-hashed message.
 *
 * 	@param[in]	grp
 *              The context for the elliptic curve to use.
 *              This must be initialized and have group parameters
 *              set, for example through mbedtls_ecp_group_load().
 *
 *  @param[in]	buf
 *        		The hashed content that was signed. This must be a readable
 *              buffer of length \p blen Bytes. It may be \c NULL if
 *              \p blen is zero.
 *
 * @param[in]	blen
 *              The length of \p buf in Bytes.
 *
 * @param[in]	Q
 *              The public key to use for verification. This must be
 *              initialized and setup.
 *
 * 	@param[in]	r
 * 		        The first integer of the signature.
 *
 * 	@param[in]	s
 *              The second integer of the signature.
 *
 * 	@param[in]	rs_ctx
 * 			    Unused parameter
 *
 * @return      \c 0 on success.
 *
 * @return      #MBEDTLS_ERR_ECP_BAD_INPUT_DATA if the signature
 *              is invalid.
 *
 * @return      An \c MBEDTLS_ERR_ECP_XXX or \c MBEDTLS_MPI_XXX
 *              error code on failure for any other reason.
 */
static int ecdsa_verify_restartable( mbedtls_ecp_group *grp,
				 const unsigned char *buf, size_t blen,
				 const mbedtls_ecp_point *Q,
				 const mbedtls_mpi *r, const mbedtls_mpi *s,
				 mbedtls_ecdsa_restart_ctx *rs_ctx );

#endif /* MBEDTLS_ECDSA_VERIFY_ALT */

/*==================================================================================================
*                                       LOCAL FUNCTIONS
==================================================================================================*/

#if defined(MBEDTLS_ECDSA_SIGN_ALT)
/*************************************************************************************************
* Description: This function computes the ECDSA signature of a previously-hashed message.
************************************************************************************************/
static int ecdsa_sign_restartable( mbedtls_ecp_group *grp,
                mbedtls_mpi *r, mbedtls_mpi *s,
                const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                int (*f_rng_blind)(void *, unsigned char *, size_t),
                void *p_rng_blind,
                mbedtls_ecdsa_restart_ctx *rs_ctx )
{
    uint8_t hseEccCurveId = 0U;
    uint8_t hashalgo = 0U;
	uint8_t *pR = NULL, *pS = NULL;
    uint32_t pRLen = 0U, pSLen = 0U;
    hseKeyHandle_t keyHandle = HSE_INVALID_KEY_HANDLE;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
	mbedtls_ecp_point Q;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

	/* Unused parameters */
	(void)f_rng;
	(void)p_rng;
	(void)f_rng_blind;
	(void)p_rng_blind;
	(void)rs_ctx;

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if( ! mbedtls_ecdsa_can_do( grp->id ) || grp->N.p == NULL )
    {
    	return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    }

    /* Make sure d is in range 1..n-1 */
    if( (mbedtls_mpi_cmp_int( d, 1 ) < 0 ) || (mbedtls_mpi_cmp_mpi( d, &grp->N ) >= 0) )
    {
    	return( MBEDTLS_ERR_ECP_INVALID_KEY );
    }

    /* Identify the hash algorithm */
    switch(blen)
  {
    	case 20:
    		hashalgo = HSE_HASH_ALGO_SHA_1;
    		break;
    	case 28:
    		hashalgo = HSE_HASH_ALGO_SHA2_224;
    		break;
    	case 32:
    		hashalgo = HSE_HASH_ALGO_SHA2_256;
    		break;
    	case 48:
    		hashalgo = HSE_HASH_ALGO_SHA2_384;
    		break;
    	case 64:
    		hashalgo = HSE_HASH_ALGO_SHA2_512;
    		break;
    	case 16:
#ifdef HSE_HASH_ALGO_MD5
    		hashalgo = HSE_HASH_ALGO_MD5;
    		break;
#else
    		return ( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE ) ;
#endif
		default:
			return ( MBEDTLS_ERR_ECP_BAD_INPUT_DATA ) ;
    }

    switch(	grp->id )
	{
		case MBEDTLS_ECP_DP_SECP256R1:
			hseEccCurveId = HSE_EC_SEC_SECP256R1;
			break ;
		case MBEDTLS_ECP_DP_SECP384R1:
			hseEccCurveId = HSE_EC_SEC_SECP384R1;
			break ;
		case MBEDTLS_ECP_DP_SECP521R1:
			hseEccCurveId = HSE_EC_SEC_SECP521R1;
			break ;
		case MBEDTLS_ECP_DP_BP256R1:
			hseEccCurveId = HSE_EC_BRAINPOOL_BRAINPOOLP256R1;
			break ;
		case MBEDTLS_ECP_DP_BP384R1:
			hseEccCurveId = HSE_EC_BRAINPOOL_BRAINPOOLP384R1;
			break ;
		case MBEDTLS_ECP_DP_BP512R1:
			hseEccCurveId = HSE_EC_BRAINPOOL_BRAINPOOLP512R1;
			break ;
		case MBEDTLS_ECP_DP_SECP192R1:
		case MBEDTLS_ECP_DP_SECP224R1:
		case MBEDTLS_ECP_DP_SECP192K1:
		case MBEDTLS_ECP_DP_SECP224K1:
		case MBEDTLS_ECP_DP_SECP256K1:
			ret = nxp_hse_ecc_loadusercurve(grp);
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
			break ;
		default:
			return ( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
	}

    /* Initialize ECP point Q */
	mbedtls_ecp_point_init( &Q );

	/* Check if d contains key handle or Private key */
	if(mbedtls_mpi_size(d) > sizeof(hseKeyHandle_t))
	{
		MBEDTLS_MPI_CHK(mbedtls_ecp_mul( grp, &Q, d, &grp->G, f_rng, p_rng ));

		/* Get Private key handle from private key mpi d */
		ret = nxp_hse_ecc_loadkey(EC_OPS_SIGN, hseEccCurveId, grp, NULL, &Q, d, NULL, &keyHandle, NULL, NULL);
		if(NO_ERROR != ret)
		{
			ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
			goto cleanup;
		}
		
		/* save private keyhandle in group */
		grp->keyHandle = keyHandle;
	}
	else
	{
		/* Copy Key handle from d */
		  memcpy((char*)&keyHandle, d->p, sizeof(hseKeyHandle_t));
	}

	/* Allocate memory for r and s */
	pRLen = BITS_TO_BYTES(grp->nbits);
	pSLen = BITS_TO_BYTES(grp->nbits);
	pR = mbedtls_calloc(1,pRLen);
	pS = mbedtls_calloc(1,pSLen);
	if((pR == NULL) || (pS == NULL))
	{
		/* return Error */
		ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
		goto cleanup;
	}

	/* ECDSA Sign request */
	srvResponse = HSE_Ecdsa(HSE_AUTH_DIR_GENERATE, hashalgo, keyHandle,
			(const uint8_t*)buf, (const uint32_t)blen, TRUE, pR, pS, &pRLen, &pSLen);

	if(HSE_SRV_RSP_OK != srvResponse)
	{
		if(HSE_SRV_RSP_INVALID_PARAM == srvResponse)
		{
			ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
		}
		else
		{
			ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
		}
	}
	else
	{
		mbedtls_mpi_read_binary(r, pR, pRLen);
		mbedtls_mpi_read_binary(s, pS, pSLen);
		ret = NO_ERROR ;
	}

cleanup:

	mbedtls_ecp_point_free(&Q);

	if(NULL != pR)
	{
		/* Zeroize r */
		mbedtls_platform_zeroize(pR, pRLen);
		mbedtls_free(pR);
	}

	if(NULL != pS)
	{
		/* Zeroize s */
		mbedtls_platform_zeroize(pS, pSLen);
		mbedtls_free(pS);
	}

    return( ret );
}

#endif /* MBEDTLS_ECDSA_SIGN_ALT */

#if defined(MBEDTLS_ECDSA_VERIFY_ALT)
/*************************************************************************************************
* Description: This function verifies the ECDSA signature of a previously-hashed message.
************************************************************************************************/
static int ecdsa_verify_restartable( mbedtls_ecp_group *grp,
					 const unsigned char *buf, size_t blen,
					 const mbedtls_ecp_point *Q,
					 const mbedtls_mpi *r, const mbedtls_mpi *s,
					 mbedtls_ecdsa_restart_ctx *rs_ctx )
{
	uint8_t hseEccCurveId = 0U;
	uint8_t hashalgo = 0U;
    uint8_t *pR = NULL, *pS = NULL;
    uint32_t pRLen = 0U, pSLen = 0U;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
    hseKeyHandle_t keyHandle = HSE_INVALID_KEY_HANDLE;
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* Unused parameters */
    (void) rs_ctx;

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if( ! mbedtls_ecdsa_can_do( grp->id ) || grp->N.p == NULL )
    {
    	return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    }

    if( (mbedtls_mpi_cmp_int( r, 1 ) < 0) || (mbedtls_mpi_cmp_mpi( r, &grp->N ) >= 0) ||
        (mbedtls_mpi_cmp_int( s, 1 ) < 0) || (mbedtls_mpi_cmp_mpi( s, &grp->N ) >= 0) )
    {
        return ( MBEDTLS_ERR_ECP_VERIFY_FAILED );
    }

    /* Identify the hash algorithm */
    switch(blen)
	{
		case 20:
			hashalgo = HSE_HASH_ALGO_SHA_1;
			break;
		case 28:
			hashalgo = HSE_HASH_ALGO_SHA2_224;
			break;
		case 32:
			hashalgo = HSE_HASH_ALGO_SHA2_256;
			break;
		case 48:
			hashalgo = HSE_HASH_ALGO_SHA2_384;
			break;
		case 64:
			hashalgo = HSE_HASH_ALGO_SHA2_512;
			break;
		case 16:
#ifdef HSE_HASH_ALGO_MD5
    		hashalgo = HSE_HASH_ALGO_MD5;
    		break;
#else
    		return ( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE ) ;
#endif
		default:
			return ( MBEDTLS_ERR_ECP_BAD_INPUT_DATA);
	}

	switch(	grp->id )
	{
		case MBEDTLS_ECP_DP_SECP256R1:
			hseEccCurveId = HSE_EC_SEC_SECP256R1;
			break ;
		case MBEDTLS_ECP_DP_SECP384R1:
			hseEccCurveId = HSE_EC_SEC_SECP384R1;
			break ;
		case MBEDTLS_ECP_DP_SECP521R1:
			hseEccCurveId = HSE_EC_SEC_SECP521R1;
			break ;
		case MBEDTLS_ECP_DP_BP256R1:
			hseEccCurveId = HSE_EC_BRAINPOOL_BRAINPOOLP256R1;
			break ;
		case MBEDTLS_ECP_DP_BP384R1:
			hseEccCurveId = HSE_EC_BRAINPOOL_BRAINPOOLP384R1 ;
			break ;
		case MBEDTLS_ECP_DP_BP512R1:
			hseEccCurveId = HSE_EC_BRAINPOOL_BRAINPOOLP512R1;
			break ;
		case MBEDTLS_ECP_DP_SECP192R1:
		case MBEDTLS_ECP_DP_SECP224R1:
		case MBEDTLS_ECP_DP_SECP192K1:
		case MBEDTLS_ECP_DP_SECP224K1:
		case MBEDTLS_ECP_DP_SECP256K1:
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
			break ;
		default:
			return ( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
	}

	/* Load Public Key */
	ret = nxp_hse_ecc_loadkey(EC_OPS_VERIFY, hseEccCurveId, grp, NULL, Q, NULL, &keyHandle, NULL, NULL, NULL);
	if(NO_ERROR != ret )
	{
		ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
		goto cleanup;
	}

	/* Allocate memory for r and s */
	pRLen = BITS_TO_BYTES(grp->nbits);
	pSLen = BITS_TO_BYTES(grp->nbits);
	pR = mbedtls_calloc(1,pRLen);
	pS = mbedtls_calloc(1,pSLen);
	if((pR == NULL) || (pS == NULL))
	{
		/* return Error */
		ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
		goto cleanup;
	}

	/* Copy mpi structure to binary */
	ret  = mbedtls_mpi_write_binary(r, pR, pRLen);
	if(NO_ERROR != ret)
	{
		ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
		goto cleanup;
	}

	ret  = mbedtls_mpi_write_binary(s, pS, pSLen);
	if(NO_ERROR != ret)
	{
		ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
		goto cleanup;
	}

	/* ECDSA Verify request */
	srvResponse = HSE_Ecdsa(HSE_AUTH_DIR_VERIFY, hashalgo, keyHandle,
			(const uint8_t*)buf, (const uint32_t)blen, TRUE, pR, pS, &pRLen, &pSLen);

	switch(srvResponse)
	{
		case HSE_SRV_RSP_OK:
			ret = NO_ERROR;
			break;
		case HSE_SRV_RSP_INVALID_PARAM:
		case HSE_SRV_RSP_VERIFY_FAILED:
		default:
			ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
			break;
	}

	/* Unload public key handle */
    nxp_hse_ecc_unloadkey(keyHandle);

cleanup:

	if(NULL != pR)
	{
		/* Zeroize r */
		mbedtls_platform_zeroize(pR, pRLen);
		mbedtls_free(pR);
	}

	if(NULL != pS)
	{
		/* Zeroize s */
		mbedtls_platform_zeroize(pS, pSLen);
		mbedtls_free(pS);
	}

	return(ret);
}

#endif /* MBEDTLS_ECDSA_VERIFY_ALT */

/*==================================================================================================
*                                       GLOBAL FUNCTIONS
==================================================================================================*/
#if defined(MBEDTLS_ECDSA_SIGN_ALT)
/*************************************************************************************************
* Description: This function checks whether a given group can be used for ECDSA.
************************************************************************************************/
int mbedtls_ecdsa_can_do( mbedtls_ecp_group_id gid )
{
    switch( gid )
    {
#ifdef MBEDTLS_ECP_DP_CURVE25519_ENABLED
        case MBEDTLS_ECP_DP_CURVE25519: return 0;
#endif
#ifdef MBEDTLS_ECP_DP_CURVE448_ENABLED
        case MBEDTLS_ECP_DP_CURVE448: return 0;
#endif
    default: return 1;
    }
}

/*************************************************************************************************
* Description: This function computes the ECDSA signature of a  previously-hashed message.
************************************************************************************************/
int mbedtls_ecdsa_sign( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
						const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
						int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
	ECDSA_ALT_VALIDATE_RET( grp   != NULL );
	ECDSA_ALT_VALIDATE_RET( r     != NULL );
	ECDSA_ALT_VALIDATE_RET( s     != NULL );
	ECDSA_ALT_VALIDATE_RET( d     != NULL );
	ECDSA_ALT_VALIDATE_RET( buf   != NULL || blen == 0 );

	return( ecdsa_sign_restartable( grp, r, s, d, buf, blen,
									f_rng, p_rng, f_rng, p_rng, NULL ) );

}
#endif /* MBEDTLS_ECDSA_SIGN_ALT */


#if defined(MBEDTLS_ECDSA_VERIFY_ALT)
/*************************************************************************************************
* Description: This function verifies the ECDSA signature of a previously-hashed message.
************************************************************************************************/
int mbedtls_ecdsa_verify( mbedtls_ecp_group *grp,
                          const unsigned char *buf, size_t blen,
                          const mbedtls_ecp_point *Q,
                          const mbedtls_mpi *r,
                          const mbedtls_mpi *s)
{
	ECDSA_ALT_VALIDATE_RET( grp != NULL );
	ECDSA_ALT_VALIDATE_RET( Q   != NULL );
	ECDSA_ALT_VALIDATE_RET( r   != NULL );
	ECDSA_ALT_VALIDATE_RET( s   != NULL );
	ECDSA_ALT_VALIDATE_RET( buf != NULL || blen == 0 );

    return( ecdsa_verify_restartable( grp, buf, blen, Q, r, s, NULL ) );
}
#endif /* MBEDTLS_ECDSA_VERIFY_ALT */

#if defined(MBEDTLS_ECDSA_GENKEY_ALT)
/*************************************************************************************************
* Description: This function generates an ECDSA keypair on the given curve.
************************************************************************************************/
int mbedtls_ecdsa_genkey( mbedtls_ecdsa_context *ctx, mbedtls_ecp_group_id gid,
                  int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret = 0;

    ECDSA_ALT_VALIDATE_RET( ctx   != NULL );
    ECDSA_ALT_VALIDATE_RET( f_rng != NULL );

    ret = mbedtls_ecp_group_load( &ctx->grp, gid );
    if( ret != 0 )
    {
    	return( ret );
    }

   return( mbedtls_ecp_gen_keypair( &ctx->grp, &ctx->d,
                                    &ctx->Q, f_rng, p_rng ) );
}

#endif /* MBEDTLS_ECDSA_GENKEY_ALT */
