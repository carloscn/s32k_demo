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

#if defined(MBEDTLS_ECP_ALT) && defined(MBEDTLS_USE_NXP_HSE_CRYPTO)

#include "nxp_hse_ecc.h"

/*==================================================================================================
*                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL MACROS
==================================================================================================*/

#define NXP_HSE_ECC_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA )

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

/**
 * 	@brief		This function loads ECC key-pair for share secret
 * 				computation and returns public and private key-handles
 *
 *	@param[in] 	hseEccCurveId
 *				HSE ECC Curve ID
 *
 *	@param[in]	grp
 *				The ECP group to generate a key pair for.
 *              This must be initialized and have group parameters
 *              set, for example through mbedtls_ecp_group_load().
 *
 * 	@param[in]	Qpeer
 * 				The Peer Public key.
 *
 * 	@param[in]	d
 * 				The private key.
 *
 * 	@param[out]	pubKeyHandle
 * 				Public key-handle
 *
 * 	@param[out]	prvKeyHandle
 * 				Private key-handle
 *
 *	@return		\c 0 on success.
 *
 * 	@return     #MBEDTLS_ERR_ECP_INVALID_KEY error if the key is
 *              invalid.
 * 	@return     #MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation
 * 				failed.
 *
 */
static int shared_secret_loadkey(uint8_t hseEccCurveId, mbedtls_ecp_group *grp,
			const mbedtls_ecp_point *Qpeer,	const mbedtls_mpi *d, hseKeyHandle_t *pubKeyHandle,
			hseKeyHandle_t *prvKeyHandle, int (*f_rng)(void *, unsigned char *, size_t),
			void *p_rng);

/**
 * 	@brief		This function loads ECC key-pair for sign operation and
 * 				returns private key-handle.
 *
 *	@param[in] 	hseEccCurveId
 *				HSE ECC Curve ID
 *
 *	@param[in]	grp
 *				The ECP group to generate a key pair for.
 *              This must be initialized and have group parameters
 *              set, for example through mbedtls_ecp_group_load().
 *
 * 	@param[in]	Q
 * 				The Public key.
 *
 * 	@param[in]	d
 * 				The private key.
 *
 * 	@param[out]	prvKeyHandle
 * 				Private key-handle
 *
 *	@return		\c 0 on success.
 *
 * 	@return     #MBEDTLS_ERR_ECP_INVALID_KEY error if the key is
 *              invalid.
 * 	@return     #MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation
 * 				failed.
 *
 */
static int sign_loadkey(uint8_t hseEccCurveId, mbedtls_ecp_group *grp, const mbedtls_ecp_point *Q,
				const mbedtls_mpi *d, hseKeyHandle_t *prvKeyHandle);

/**
 * 	@brief		This function loads Public key for verify operation and
 * 				returns Public key-handle.
 *
 *	@param[in] 	hseEccCurveId
 *				HSE ECC Curve ID
 *
 *	@param[in]	grp
 *				The ECP group to generate a key pair for.
 *              This must be initialized and have group parameters
 *              set, for example through mbedtls_ecp_group_load().
 *
 * 	@param[in]	Q
 * 				The Public key.
 *
 * 	@param[out]	pubKeyHandle
 * 				Public key-handle
 *
 *	@return		\c 0 on success.
 *
 * 	@return     #MBEDTLS_ERR_ECP_INVALID_KEY error if the key is
 *              invalid.
 * 	@return     #MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation
 * 				failed.
 *
 */
static int verify_loadkey(uint8_t hseEccCurveId, mbedtls_ecp_group *grp,
			const mbedtls_ecp_point *Q, hseKeyHandle_t *pubKeyHandle);

/*==================================================================================================
*                                       LOCAL FUNCTIONS
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
* Description: This function loads ECC key-pair for shared secret computation
************************************************************************************************/
static int shared_secret_loadkey(uint8_t hseEccCurveId, mbedtls_ecp_group *grp,
			const mbedtls_ecp_point *Qpeer,	const mbedtls_mpi *d, hseKeyHandle_t *pubKeyHandle,
			hseKeyHandle_t *prvKeyHandle, int (*f_rng)(void *, unsigned char *, size_t),
			void *p_rng)
{
    int ret = 0;
    size_t olen = 0;
    uint32_t size_q = 0U, size_qPeer = 0U, size_d = 0U, size_n = 0U;
    unsigned char *pQ = NULL;
    unsigned char *pQpeer = NULL;
    unsigned char *pD = NULL;
    mbedtls_ecp_point q;
    key_import_param_t key_import_param_private;
    key_import_param_t key_import_param_public;
    KeymgmtErrCodeT err;

    memset(&key_import_param_private, 0x00, sizeof(key_import_param_t));
    memset(&key_import_param_public, 0x00, sizeof(key_import_param_t));

	mbedtls_ecp_point_init(&q);

	/* Check if d contains key handle or key */
	if(mbedtls_mpi_size(d) > sizeof(hseKeyHandle_t))
	{
		/* d contains private key, calculate public key */
		MBEDTLS_MPI_CHK(mbedtls_ecp_mul( grp, &q, d, &grp->G, f_rng, p_rng ));

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
		if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_MONTGOMERY )
		{
			/* Allocate memory of Public key length */
			size_q = mbedtls_mpi_size( &grp->P );
		}
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
		if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
		{
			/* Allocate Memory Buffer for q */
			size_q = (2*BITS_TO_BYTES(grp->nbits)) + 1;
		}
#endif
		pQ = (uint8_t*)mbedtls_calloc( 1, size_q);
		if(NULL == pQ)
		{
			/* Return error */
			return MBEDTLS_ERR_MPI_ALLOC_FAILED;
		}

		/* Export a Public key (q) point into unsigned binary data  */
		ret = mbedtls_ecp_point_write_binary(grp, &q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pQ, size_q);
		if(NO_ERROR != ret)
		{
			ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
			goto cleanup;
		}

		/* need to check in case both keys need to import */
		/* Allocate Memory Buffer for D */
		size_n = BITS_TO_BYTES(grp->nbits);
		size_d = mbedtls_mpi_size(d);
		pD = (uint8_t*)mbedtls_calloc(1, size_n);
		if(NULL == pD)
		{
			ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
			goto cleanup;
		}

		/* Copy mpi structure to binary */
		ret  = mbedtls_mpi_write_binary(d, &pD[size_n - size_d], size_d);
		if(NO_ERROR != ret)
		{
			ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
			goto cleanup;
		}

		/* Load Public/Private Key Pair */
		key_import_param_private.key_type = HSE_KEY_TYPE_ECC_PAIR;
		key_import_param_private.key_catalog = HSE_KEY_CATALOG_ID_RAM;
		key_import_param_private.key_param.ecc_keypair_param.eccCurveId = hseEccCurveId;
		key_import_param_private.key_param.ecc_keypair_param.D = pD;
		key_import_param_private.key_param.ecc_keypair_param.size_D = grp->nbits;
		key_import_param_private.key_param.ecc_keypair_param.size_Q = grp->nbits;
	#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
			if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_MONTGOMERY )
			{
				key_import_param_private.key_param.ecc_keypair_param.Q = pQ;
			}
	#endif
	#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
			if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
			{
				key_import_param_private.key_param.ecc_keypair_param.Q = &pQ[1];
			}
	#endif
			err = KeystoreMgmt_FindImportSlot(&key_import_param_private, prvKeyHandle);

			/* Immediately Zeroize Private Key irrespective of outcome. Will free memory later */
			mbedtls_platform_zeroize(pD, size_d);

			if(err != KEYMGMT_ERR_SUCCESS)
			{
				ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
				goto cleanup;
			}
    }
    else
    {
        /* Copy Private key handle*/
        (void)memcpy((char*)prvKeyHandle, d->p, sizeof(hseKeyHandle_t));
    }

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
	if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_MONTGOMERY )
	{
		/* Allocate memory of Public key length */
		size_qPeer = mbedtls_mpi_size( &grp->P );
	}
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
	if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
	{
		/* Allocate Memory Buffer for q */
		size_qPeer = (2*BITS_TO_BYTES(grp->nbits)) + 1;
	}
#endif
	pQpeer = (uint8_t*)mbedtls_calloc( 1, size_qPeer);
	if(NULL == pQpeer)
	{
		/* Return error */
		return MBEDTLS_ERR_MPI_ALLOC_FAILED;
	}

	/* Export Peer Public key (Qpeer) point into unsigned binary data  */
	ret = mbedtls_ecp_point_write_binary(grp, Qpeer, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pQpeer, size_qPeer);
	if(NO_ERROR != ret)
	{
		ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
		goto cleanup;
	}

	/*
	 * Import Peer Public key to HSE
	 * */
	key_import_param_public.key_type = HSE_KEY_TYPE_ECC_PUB;
	key_import_param_public.key_catalog = HSE_KEY_CATALOG_ID_RAM;
	key_import_param_public.key_param.ecc_pubkey_param.eccCurveId = hseEccCurveId;
#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
	if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_MONTGOMERY )
	{
		key_import_param_public.key_param.ecc_pubkey_param.Q = pQpeer;
		key_import_param_public.key_param.ecc_pubkey_param.size_Q = BYTES_TO_BITS(mbedtls_mpi_size( &grp->P ));
	}
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
	if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
	{
		key_import_param_public.key_param.ecc_pubkey_param.Q = &pQpeer[1];
		key_import_param_public.key_param.ecc_pubkey_param.size_Q = grp->nbits;
	}
#endif
	err = KeystoreMgmt_FindImportSlot(&key_import_param_public, pubKeyHandle);
	if(err != KEYMGMT_ERR_SUCCESS)
	{
		ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
	}

cleanup:

	/* Free ECP point q */
	mbedtls_ecp_point_free(&q);

	/* Free and Zeroize Public key pQ */
	if(NULL != pQ)
	{
		mbedtls_platform_zeroize(pQ, size_q);
		mbedtls_free(pQ);
		pQ = NULL;
	}

	/* Free Private key pD */
	if(NULL != pD)
	{
		mbedtls_free(pD);
		pD = NULL;
	}

	/* Free and Zeroize Peer Public key pQpeer */
	if(NULL != pQpeer)
	{
		mbedtls_platform_zeroize(pQpeer, size_qPeer);
		mbedtls_free(pQpeer);
		pQpeer = NULL;
	}

	return( ret );
}

/*************************************************************************************************
* Description: This function loads ECC key-pair for signature operation
************************************************************************************************/
static int sign_loadkey(uint8_t hseEccCurveId, mbedtls_ecp_group *grp, const mbedtls_ecp_point *Q,
				const mbedtls_mpi *d, hseKeyHandle_t *prvKeyHandle)
{
    int ret = 0;
    size_t olen = 0;
    uint32_t size_q = 0U, size_d = 0U, size_n = 0U;
    unsigned char *q = NULL;
    unsigned char *pD = NULL;
    KeymgmtErrCodeT err;
    key_import_param_t key_import_param_private;

    memset(&key_import_param_private, 0x00, sizeof(key_import_param_t));

    /* Signature generation & Compute shared secret input parameter check conditions */
    if ((d == NULL) && (Q == NULL))
    {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

	/* Check if Q is non-zero */
	if(NO_ERROR == mbedtls_ecp_check_pubkey(grp, Q))
	{
#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
		if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_MONTGOMERY )
		{
			/* Allocate memory of Public key length */
			size_q = mbedtls_mpi_size( &grp->P );
		}
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
		if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
		{
			/* Allocate Memory Buffer for q */
			size_q = (2*BITS_TO_BYTES(grp->nbits)) + 1;
		}
#endif
		q = (uint8_t*)mbedtls_calloc( 1, size_q);
		if(NULL == q)
		{
			/* Return error */
			return MBEDTLS_ERR_MPI_ALLOC_FAILED;
		}

		/* Get Peer Public key from peer public key mpi Q */
		ret = mbedtls_ecp_point_write_binary(grp, Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, q, size_q);
		if(NO_ERROR != ret)
		{
			ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
			goto cleanup;
		}
	}

    /* Check if d contains key handle or key */
    if(mbedtls_mpi_size(d) > sizeof(hseKeyHandle_t))
    {
        /* need to check in case both keys need to import */
        /* Allocate Memory Buffer for D */
        size_n = BITS_TO_BYTES(grp->nbits);
        size_d = mbedtls_mpi_size(d);
        pD = (uint8_t*)mbedtls_calloc(1, size_n);
        if(NULL == pD)
        {
            ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
            goto cleanup;
        }

        /* Copy mpi structure to binary */
        ret  = mbedtls_mpi_write_binary(d, &pD[size_n - size_d], size_d);
        if(NO_ERROR != ret)
        {
            ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            goto cleanup;
        }

        /* Load Public/Private Key Pair */
        key_import_param_private.key_type = HSE_KEY_TYPE_ECC_PAIR;
        key_import_param_private.key_catalog = HSE_KEY_CATALOG_ID_RAM;
        key_import_param_private.key_param.ecc_keypair_param.eccCurveId = hseEccCurveId;
        key_import_param_private.key_param.ecc_keypair_param.D = pD;
        key_import_param_private.key_param.ecc_keypair_param.size_D = grp->nbits;
        key_import_param_private.key_param.ecc_keypair_param.size_Q = grp->nbits;
#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
        if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_MONTGOMERY )
        {
        	key_import_param_private.key_param.ecc_keypair_param.Q = q;
        }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
        if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
        {
        	key_import_param_private.key_param.ecc_keypair_param.Q = &q[1];
        }
#endif
        err = KeystoreMgmt_FindImportSlot(&key_import_param_private, prvKeyHandle);

        /* Immediately Zeroize Private Key irrespective of outcome. Will free memory later */
        mbedtls_platform_zeroize(pD, size_d);

        if(err != KEYMGMT_ERR_SUCCESS)
        {
            ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            goto cleanup;
        }
    }
    else
    {
        /* Copy Private key handle*/
        (void)memcpy((char*)prvKeyHandle, d->p, sizeof(hseKeyHandle_t));
    }

cleanup:

	/* Free and Zeroize Public key q */
	if(NULL != q)
	{
		mbedtls_platform_zeroize(q, size_q);
		mbedtls_free(q);
		q = NULL;
	}

	/* Free Private key pD */
	if(NULL != pD)
	{
		mbedtls_free(pD);
		pD = NULL;
	}

	return( ret );

}

/*************************************************************************************************
* Description: This function loads the Public key for verify operation
************************************************************************************************/
static int verify_loadkey(uint8_t hseEccCurveId, mbedtls_ecp_group *grp,
			const mbedtls_ecp_point *Q, hseKeyHandle_t *pubKeyHandle)
{
    int ret = 0;
    size_t olen = 0;
    uint32_t size_q = 0U;
    unsigned char *q = NULL;
    KeymgmtErrCodeT err;
    key_import_param_t key_import_param_public;

    memset(&key_import_param_public, 0x00, sizeof(key_import_param_t));

    /* Signature verification nput parameter check condition */
    if (Q == NULL)
    {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

	/* Check if Q is non-zero */
	if(NO_ERROR == mbedtls_ecp_check_pubkey(grp, Q))
	{
#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
		if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_MONTGOMERY )
		{
			/* Allocate memory of Public key length */
			size_q = mbedtls_mpi_size( &grp->P );
		}
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
		if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
		{
			/* Allocate Memory Buffer for q */
			size_q = (2*BITS_TO_BYTES(grp->nbits)) + 1;
		}
#endif
		q = (uint8_t*)mbedtls_calloc( 1, size_q);
		if(NULL == q)
		{
			/* Return error */
			return MBEDTLS_ERR_MPI_ALLOC_FAILED;
		}

		/* Get Peer Public key from peer public key mpi Q */
		ret = mbedtls_ecp_point_write_binary(grp, Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, q, size_q);
		if(NO_ERROR != ret)
		{
			ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
			goto cleanup;
		}
	}

    /* Load Public key for Verify operation */
    key_import_param_public.key_type = HSE_KEY_TYPE_ECC_PUB;
    key_import_param_public.key_catalog = HSE_KEY_CATALOG_ID_RAM;
    key_import_param_public.key_param.ecc_pubkey_param.eccCurveId = hseEccCurveId;
#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_MONTGOMERY )
    {
		key_import_param_public.key_param.ecc_pubkey_param.Q = q;
        key_import_param_public.key_param.ecc_pubkey_param.size_Q = BYTES_TO_BITS(mbedtls_mpi_size( &grp->P ));
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
    {
        key_import_param_public.key_param.ecc_pubkey_param.Q = &q[1];
        key_import_param_public.key_param.ecc_pubkey_param.size_Q = grp->nbits;
    }
#endif
    err = KeystoreMgmt_FindImportSlot(&key_import_param_public, pubKeyHandle);
    if(err != KEYMGMT_ERR_SUCCESS)
    {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

cleanup:

	/* Free and Zeroize Public key q */
	if(NULL != q)
	{
		mbedtls_platform_zeroize(q, size_q);
		mbedtls_free(q);
		q = NULL;
	}

	return (ret);
}

/*==================================================================================================
*                                       GLOBAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
 * Description: Import a point from unsigned binary data
************************************************************************************************/
int nxp_hse_ecp_point_read_binary( const mbedtls_ecp_group *grp,
                                   mbedtls_ecp_point *pt,
								   const unsigned char *buf, size_t ilen )
{
    int ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    size_t plen;
    NXP_HSE_ECC_VALIDATE_RET( grp != NULL );
    NXP_HSE_ECC_VALIDATE_RET( pt  != NULL );
    NXP_HSE_ECC_VALIDATE_RET( buf != NULL );

    if( ilen < 1 )
    {
    	return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    }

    plen = mbedtls_mpi_size( &grp->P );

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_MONTGOMERY )
    {
        if( plen != ilen )
            return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

        MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary_le( &pt->X, buf, plen ) );
        mbedtls_mpi_free( &pt->Y );

        MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &pt->Z, 1 ) );
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
    {
        if( buf[0] == 0x00 )
        {
            if( ilen == 1 )
                return( mbedtls_ecp_set_zero( pt ) );
            else
                return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
        }

        if( buf[0] != 0x04 )
            return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );

        if( ilen != 2 * plen + 1 )
            return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

        MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &pt->X, buf + 1, plen ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &pt->Y,
                                                  buf + 1 + plen, plen ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &pt->Z, 1 ) );
    }
#endif

cleanup:
    return( ret );
}

/*************************************************************************************************
 * Description: This function loads ECC key-pair, returns public and private key-handles
************************************************************************************************/
int nxp_hse_ecc_loadkey(nxp_hse_ecc_ops_t ops, uint8_t hseEccCurveId, mbedtls_ecp_group *grp,
						const mbedtls_ecp_point *Qp, const mbedtls_ecp_point *Q,
						const mbedtls_mpi *d, hseKeyHandle_t *pubKeyHandle,
						hseKeyHandle_t *prvKeyHandle, int (*f_rng)(void *, unsigned char *, size_t),
						void *p_rng )
{
    int ret = 0;

    /* Get the private or public key handles based on the operations */
    switch(ops)
    {
    	case EC_OPS_SHAREDSECRET:
    		ret = shared_secret_loadkey(hseEccCurveId, grp, Qp, d, pubKeyHandle, prvKeyHandle, f_rng, p_rng);
    		break;
		case EC_OPS_SIGN:
			ret = sign_loadkey(hseEccCurveId, grp, Q, d, prvKeyHandle);
			break;
		case EC_OPS_VERIFY:
			ret = verify_loadkey(hseEccCurveId, grp, Q, pubKeyHandle);
			break;
		default:
			ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
			break;
    }

    return( ret );
}

/*************************************************************************************************
 * Description: This function Exports ECC Public Key
************************************************************************************************/
int nxp_hse_ecc_export_public_key(mbedtls_ecp_group *grp,  hseKeyHandle_t KeyHandle , mbedtls_ecp_point *pt)
{
	uint8_t *pN = NULL;
	uint32_t pNLen = 0U;
	uint8_t hseEccCurveId = 0U;
	uint16_t keyBitLen = 0U;
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

	switch(	grp->id )
	{
		case MBEDTLS_ECP_DP_NONE :
			hseEccCurveId = HSE_EC_CURVE_NONE ;
			break ;
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
#ifdef HSE_SPT_EC_448_CURVE448
        case MBEDTLS_ECP_DP_CURVE448 :
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
				return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
			}
			else
			{
				/* Load User Curve Id into hseEccCurveId */
				hseEccCurveId = grp->userCurveId;
			}
            break;
		default:
			return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA ) ;
	}

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_MONTGOMERY )
    {
        /* Allocate memory of Public key length */
    	pNLen = mbedtls_mpi_size( &grp->P );
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
    {
        /* Allocate memory of Public key length + 1 (for uncompressed key format) */
    	pNLen = 2 * BITS_TO_BYTES(grp->pbits) + 1;
    }
#endif

	pN = mbedtls_calloc(1, pNLen);
	if(pN == NULL)
	{
		/* Return error */
		return( MBEDTLS_ERR_MPI_ALLOC_FAILED );
	}

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_MONTGOMERY )
    {
    	keyBitLen = BYTES_TO_BITS(pNLen);
    	ret = HSE_ExportEccPubKey(KeyHandle, hseEccCurveId, keyBitLen, pN);
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
    {
    	keyBitLen = grp->nbits;
    	ret = HSE_ExportEccPubKey(KeyHandle, hseEccCurveId, keyBitLen, &pN[1]);
    }
#endif

	/* Export Public key */
	if(HSE_SRV_RSP_OK == ret)
	{
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
		if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
		{
			/* Set First byte as 4 for uncompressed Public Key */
			pN[0] = 0x04;
		}
#endif
		/* Copy Public key to the pt */
		ret = nxp_hse_ecp_point_read_binary(grp, pt, pN, pNLen);
		if(NO_ERROR != ret)
		{
			/* Failed to copy public key to pt */
			 ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
		}
	}
	else
	{
		/* Failed to export public key */
		ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
	}

	if(NULL != pN)
	{
		/* Zeroize Public Key */
		mbedtls_platform_zeroize(pN, pNLen);

		/* Free Memory Buffer */
		mbedtls_free( pN );

		/* Initialize to NULL */
		pN = NULL;
	}

	return( ret );
}

/*************************************************************************************************
 * Description: Unload ECC RAM key
************************************************************************************************/
void nxp_hse_ecc_unloadkey( hseKeyHandle_t KeyHandle )
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

/*************************************************************************************************
 * Description: Unload ECC RAM key from group
************************************************************************************************/
void nxp_hse_ecc_free(mbedtls_ecp_group *grp)
{
	/* Simple sanity check */
    if( grp == NULL)
    {
    	return;
    }

    nxp_hse_ecc_unloadkey(grp->keyHandle);

    grp->keyHandle = HSE_INVALID_KEY_HANDLE;
}

/*************************************************************************************************
 * Description: Load User curve on HSE from ecp grp
************************************************************************************************/
int nxp_hse_ecc_loadusercurve(mbedtls_ecp_group *grp)
{
	/* Return value */
	int ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
	KeymgmtErrCodeT err = KEYMGMT_ERR_SUCCESS;
	size_t olen = 0U;
	uint8_t grp_hdl = 0U;
	uint8_t *pA = NULL,*pB = NULL,*pP = NULL,*pN = NULL, *pG = NULL;
	size_t size_A = 0U, size_B = 0U, size_P = 0U, size_N = 0U, size_G = 0U;
	load_ecc_group_param_t EccUserCurve;

	/* Assign user ecc curve ID based on grp->id */
	switch(grp->id)
	{
	case MBEDTLS_ECP_DP_SECP192R1 :
		EccUserCurve.EccCurveId = SECP192R1;
		break;
	case MBEDTLS_ECP_DP_SECP224R1 :
		EccUserCurve.EccCurveId = SECP224R1;
		break;
	case MBEDTLS_ECP_DP_SECP192K1 :
		EccUserCurve.EccCurveId = SECP192K1;
		break;
	case MBEDTLS_ECP_DP_SECP224K1 :
		EccUserCurve.EccCurveId = SECP224K1;
		break;
	case MBEDTLS_ECP_DP_SECP256K1 :
		EccUserCurve.EccCurveId = SECP256K1;
		break;
	/* Montgomery curve parameters cannot be loaded by HSE Load ECC service */
	case MBEDTLS_ECP_DP_CURVE25519 :
	case MBEDTLS_ECP_DP_CURVE448 :
	default:
		ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
		goto cleanup;
	}

	/* Get HSE User Curve ID */
	grp_hdl = KeystoreMgmt_UserECCGroupGetHandle(&EccUserCurve);
	if(grp_hdl == INVALID_GRP_HANDLE)
	{
		/* Return MBEDTLS_ERR_ECP_HW_ACCEL_FAILED if grp_hdl is INVALID_GRP_HANDLE */
		ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
		goto cleanup;
	}

	/* Calculate size of curve components */
	size_A = mbedtls_mpi_size(&grp->A);
	size_B = mbedtls_mpi_size(&grp->B);
	size_P = mbedtls_mpi_size(&grp->P);
	size_N = mbedtls_mpi_size(&grp->N);

	/* HSE expects an array of size 2 * #HSE_BITS_TO_BYTES(#pBitLen) and
	 *  1 byte for uncompressed format */
	size_G = (BITS_TO_BYTES(grp->pbits)*2U+1U);

	/* Allocate memory */
	if(size_A != grp->pbits)
	{
		size_A = size_P;
	}
	if(size_B != grp->pbits)
	{
		size_B = size_P;
	}

	pA = mbedtls_calloc(1,size_A);
	if(NULL == pA)
	{
		ret = MBEDTLS_ERR_ECP_ALLOC_FAILED;
		goto cleanup;
	}

	pB = mbedtls_calloc(1,size_B);
	if(NULL == pB)
	{
		ret = MBEDTLS_ERR_ECP_ALLOC_FAILED;
		goto cleanup;
	}

	pP = mbedtls_calloc(1,size_P);
	if(NULL == pP)
	{
		ret = MBEDTLS_ERR_ECP_ALLOC_FAILED;
		goto cleanup;
	}

	pN = mbedtls_calloc(1,size_N);
	if(NULL == pN)
	{
		ret = MBEDTLS_ERR_ECP_ALLOC_FAILED;
		goto cleanup;
	}

	pG = mbedtls_calloc(1,size_G);
	if(NULL == pG)
	{
		ret = MBEDTLS_ERR_ECP_ALLOC_FAILED;
		goto cleanup;
	}

	/* Convert curve components from mpi to binary form */
	MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&grp->A, pA, size_A));
	MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&grp->B, pB, size_B));
	MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&grp->P, pP, size_P));
	MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&grp->N, pN, size_N));
	MBEDTLS_MPI_CHK(mbedtls_ecp_point_write_binary(grp, &grp->G,\
			MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pG, size_G));

	/* Allocate and load ECC curve Parameters */
	EccUserCurve.ecc_load_user_curve_param.eccCurveId = grp_hdl;
	EccUserCurve.ecc_load_user_curve_param.pBitLen = grp->pbits;
	EccUserCurve.ecc_load_user_curve_param.nBitLen = grp->nbits;
	EccUserCurve.ecc_load_user_curve_param.pA = pA;
	EccUserCurve.ecc_load_user_curve_param.pB = pB;
	EccUserCurve.ecc_load_user_curve_param.pP = pP;
	EccUserCurve.ecc_load_user_curve_param.pN = pN;
	EccUserCurve.ecc_load_user_curve_param.pG = &pG[1];

	/* Load User curve components onto HSE */
	err = KeystoreMgmt_UserECCGroupAllocate(EccUserCurve);
	if(err != KEYMGMT_ERR_SUCCESS)
	{
		/* Return error */
		ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
	}
	else
	{
		/* Load the HSE User defined curve Id to userCurveId in group */
		grp->userCurveId = grp_hdl;
		ret = 0U;
	}

cleanup:
	if(NULL != pA)
	{
		mbedtls_free(pA);
	}
	if(NULL != pB)
	{
		mbedtls_free(pB);
	}
	if(NULL != pP)
	{
		mbedtls_free(pP);
	}
	if(NULL != pN)
	{
		mbedtls_free(pN);
	}
	if(NULL != pG)
	{
		mbedtls_free(pG);
	}

	/* Return the service response */
	return( ret );
}

#endif /* MBEDTLS_ECP_ALT && MBEDTLS_USE_NXP_HSE_CRYPTO */
