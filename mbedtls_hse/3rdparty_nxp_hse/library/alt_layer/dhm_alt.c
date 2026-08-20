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

#if defined(MBEDTLS_DHM_C)

#include <string.h>
#include "mbedtls/dhm.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "keystore_mgmt.h"
#include "hse_host_km_gen_key.h"
#include "nxp_hse_dhm.h"

#if defined(MBEDTLS_PEM_PARSE_C)
#include "mbedtls/pem.h"
#endif

#if defined(MBEDTLS_ASN1_PARSE_C)
#include "mbedtls/asn1.h"
#endif

#if defined(MBEDTLS_DHM_ALT)
/*==================================================================================================
*                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL MACROS
==================================================================================================*/
#define DHM_ALT_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_DHM_BAD_INPUT_DATA )
#define DHM_ALT_VALIDATE( cond )        \
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

/*************************************************************************************************
* Description: helper to validate the mbedtls_mpi size and import it
************************************************************************************************/
static int dhm_read_bignum( mbedtls_mpi *X,
                            unsigned char **p,
                            const unsigned char *end )
{
    int ret, n;

    if( end - *p < 2 )
        return( MBEDTLS_ERR_DHM_BAD_INPUT_DATA );

    n = ( (*p)[0] << 8 ) | (*p)[1];
    (*p) += 2;

    if( (int)( end - *p ) < n )
        return( MBEDTLS_ERR_DHM_BAD_INPUT_DATA );

    if( ( ret = mbedtls_mpi_read_binary( X, *p, n ) ) != 0 )
        return( MBEDTLS_ERR_DHM_READ_PARAMS_FAILED + ret );

    (*p) += n;

    return( 0 );
}

/*************************************************************************************************
* Description: Verify sanity of parameter with regards to P
* 				Parameter should be: 2 <= public_param <= P - 2
* 				This means that we need to return an error if
* 				public_param < 2 or public_param > P-2
* 				For more information on the attack, see:
* 				http://www.cl.cam.ac.uk/~rja14/Papers/psandqs.pdf
* 				http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2005-2643
************************************************************************************************/
static int dhm_check_range( const mbedtls_mpi *param, const mbedtls_mpi *P )
{
    mbedtls_mpi L, U;
    int ret = 0;

    mbedtls_mpi_init( &L ); mbedtls_mpi_init( &U );

    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &L, 2 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &U, P, 2 ) );

    if( mbedtls_mpi_cmp_mpi( param, &L ) < 0 ||
        mbedtls_mpi_cmp_mpi( param, &U ) > 0 )
    {
        ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
    }

cleanup:
    mbedtls_mpi_free( &L ); mbedtls_mpi_free( &U );
    return( ret );
}

#if defined(MBEDTLS_ASN1_PARSE_C)
#if defined(MBEDTLS_FS_IO)

/*************************************************************************************************
* Description: Load all data from a file into a given buffer.
* 				The file is expected to contain either PEM or DER encoded data.
* 				A terminating null byte is always appended. It is included in the announced
* 				length only if the data looks like it is PEM encoded.
************************************************************************************************/
static int load_file( const char *path, unsigned char **buf, size_t *n )
{
    FILE *f;
    long size;

    if( ( f = fopen( path, "rb" ) ) == NULL )
        return( MBEDTLS_ERR_DHM_FILE_IO_ERROR );

    fseek( f, 0, SEEK_END );
    if( ( size = ftell( f ) ) == -1 )
    {
        fclose( f );
        return( MBEDTLS_ERR_DHM_FILE_IO_ERROR );
    }
    fseek( f, 0, SEEK_SET );

    *n = (size_t) size;

    if( *n + 1 == 0 ||
        ( *buf = mbedtls_calloc( 1, *n + 1 ) ) == NULL )
    {
        fclose( f );
        return( MBEDTLS_ERR_DHM_ALLOC_FAILED );
    }

    if( fread( *buf, 1, *n, f ) != *n )
    {
        fclose( f );

        mbedtls_platform_zeroize( *buf, *n + 1 );
        mbedtls_free( *buf );

        return( MBEDTLS_ERR_DHM_FILE_IO_ERROR );
    }

    fclose( f );

    (*buf)[*n] = '\0';

    if( strstr( (const char *) *buf, "-----BEGIN " ) != NULL )
        ++*n;

    return( 0 );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_ASN1_PARSE_C */
/*==================================================================================================
*                                       GLOBAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
* Description: Initialize DH context
************************************************************************************************/
void mbedtls_dhm_init( mbedtls_dhm_context *ctx )
{
    DHM_ALT_VALIDATE( ctx != NULL );
    memset( ctx, 0, sizeof( mbedtls_dhm_context ) );
}

/*************************************************************************************************
* Description: Parse the ServerKeyExchange parameters
************************************************************************************************/
int mbedtls_dhm_read_params( mbedtls_dhm_context *ctx,
                     unsigned char **p,
                     const unsigned char *end )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    DHM_ALT_VALIDATE_RET( ctx != NULL );
    DHM_ALT_VALIDATE_RET( p != NULL && *p != NULL );
    DHM_ALT_VALIDATE_RET( end != NULL );

    if( ( ret = dhm_read_bignum( &ctx->P,  p, end ) ) != 0 ||
        ( ret = dhm_read_bignum( &ctx->G,  p, end ) ) != 0 ||
        ( ret = dhm_read_bignum( &ctx->GY, p, end ) ) != 0 )
        return( ret );

    if( ( ret = dhm_check_range( &ctx->GY, &ctx->P ) ) != 0 )
        return( ret );

    ctx->len = mbedtls_mpi_size( &ctx->P );

    return( 0 );
}

/*************************************************************************************************
* Description: Setup and write the ServerKeyExchange parameters
************************************************************************************************/
int mbedtls_dhm_make_params( mbedtls_dhm_context *ctx, int x_size,
                     unsigned char *output, size_t *olen,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
    int ret = 0;
    size_t n1, n2, n3;
    unsigned char *p;
	uint8_t *pG = NULL, *pMod = NULL, *pPub = NULL;
	uint32_t size_G = 0U, size_Mod = 0U, size_Pub = 0U;
	hseKeyHandle_t keyHandle = HSE_INVALID_KEY_HANDLE;
	key_import_param_t key_import_param = {0};
	key_gen_param_t key_gen_param = {0};

	/* Input param validity check */
    DHM_ALT_VALIDATE_RET( ctx != NULL );
    DHM_ALT_VALIDATE_RET( output != NULL );
    DHM_ALT_VALIDATE_RET( olen != NULL );
    DHM_ALT_VALIDATE_RET( f_rng != NULL );

    (void) p_rng;
    (void) f_rng;

    if( mbedtls_mpi_cmp_int( &ctx->P, 0 ) == 0 )
    {
    	return( MBEDTLS_ERR_DHM_BAD_INPUT_DATA );
    }

	/* Get the Base G and its len */
	size_G = mbedtls_mpi_size( &ctx->G  );
	if(size_G != 0)
	{
		pG = mbedtls_calloc(1, size_G);
		if( NULL == pG)
		{
			/* Unable to allocate memory */
			ret = MBEDTLS_ERR_DHM_ALLOC_FAILED;
			goto cleanup;
		}

		ret = mbedtls_mpi_write_binary(&ctx->G, pG, size_G);
		if( NO_ERROR != ret )
		{
			ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
			goto cleanup;
		}
	}
	else
	{
		ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
		goto cleanup;
	}

    /* get the size of Prime modulus and public key */
    size_Mod = x_size;
	size_Pub = x_size;

	if(x_size != 0)
	{
		/* Get Prime Modulus */
		pMod = mbedtls_calloc(1, size_Mod);
		if( NULL == pMod )
		{
			/* Unable to allocate memory */
			ret = MBEDTLS_ERR_DHM_ALLOC_FAILED;
			goto cleanup;
		}

		ret = mbedtls_mpi_write_binary(&ctx->P, pMod, size_Mod);
		if( NO_ERROR != ret )
		{
			ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
			goto cleanup;
		}

		/* allocate buffer for public key */
		pPub = mbedtls_calloc(1, size_Pub);
		if( NULL == pPub)
		{
			ret = MBEDTLS_ERR_DHM_ALLOC_FAILED;
			goto cleanup;
		}
	}
	else
	{
		ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
		goto cleanup;
	}

    /* Allocate the DHM key pair key slot*/
	key_import_param.key_type 							= HSE_KEY_TYPE_DH_PAIR;
	key_import_param.key_catalog 						= HSE_KEY_CATALOG_ID_RAM;
	key_import_param.key_param.dh_keypair_param.pubLen 	= BYTES_TO_BITS( size_Pub );
	if(KEYMGMT_ERR_SUCCESS != KeystoreMgmt_FindAllocateSlot(&key_import_param, &keyHandle))
	{
		/* Unable to get key pair handle */
		ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
		goto cleanup;
	}

    /* Generate the DH Key pair and get the public key */
	key_gen_param.key_catalog 									= HSE_KEY_CATALOG_ID_RAM;
	key_gen_param.key_type 										= HSE_KEY_TYPE_DH_PAIR;
	key_gen_param.key_param.dh_keypair_gen_param.baseGLength	= size_G;
	key_gen_param.key_param.dh_keypair_gen_param.pBaseG			= pG;
	key_gen_param.key_param.dh_keypair_gen_param.modulusLength	= size_Mod;
	key_gen_param.key_param.dh_keypair_gen_param.pModulus		= pMod;
	key_gen_param.key_param.dh_keypair_gen_param.pPubKey		= pPub;
	if(KEYMGMT_ERR_SUCCESS == KeystoreMgmt_Genkey(keyHandle, &key_gen_param))
	{
		/* Import X from unsigned binary data, big endian */
		ret = mbedtls_mpi_read_binary(&ctx->GX, pPub, size_Pub);
		if( NO_ERROR != ret )
		{
			ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
			goto cleanup;
		}

		/* Copy Private key handle to Private key mpi X */
		MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&ctx->X, (mbedtls_mpi_sint)keyHandle));

		/* Copy private key handle to DH context */
		ctx->keyHandle = keyHandle;
	}
	else
	{
		ret = MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED;
		goto cleanup;
	}

    /*
     * export P, G, GX
     */
#define DHM_MPI_EXPORT( X, n )                                          \
    do {                                                                \
        MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( ( X ),               \
                                                   p + 2,               \
                                                   ( n ) ) );           \
        *p++ = (unsigned char)( ( n ) >> 8 );                           \
        *p++ = (unsigned char)( ( n )      );                           \
        p += ( n );                                                     \
    } while( 0 )

    n1 = mbedtls_mpi_size( &ctx->P  );
    n2 = mbedtls_mpi_size( &ctx->G  );
    n3 = mbedtls_mpi_size( &ctx->GX );

    p = output;
    DHM_MPI_EXPORT( &ctx->P , n1 );
    DHM_MPI_EXPORT( &ctx->G , n2 );
    DHM_MPI_EXPORT( &ctx->GX, n3 );

    *olen = p - output;

    ctx->len = n1;

cleanup:

	if(pG != NULL)
	{
		mbedtls_free(pG);
		pG = NULL;
	}

	if(pMod != NULL)
	{
		mbedtls_free(pMod);
		pMod = NULL;
	}

	if(pPub != NULL)
	{
		/* Zeroize Public key buffer */
		mbedtls_platform_zeroize(pPub, size_Pub);
		mbedtls_free(pPub);
		pPub = NULL;
	}

    return( ret );
}

/*************************************************************************************************
* Description: Set prime modulus and generator
************************************************************************************************/
int mbedtls_dhm_set_group( mbedtls_dhm_context *ctx,
                           const mbedtls_mpi *P,
                           const mbedtls_mpi *G )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    DHM_ALT_VALIDATE_RET( ctx != NULL );
    DHM_ALT_VALIDATE_RET( P != NULL );
    DHM_ALT_VALIDATE_RET( G != NULL );

    if( ( ret = mbedtls_mpi_copy( &ctx->P, P ) ) != 0 ||
        ( ret = mbedtls_mpi_copy( &ctx->G, G ) ) != 0 )
    {
        return( MBEDTLS_ERR_DHM_SET_GROUP_FAILED + ret );
    }

    ctx->len = mbedtls_mpi_size( &ctx->P );
    return( 0 );
}

/*************************************************************************************************
* Description: Import the peer's public value G^Y
************************************************************************************************/
int mbedtls_dhm_read_public( mbedtls_dhm_context *ctx,
                     const unsigned char *input, size_t ilen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    DHM_ALT_VALIDATE_RET( ctx != NULL );
    DHM_ALT_VALIDATE_RET( input != NULL );

    if( ilen < 1 || ilen > ctx->len )
        return( MBEDTLS_ERR_DHM_BAD_INPUT_DATA );

    if( ( ret = mbedtls_mpi_read_binary( &ctx->GY, input, ilen ) ) != 0 )
        return( MBEDTLS_ERR_DHM_READ_PUBLIC_FAILED + ret );

    return( 0 );
}

/*************************************************************************************************
* Description: Create own private value X and export G^X
************************************************************************************************/
int mbedtls_dhm_make_public( mbedtls_dhm_context *ctx, int x_size,
                     unsigned char *output, size_t olen,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
	int ret = 0;
	uint8_t *pG = NULL, *pMod = NULL, *pPub = NULL;
	uint32_t size_G = 0U, size_Mod = 0U, size_Pub = 0U;
	hseKeyHandle_t keyHandle = HSE_INVALID_KEY_HANDLE;
	key_import_param_t key_import_param = {0};
	key_gen_param_t key_gen_param = {0};

	/* Input params validity check */
    DHM_ALT_VALIDATE_RET( ctx != NULL );
    DHM_ALT_VALIDATE_RET( output != NULL );
    DHM_ALT_VALIDATE_RET( f_rng != NULL );

    if( olen < 1 || olen > ctx->len )
    {
    	return( MBEDTLS_ERR_DHM_BAD_INPUT_DATA );
    }

    if( mbedtls_mpi_cmp_int( &ctx->P, 0 ) == 0 )
    {
    	return( MBEDTLS_ERR_DHM_BAD_INPUT_DATA );
    }

	(void) p_rng;
	(void) f_rng;

	/* Get Base G and its len */
	size_G = mbedtls_mpi_size( &ctx->G  );
	if(size_G != 0)
	{
		pG = mbedtls_calloc(1, size_G);
		if( NULL == pG)
		{
			ret = MBEDTLS_ERR_DHM_ALLOC_FAILED;
			goto cleanup;
		}

		ret = mbedtls_mpi_write_binary(&ctx->G, pG, size_G);
		if( NO_ERROR != ret )
		{
			ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
			goto cleanup;
		}
	}
	else
	{
		ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
		goto cleanup;
	}

	/* get the size of Prime modulus and public key */
	size_Mod = x_size;
	size_Pub = x_size;

	if( x_size != 0)
	{
		/* Get Prime Modulus */
		pMod = mbedtls_calloc(1, size_Mod);
		if( NULL == pMod )
		{
			ret = MBEDTLS_ERR_DHM_ALLOC_FAILED;
			goto cleanup;
		}

		ret = mbedtls_mpi_write_binary(&ctx->P, pMod, size_Mod);
		if( NO_ERROR != ret )
		{
			ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
			goto cleanup;
		}

		/* allocate buffer for public key */
		pPub = mbedtls_calloc(1, size_Pub);
		if( NULL == pPub)
		{
			ret = MBEDTLS_ERR_DHM_ALLOC_FAILED;
			goto cleanup;
		}
	}
	else
	{
		ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
		goto cleanup;
	}

    /* Allocate the DHM key pair key slot*/
	key_import_param.key_type 							= HSE_KEY_TYPE_DH_PAIR;
	key_import_param.key_catalog 						= HSE_KEY_CATALOG_ID_RAM;
	key_import_param.key_param.dh_keypair_param.pubLen 	= BYTES_TO_BITS( size_Pub );
	if(KEYMGMT_ERR_SUCCESS != KeystoreMgmt_FindAllocateSlot(&key_import_param, &keyHandle))
	{
		/* Unable to get key pair handle */
		ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
		goto cleanup;
	}

    /* Generate the Key pair and export the public key */
	key_gen_param.key_catalog 									= HSE_KEY_CATALOG_ID_RAM;
	key_gen_param.key_type 										= HSE_KEY_TYPE_DH_PAIR;
	key_gen_param.key_param.dh_keypair_gen_param.baseGLength	= size_G;
	key_gen_param.key_param.dh_keypair_gen_param.pBaseG			= pG;
	key_gen_param.key_param.dh_keypair_gen_param.modulusLength	= size_Mod;
	key_gen_param.key_param.dh_keypair_gen_param.pModulus		= pMod;
	key_gen_param.key_param.dh_keypair_gen_param.pPubKey		= pPub;
	if(KEYMGMT_ERR_SUCCESS == KeystoreMgmt_Genkey(keyHandle, &key_gen_param))
	{
		/* Import X from unsigned binary data, big endian */
		ret = mbedtls_mpi_read_binary(&ctx->GX, pPub, size_Pub);
		if( NO_ERROR != ret )
		{
			ret = MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED;
			goto cleanup;
		}

		/* Copy Private key handle to Private key mpi X */
		MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&ctx->X, (mbedtls_mpi_sint)keyHandle));

		/* Copy private key handle to DH context */
		ctx->keyHandle = keyHandle;
	}
	else
	{
		ret = MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED;
		goto cleanup;
	}

    if( ( ret = dhm_check_range( &ctx->GX, &ctx->P ) ) != 0 )
    {
    	ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
    	goto cleanup;
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->GX, output, olen ) );

cleanup:

	if(pG != NULL)
	{
		mbedtls_free(pG);
		pG = NULL;
	}

	if(pMod != NULL)
	{
		mbedtls_free(pMod);
		pMod = NULL;
	}

	if(pPub != NULL)
	{
		/* Zeroize Public key buffer */
		mbedtls_platform_zeroize(pPub, size_Mod);
		mbedtls_free(pPub);
		pPub = NULL;
	}

    return( ret );
}

/*************************************************************************************************
* Description: Derive and export the shared secret (G^Y)^X mod P
************************************************************************************************/
int mbedtls_dhm_calc_secret( mbedtls_dhm_context *ctx,
                     unsigned char *output, size_t output_size, size_t *olen,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
    int ret = 0;
	KeymgmtErrCodeT err;
	key_import_param_t key_import_param_shared = {0};
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
	hseKeyHandle_t peerKeyhandle = HSE_INVALID_KEY_HANDLE;
	hseKeyHandle_t sharedSecretKeyHandle = HSE_INVALID_KEY_HANDLE;
	hseKeyHandle_t prvKeyhandle = HSE_INVALID_KEY_HANDLE;

	(void)f_rng;
	(void)p_rng;

	/* Input param validity check */
    DHM_ALT_VALIDATE_RET( ctx != NULL );
    DHM_ALT_VALIDATE_RET( output != NULL );
    DHM_ALT_VALIDATE_RET( olen != NULL );

    if( output_size < ctx->len )
        return( MBEDTLS_ERR_DHM_BAD_INPUT_DATA );

    if( ( ret = dhm_check_range( &ctx->GY, &ctx->P ) ) != 0 )
        return( ret );

    /* Load own Public and Private key, load peers public key, get key handles */
    ret = nxp_dhm_loadkey(ctx, &peerKeyhandle, &prvKeyhandle);
    if( NO_ERROR == ret )
    {
		/* Compute shared secret key */
		key_import_param_shared.key_type 						= HSE_KEY_TYPE_SHARED_SECRET;
		key_import_param_shared.key_catalog 					= HSE_KEY_CATALOG_ID_RAM;
		key_import_param_shared.key_param.sym_key_param.size 	= BYTES_TO_BITS(ctx->len);

		err = KeystoreMgmt_FindAllocateSlot(&key_import_param_shared, &sharedSecretKeyHandle);
		if(KEYMGMT_ERR_SUCCESS == err )
		{
			/* Send the request */
			srvResponse = HSE_GenerateDhSharedSecret(prvKeyhandle, peerKeyhandle, sharedSecretKeyHandle );

			if(HSE_SRV_RSP_OK == srvResponse)
			{
#if defined (MBEDTLS_DEBUG_C)
					mbedtls_printf("\nPrivate keyHandle 0x%02x | Peer KeyHandle : 0x%02x |"
							" Shared Secret KeyHandle 0x%02x|\n", prvKeyhandle, peerKeyhandle, sharedSecretKeyHandle );
#endif /* MBEDTLS_DEBUG_C */
				/* Copy shared secret key handle to Shared secret mpi z */
				ret = mbedtls_mpi_lset(&ctx->K, (mbedtls_mpi_sint)sharedSecretKeyHandle );
				if( NO_ERROR != ret )
				{
					ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
					goto cleanup;
				}
			}
			else
			{
				ret = MBEDTLS_ERR_DHM_CALC_SECRET_FAILED;
				goto cleanup;
			}
		}
		else
		{
			ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
#if defined (MBEDTLS_DEBUG_C)
			mbedtls_printf("%s:%d:returned %d (-0x%04x)\n", __FILE__, __LINE__, ret, (unsigned int) -ret );
#endif /* MBEDTLS_DEBUG_C */
			goto cleanup;
		}
    }
	else
	{
		ret = MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
#if defined (MBEDTLS_DEBUG_C)
		mbedtls_printf("%s:%d:returned %d (-0x%04x)\n", __FILE__, __LINE__, ret, (unsigned int) -ret );
#endif /* MBEDTLS_DEBUG_C */
		goto cleanup;
	}

    *olen = mbedtls_mpi_size( &ctx->K );

    /* Get Pre-master secret */
	memcpy(output, ctx->K.p, sizeof(hseKeyHandle_t));

cleanup:

	/* Unload peer public key */
	nxp_hse_dhm_unloadkey(peerKeyhandle);

	return( ret );
}

/*************************************************************************************************
* Description: Free the components of a DHM key
************************************************************************************************/
void mbedtls_dhm_free( mbedtls_dhm_context *ctx )
{
    if( ctx == NULL )
        return;

    //TODO: Check better to free keyhandles
    /* unload private key handle */
    nxp_hse_dhm_unloadkey((hseKeyHandle_t)ctx->keyHandle);

    mbedtls_mpi_free( &ctx->pX );
    mbedtls_mpi_free( &ctx->Vf );
    mbedtls_mpi_free( &ctx->Vi );
    mbedtls_mpi_free( &ctx->RP );
    mbedtls_mpi_free( &ctx->K  );
    mbedtls_mpi_free( &ctx->GY );
    mbedtls_mpi_free( &ctx->GX );
    mbedtls_mpi_free( &ctx->X  );
    mbedtls_mpi_free( &ctx->G  );
    mbedtls_mpi_free( &ctx->P  );

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_dhm_context ) );
}

#if defined(MBEDTLS_ASN1_PARSE_C)
/*************************************************************************************************
* Description: Parse DHM parameters
************************************************************************************************/
int mbedtls_dhm_parse_dhm( mbedtls_dhm_context *dhm, const unsigned char *dhmin,
                   size_t dhminlen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    unsigned char *p, *end;
#if defined(MBEDTLS_PEM_PARSE_C)
    mbedtls_pem_context pem;
#endif /* MBEDTLS_PEM_PARSE_C */

    DHM_ALT_VALIDATE_RET( dhm != NULL );
    DHM_ALT_VALIDATE_RET( dhmin != NULL );

#if defined(MBEDTLS_PEM_PARSE_C)
    mbedtls_pem_init( &pem );

    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if( dhminlen == 0 || dhmin[dhminlen - 1] != '\0' )
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    else
        ret = mbedtls_pem_read_buffer( &pem,
                               "-----BEGIN DH PARAMETERS-----",
                               "-----END DH PARAMETERS-----",
                               dhmin, NULL, 0, &dhminlen );

    if( ret == 0 )
    {
        /*
         * Was PEM encoded
         */
        dhminlen = pem.buflen;
    }
    else if( ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
        goto exit;

    p = ( ret == 0 ) ? pem.buf : (unsigned char *) dhmin;
#else
    p = (unsigned char *) dhmin;
#endif /* MBEDTLS_PEM_PARSE_C */
    end = p + dhminlen;

    /*
     *  DHParams ::= SEQUENCE {
     *      prime              INTEGER,  -- P
     *      generator          INTEGER,  -- g
     *      privateValueLength INTEGER OPTIONAL
     *  }
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        ret = MBEDTLS_ERR_DHM_INVALID_FORMAT + ret;
        goto exit;
    }

    end = p + len;

    if( ( ret = mbedtls_asn1_get_mpi( &p, end, &dhm->P  ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( &p, end, &dhm->G ) ) != 0 )
    {
        ret = MBEDTLS_ERR_DHM_INVALID_FORMAT + ret;
        goto exit;
    }

    if( p != end )
    {
        /* This might be the optional privateValueLength.
         * If so, we can cleanly discard it */
        mbedtls_mpi rec;
        mbedtls_mpi_init( &rec );
        ret = mbedtls_asn1_get_mpi( &p, end, &rec );
        mbedtls_mpi_free( &rec );
        if ( ret != 0 )
        {
            ret = MBEDTLS_ERR_DHM_INVALID_FORMAT + ret;
            goto exit;
        }
        if ( p != end )
        {
            ret = MBEDTLS_ERR_DHM_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
            goto exit;
        }
    }

    ret = 0;

    dhm->len = mbedtls_mpi_size( &dhm->P );

exit:
#if defined(MBEDTLS_PEM_PARSE_C)
    mbedtls_pem_free( &pem );
#endif
    if( ret != 0 )
        mbedtls_dhm_free( dhm );

    return( ret );
}

#if defined(MBEDTLS_FS_IO)
/*************************************************************************************************
* Description: Load and parse DHM parameters
************************************************************************************************/
int mbedtls_dhm_parse_dhmfile( mbedtls_dhm_context *dhm, const char *path )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n;
    unsigned char *buf;
    DHM_ALT_VALIDATE_RET( dhm != NULL );
    DHM_ALT_VALIDATE_RET( path != NULL );

    if( ( ret = load_file( path, &buf, &n ) ) != 0 )
        return( ret );

    ret = mbedtls_dhm_parse_dhm( dhm, buf, n );

    mbedtls_platform_zeroize( buf, n );
    mbedtls_free( buf );

    return( ret );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_ASN1_PARSE_C */
#endif /* MBEDTLS_DHM_ALT */
#endif /* MBEDTLS_DHM_C */
