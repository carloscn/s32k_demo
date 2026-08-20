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

#if defined(MBEDTLS_RSA_ALT)
#include <string.h>
#include <mbedtls/platform.h>
#include "mbedtls/rsa_internal.h"

#include "mbedtls/error.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/rsa.h"
#include "mbedtls/oid.h"
#include "keystore_mgmt.h"
#include "device.h"
#include "hse_host_sign.h"
#include "global_variables.h"

/*==================================================================================================
*                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL MACROS
==================================================================================================*/

/* Parameter validation macros. */
#define RSA_ALT_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_RSA_BAD_INPUT_DATA )
#define RSA_ALT_VALIDATE( cond )        \
    MBEDTLS_INTERNAL_VALIDATE( cond )

#define LE_TO_BE32(x)	((((x)&0xFF)<<24)|(((x)&0xFF00)<<8)|(((x)&0xFF0000)>>8)|(((x)&0xFF000000)>>24))

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

#define CRYPTO_43_HSE_START_SEC_VAR_CLEARED_UNSPECIFIED_NO_CACHEABLE
#include "Crypto_43_HSE_MemMap.h"
key_import_param_t key_import_param;
#define CRYPTO_43_HSE_STOP_SEC_VAR_CLEARED_UNSPECIFIED_NO_CACHEABLE
#include "Crypto_43_HSE_MemMap.h"
/*==================================================================================================
*                                   LOCAL FUNCTION PROTOTYPES
==================================================================================================*/

/**
 * 	@brief		Checks whether the context fields are set in such a way
 * 				that the RSA primitives will be able to execute without error.
 * 				It does *not* make guarantees for consistency of the parameters.
 *
 * 	@param[in]	ctx
 *				The RSA Context
 *
 * 	@param[in]	is_priv
 *				is_priv set for private key operation
 *
 *	@param[in]	blinding_needed
 *				blinding_needed is only used for NO_CRT to decide whether P,Q need to be present or not
 *
 *  @return		\c 0 on success.
 *
 *	@return		#MBEDTLS_ERR_RSA_BAD_INPUT_DATA for bad input
 *
 */
static int rsa_check_context( mbedtls_rsa_context const *ctx, int is_priv,
							  int blinding_needed );

/**
 * 	@brief		This function loads RSA key-pair, returns public and private key-handles in ctx
 *
 * 	@param[in]	ctx
 *				The RSA Context
 *
 * 	@param[in]	mode
 *				MBEDTLS_RSA_PUBLIC or MBEDTLS_RSA_PRIVATE
 *
 *  @return		\c 0 on success.
 *
 *	@return		#MBEDTLS_ERR_RSA_BAD_INPUT_DATA for bad input
 *				MBEDTLS_ERR_MPI_ALLOC_FAILED for memory allocation failure
 *
 */
static int mbedtls_rsa_loadkey(mbedtls_rsa_context *ctx, int mode);

/**
 * 	@brief		This function unloads RSA key-pair
 *
 * 	@param[in]	ctx
 *				The RSA Context
 *
 * 	@param[in]	mode
 *				MBEDTLS_RSA_PUBLIC or MBEDTLS_RSA_PRIVATE
 *
 *  @return		void
 *
 */
static void mbedtls_rsa_unloadkey(mbedtls_rsa_context *ctx, int mode);

/**
 * 	@brief		Turn zero-or-nonzero into zero-or-all-bits-one, without branches.
 *
 * 	@param[in]	value
 *				The value to analyze.
 *
 *  @return		0 if \p value is zero, otherwise all-bits-one.
 *
 */
static unsigned all_or_nothing_int( unsigned value );

/**
 * 	@brief	 	Check whether a size is out of bounds, without branches.
 * 	 			This is equivalent to `size > max`, but is likely to be compiled to
 * 				to code using bitwise operation rather than a branch.
 *
 * 	@param[in]	size
 *				Size to check.
 *
 * 	@param[in]	max
 *			    Maximum desired value for \p size.
 *
 *  @return		\c 0 if `size <= max`.
 *  @return     \c 1 if `size > max`.
 *
 */
static unsigned size_greater_than( size_t size, size_t max );

/**
 * 	@brief		Choose between two integer values, without branches.
 * 				This is equivalent to `cond ? if1 : if0`, but is likely to be compiled
 * 				to code using bitwise operation rather than a branch.
 *
 * 	@param[in]	cond
 *				Condition to test.
 *
 * 	@param[in]	if1
 *				Value to use if \p cond is nonzero.
 *
 *  @param[in]	if0
 *				Value to use if \p cond is zero.
 *
 *  @return		\c if1 if \p cond is nonzero, otherwise \c if0.
 *
 */
static unsigned if_int( unsigned cond, unsigned if1, unsigned if0 );

/**
 * 	@brief		Shift some data towards the left inside a buffer without leaking
 * 				the length of the data through side channels.
 *
 *				`mem_move_to_left(start, total, offset)` is functionally equivalent to
 * 				```
 * 				memmove(start, start + offset, total - offset);
 * 				memset(start + offset, 0, total - offset);
 * 				```
 * 				but it strives to use a memory access pattern (and thus total timing)
 * 				that does not depend on \p offset. This timing independence comes at
 * 				the expense of performance.
 *
 * 	@param[in]	start
 *				Pointer to the start of the buffer.
 *
 * 	@param[in]	total
 *				Total size of the buffer.
 *
 *  @return		offset
 *				Offset from which to copy \p total - \p offset bytes.
 *
 *	@return		void
 *
 */
static void mem_move_to_left( void *start, size_t total, size_t offset );

/**
 * 	@brief		constant-time buffer comparison
 *
 * 	@param[in]	a
 *				The pointer to a block of memory.
 *
 * 	@param[in]	b
 *				The pointer to a block of memory.
 *
 * @param[in]	n
 *			    The number of bytes to be compared.
 *
 *  @return		difference between a and b.
 *
 */
static inline int mbedtls_safer_memcmp( const void *a, const void *b, size_t n );

/**
 * 	@brief		Construct a PKCS v1.5 encoding of a hashed message
 * 				This is used both for signature generation and verification.
 *
 * 	@param[in]	md_alg
 *				Identifies the hash algorithm used to generate the given hash;
 *				MBEDTLS_MD_NONE if raw data is signed.
 *
 * 	@param[in]	hashlen
 *				Length of hash in case hashlen is MBEDTLS_MD_NONE.
 *
 * @param[in]	hash
 *				Buffer containing the hashed message or the raw data.
 *
 * 	@param[in]	dst_len
 *				Length of the encoded message.
 *
 *  @param[in]	dst
 *				Buffer to hold the encoded message.
 *
 *  @return		\c 0 on success.
 *
 *	@return		#MBEDTLS_ERR_RSA_BAD_INPUT_DATA for bad input
 *
 * Assumptions:
 * - hash has size hashlen if md_alg == MBEDTLS_MD_NONE.
 * - hash has size corresponding to md_alg if md_alg != MBEDTLS_MD_NONE.
 * - dst points to a buffer of size at least dst_len.
 *
 */
static int rsa_rsassa_pkcs1_v15_encode_check( mbedtls_md_type_t md_alg,
                                        unsigned int hashlen,
                                        const unsigned char *hash,
                                        size_t dst_len,
                                        unsigned char *dst );

#if defined(MBEDTLS_PKCS1_V21) && defined(MBEDTLS_USE_NXP_HSE_PKCS21_VERIFY_WORKAROUND)
/**
 * 	@brief		Generate and apply the MGF1 operation (from PKCS#1 v2.1) to a buffer.
 *
 * 	@param[in]	dst
 *				buffer to mask
 *
 * 	@param[in]	dlen
 *				length of destination buffer
 *
 * @param[in]	src
 *			    source of the mask generation
 *
 *	@param[in]	slen
 *				length of the source buffer
 *
 * 	@param[in]	md_ctx
 *				message digest context to use
 *
 *  @return		\c 0 on success.
 *  			error code on failure
 *
 */
static int mgf_mask( unsigned char *dst, size_t dlen, unsigned char *src,
                      size_t slen, mbedtls_md_context_t *md_ctx );
#endif/* MBEDTLS_PKCS1_V21 && MBEDTLS_USE_NXP_HSE_PKCS21_VERIFY_WORKAROUND */

/*==================================================================================================
*                                       LOCAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
* Description:  Checks whether the context fields are set in such a way
 * 				that the RSA primitives will be able to execute without error.
 * 				It does *not* make guarantees for consistency of the parameters.
************************************************************************************************/
static int rsa_check_context( mbedtls_rsa_context const *ctx, int is_priv,
							  int blinding_needed )
{
#if !defined(MBEDTLS_RSA_NO_CRT)
	/* blinding_needed is only used for NO_CRT to decide whether
	 * P,Q need to be present or not. */
	((void) blinding_needed);
#endif

	if( ctx->len != mbedtls_mpi_size( &ctx->N ) ||
		ctx->len > MBEDTLS_MPI_MAX_SIZE )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

	/*
	 * 1. Modular exponentiation needs positive, odd moduli.
	 */

	/* Modular exponentiation wrt. N is always used for
	 * RSA public key operations. */
	if( mbedtls_mpi_cmp_int( &ctx->N, 0 ) <= 0 ||
		mbedtls_mpi_get_bit( &ctx->N, 0 ) == 0	)
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

#if !defined(MBEDTLS_RSA_NO_CRT)
	/* Modular exponentiation for P and Q is only
	 * used for private key operations and if CRT
	 * is used. */
	if( is_priv &&
		( mbedtls_mpi_cmp_int( &ctx->P, 0 ) <= 0 ||
		  mbedtls_mpi_get_bit( &ctx->P, 0 ) == 0 ||
		  mbedtls_mpi_cmp_int( &ctx->Q, 0 ) <= 0 ||
		  mbedtls_mpi_get_bit( &ctx->Q, 0 ) == 0  ) )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}
#endif /* !MBEDTLS_RSA_NO_CRT */

	/*
	 * 2. Exponents must be positive
	 */

	/* Always need E for public key operations */
	if( mbedtls_mpi_cmp_int( &ctx->E, 0 ) <= 0 )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

	/* 
		If key of type HSE_KEY_TYPE_RSA_PAIR is already loaded then we must not check 
		for private key components as they might not be present if key is loaded from outside
	*/
	if(is_priv && 
		(KeystoreMgmt_GetKeyType(ctx->keyHandle)== HSE_KEY_TYPE_RSA_PAIR))
	{
		return ( 0 );
	}
	
#if defined(MBEDTLS_RSA_NO_CRT)
	/* For private key operations, use D or DP & DQ
	 * as (unblinded) exponents. */
	if( is_priv && mbedtls_mpi_cmp_int( &ctx->D, 0 ) <= 0 )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}
#else
	if( is_priv &&
		( mbedtls_mpi_cmp_int( &ctx->DP, 0 ) <= 0 ||
		  mbedtls_mpi_cmp_int( &ctx->DQ, 0 ) <= 0  ) )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}
#endif /* MBEDTLS_RSA_NO_CRT */

	/* Blinding shouldn't make exponents negative either,
	 * so check that P, Q >= 1 if that hasn't yet been
	 * done as part of 1. */
#if defined(MBEDTLS_RSA_NO_CRT)
	if( is_priv && blinding_needed &&
		( mbedtls_mpi_cmp_int( &ctx->P, 0 ) <= 0 ||
		  mbedtls_mpi_cmp_int( &ctx->Q, 0 ) <= 0 ) )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}
#endif

	/* It wouldn't lead to an error if it wasn't satisfied,
	 * but check for QP >= 1 nonetheless. */
#if !defined(MBEDTLS_RSA_NO_CRT)
	if( is_priv &&
		mbedtls_mpi_cmp_int( &ctx->QP, 0 ) <= 0 )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}
#endif

	return( 0 );
}

/*************************************************************************************************
 * Description: This function loads RSA key-pair, returns public and private key-handles in ctx
************************************************************************************************/
static int mbedtls_rsa_loadkey(mbedtls_rsa_context *ctx, int mode)
{
	int ret = NO_ERROR;
	KeymgmtErrCodeT err;
	uint32_t size_N, size_E, size_D;
	unsigned char *N = NULL, *E = NULL, *D = NULL;
//	key_import_param_t key_import_param;
	
	/* Check for key already loaded */
	if(ctx->keyHandle != HSE_INVALID_KEY_HANDLE)
	{
		return( ret );
	}

	memset(&key_import_param, 0x00, sizeof(key_import_param_t));

	do 
	{
		/* Allocate Memory Buffer for N & E */
		size_N = mbedtls_mpi_size(&ctx->N);

		if(size_N < BITS_TO_BYTES(HSE_KEY1024_BITS))
		{
			return ( MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION );
		}

		size_E = mbedtls_mpi_size(&ctx->E);
		
		N = (uint8_t*)mbedtls_calloc( 1, size_N); 
		E = (uint8_t*)mbedtls_calloc( 1, size_E);
		if((N == NULL) || (E == NULL))
		{
			/* Return error */
			ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
			break;
		}

		/* Copy mpi structure to binary */
		mbedtls_mpi_write_binary(&ctx->N, N, size_N);
		mbedtls_mpi_write_binary(&ctx->E, E, size_E);
		
		/* Load the key based upon operation */
		if(mode == MBEDTLS_RSA_PUBLIC)
		{			
			/* Load Public Key */
			key_import_param.key_type = HSE_KEY_TYPE_RSA_PUB;
			key_import_param.key_catalog = HSE_KEY_CATALOG_ID_RAM;
			key_import_param.key_param.rsa_pubkey_param.N = N;
			key_import_param.key_param.rsa_pubkey_param.E = E;
			key_import_param.key_param.rsa_pubkey_param.size_N = BYTES_TO_BITS(size_N);
			key_import_param.key_param.rsa_pubkey_param.size_E = size_E;
		}
		else if(mode == MBEDTLS_RSA_PRIVATE)
		{
		
			/* Allocate Memory Buffer for D */
			size_D = mbedtls_mpi_size(&ctx->D);
			
			D = (uint8_t*)mbedtls_calloc( 1, size_D);
			
			if (NULL == D)
			{
				/* Return error */
				ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
				break;
			}
			
			/* Copy mpi structure to binary */
			mbedtls_mpi_write_binary(&ctx->D, D, size_D);
			
			/* Load Public Key */
			key_import_param.key_type = HSE_KEY_TYPE_RSA_PAIR;
			key_import_param.key_catalog = HSE_KEY_CATALOG_ID_NVM;
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

		err = KeystoreMgmt_FindImportSlot(&key_import_param, &ctx->keyHandle);
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
		mbedtls_free(N);
	}

	if (NULL != E)
	{
		mbedtls_free(E);
	}

	if (NULL != D)
	{
		mbedtls_free(D);		
	}

	return (ret);
}

/*************************************************************************************************
 * Description: This function unloads RSA key-pair
************************************************************************************************/
static void mbedtls_rsa_unloadkey(mbedtls_rsa_context *ctx, int mode)
{
	(void) mode;

	/* Check for key not loaded */
	if(ctx->keyHandle == HSE_INVALID_KEY_HANDLE)
	{
		return;
	}

	/* Load the key based upon operation */
//	if(ctx->privkey_flag == 0)
	{
		(void)KeyStoreMgmt_FreeKey(ctx->keyHandle);
		ctx->keyHandle = HSE_INVALID_KEY_HANDLE;
	}

	return;
}

#if defined(MBEDTLS_PKCS1_V15)
/*************************************************************************************************
 * Description: Turn zero-or-nonzero into zero-or-all-bits-one, without branches.
************************************************************************************************/
static unsigned all_or_nothing_int( unsigned value )
{
    /* MSVC has a warning about unary minus on unsigned, but this is
     * well-defined and precisely what we want to do here */
#if defined(_MSC_VER)
#pragma warning( push )
#pragma warning( disable : 4146 )
#endif
    return( - ( ( value | - value ) >> ( sizeof( value ) * 8 - 1 ) ) );
#if defined(_MSC_VER)
#pragma warning( pop )
#endif
}

/*************************************************************************************************
 * Description: Check whether a size is out of bounds, without branches.
 * This is equivalent to `size > max`, but is likely to be compiled to
 * to code using bitwise operation rather than a branch.
************************************************************************************************/
static unsigned size_greater_than( size_t size, size_t max )
{
    /* Return the sign bit (1 for negative) of (max - size). */
    return( ( max - size ) >> ( sizeof( size_t ) * 8 - 1 ) );
}

/*************************************************************************************************
 * Description: Choose between two integer values, without branches.
 * This is equivalent to `cond ? if1 : if0`, but is likely to be compiled
 * to code using bitwise operation rather than a branch.
************************************************************************************************/
static unsigned if_int( unsigned cond, unsigned if1, unsigned if0 )
{
    unsigned mask = all_or_nothing_int( cond );
    return( ( mask & if1 ) | (~mask & if0 ) );
}

/*************************************************************************************************
 * Description: Shift some data towards the left inside a buffer without leaking
 * the length of the data through side channels.
************************************************************************************************/
static void mem_move_to_left( void *start,
                              size_t total,
                              size_t offset )
{
    volatile unsigned char *buf = start;
    size_t i, n;
    if( total == 0 )
    {
    	return;
    }

    for( i = 0; i < total; i++ )
    {
        unsigned no_op = size_greater_than( total - offset, i );
        /* The first `total - offset` passes are a no-op. The last
         * `offset` passes shift the data one byte to the left and
         * zero out the last byte. */
        for( n = 0; n < total - 1; n++ )
        {
            unsigned char current = buf[n];
            unsigned char next = buf[n+1];
            buf[n] = if_int( no_op, current, next );
        }

        buf[total-1] = if_int( no_op, buf[total-1], 0 );
    }
}

#endif /* MBEDTLS_PKCS1_V15 */
#if defined(MBEDTLS_PKCS1_V15)
/*************************************************************************************************
 * Description: Constant-time buffer comparison
************************************************************************************************/
static inline int mbedtls_safer_memcmp( const void *a, const void *b, size_t n )
{
    size_t i;
    const unsigned char *A = (const unsigned char *) a;
    const unsigned char *B = (const unsigned char *) b;
    unsigned char diff = 0;

    for( i = 0; i < n; i++ )
    {
    	diff |= A[i] ^ B[i];
    }

    return( diff );
}

/*************************************************************************************************
 * Description: Implementation of the PKCS#1 v2.1 RSASSA-PKCS1-V1_5-SIGN function
 *  Construct a PKCS v1.5 encoding of a hashed message.
 *  This is used both for signature generation and verification.
************************************************************************************************/
static int rsa_rsassa_pkcs1_v15_encode_check( mbedtls_md_type_t md_alg,
                                        unsigned int hashlen,
                                        const unsigned char *hash,
                                        size_t dst_len,
                                        unsigned char *dst )
{
    size_t oid_size  = 0;
    size_t nb_pad    = dst_len;
    unsigned char *p = dst;
    const char *oid  = NULL;

    /* Are we signing hashed or raw data? */
    if( md_alg != MBEDTLS_MD_NONE )
    {
        const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type( md_alg );
        if( md_info == NULL )
        {
        	return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
        }

        if( mbedtls_oid_get_oid_by_md( md_alg, &oid, &oid_size ) != 0 )
        {
        	return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
        }

        hashlen = mbedtls_md_get_size( md_info );

        /* Double-check that 8 + hashlen + oid_size can be used as a
         * 1-byte ASN.1 length encoding and that there's no overflow. */
        if( 8 + hashlen + oid_size  >= 0x80         ||
            10 + hashlen            <  hashlen      ||
            10 + hashlen + oid_size <  10 + hashlen )
        {
        	return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
        }

        /*
         * Static bounds check:
         * - Need 10 bytes for five tag-length pairs.
         *   (Insist on 1-byte length encodings to protect against variants of
         *    Bleichenbacher's forgery attack against lax PKCS#1v1.5 verification)
         * - Need hashlen bytes for hash
         * - Need oid_size bytes for hash alg OID.
         */
        if( nb_pad < 10 + hashlen + oid_size )
        {
        	return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
        }

        nb_pad -= 10 + hashlen + oid_size;
		return ( 0 );
    }
    else
    {
        if( nb_pad < hashlen )
        {
        	return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
        }

        nb_pad -= hashlen;
    }

    /* Need space for signature header and padding delimiter (3 bytes),
     * and 8 bytes for the minimal padding */
    if( nb_pad < 3 + 8 )
    {
    	return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }

    nb_pad -= 3;

    /* Now nb_pad is the amount of memory to be filled
     * with padding, and at least 8 bytes long. */

    /* Write signature header and padding */
    *p++ = 0;
    *p++ = MBEDTLS_RSA_SIGN;
    memset( p, 0xFF, nb_pad );
    p += nb_pad;
    *p++ = 0;

    /* Are we signing raw data? */
    if( md_alg == MBEDTLS_MD_NONE )
    {
        memcpy( p, hash, hashlen );
        return( 0 );
    }

    return( 0 );
}
#endif /* MBEDTLS_PKCS1_V15 */

#if defined(MBEDTLS_PKCS1_V21) && defined(MBEDTLS_USE_NXP_HSE_PKCS21_VERIFY_WORKAROUND)
/*************************************************************************************************
 * Description: Generate and apply the MGF1 operation (from PKCS#1 v2.1) to a buffer.
************************************************************************************************/
static int mgf_mask( unsigned char *dst, size_t dlen, unsigned char *src,
                      size_t slen, mbedtls_md_context_t *md_ctx )
{
    unsigned char mask[MBEDTLS_MD_MAX_SIZE];
    unsigned char counter[4];
    unsigned char *p;
    unsigned int hlen;
    size_t i, use_len;
    int ret = 0;

    memset( mask, 0, MBEDTLS_MD_MAX_SIZE );
    memset( counter, 0, 4 );

    hlen = mbedtls_md_get_size( md_ctx->md_info );

    /* Generate and apply dbMask */
    p = dst;

    while( dlen > 0 )
    {
        use_len = hlen;
        if( dlen < hlen )
            use_len = dlen;

        if( ( ret = mbedtls_md_starts( md_ctx ) ) != 0 )
            goto exit;
        if( ( ret = mbedtls_md_update( md_ctx, src, slen ) ) != 0 )
            goto exit;
        if( ( ret = mbedtls_md_update( md_ctx, counter, 4 ) ) != 0 )
            goto exit;
        if( ( ret = mbedtls_md_finish( md_ctx, mask ) ) != 0 )
            goto exit;

        for( i = 0; i < use_len; ++i )
            *p++ ^= mask[i];

        counter[3]++;

        dlen -= use_len;
    }

exit:
    mbedtls_platform_zeroize( mask, sizeof( mask ) );

    return( ret );
}
#endif /* MBEDTLS_PKCS1_V21 && MBEDTLS_USE_NXP_HSE_PKCS21_VERIFY_WORKAROUND */

/*==================================================================================================
*                                       GLOBAL FUNCTIONS
==================================================================================================*/
/*************************************************************************************************
* Description:  This function initializes the specified RSA context.
************************************************************************************************/
void mbedtls_rsa_init( mbedtls_rsa_context *ctx,
                       int padding,
                       int hash_id )
{
	/* Simple sanity check */
    RSA_ALT_VALIDATE( ctx != NULL ) ;
    RSA_ALT_VALIDATE( (padding == MBEDTLS_RSA_PKCS_V15) ||
                      (padding == MBEDTLS_RSA_PKCS_V21) ) ;

    memset( ctx, 0, sizeof( mbedtls_rsa_context ) );

    mbedtls_rsa_set_padding( ctx, padding, hash_id ) ;
	ctx->keyHandle = HSE_INVALID_KEY_HANDLE;
}

/*************************************************************************************************
* Description:  Set padding for an existing RSA context.
************************************************************************************************/
void mbedtls_rsa_set_padding( mbedtls_rsa_context *ctx, int padding,
                              int hash_id )
{
	/* Simple sanity check */
	RSA_ALT_VALIDATE( ctx != NULL ) ;

    ctx->padding = padding ;
    ctx->hash_id = hash_id ;
}

/*************************************************************************************************
* Description: Get length in bytes of RSA modulus.
************************************************************************************************/
size_t mbedtls_rsa_get_len( const mbedtls_rsa_context *ctx )
{
    return( ctx->len );
}

#if defined(MBEDTLS_GENPRIME)
/*************************************************************************************************
* Description:  Generate an RSA keypair.
************************************************************************************************/
int mbedtls_rsa_gen_key( mbedtls_rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         unsigned int nbits, int exponent )
{
	KeymgmtErrCodeT err;
	hseKeyHandle_t keyhandle = HSE_INVALID_KEY_HANDLE;
	uint8_t *pN = NULL;
//	key_import_param_t key_import_param;
	uint32_t modlen;
	uint32_t exp_bigendian;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    RSA_ALT_VALIDATE_RET( ctx != NULL );
    RSA_ALT_VALIDATE_RET( f_rng != NULL );

	(void) f_rng;
	(void) p_rng;
	
	memset(&key_import_param, 0x00, sizeof(key_import_param_t));

    if( nbits < 128 || exponent < 3 || nbits % 2 != 0 )
    {
    	return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }

	if(nbits < 1024)
	{
		return ( MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION );
	}

	/* Import Exponent */
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &ctx->E, exponent ) );

	do
	{
		/* Find Target Key Handle */
		key_import_param.key_type = HSE_KEY_TYPE_RSA_PAIR;			
		key_import_param.key_catalog = HSE_KEY_CATALOG_ID_NVM;		
		key_import_param.key_param.rsa_keypair_param.N_len = nbits;

		err = KeystoreMgmt_FindAllocateSlot(&key_import_param, &keyhandle);
		if(err != KEYMGMT_ERR_SUCCESS)
		{
			ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
			break;
		}

		/* Declare the scheme */
		/* Public Key Modulus exported outside */
		modlen = (nbits+7U)>>3;
		pN = mbedtls_calloc(modlen, 1);
		if(pN == NULL)
		{
			ret = MBEDTLS_ERR_RSA_KEY_GEN_FAILED;
			break;
		}

		/* Convert exponent to big endian form */
		exp_bigendian = LE_TO_BE32(exponent);
		key_gen_param_t key_gen_param = {	\
			.key_catalog = HSE_KEY_CATALOG_ID_NVM,
			.key_type = HSE_KEY_TYPE_RSA_PAIR,
			.key_param.rsa_keypair_gen_param.keybitlen = nbits,
			.key_param.rsa_keypair_gen_param.eLen = sizeof(exp_bigendian),
			.key_param.rsa_keypair_gen_param.pE = (const uint8_t *)&exp_bigendian,
			.key_param.rsa_keypair_gen_param.pN = pN
		};

		/* Send the request to HSE to generate RSA keypair */
		err = KeystoreMgmt_Genkey(keyhandle, &key_gen_param);
		if(err == KEYMGMT_ERR_SUCCESS)
		{
			mbedtls_mpi_read_binary(&ctx->N, pN, modlen);
			ctx->keyHandle = keyhandle;
			ctx->len = mbedtls_mpi_size( &ctx->N );
			ctx->privkey_flag = 1U;
			ret = NO_ERROR;
		}
		else
		{
			ret = MBEDTLS_ERR_RSA_KEY_GEN_FAILED;
		}
	}while ( 0 );

cleanup:
	if(pN != NULL)
	{
		mbedtls_free(pN);
		pN = NULL;
	}
	if (ret != NO_ERROR)
	{
		mbedtls_rsa_free(ctx);
	}

	/* Return the response */
	return( ret ) ;
}
#endif /* MBEDTLS_GENPRIME */

#if defined(MBEDTLS_PKCS1_V15)
/*************************************************************************************************
* Description: Implementation of the PKCS#1 v1.5 RSAES-PKCS1-V1_5-ENCRYPT function.
************************************************************************************************/
int mbedtls_rsa_rsaes_pkcs1_v15_encrypt( mbedtls_rsa_context *ctx,
										 int (*f_rng)(void *, unsigned char *, size_t),
										 void *p_rng,
										 int mode, size_t ilen,
										 const unsigned char *input,
										 unsigned char *output )
{
	hseSrvResponse_t srvResponse;
	bool_t isKeyLoadedImplicitly = false;
	uint32_t olen;
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	size_t nb_pad;
	unsigned char *p = output;

	/* Unused parameters */
	(void)f_rng;
	(void)p_rng;

	RSA_ALT_VALIDATE_RET( ctx != NULL );
	RSA_ALT_VALIDATE_RET( mode == MBEDTLS_RSA_PRIVATE ||
					  mode == MBEDTLS_RSA_PUBLIC );
	RSA_ALT_VALIDATE_RET( output != NULL );
	RSA_ALT_VALIDATE_RET( ilen == 0 || input != NULL );

	if( mode == MBEDTLS_RSA_PRIVATE && ctx->padding != MBEDTLS_RSA_PKCS_V15 )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

	/* Output length = length of Public Key Modulus */
	olen = ctx->len;

	/* first comparison checks for overflow */
	if( (ilen + 11 < ilen) || (olen < ilen + 11) )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

	do
	{
		if(MBEDTLS_RSA_PUBLIC == mode)
		{
			/*Check if Key handle is valid (i.e. Key was loaded @ host explicitly) else Key handle will be loaded implicitly after getting the Keys in HSE*/
			if(ctx->keyHandle == HSE_INVALID_KEY_HANDLE)
			{
				isKeyLoadedImplicitly = true;
			}
			/* Load Key */
			if(NO_ERROR != (ret = mbedtls_rsa_loadkey(ctx, mode)))
			{
				ret = MBEDTLS_ERR_RSA_PUBLIC_FAILED + ret;
				break;
			}

			/* Perform RSA Encrypt operation */
			/* Send the request */
			srvResponse = HSE_RsaEsPkcs_v1_5(HSE_CIPHER_DIR_ENCRYPT, ctx->keyHandle, input,
					(uint32_t)ilen, (uint8_t *)output, &olen);
			switch(srvResponse)
			{
				case HSE_SRV_RSP_OK:
					/* Return with NO_ERROR on success */
					ret = NO_ERROR ;
					break;
				case HSE_SRV_RSP_INVALID_PARAM:
				default:
					ret = MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
					break;
			}
		}
		else
		{
			/* When Mode is PRIVATE */
			nb_pad = olen - 3 - ilen;

			/* Prepare EM */
			*p++ = 0;
			*p++ = MBEDTLS_RSA_SIGN;

			while( nb_pad-- > 0 )
			{
				*p++ = 0xFF;
			}

			*p++ = 0;

			if( ilen != 0 )
			{
				memcpy( p, input, ilen );
			}
			/* Perform Private Key Operation */
			ret = mbedtls_rsa_private( ctx, f_rng, p_rng, output, output );
		}
	}while(0);

	if(isKeyLoadedImplicitly==true)
	{
		isKeyLoadedImplicitly = 0;
		/* Unload key */
		mbedtls_rsa_unloadkey(ctx, mode);
	}
	
	return ret ;
}

/*************************************************************************************************
* Description:  Implementation of the PKCS#1 v1.5 RSAES-PKCS1-V1_5-DECRYPT function.
************************************************************************************************/
int mbedtls_rsa_rsaes_pkcs1_v15_decrypt( mbedtls_rsa_context *ctx,
										 int (*f_rng)(void *, unsigned char *, size_t),
										 void *p_rng,
										 int mode, size_t *olen,
										 const unsigned char *input,
										 unsigned char *output,
										 size_t output_max_len )
{

	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	bool_t isKeyLoadedImplicitly = false;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
	size_t ilen, i, plaintext_max_size;
	unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
	/* The following variables take sensitive values: their value must
	 * not leak into the observable behavior of the function other than
	 * the designated outputs (output, olen, return value). Otherwise
	 * this would open the execution of the function to
	 * side-channel-based variants of the Bleichenbacher padding oracle
	 * attack. Potential side channels include overall timing, memory
	 * access patterns (especially visible to an adversary who has access
	 * to a shared memory cache), and branches (especially visible to
	 * an adversary who has access to a shared code cache or to a shared
	 * branch predictor). */
	size_t pad_count = 0;
	unsigned bad = 0;
	unsigned char pad_done = 0;
	uint32_t plaintext_size = 0;
	unsigned output_too_large;
	

	RSA_ALT_VALIDATE_RET( ctx != NULL );
	RSA_ALT_VALIDATE_RET( mode == MBEDTLS_RSA_PRIVATE ||
					  mode == MBEDTLS_RSA_PUBLIC );
	RSA_ALT_VALIDATE_RET( output_max_len == 0 || output != NULL );
	RSA_ALT_VALIDATE_RET( input != NULL );
	RSA_ALT_VALIDATE_RET( olen != NULL );

	/* Unused parameters */
	(void)f_rng;
	(void)p_rng;

	ilen = ctx->len;
	plaintext_max_size = ( output_max_len > ilen - 11 ? ilen - 11 : output_max_len );

	if( (mode == MBEDTLS_RSA_PRIVATE) && (ctx->padding != MBEDTLS_RSA_PKCS_V15) )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

	if( ilen < 16 || ilen > MBEDTLS_MPI_MAX_SIZE )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

	if(output_max_len == 0)
	{
		/* Do nothing and simply return */
		*olen = output_max_len;
		return ( NO_ERROR );
	}

	/* Set Output length to max length */
	plaintext_size = output_max_len;

	do
	{
		if(MBEDTLS_RSA_PRIVATE == mode)
		{
			/*Check if Key handle is valid (i.e. Key was loaded @ host explicitly) else Key handle will be loaded implicitly after getting the Keys in HSE*/
			if(ctx->keyHandle == HSE_INVALID_KEY_HANDLE)
			{
				isKeyLoadedImplicitly = true;
			}
			/* Load Key */
			if(NO_ERROR != (ret = mbedtls_rsa_loadkey(ctx, mode)))
			{
				ret = MBEDTLS_ERR_RSA_PRIVATE_FAILED + ret;
				break;
			}
			/* Send the request */
			srvResponse = HSE_RsaEsPkcs_v1_5( HSE_CIPHER_DIR_DECRYPT, ctx->keyHandle,
					input, ctx->len,(uint8_t *)output, &plaintext_size) ;

			switch(srvResponse)
			{
				case HSE_SRV_RSP_OK: 
					/* Report the amount of data we copied to the output buffer. In case
					 * of errors (bad padding or output too large), the value of *olen
					 * when this function returns is not specified. Making it equivalent
					 * to the good case limits the risks of leaking the padding validity. */
					*olen = plaintext_size;
					/* Return with NO_ERROR on success */
					ret = NO_ERROR ;
					break;
				case HSE_SRV_RSP_INVALID_PARAM:
				default:
					
					*olen = 0;
					/* Return with Error Codes */
					ret = MBEDTLS_ERR_RSA_PRIVATE_FAILED + MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
					break;
			}
		}
		else
		{
			/* When Mode is PUBLIC */
			ret = mbedtls_rsa_public(ctx, input, buf);
			if(NO_ERROR != ret)
			{
				break;
			}

			/* Check and get padding length in constant time and constant
			 * memory trace. The first byte must be 0. */
			bad |= buf[0];
			{
				/* Decode EMSA-PKCS1-v1_5 padding: 0x00 || 0x01 || PS || 0x00
				 * where PS must be at least 8 bytes with the value 0xFF. */
				bad |= buf[1] ^ MBEDTLS_RSA_SIGN;
			
				/* Read the whole buffer. Set pad_done to nonzero if we find
				 * the 0x00 byte and remember the padding length in pad_count.
				 * If there's a non-0xff byte in the padding, the padding is bad. */
				for( i = 2; i < ilen; i++ )
				{
					pad_done |= if_int( buf[i], 0, 1 );
					pad_count += if_int( pad_done, 0, 1 );
					bad |= if_int( pad_done, 0, buf[i] ^ 0xFF );
				}
			}
			
			/* If pad_done is still zero, there's no data, only unfinished padding. */
			bad |= if_int( pad_done, 0, 1 );
			
			/* There must be at least 8 bytes of padding. */
			bad |= size_greater_than( 8, pad_count );
			
			/* If the padding is valid, set plaintext_size to the number of
			 * remaining bytes after stripping the padding. If the padding
			 * is invalid, avoid leaking this fact through the size of the
			 * output: use the maximum message size that fits in the output
			 * buffer. Do it without branches to avoid leaking the padding
			 * validity through timing. RSA keys are small enough that all the
			 * size_t values involved fit in unsigned int. */
			plaintext_size = if_int( bad,
									 (unsigned) plaintext_max_size,
									 (unsigned) ( ilen - pad_count - 3 ) );
			
			/* Set output_too_large to 0 if the plaintext fits in the output
			 * buffer and to 1 otherwise. */
			output_too_large = size_greater_than( plaintext_size,
												  plaintext_max_size );
			
			/* Set ret without branches to avoid timing attacks. Return:
			 * - INVALID_PADDING if the padding is bad (bad != 0).
			 * - OUTPUT_TOO_LARGE if the padding is good but the decrypted
			 *	 plaintext does not fit in the output buffer.
			 * - 0 if the padding is correct. */
			ret = - (int) if_int( bad, - MBEDTLS_ERR_RSA_INVALID_PADDING,
						  if_int( output_too_large, - MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE,
								  0 ) );
			
			/* If the padding is bad or the plaintext is too large, zero the
			 * data that we're about to copy to the output buffer.
			 * We need to copy the same amount of data
			 * from the same buffer whether the padding is good or not to
			 * avoid leaking the padding validity through overall timing or
			 * through memory or cache access patterns. */
			bad = all_or_nothing_int( bad | output_too_large );
			for( i = 11; i < ilen; i++ )
			{
				buf[i] &= ~bad;
			}
			
			/* If the plaintext is too large, truncate it to the buffer size.
			 * Copy anyway to avoid revealing the length through timing, because
			 * revealing the length is as bad as revealing the padding validity
			 * for a Bleichenbacher attack. */
			plaintext_size = if_int( output_too_large,
									 (unsigned) plaintext_max_size,
									 (unsigned) plaintext_size );
			
			/* Move the plaintext to the leftmost position where it can start in
			 * the working buffer, i.e. make it start plaintext_max_size from
			 * the end of the buffer. Do this with a memory access trace that
			 * does not depend on the plaintext size. After this move, the
			 * starting location of the plaintext is no longer sensitive
			 * information. */
			mem_move_to_left( buf + ilen - plaintext_max_size,
							  plaintext_max_size,
							  plaintext_max_size - plaintext_size );
			
			/* Finally copy the decrypted plaintext plus trailing zeros into the output
			 * buffer. If output_max_len is 0, then output may be an invalid pointer
			 * and the result of memcpy() would be undefined; prevent undefined
			 * behavior making sure to depend only on output_max_len (the size of the
			 * user-provided output buffer), which is independent from plaintext
			 * length, validity of padding, success of the decryption, and other
			 * secrets. */
			if( output_max_len != 0 )
			{
				memcpy( output, buf + ilen - plaintext_max_size, plaintext_max_size );
				*olen = plaintext_size;
			}
		}
	}while(0);

	mbedtls_platform_zeroize( buf, sizeof( buf ) );

	if(isKeyLoadedImplicitly==true)
	{
		isKeyLoadedImplicitly = 0;
		/* Unload key */
		mbedtls_rsa_unloadkey(ctx, mode);
	}
	return( ret );

}
#endif /* MBEDTLS_PKCS1_V15 */

#if defined(MBEDTLS_PKCS1_V21)
/*************************************************************************************************
* Description:  Implementation of the PKCS#1 v2.1 RSAES-OAEP-ENCRYPT function.
************************************************************************************************/
int mbedtls_rsa_rsaes_oaep_encrypt( mbedtls_rsa_context *ctx,
									int (*f_rng)(void *, unsigned char *, size_t),
									void *p_rng,
									int mode,
									const unsigned char *label, size_t label_len,
									size_t ilen,
									const unsigned char *input,
									unsigned char *output )
{
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
	hseHashAlgo_t hash_algo = HSE_HASH_ALGO_NULL;
	bool_t isKeyLoadedImplicitly = false;
	uint32_t olen;
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	unsigned int hlen;
	const mbedtls_md_info_t *md_info;

	RSA_ALT_VALIDATE_RET( ctx != NULL );
	RSA_ALT_VALIDATE_RET( mode == MBEDTLS_RSA_PRIVATE ||
					  mode == MBEDTLS_RSA_PUBLIC );
	RSA_ALT_VALIDATE_RET( output != NULL );
	RSA_ALT_VALIDATE_RET( ilen == 0 || input != NULL );
	RSA_ALT_VALIDATE_RET( label_len == 0 || label != NULL );

	if( (mode == MBEDTLS_RSA_PRIVATE) && (ctx->padding != MBEDTLS_RSA_PKCS_V21) )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

	if( f_rng == NULL )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

	if( mode != MBEDTLS_RSA_PUBLIC)
	{
		return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
	}	
	
	/* Unused Parameters */
	(void)p_rng;

	md_info = mbedtls_md_info_from_type( (mbedtls_md_type_t) ctx->hash_id );
	if( md_info == NULL )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

	olen = ctx->len;
	hlen = mbedtls_md_get_size( md_info );

	/* first comparison checks for overflow */
	if( (ilen + 2 * hlen + 2 < ilen) || (olen < ilen + 2 * hlen + 2) )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

	memset( output, 0, olen );

	/* Choose HSE Supported HASH Algorithm */
	switch(	ctx->hash_id )
	{
#if !defined(S32N55)
		case MBEDTLS_MD_SHA1:
			hash_algo = HSE_HASH_ALGO_SHA_1;
			break ;
#endif
		case MBEDTLS_MD_SHA224:
			hash_algo = HSE_HASH_ALGO_SHA2_224;
			break ;
		case MBEDTLS_MD_SHA256:
			hash_algo = HSE_HASH_ALGO_SHA2_256;
			break ;
		case MBEDTLS_MD_SHA384:
			hash_algo = HSE_HASH_ALGO_SHA2_384;
			break ;
		case MBEDTLS_MD_SHA512:
			hash_algo = HSE_HASH_ALGO_SHA2_512;
			break ;
		case MBEDTLS_MD_MD5:
		case MBEDTLS_MD_MD2:
		case MBEDTLS_MD_MD4:
		case MBEDTLS_MD_RIPEMD160:
			return ( MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION );
		default:
			return ( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

	do
	{
		/*Check if Key handle is valid (i.e. Key was loaded @ host explicitly) else Key handle will be loaded implicitly after getting the Keys in HSE*/
		if(ctx->keyHandle == HSE_INVALID_KEY_HANDLE)
		{
			isKeyLoadedImplicitly = true;
		}
		/* Load Key */
		ret = mbedtls_rsa_loadkey(ctx, mode);
		if(ret != NO_ERROR)
		{
			break;
		}
		/* Send the request */
		srvResponse = HSE_RsaEsOaep(hash_algo, HSE_CIPHER_DIR_ENCRYPT, ctx->keyHandle, (uint8_t*)label,
				(uint32_t)label_len, (uint8_t*)input, (uint32_t)ilen, (uint8_t*)output, &olen) ;

		if(HSE_SRV_RSP_OK != srvResponse)
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_RSA_HW_ACCEL_FAILED ;
		}
		else
		{
			/* Return with NO_ERROR on success */
			ret = NO_ERROR ;
		}
	} while(0);

	if(isKeyLoadedImplicitly==true)
	{
		isKeyLoadedImplicitly = 0;
		/* Unload key */
		mbedtls_rsa_unloadkey(ctx, mode);
	}

	return( ret ) ;
}

/*************************************************************************************************
* Description:  Implementation of the PKCS#1 v2.1 RSAES-OAEP-DECRYPT function.
************************************************************************************************/
int mbedtls_rsa_rsaes_oaep_decrypt( mbedtls_rsa_context *ctx,
									int (*f_rng)(void *, unsigned char *, size_t),
									void *p_rng,
									int mode,
									const unsigned char *label, size_t label_len,
									size_t *olen,
									const unsigned char *input,
									unsigned char *output,
									size_t output_max_len )
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	bool_t isKeyLoadedImplicitly = false;
	size_t ilen;
	unsigned int hlen;
	const mbedtls_md_info_t *md_info;
	hseSrvResponse_t srvResponse;
	hseHashAlgo_t hash_algo = HSE_HASH_ALGO_NULL;
	uint32_t output_length;

	RSA_ALT_VALIDATE_RET( ctx != NULL );
	RSA_ALT_VALIDATE_RET( mode == MBEDTLS_RSA_PRIVATE ||
					  mode == MBEDTLS_RSA_PUBLIC );
	RSA_ALT_VALIDATE_RET( output_max_len == 0 || output != NULL );
	RSA_ALT_VALIDATE_RET( label_len == 0 || label != NULL );
	RSA_ALT_VALIDATE_RET( input != NULL );
	RSA_ALT_VALIDATE_RET( olen != NULL );

	/* Parameters sanity checks */
	if( (mode == MBEDTLS_RSA_PRIVATE) && (ctx->padding != MBEDTLS_RSA_PKCS_V21) )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

	if(mode != MBEDTLS_RSA_PRIVATE)
	{
		return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
	}

	/* Unused parameters */
	(void)f_rng;
	(void)p_rng;

	ilen = ctx->len;

	if( (ilen < 16) || (ilen > MBEDTLS_MPI_MAX_SIZE) /*sizeof( buf )*/ )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

	md_info = mbedtls_md_info_from_type( (mbedtls_md_type_t) ctx->hash_id );
	if( md_info == NULL )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

	hlen = mbedtls_md_get_size( md_info );

	/* checking for integer underflow */
	if( 2 * hlen + 2 > ilen )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

	if(output_max_len == 0)
	{
		/* Do nothing and simply return */
		*olen = output_max_len;
		return ( NO_ERROR );
	}

	/* Choose HSE Supported HASH Algorithm */
	switch(	ctx->hash_id )
	{
#if  !defined(S32N55)
		case MBEDTLS_MD_SHA1:
			hash_algo = HSE_HASH_ALGO_SHA_1;
			break ;
#endif
		case MBEDTLS_MD_SHA224:
			hash_algo = HSE_HASH_ALGO_SHA2_224;
			break ;
		case MBEDTLS_MD_SHA256:
			hash_algo = HSE_HASH_ALGO_SHA2_256;
			break ;
		case MBEDTLS_MD_SHA384:
			hash_algo = HSE_HASH_ALGO_SHA2_384;
			break ;
		case MBEDTLS_MD_SHA512:
			hash_algo = HSE_HASH_ALGO_SHA2_512 ;
			break ;
		case MBEDTLS_MD_MD5:
		case MBEDTLS_MD_MD2:
		case MBEDTLS_MD_MD4:
		case MBEDTLS_MD_RIPEMD160:
			return ( MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION );
		default:
			return ( MBEDTLS_ERR_RSA_BAD_INPUT_DATA ) ;
	}

	do
	{
		/*Check if Key handle is valid (i.e. Key was loaded @ host explicitly) else Key handle will be loaded implicitly after getting the Keys in HSE*/
		if(ctx->keyHandle == HSE_INVALID_KEY_HANDLE)
		{
			isKeyLoadedImplicitly = true;
		}
		/* Load Key */
		ret = mbedtls_rsa_loadkey(ctx, mode);
		if(ret != NO_ERROR)
		{
			break;
		}

		output_length = output_max_len;

		/* Send the request */
		srvResponse = HSE_RsaEsOaep(hash_algo, HSE_CIPHER_DIR_DECRYPT, ctx->keyHandle, (uint8_t*)label,
				(uint32_t)label_len, (uint8_t*)input, ctx->len, (uint8_t*)output, &output_length) ;

		if(HSE_SRV_RSP_OK != srvResponse)
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_RSA_PRIVATE_FAILED;
		}
		else
		{
			/* Return with NO_ERROR on success */
			*olen = output_length;
			ret = NO_ERROR ;
		}
	}while(0);

	if(isKeyLoadedImplicitly==true)
	{
		isKeyLoadedImplicitly = 0;
		/* Unload key */
		mbedtls_rsa_unloadkey(ctx, mode);
	}

	return( ret ) ;
}
#endif /* MBEDTLS_PKCS1_V21 */

#if defined(MBEDTLS_PKCS1_V15)
/*************************************************************************************************
* Description:  Do an RSA operation to sign the message digest.
************************************************************************************************/
int mbedtls_rsa_rsassa_pkcs1_v15_sign( mbedtls_rsa_context *ctx,
									   int (*f_rng)(void *, unsigned char *, size_t),
									   void *p_rng,
									   int mode,
									   mbedtls_md_type_t md_alg,
									   unsigned int hashlen,
									   const unsigned char *hash,
									   unsigned char *sig )
{
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
	hseHashAlgo_t hash_algo = 0 ;
	uint32_t signLen = 0 ;
	unsigned char *encoded = NULL;
	unsigned char *encoded_expected = NULL;
    bool_t isKeyLoadedImplicitly = false;

    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    RSA_ALT_VALIDATE_RET( ctx != NULL );
    RSA_ALT_VALIDATE_RET( mode == MBEDTLS_RSA_PRIVATE ||
                      mode == MBEDTLS_RSA_PUBLIC );
    RSA_ALT_VALIDATE_RET( ( md_alg  == MBEDTLS_MD_NONE &&
                        hashlen == 0 ) ||
                      hash != NULL );
    RSA_ALT_VALIDATE_RET( sig != NULL );

	if(mode != MBEDTLS_RSA_PRIVATE)
	{
		return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
	}

    if( (mode == MBEDTLS_RSA_PRIVATE) && (ctx->padding != MBEDTLS_RSA_PKCS_V15) )
	{
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

	/* Set Signature length = Public Key Modulus Length */
	signLen = ctx->len;

	do
	{
		if(md_alg == MBEDTLS_MD_NONE)
		{
	    	/* We are operating on Raw Data. So we should be encrypting with public key */
			encoded = mbedtls_calloc(1, signLen);
			encoded_expected = mbedtls_calloc(1, signLen);
			if ((NULL == encoded) || (NULL == encoded_expected))
			{
				ret = MBEDTLS_ERR_RSA_PRIVATE_FAILED + MBEDTLS_ERR_MPI_ALLOC_FAILED;
				break;
			}

			/* Prepare Encoded Buffer for RSA-SSA operation */
			ret = rsa_rsassa_pkcs1_v15_encode_check(md_alg, 
				hashlen, hash, signLen, sig);
			if(ret != NO_ERROR)
			{
				break;
			}

			/* Decrypt the Signature */
			ret = mbedtls_rsa_private(ctx, f_rng, p_rng, sig, encoded_expected);
			if(ret != NO_ERROR)
			{
				break;
			}

			/* Generate Signature using raw scheme */
			ret = mbedtls_rsa_public(ctx, encoded_expected, encoded);
			if(ret != NO_ERROR)
			{
				break;
			}

			/* Compare*/
			if( ( ret = mbedtls_safer_memcmp( sig, encoded,
											  signLen ) ) != 0 )
			{
				ret = MBEDTLS_ERR_RSA_VERIFY_FAILED;
			}

			memcpy( sig, encoded_expected, ctx->len );
			break;
		}
		else
		{
		
			/* Check input buffer length parameters */
			ret = rsa_rsassa_pkcs1_v15_encode_check(md_alg, hashlen, hash, signLen, NULL);
			if(ret != NO_ERROR)
			{
				break;
			}

	        const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type( md_alg );
	        if( md_info == NULL )
	        {
	        	return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	        }

			hashlen = mbedtls_md_get_size( md_info );

			/* Choose HSE Supported HASH Algorithm */
			switch(	md_alg )
			{
#if !defined(S32N55)
				case MBEDTLS_MD_SHA1:
					hash_algo = HSE_HASH_ALGO_SHA_1;
					break ;
#endif
				case MBEDTLS_MD_SHA224:
					hash_algo = HSE_HASH_ALGO_SHA2_224;
					break ;
				case MBEDTLS_MD_SHA256:
					hash_algo = HSE_HASH_ALGO_SHA2_256;
					break ;
				case MBEDTLS_MD_SHA384:
					hash_algo = HSE_HASH_ALGO_SHA2_384;
					break ;
				case MBEDTLS_MD_SHA512:
					hash_algo = HSE_HASH_ALGO_SHA2_512;
					break ;
				case MBEDTLS_MD_MD5:
				case MBEDTLS_MD_MD2:
				case MBEDTLS_MD_MD4:
				case MBEDTLS_MD_RIPEMD160:
					return MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION;
				default:
					return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
			}

			/*Check if Key handle is valid (i.e. Key was loaded @ host explicitly) else Key handle will be loaded implicitly after getting the Keys in HSE*/
            if(ctx->keyHandle == HSE_INVALID_KEY_HANDLE)
			{
				isKeyLoadedImplicitly = true;
			}

			/* Load Key */
			ret = mbedtls_rsa_loadkey(ctx, MBEDTLS_RSA_PRIVATE);
			if(NO_ERROR != ret )
			{
				ret = MBEDTLS_ERR_RSA_PRIVATE_FAILED + ret;
				break;
			}

			signLen = ctx->len ;

			/* Send the request */
			srvResponse = HSE_RsaSaPkcs_v1_5(HSE_AUTH_DIR_GENERATE, hash_algo, ctx->keyHandle,
					(uint8_t*)hash, (uint32_t)hashlen, TRUE, (uint8_t*)sig, &signLen) ;

			switch(srvResponse)
			{
				case HSE_SRV_RSP_OK:
					ret = NO_ERROR;
					break;
				case HSE_SRV_RSP_NOT_SUPPORTED:
					ret = MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION;
					break;
				case HSE_SRV_RSP_VERIFY_FAILED:
					ret = MBEDTLS_ERR_RSA_VERIFY_FAILED;
					break;
				default:
					ret = MBEDTLS_ERR_RSA_PRIVATE_FAILED + MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
					break;
			}
		}
	}while(0);

	if(isKeyLoadedImplicitly==true)
	{
		isKeyLoadedImplicitly = 0;
		/* Unload key */
		mbedtls_rsa_unloadkey(ctx, mode);
	}
	return( ret ) ;
}

/*************************************************************************************************
* Description:  Implementation of the PKCS#1 v1.5 RSASSA-PKCS1-v1_5-VERIFY function.
************************************************************************************************/
int mbedtls_rsa_rsassa_pkcs1_v15_verify( mbedtls_rsa_context *ctx,
										 int (*f_rng)(void *, unsigned char *, size_t),
										 void *p_rng,
										 int mode,
										 mbedtls_md_type_t md_alg,
										 unsigned int hashlen,
										 const unsigned char *hash,
										 const unsigned char *sig )
{
	int ret = 0;
	bool_t isKeyLoadedImplicitly = false;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
	hseHashAlgo_t hash_algo = 0 ;
	uint32_t signLen = 0 ;
	unsigned char *encoded = NULL;
	unsigned char *encoded_expected = NULL;

	/* Simple sanity check */
    RSA_ALT_VALIDATE_RET( ctx != NULL );
    RSA_ALT_VALIDATE_RET( mode == MBEDTLS_RSA_PRIVATE ||
                      mode == MBEDTLS_RSA_PUBLIC );
    RSA_ALT_VALIDATE_RET( sig != NULL );
    RSA_ALT_VALIDATE_RET( ( md_alg  == MBEDTLS_MD_NONE &&
                        hashlen == 0 ) ||
                      hash != NULL );

    if( mode == MBEDTLS_RSA_PRIVATE && ctx->padding != MBEDTLS_RSA_PKCS_V15 )
    {
    	return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }

	if(mode != MBEDTLS_RSA_PUBLIC)
	{
		return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
	}

	/* Unused parameters */
	(void)f_rng;
	(void)p_rng;

	/* Set Signature length = size of Modulus */
	signLen = ctx->len ;

	do
	{
		if(md_alg == MBEDTLS_MD_NONE)
		{
	    	/* We are operating on Raw Data. So we should be encrypting with public key */
			encoded = mbedtls_calloc(1, signLen);
			encoded_expected = mbedtls_calloc(1, signLen);
			if ((NULL == encoded) || (NULL == encoded_expected))
			{
				ret = MBEDTLS_ERR_RSA_PUBLIC_FAILED + MBEDTLS_ERR_MPI_ALLOC_FAILED;
				break;
			}

			/* Prepare Encoded Buffer for RSA-SSA operation */
			ret = rsa_rsassa_pkcs1_v15_encode_check(md_alg, 
				hashlen, hash, signLen, encoded);
			if(ret != NO_ERROR)
			{
				break;
			}

			/* Encrypt the Signature */
			ret = mbedtls_rsa_public(ctx, sig, encoded_expected);
			if(ret != NO_ERROR)
			{
				break;
			}

			/* Compare */
			if( ( ret = mbedtls_safer_memcmp( encoded, encoded_expected,
											  signLen ) ) != 0 )
			{
				ret = MBEDTLS_ERR_RSA_VERIFY_FAILED;
			}
			break;
	    }
		else
		{
			/* Check input buffer length parameters */
			ret = rsa_rsassa_pkcs1_v15_encode_check(md_alg, hashlen, hash, signLen, NULL);
			if(ret != NO_ERROR)
			{
				break;
			}

	        const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type( md_alg );
	        if( md_info == NULL )
	        {
	        	return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	        }
			
	        /* Update hashlen */
	        hashlen = mbedtls_md_get_size( md_info );

			/* Choose HSE Supported HASH Algorithm */
			switch( md_alg )
			{
#if !defined(S32N55)
				case MBEDTLS_MD_SHA1:
					hash_algo = HSE_HASH_ALGO_SHA_1;
					break ;
#endif
				case MBEDTLS_MD_SHA224:
					hash_algo = HSE_HASH_ALGO_SHA2_224;
					break ;
				case MBEDTLS_MD_SHA256:
					hash_algo = HSE_HASH_ALGO_SHA2_256;
					break ;
				case MBEDTLS_MD_SHA384:
					hash_algo = HSE_HASH_ALGO_SHA2_384;
					break ;
				case MBEDTLS_MD_SHA512:
					hash_algo = HSE_HASH_ALGO_SHA2_512;
					break ;
				case MBEDTLS_MD_MD5:
				case MBEDTLS_MD_MD2:
				case MBEDTLS_MD_MD4:
				case MBEDTLS_MD_RIPEMD160:
					return ( MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION );
				default:
					return ( MBEDTLS_ERR_RSA_BAD_INPUT_DATA ) ;
			}
			/*Check if Key handle is valid (i.e. Key was loaded @ host explicitly) else Key handle will be loaded implicitly after getting the Keys in HSE*/
			if(ctx->keyHandle == HSE_INVALID_KEY_HANDLE)
			{
				isKeyLoadedImplicitly = true;
			}

			/*Check if Key handle is valid (i.e. Key was loaded @ host explicitly) else Key handle will be loaded implicitly after getting the Keys in HSE*/
			if(ctx->keyHandle == HSE_INVALID_KEY_HANDLE)
			{
				isKeyLoadedImplicitly = true;
			}

			/* Load Key */
			ret = mbedtls_rsa_loadkey(ctx, MBEDTLS_RSA_PUBLIC);
			if(NO_ERROR != ret )
			{
				ret = MBEDTLS_ERR_RSA_PUBLIC_FAILED + ret;
				break;
			}

			/* Send the request */
			srvResponse = HSE_RsaSaPkcs_v1_5( HSE_AUTH_DIR_VERIFY, hash_algo, ctx->keyHandle,
					(uint8_t*)hash, (uint32_t)hashlen, TRUE, (uint8_t*)sig, &signLen ) ;

			switch(srvResponse)
			{
				case HSE_SRV_RSP_OK:
					ret = NO_ERROR;
					break;
				case HSE_SRV_RSP_NOT_SUPPORTED:
					ret = MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION;
					break;
				case HSE_SRV_RSP_VERIFY_FAILED:
					ret = MBEDTLS_ERR_RSA_VERIFY_FAILED;
					break;
				default:
					ret = MBEDTLS_ERR_RSA_PUBLIC_FAILED + MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
					break;
			}
		}
	}while(0);

	if (NULL != encoded)
	{
		mbedtls_platform_zeroize(encoded, signLen);
		mbedtls_free(encoded);
	}

	if (NULL != encoded_expected)
	{
		mbedtls_platform_zeroize(encoded_expected, signLen);
		mbedtls_free(encoded_expected);
	}

	/* Unload key */
	if(isKeyLoadedImplicitly==true)
	{
		isKeyLoadedImplicitly = 0;
		/* Unload key */
		mbedtls_rsa_unloadkey(ctx, mode);
	}

	if(isKeyLoadedImplicitly==true)
	{
		isKeyLoadedImplicitly = 0;
		/* Unload key */
		mbedtls_rsa_unloadkey(ctx, mode);
	}
	return( ret ) ;
}
#endif /* MBEDTLS_PKCS1_V15 */

#if defined(MBEDTLS_PKCS1_V21)
/*************************************************************************************************
* Description:  Implementation of the PKCS#1 v2.1 RSASSA-PSS-SIGN function.
************************************************************************************************/
int mbedtls_rsa_rsassa_pss_sign( mbedtls_rsa_context *ctx,
								 int (*f_rng)(void *, unsigned char *, size_t),
								 void *p_rng,
								 int mode,
								 mbedtls_md_type_t md_alg,
								 unsigned int hashlen,
								 const unsigned char *hash,
								 unsigned char *sig )
{
    size_t olen;
    bool_t isKeyLoadedImplicitly = false;
    size_t slen, min_slen, hlen;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const mbedtls_md_info_t *md_info;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
	hseHashAlgo_t hash_algo = 0 ;
	uint32_t signLen = 0 ;

    RSA_ALT_VALIDATE_RET( ctx != NULL );
    RSA_ALT_VALIDATE_RET( mode == MBEDTLS_RSA_PRIVATE ||
                      mode == MBEDTLS_RSA_PUBLIC );
    RSA_ALT_VALIDATE_RET( ( md_alg  == MBEDTLS_MD_NONE &&
                        hashlen == 0 ) ||
                      hash != NULL );
    RSA_ALT_VALIDATE_RET( sig != NULL );

	if(mode != MBEDTLS_RSA_PRIVATE)
	{
		return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
	}

    if( (mode == MBEDTLS_RSA_PRIVATE) && (ctx->padding != MBEDTLS_RSA_PKCS_V21) )
	{
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

    if( f_rng == NULL )
	{
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

	/* Unused parameters */
	(void)p_rng;

	/* Set Signature length = Public Key Modulus Length */
	signLen = ctx->len;
	olen = ctx->len;

	if( md_alg != MBEDTLS_MD_NONE )
	{
		/* Gather length of hash to sign */
		md_info = mbedtls_md_info_from_type( md_alg );
		if( md_info == NULL )
		{
			return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
		}
	
		hashlen = mbedtls_md_get_size( md_info );
	}
	
	/* Get Hash Length based on ctx->Hash */
	md_info = mbedtls_md_info_from_type( (mbedtls_md_type_t) ctx->hash_id );
	if( md_info == NULL )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}
	
	hlen = mbedtls_md_get_size( md_info );
	
	/* Calculate the largest possible salt length. Normally this is the hash
	 * length, which is the maximum length the salt can have. If there is not
	 * enough room, use the maximum salt length that fits. The constraint is
	 * that the hash length plus the salt length plus 2 bytes must be at most
	 * the key length. This complies with FIPS 186-4 §5.5 (e) and RFC 8017
	 * (PKCS#1 v2.2) §9.1.1 step 3. */
	min_slen = hlen - 2;
	if( olen < hlen + min_slen + 2 )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}
	else if( olen >= hlen + hlen + 2 )
	{
		slen = hlen;
	}
	else
	{
		slen = olen - hlen - 2;
	}
	
	memset( sig, 0, olen );


	/* Choose HSE Supported HASH Algorithm */
	switch( ctx->hash_id)
	{
#if !defined(S32N55)
		case MBEDTLS_MD_SHA1:
			hash_algo = HSE_HASH_ALGO_SHA_1;
			break ;
#endif
		case MBEDTLS_MD_SHA224:
			hash_algo = HSE_HASH_ALGO_SHA2_224;
			break ;
		case MBEDTLS_MD_SHA256:
			hash_algo = HSE_HASH_ALGO_SHA2_256;
			break;
		case MBEDTLS_MD_SHA384:
			hash_algo = HSE_HASH_ALGO_SHA2_384;
			break ;
		case MBEDTLS_MD_SHA512:
			hash_algo = HSE_HASH_ALGO_SHA2_512;
			break ;
		case MBEDTLS_MD_MD5:
		case MBEDTLS_MD_MD2:
		case MBEDTLS_MD_MD4:
		case MBEDTLS_MD_RIPEMD160:
			return MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION;
		default:
			return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
	}

	do
	{
		/*Check if Key handle is valid (i.e. Key was loaded @ host explicitly) else Key handle will be loaded implicitly after getting the Keys in HSE*/
		if(ctx->keyHandle == HSE_INVALID_KEY_HANDLE)
		{
			isKeyLoadedImplicitly = true;
		}
		/* Load Key */
		ret = mbedtls_rsa_loadkey(ctx, mode);
		if(NO_ERROR != ret )
		{
			break;
		}

		/* Send the request */
		srvResponse = HSE_RsaSaPss(HSE_AUTH_DIR_GENERATE, hash_algo, slen, ctx->keyHandle,
				(uint8_t*)hash, (uint32_t)hashlen, TRUE, (uint8_t*)sig, &signLen) ;

		if(HSE_SRV_RSP_OK != srvResponse)
		{
			/* Return with Error Codes */
			ret = MBEDTLS_ERR_RSA_PRIVATE_FAILED + MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
		}
		else
		{
			/* Return with NO_ERROR on success */
			ret = NO_ERROR ;
		}
	}while(0);

		if(isKeyLoadedImplicitly==true)
		{
			isKeyLoadedImplicitly = 0;
			/* Unload key */
			mbedtls_rsa_unloadkey(ctx, mode);
		}

	return( ret ) ;
}

/*************************************************************************************************
* Description:  Implementation of the PKCS#1 v2.1 RSASSA-PSS-VERIFY function.
************************************************************************************************/
int mbedtls_rsa_rsassa_pss_verify( mbedtls_rsa_context *ctx,
								   int (*f_rng)(void *, unsigned char *, size_t),
								   void *p_rng,
								   int mode,
								   mbedtls_md_type_t md_alg,
								   unsigned int hashlen,
								   const unsigned char *hash,
								   const unsigned char *sig )
{
	const mbedtls_md_info_t *md_info;
    mbedtls_md_type_t mgf1_hash_id;

    RSA_ALT_VALIDATE_RET( ctx != NULL );
    RSA_ALT_VALIDATE_RET( mode == MBEDTLS_RSA_PRIVATE ||
                      mode == MBEDTLS_RSA_PUBLIC );
    RSA_ALT_VALIDATE_RET( sig != NULL );
    RSA_ALT_VALIDATE_RET( ( md_alg  == MBEDTLS_MD_NONE &&
                        hashlen == 0 ) ||
                      hash != NULL );

    mgf1_hash_id = ( ctx->hash_id != MBEDTLS_MD_NONE )
                             ? (mbedtls_md_type_t) ctx->hash_id
                             : md_alg;

	if( md_alg != MBEDTLS_MD_NONE )
	{
		/* Gather length of hash to sign */
		md_info = mbedtls_md_info_from_type( md_alg );
		if( md_info == NULL )
		{
			return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
		}

		hashlen = mbedtls_md_get_size( md_info );
	}

    return( mbedtls_rsa_rsassa_pss_verify_ext( ctx, f_rng, p_rng, mode,
                                       md_alg, hashlen, hash,
                                       mgf1_hash_id, MBEDTLS_RSA_SALT_LEN_ANY,
                                       sig ) );
}

/*************************************************************************************************
* Description: Implementation of the PKCS#1 v2.1 RSASSA-PSS-VERIFY function.
************************************************************************************************/
int mbedtls_rsa_rsassa_pss_verify_ext( mbedtls_rsa_context *ctx,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng,
                               int mode,
                               mbedtls_md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               mbedtls_md_type_t mgf1_hash_id,
                               int expected_salt_len,
                               const unsigned char *sig )
{

	/* Work around for : PKCS2.1 signature verification for salt length = -1 */
#ifdef MBEDTLS_USE_NXP_HSE_PKCS21_VERIFY_WORKAROUND
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	size_t siglen;
	unsigned char *p;
	unsigned char *hash_start;
	unsigned char result[MBEDTLS_MD_MAX_SIZE];
	unsigned char zeros[8];
	unsigned int hlen;
	size_t observed_salt_len, msb;
	const mbedtls_md_info_t *md_info;
	mbedtls_md_context_t md_ctx;
	unsigned char buf[MBEDTLS_MPI_MAX_SIZE];

	RSA_ALT_VALIDATE_RET( ctx != NULL );
	RSA_ALT_VALIDATE_RET( mode == MBEDTLS_RSA_PRIVATE ||
					  mode == MBEDTLS_RSA_PUBLIC );
	RSA_ALT_VALIDATE_RET( sig != NULL );
	RSA_ALT_VALIDATE_RET( ( md_alg  == MBEDTLS_MD_NONE &&
						hashlen == 0 ) ||
					  hash != NULL );

	if( mode == MBEDTLS_RSA_PRIVATE && ctx->padding != MBEDTLS_RSA_PKCS_V21 )
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

	siglen = ctx->len;

	if( siglen < 16 || siglen > sizeof( buf ) )
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

	ret = ( mode == MBEDTLS_RSA_PUBLIC )
		  ? mbedtls_rsa_public(  ctx, sig, buf )
		  : mbedtls_rsa_private( ctx, f_rng, p_rng, sig, buf );

	if( ret != 0 )
		return( ret );

	p = buf;

	if( buf[siglen - 1] != 0xBC )
		return( MBEDTLS_ERR_RSA_INVALID_PADDING );

	if( md_alg != MBEDTLS_MD_NONE )
	{
		/* Gather length of hash to sign */
		md_info = mbedtls_md_info_from_type( md_alg );
		if( md_info == NULL )
			return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

		hashlen = mbedtls_md_get_size( md_info );
	}

	md_info = mbedtls_md_info_from_type( mgf1_hash_id );
	if( md_info == NULL )
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

	hlen = mbedtls_md_get_size( md_info );

	memset( zeros, 0, 8 );

	/*
	 * Note: EMSA-PSS verification is over the length of N - 1 bits
	 */
	msb = mbedtls_mpi_bitlen( &ctx->N ) - 1;

	if( buf[0] >> ( 8 - siglen * 8 + msb ) )
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

	/* Compensate for boundary condition when applying mask */
	if( msb % 8 == 0 )
	{
		p++;
		siglen -= 1;
	}

	if( siglen < hlen + 2 )
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	hash_start = p + siglen - hlen - 1;

	mbedtls_md_init( &md_ctx );
	if( ( ret = mbedtls_md_setup( &md_ctx, md_info, 0 ) ) != 0 )
		goto exit;

	ret = mgf_mask( p, siglen - hlen - 1, hash_start, hlen, &md_ctx );
	if( ret != 0 )
		goto exit;

	buf[0] &= 0xFF >> ( siglen * 8 - msb );

	while( p < hash_start - 1 && *p == 0 )
		p++;

	if( *p++ != 0x01 )
	{
		ret = MBEDTLS_ERR_RSA_INVALID_PADDING;
		goto exit;
	}

	observed_salt_len = hash_start - p;

	if( expected_salt_len != MBEDTLS_RSA_SALT_LEN_ANY &&
		observed_salt_len != (size_t) expected_salt_len )
	{
		ret = MBEDTLS_ERR_RSA_INVALID_PADDING;
		goto exit;
	}

	/*
	 * Generate H = Hash( M' )
	 */
	ret = mbedtls_md_starts( &md_ctx );
	if ( ret != 0 )
		goto exit;
	ret = mbedtls_md_update( &md_ctx, zeros, 8 );
	if ( ret != 0 )
		goto exit;
	ret = mbedtls_md_update( &md_ctx, hash, hashlen );
	if ( ret != 0 )
		goto exit;
	ret = mbedtls_md_update( &md_ctx, p, observed_salt_len );
	if ( ret != 0 )
		goto exit;
	ret = mbedtls_md_finish( &md_ctx, result );
	if ( ret != 0 )
		goto exit;

	if( memcmp( hash_start, result, hlen ) != 0 )
	{
		ret = MBEDTLS_ERR_RSA_VERIFY_FAILED;
		goto exit;
	}

exit:
	mbedtls_md_free( &md_ctx );

	return( ret );

#else
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR ;
    const mbedtls_md_info_t *md_info;
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
	hseHashAlgo_t hash_algo;
	uint32_t signLen;

    RSA_ALT_VALIDATE_RET( ctx != NULL );
    RSA_ALT_VALIDATE_RET( mode == MBEDTLS_RSA_PRIVATE ||
                      mode == MBEDTLS_RSA_PUBLIC );
    RSA_ALT_VALIDATE_RET( sig != NULL );
    RSA_ALT_VALIDATE_RET( ( md_alg  == MBEDTLS_MD_NONE &&
                        hashlen == 0 ) ||
                      hash != NULL );

	/* Unused parameters */
	(void)f_rng;
	(void)p_rng;

	if( (mode == MBEDTLS_RSA_PRIVATE) && (ctx->padding != MBEDTLS_RSA_PKCS_V21) )
	{
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

	if(mode != MBEDTLS_RSA_PUBLIC)
	{
		return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
	}

    signLen = ctx->len;

    if( (signLen < 16) || (signLen > sizeof( buf )) )
	{
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

	if( md_alg != MBEDTLS_MD_NONE )
	{
		/* Gather length of hash to sign */
		md_info = mbedtls_md_info_from_type( md_alg );
		if( md_info == NULL )
		{
			return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
		}
	
		hashlen = mbedtls_md_get_size( md_info );
	}
	/* Choose HSE Supported HASH Algorithm */
	switch(	mgf1_hash_id )
	{
#if !defined(S32N55)
		case MBEDTLS_MD_SHA1:
			hash_algo = HSE_HASH_ALGO_SHA_1;
			break ;
#endif
		case MBEDTLS_MD_SHA224:
			hash_algo = HSE_HASH_ALGO_SHA2_224;
			break ;
		case MBEDTLS_MD_SHA256:
			hash_algo = HSE_HASH_ALGO_SHA2_256;
			break ;
		case MBEDTLS_MD_SHA384:
			hash_algo = HSE_HASH_ALGO_SHA2_384;
			break ;
		case MBEDTLS_MD_SHA512:
			hash_algo = HSE_HASH_ALGO_SHA2_512;
			break ;
		case MBEDTLS_MD_MD5:
		case MBEDTLS_MD_MD2:
		case MBEDTLS_MD_MD4:
		case MBEDTLS_MD_RIPEMD160:
			return ( MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION );
		default:
			return ( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

	do
	{
		/* Load Key */
		ret = mbedtls_rsa_loadkey(ctx, MBEDTLS_RSA_PUBLIC);
		if(NO_ERROR != ret )
		{
			ret = MBEDTLS_ERR_RSA_PUBLIC_FAILED + ret;
			break;
		}
		
		/* Send the request */
		srvResponse = HSE_RsaSaPss(HSE_AUTH_DIR_VERIFY, hash_algo, (uint32_t)expected_salt_len, ctx->keyHandle,
				(uint8_t*)hash, (uint32_t)hashlen, TRUE, (uint8_t*)sig, &signLen) ;
		
		switch(srvResponse)
		{
			case HSE_SRV_RSP_OK:
				ret = NO_ERROR;
				break;
			case HSE_SRV_RSP_NOT_SUPPORTED:
				ret = MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION;
				break;
			case HSE_SRV_RSP_VERIFY_FAILED:
				ret = MBEDTLS_ERR_RSA_VERIFY_FAILED;
				break;
			default:
				ret = MBEDTLS_ERR_RSA_PUBLIC_FAILED + MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
				break;
		}
	}while(0);

	mbedtls_rsa_unloadkey(ctx, mode);

	return( ret) ;
#endif /* MBEDTLS_USE_NXP_HSE_PKCS21_VERIFY_WORKAROUND */
}
#endif /* MBEDTLS_PKCS1_V21 */

/*************************************************************************************************
* Description:  Add the message padding, then do an RSA operation.
************************************************************************************************/
int mbedtls_rsa_pkcs1_encrypt( mbedtls_rsa_context *ctx,
							   int (*f_rng)(void *, unsigned char *, size_t),
							   void *p_rng,
							   int mode, size_t ilen,
							   const unsigned char *input,
							   unsigned char *output )
{
	/* Simple sanity check */
	RSA_ALT_VALIDATE_RET( ctx != NULL );
	RSA_ALT_VALIDATE_RET( mode == MBEDTLS_RSA_PRIVATE ||
                      mode == MBEDTLS_RSA_PUBLIC );
	RSA_ALT_VALIDATE_RET( output != NULL );
	RSA_ALT_VALIDATE_RET( ilen == 0 || input != NULL );

    switch( ctx->padding )
    {
#if defined(MBEDTLS_PKCS1_V15)
        case MBEDTLS_RSA_PKCS_V15:
            return mbedtls_rsa_rsaes_pkcs1_v15_encrypt( ctx, f_rng, p_rng, mode, ilen,
                                                input, output );
#endif

#if defined(MBEDTLS_PKCS1_V21)
        case MBEDTLS_RSA_PKCS_V21:
            return mbedtls_rsa_rsaes_oaep_encrypt( ctx, f_rng, p_rng, mode, NULL, 0,
                                           ilen, input, output );
#endif

        default:
            return( MBEDTLS_ERR_RSA_INVALID_PADDING );
    }
}

/*************************************************************************************************
* Description:  Do an RSA operation, then remove the message padding.
************************************************************************************************/
int mbedtls_rsa_pkcs1_decrypt( mbedtls_rsa_context *ctx,
							   int (*f_rng)(void *, unsigned char *, size_t),
							   void *p_rng,
							   int mode, size_t *olen,
							   const unsigned char *input,
							   unsigned char *output,
							   size_t output_max_len)
{
	/* Simple sanity check */
    RSA_ALT_VALIDATE_RET( ctx != NULL );
    RSA_ALT_VALIDATE_RET( mode == MBEDTLS_RSA_PRIVATE ||
                      mode == MBEDTLS_RSA_PUBLIC );
    RSA_ALT_VALIDATE_RET( output_max_len == 0 || output != NULL );
    RSA_ALT_VALIDATE_RET( input != NULL );
    RSA_ALT_VALIDATE_RET( olen != NULL );

    switch( ctx->padding )
    {
#if defined(MBEDTLS_PKCS1_V15)
        case MBEDTLS_RSA_PKCS_V15:
            return mbedtls_rsa_rsaes_pkcs1_v15_decrypt( ctx, f_rng, p_rng, mode, olen,
                                                input, output, output_max_len );
#endif

#if defined(MBEDTLS_PKCS1_V21)
        case MBEDTLS_RSA_PKCS_V21:
            return mbedtls_rsa_rsaes_oaep_decrypt( ctx, f_rng, p_rng, mode, NULL, 0,
                                           olen, input, output,
                                           output_max_len );
#endif

        default:
            return( MBEDTLS_ERR_RSA_INVALID_PADDING );
    }
}

/*************************************************************************************************
* Description: Do an RSA operation to sign the message digest.
************************************************************************************************/
int mbedtls_rsa_pkcs1_sign( mbedtls_rsa_context *ctx,
							int (*f_rng)(void *, unsigned char *, size_t),
							void *p_rng,
							int mode,
							mbedtls_md_type_t md_alg,
							unsigned int hashlen,
							const unsigned char *hash,
							unsigned char *sig )
{
	/* Simple sanity check */
	RSA_ALT_VALIDATE_RET( ctx != NULL );
	RSA_ALT_VALIDATE_RET( mode == MBEDTLS_RSA_PRIVATE ||
                      mode == MBEDTLS_RSA_PUBLIC );
	RSA_ALT_VALIDATE_RET( ( md_alg  == MBEDTLS_MD_NONE &&
                        hashlen == 0 ) ||
                      hash != NULL );
	RSA_ALT_VALIDATE_RET( sig != NULL );

    switch( ctx->padding )
    {
#if defined(MBEDTLS_PKCS1_V15)
        case MBEDTLS_RSA_PKCS_V15 :
        {
        	/* Send the request */
            return mbedtls_rsa_rsassa_pkcs1_v15_sign( ctx, f_rng, p_rng, mode, md_alg, hashlen, hash, sig ) ;
        }
#endif

#if defined(MBEDTLS_PKCS1_V21)
        case MBEDTLS_RSA_PKCS_V21 :
        {
        	/* Send the request */
            return mbedtls_rsa_rsassa_pss_sign( ctx, f_rng, p_rng, mode, md_alg, hashlen, hash, sig ) ;
        }
#endif

        default :
        {
        	/* Return with Error Codes */
        	return( MBEDTLS_ERR_RSA_INVALID_PADDING ) ;
        }
    }
}

/*************************************************************************************************
* Description: Do an RSA operation and check the message digest.
************************************************************************************************/
int mbedtls_rsa_pkcs1_verify( mbedtls_rsa_context *ctx,
							  int (*f_rng)(void *, unsigned char *, size_t),
							  void *p_rng,
							  int mode,
							  mbedtls_md_type_t md_alg,
							  unsigned int hashlen,
							  const unsigned char *hash,
							  const unsigned char *sig )
{
    RSA_ALT_VALIDATE_RET( ctx != NULL );
    RSA_ALT_VALIDATE_RET( mode == MBEDTLS_RSA_PRIVATE ||
                      mode == MBEDTLS_RSA_PUBLIC );
    RSA_ALT_VALIDATE_RET( sig != NULL );
    RSA_ALT_VALIDATE_RET( ( md_alg  == MBEDTLS_MD_NONE &&
                        	hashlen == 0 ) || hash != NULL );

    switch( ctx->padding )
    {
#if defined(MBEDTLS_PKCS1_V15)
        case MBEDTLS_RSA_PKCS_V15 :
        {
        	/* Send the request */
            return mbedtls_rsa_rsassa_pkcs1_v15_verify( ctx, f_rng, p_rng, mode, md_alg, hashlen, hash, sig ) ;
        }
#endif

#if defined(MBEDTLS_PKCS1_V21)
        case MBEDTLS_RSA_PKCS_V21 :
        {
        	/* Send the request */
            return mbedtls_rsa_rsassa_pss_verify( ctx, f_rng, p_rng, mode, md_alg, hashlen, hash, sig ) ;
        }
#endif

        default :
        {
        	/* Return with Error Codes */
            return( MBEDTLS_ERR_RSA_INVALID_PADDING );
        }
    }
}

/*************************************************************************************************
* Description: This function imports the core parameters of an RSA key.
************************************************************************************************/
int mbedtls_rsa_import( mbedtls_rsa_context *ctx,
                        const mbedtls_mpi *N,
                        const mbedtls_mpi *P, const mbedtls_mpi *Q,
                        const mbedtls_mpi *D, const mbedtls_mpi *E )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    RSA_ALT_VALIDATE_RET( ctx != NULL );

    if( ( N != NULL && ( ret = mbedtls_mpi_copy( &ctx->N, N ) ) != 0 ) ||
        ( P != NULL && ( ret = mbedtls_mpi_copy( &ctx->P, P ) ) != 0 ) ||
        ( Q != NULL && ( ret = mbedtls_mpi_copy( &ctx->Q, Q ) ) != 0 ) ||
        ( D != NULL && ( ret = mbedtls_mpi_copy( &ctx->D, D ) ) != 0 ) ||
        ( E != NULL && ( ret = mbedtls_mpi_copy( &ctx->E, E ) ) != 0 ) )
    {
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA + ret );
    }

    if( N != NULL )
    {
    	ctx->len = mbedtls_mpi_size( &ctx->N );
    }

    return( 0 );
}

/*************************************************************************************************
* Description: This function imports core RSA parameters, in raw big-endian binary format, into an RSA context.
************************************************************************************************/
int mbedtls_rsa_import_raw( mbedtls_rsa_context *ctx,
                            unsigned char const *N, size_t N_len,
                            unsigned char const *P, size_t P_len,
                            unsigned char const *Q, size_t Q_len,
                            unsigned char const *D, size_t D_len,
                            unsigned char const *E, size_t E_len )
{
	int ret = 0;
	RSA_ALT_VALIDATE_RET( ctx != NULL );

	if( N != NULL )
	{
		MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ctx->N, N, N_len ) );
		ctx->len = mbedtls_mpi_size( &ctx->N );
	}

	if( P != NULL )
	{
		MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ctx->P, P, P_len ) );
	}

	if( Q != NULL )
	{
		MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ctx->Q, Q, Q_len ) );
	}

	if( D != NULL )
	{
		MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ctx->D, D, D_len ) );
	}

	if( E != NULL )
	{
		MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ctx->E, E, E_len ) );
	}

cleanup:

	if( ret != 0 )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA + ret );
	}

	return( 0 );
	
}

/*************************************************************************************************
* Description: This function exports the core parameters of an RSA key.
************************************************************************************************/
int mbedtls_rsa_export( const mbedtls_rsa_context *ctx,
                        mbedtls_mpi *N, mbedtls_mpi *P, mbedtls_mpi *Q,
                        mbedtls_mpi *D, mbedtls_mpi *E )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int is_priv;
    RSA_ALT_VALIDATE_RET( ctx != NULL );

    /* Check if key is private or public */
    is_priv =
        mbedtls_mpi_cmp_int( &ctx->N, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->P, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->Q, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->D, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->E, 0 ) != 0;

    if( !is_priv )
    {
        /* If we're trying to export private parameters for a public key,
         * something must be wrong. */
        if( P != NULL || Q != NULL || D != NULL )
        {
        	return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
        }

    }

    /* Export all requested core parameters. */

    if( ( N != NULL && ( ret = mbedtls_mpi_copy( N, &ctx->N ) ) != 0 ) ||
        ( P != NULL && ( ret = mbedtls_mpi_copy( P, &ctx->P ) ) != 0 ) ||
        ( Q != NULL && ( ret = mbedtls_mpi_copy( Q, &ctx->Q ) ) != 0 ) ||
        ( D != NULL && ( ret = mbedtls_mpi_copy( D, &ctx->D ) ) != 0 ) ||
        ( E != NULL && ( ret = mbedtls_mpi_copy( E, &ctx->E ) ) != 0 ) )
    {
        return( ret );
    }

    return( 0 );
}

/*************************************************************************************************
* Description: This function exports core parameters of an RSA key in raw big-endian binary format.
************************************************************************************************/
int mbedtls_rsa_export_raw( const mbedtls_rsa_context *ctx,
                            unsigned char *N, size_t N_len,
                            unsigned char *P, size_t P_len,
                            unsigned char *Q, size_t Q_len,
                            unsigned char *D, size_t D_len,
                            unsigned char *E, size_t E_len )
{
	int ret = 0;
	int is_priv;
	RSA_ALT_VALIDATE_RET( ctx != NULL );

	/* Check if key is private or public */
	is_priv =
		mbedtls_mpi_cmp_int( &ctx->N, 0 ) != 0 &&
		mbedtls_mpi_cmp_int( &ctx->P, 0 ) != 0 &&
		mbedtls_mpi_cmp_int( &ctx->Q, 0 ) != 0 &&
		mbedtls_mpi_cmp_int( &ctx->D, 0 ) != 0 &&
		mbedtls_mpi_cmp_int( &ctx->E, 0 ) != 0;

	if( !is_priv )
	{
		/* If we're trying to export private parameters for a public key,
		 * something must be wrong. */
		if( P != NULL || Q != NULL || D != NULL )
		{
			return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
		}
	}

	if( N != NULL )
	{
		MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->N, N, N_len ) );
	}

	if( P != NULL )
	{
		MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->P, P, P_len ) );
	}

	if( Q != NULL )
	{
		MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->Q, Q, Q_len ) );
	}

	if( D != NULL )
	{
		MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->D, D, D_len ) );
	}

	if( E != NULL )
	{
		MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->E, E, E_len ) );
	}

cleanup:

	return( ret );
}

/*************************************************************************************************
* Description: This function completes an RSA context from a set of imported core parameters.
************************************************************************************************/
int mbedtls_rsa_complete( mbedtls_rsa_context *ctx )
{
	int ret = 0;
	int have_N, have_P, have_Q, have_D, have_E;
#if !defined(MBEDTLS_RSA_NO_CRT)
	int have_DP, have_DQ, have_QP;
#endif
	int n_missing, pq_missing, d_missing, is_pub, is_priv;

	RSA_ALT_VALIDATE_RET( ctx != NULL );

	have_N = ( mbedtls_mpi_cmp_int( &ctx->N, 0 ) != 0 );
	have_P = ( mbedtls_mpi_cmp_int( &ctx->P, 0 ) != 0 );
	have_Q = ( mbedtls_mpi_cmp_int( &ctx->Q, 0 ) != 0 );
	have_D = ( mbedtls_mpi_cmp_int( &ctx->D, 0 ) != 0 );
	have_E = ( mbedtls_mpi_cmp_int( &ctx->E, 0 ) != 0 );

	/*
	 * Check whether provided parameters are enough
	 * to deduce all others. The following incomplete
	 * parameter sets for private keys are supported:
	 *
	 * (1) P, Q missing.
	 * (2) D and potentially N missing.
	 *
	 */

	n_missing  =			  have_P &&  have_Q &&	have_D && have_E;
	pq_missing =   have_N && !have_P && !have_Q &&	have_D && have_E;
	d_missing  =			  have_P &&  have_Q && !have_D && have_E;
	is_pub	   =   have_N && !have_P && !have_Q && !have_D && have_E;

	/* These three alternatives are mutually exclusive */
	is_priv = n_missing || pq_missing || d_missing;

	if( !is_priv && !is_pub )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

	/* Step 1: Deduce N if P, Q are provided */

	if( !have_N && have_P && have_Q )
	{
		if( ( ret = mbedtls_mpi_mul_mpi( &ctx->N, &ctx->P,
										 &ctx->Q ) ) != 0 )
		{
			return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA + ret );
		}

		ctx->len = mbedtls_mpi_size( &ctx->N );
	}

	/* Step 2: Deduce and verify all remaining core parameters */

	if( pq_missing )
	{
		ret = mbedtls_rsa_deduce_primes( &ctx->N, &ctx->E, &ctx->D,
										 &ctx->P, &ctx->Q );
		if( ret != 0 )
		{
			return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA + ret );
		}

	}
	else if( d_missing )
	{
		if( ( ret = mbedtls_rsa_deduce_private_exponent( &ctx->P,
														 &ctx->Q,
														 &ctx->E,
														 &ctx->D ) ) != 0 )
		{
			return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA + ret );
		}
	}

	/* Step 3: Basic sanity checks */
	ret = rsa_check_context( ctx, is_priv, 1 );
	if( ret != 0 )
	{
		return ret;
	}
	else
	{
		ctx->privkey_flag = is_priv;
	}

	return( ret );
}

/*************************************************************************************************
* Description: This function exports CRT parameters of a private RSA key.
************************************************************************************************/
int mbedtls_rsa_export_crt( const mbedtls_rsa_context *ctx,
                            mbedtls_mpi *DP, mbedtls_mpi *DQ, mbedtls_mpi *QP )
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	int is_priv;
	RSA_ALT_VALIDATE_RET( ctx != NULL );

	/* Check if key is private or public */
	is_priv =
		mbedtls_mpi_cmp_int( &ctx->N, 0 ) != 0 &&
		mbedtls_mpi_cmp_int( &ctx->P, 0 ) != 0 &&
		mbedtls_mpi_cmp_int( &ctx->Q, 0 ) != 0 &&
		mbedtls_mpi_cmp_int( &ctx->D, 0 ) != 0 &&
		mbedtls_mpi_cmp_int( &ctx->E, 0 ) != 0;

	if( !is_priv )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

#if !defined(MBEDTLS_RSA_NO_CRT)
	/* Export all requested blinding parameters. */
	if( ( DP != NULL && ( ret = mbedtls_mpi_copy( DP, &ctx->DP ) ) != 0 ) ||
		( DQ != NULL && ( ret = mbedtls_mpi_copy( DQ, &ctx->DQ ) ) != 0 ) ||
		( QP != NULL && ( ret = mbedtls_mpi_copy( QP, &ctx->QP ) ) != 0 ) )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA + ret );
	}
#else
	if( ( ret = mbedtls_rsa_deduce_crt( &ctx->P, &ctx->Q, &ctx->D,
										DP, DQ, QP ) ) != 0 )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA + ret );
	}
#endif

	return( 0 );
}

/*************************************************************************************************
* Description: This function checks if a context contains at least an RSA public key.
************************************************************************************************/
int mbedtls_rsa_check_pubkey( const mbedtls_rsa_context *ctx )
{
    RSA_ALT_VALIDATE_RET( ctx != NULL );

    if( rsa_check_context( ctx, 0 /* public */, 0 /* no blinding */ ) != 0 )
    {
    	return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

    if( mbedtls_mpi_bitlen( &ctx->N ) < 128 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

    if( mbedtls_mpi_get_bit( &ctx->E, 0 ) == 0 ||
        mbedtls_mpi_bitlen( &ctx->E )     < 2  ||
        mbedtls_mpi_cmp_mpi( &ctx->E, &ctx->N ) >= 0 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

    return( 0 );
}

/*************************************************************************************************
* Description: This function checks if a context contains an RSA private key
* and perform basic consistency checks.
************************************************************************************************/
int mbedtls_rsa_check_privkey( const mbedtls_rsa_context *ctx )
{
	RSA_ALT_VALIDATE_RET( ctx != NULL );

	if( mbedtls_rsa_check_pubkey( ctx ) != 0 ||
		rsa_check_context( ctx, 1 /* private */, 1 /* blinding */ ) != 0 )
	{
		return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
	}

	if( mbedtls_rsa_validate_params( &ctx->N, &ctx->P, &ctx->Q,
									 &ctx->D, &ctx->E, NULL, NULL ) != 0 )
	{
		return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
	}

#if !defined(MBEDTLS_RSA_NO_CRT)
	else if( mbedtls_rsa_validate_crt( &ctx->P, &ctx->Q, &ctx->D,
									   &ctx->DP, &ctx->DQ, &ctx->QP ) != 0 )
	{
		return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
	}
#endif

	return( 0 );
}

/*************************************************************************************************
* Description:  This function checks a public-private RSA key pair.
************************************************************************************************/
int mbedtls_rsa_check_pub_priv( const mbedtls_rsa_context *pub,
                                const mbedtls_rsa_context *prv )
{
    RSA_ALT_VALIDATE_RET( pub != NULL );
    RSA_ALT_VALIDATE_RET( prv != NULL );

    if( mbedtls_rsa_check_pubkey( pub )  != 0 ||
        mbedtls_rsa_check_privkey( prv ) != 0 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

    if( mbedtls_mpi_cmp_mpi( &pub->N, &prv->N ) != 0 ||
        mbedtls_mpi_cmp_mpi( &pub->E, &prv->E ) != 0 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

    return( 0 );
}

/*************************************************************************************************
* Description: This function performs an RSA public key operation.
************************************************************************************************/
int mbedtls_rsa_public( mbedtls_rsa_context *ctx,
                const unsigned char *input,
                unsigned char *output )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	hseSrvResponse_t srvResponse;
    uint32_t olen;
    mbedtls_mpi T;
    RSA_ALT_VALIDATE_RET( ctx != NULL );
    RSA_ALT_VALIDATE_RET( input != NULL );
    RSA_ALT_VALIDATE_RET( output != NULL );

    if( rsa_check_context( ctx, 0 /* public */, 0 /* no blinding */ ) )
    {
    	return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }

    mbedtls_mpi_init( &T );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &T, input, ctx->len ) );

    if( mbedtls_mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

	/* Perform RSA PUBLIC Key Operation */
	do
	{
		/* Load Key */
		if(NO_ERROR != (ret = mbedtls_rsa_loadkey(ctx, MBEDTLS_RSA_PUBLIC)))
		{
			break;
		}

		/* Output buffer must be writable buffer of size ctx->len */
		olen = ctx->len;

		/* Perform RSA Encrypt operation */
		srvResponse = HSE_RsaEsNoPadding(HSE_CIPHER_DIR_ENCRYPT, ctx->keyHandle, input,
				(uint32_t)ctx->len, (uint8_t *)output, &olen);

		switch(srvResponse)
		{
			case HSE_SRV_RSP_OK: 
				/* Return with NO_ERROR on success */
				ret = NO_ERROR ;
				(void)KeyStoreMgmt_FreeKey(ctx->keyHandle);
				ctx->keyHandle = HSE_INVALID_KEY_HANDLE;
				break;
			case HSE_SRV_RSP_INVALID_PARAM:
			default:
				/* Return with Error Codes */
				ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
				break;
		}
		
	}while(0);
cleanup:
    mbedtls_mpi_free( &T );

	/* Unload key */
	mbedtls_rsa_unloadkey( ctx,MBEDTLS_RSA_PUBLIC);

    if( ret != NO_ERROR )
	{
        ret = ( MBEDTLS_ERR_RSA_PUBLIC_FAILED + ret );
	}
	return ret ;
}

/*************************************************************************************************
* Description: This function performs an RSA private key operation.
************************************************************************************************/
int mbedtls_rsa_private( mbedtls_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 const unsigned char *input,
                 unsigned char *output )
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	uint32_t olen;
	hseSrvResponse_t srvResponse;

	/* Temporary holding the result */
	mbedtls_mpi T;

	RSA_ALT_VALIDATE_RET( ctx != NULL );
	RSA_ALT_VALIDATE_RET( input  != NULL );
	RSA_ALT_VALIDATE_RET( output != NULL );

	/* Unused parameters */
	(void)p_rng;

	if( rsa_check_context( ctx, 1			  /* private key checks */,
								f_rng != NULL /* blinding y/n		*/ ) != 0 )
	{
		return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
	}

    /* MPI Initialization */
    mbedtls_mpi_init( &T );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &T, input, ctx->len ) );
    if( mbedtls_mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

	/* Perform RSA PRIVATE Key Operation */
	do
	{
		/* Load Key */
		if(NO_ERROR != (ret = mbedtls_rsa_loadkey(ctx, MBEDTLS_RSA_PRIVATE)))
		{
			break;
		}
		
		/* Output buffer must be writable buffer of size ctx->len */
		olen = ctx->len;

		/* Perform RSA Decrypt operation */
		srvResponse = HSE_RsaEsNoPadding(HSE_CIPHER_DIR_DECRYPT, ctx->keyHandle, input,
				(uint32_t)ctx->len, (uint8_t *)output, &olen);

		switch(srvResponse)
		{
			case HSE_SRV_RSP_OK: 
				/* Return with NO_ERROR on success */
				ret = NO_ERROR ;
				break;
			case HSE_SRV_RSP_INVALID_PARAM:
			default:
				/* Return with Error Codes */
				ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
				break;
		}

	}while(0);
cleanup:

    mbedtls_mpi_free( &T );

	/* Unload key */
	mbedtls_rsa_unloadkey( ctx,MBEDTLS_RSA_PRIVATE);

    if( ret != NO_ERROR )
	{
        ret = ( MBEDTLS_ERR_RSA_PRIVATE_FAILED + ret );
	}
	return ret ;
}

/*************************************************************************************************
* Description: Copy the components of an RSA key.
************************************************************************************************/
int mbedtls_rsa_copy( mbedtls_rsa_context *dst, const mbedtls_rsa_context *src )
{

	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	RSA_ALT_VALIDATE_RET( dst != NULL );
	RSA_ALT_VALIDATE_RET( src != NULL );

	dst->ver = src->ver;
	dst->len = src->len;

	MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->N, &src->N ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->E, &src->E ) );

	MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->D, &src->D ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->P, &src->P ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->Q, &src->Q ) );

	dst->padding = src->padding;
	dst->hash_id = src->hash_id;
	dst->keyHandle = HSE_INVALID_KEY_HANDLE;
	dst->privkey_flag = src->privkey_flag;

cleanup:
	if( ret != 0 )
	{
		mbedtls_rsa_free( dst );
	}

    return( 0 );
}

/*************************************************************************************************
* Description:  This function releases and clears the specified RSA context.
************************************************************************************************/
void mbedtls_rsa_free( mbedtls_rsa_context *ctx )
{
	/* Simple sanity check */
    if( ctx == NULL)
    {
    	return ;
    }

    mbedtls_mpi_free( &ctx->D  );
    mbedtls_mpi_free( &ctx->Q  );
    mbedtls_mpi_free( &ctx->P  );
    mbedtls_mpi_free( &ctx->E  );
    mbedtls_mpi_free( &ctx->N  );

	/* Free Key Handle */
	if(ctx->keyHandle != HSE_INVALID_KEY_HANDLE)
	{
		(void)KeyStoreMgmt_FreeKey(ctx->keyHandle);
	}
	
	ctx->keyHandle = HSE_INVALID_KEY_HANDLE;
}

#endif /* MBEDTLS_RSA_ALT */
