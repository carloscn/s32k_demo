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
#if defined(MBEDTLS_CONFIG_FILE)
#include MBEDTLS_CONFIG_FILE
#else
#include "mbedtls/config.h"
#endif

#if defined(MBEDTLS_ECP_INTERNAL_ALT)
#endif

#if defined(MBEDTLS_ECP_C)

#include "mbedtls/ecp.h"
#include "mbedtls/threading.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>

#if defined(MBEDTLS_ECP_ALT)
#include "nxp_hse_ecc.h"
#include "hse_host_km_utils.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#include <stdio.h>
#define mbedtls_printf     printf
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#include "mbedtls/ecp_internal.h"

#if !defined(MBEDTLS_ECP_NO_INTERNAL_RNG)
#if defined(MBEDTLS_HMAC_DRBG_C)
#include "mbedtls/hmac_drbg.h"
#elif defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/ctr_drbg.h"
#else
#error "Invalid configuration detected. Include check_config.h to ensure that the configuration is valid."
#endif
#endif /* MBEDTLS_ECP_NO_INTERNAL_RNG */

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

/*==================================================================================================
*                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL MACROS
==================================================================================================*/
/* Parameter validation macros based on platform_util.h */
#define ECP_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA )
#define ECP_VALIDATE( cond )        \
    MBEDTLS_INTERNAL_VALIDATE( cond )

/*
 * Fast mod-p functions expect their argument to be in the 0..p^2 range.
 *
 * In order to guarantee that, we need to ensure that operands of
 * mbedtls_mpi_mul_mpi are in the 0..p range. So, after each operation we will
 * bring the result back to this range.
 *
 * The following macros are shortcuts for doing that.
 */

/*
 * Reduce a mbedtls_mpi mod p in-place, general case, to use after mbedtls_mpi_mul_mpi
 */
#if defined(MBEDTLS_SELF_TEST)
#define INC_MUL_COUNT   mul_count++;
#else
#define INC_MUL_COUNT
#endif

#define MOD_MUL( N )                                                    \
    do                                                                  \
    {                                                                   \
        MBEDTLS_MPI_CHK( ecp_modp( &(N), grp ) );                       \
        INC_MUL_COUNT                                                   \
    } while( 0 )

/*==================================================================================================
*                                      LOCAL CONSTANTS
==================================================================================================*/

/*==================================================================================================
*                                      LOCAL VARIABLES
==================================================================================================*/
#if defined(MBEDTLS_SELF_TEST)
/*
 * Counts of point addition and doubling, and field multiplications.
 * Used to test resistance of point multiplication to simple timing attacks.
 */
static unsigned long add_count, dbl_count, mul_count;
#endif

/*==================================================================================================
*                                      GLOBAL CONSTANTS
==================================================================================================*/
/*
 * List of supported curves:
 *  - internal ID
 *  - TLS NamedCurve ID (RFC 4492 sec. 5.1.1, RFC 7071 sec. 2, RFC 8446 sec. 4.2.7)
 *  - size in bits
 *  - readable name
 *
 * Curves are listed in order: largest curves first, and for a given size,
 * fastest curves first. This provides the default order for the SSL module.
 *
 * Reminder: update profiles in x509_crt.c when adding a new curves!
 */
static const mbedtls_ecp_curve_info ecp_supported_curves[] =
{
#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
    { MBEDTLS_ECP_DP_SECP521R1,    25,     521,    "secp521r1"         },
#endif
#if defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)
    { MBEDTLS_ECP_DP_BP512R1,      28,     512,    "brainpoolP512r1"   },
#endif
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
    { MBEDTLS_ECP_DP_SECP384R1,    24,     384,    "secp384r1"         },
#endif
#if defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)
    { MBEDTLS_ECP_DP_BP384R1,      27,     384,    "brainpoolP384r1"   },
#endif
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
    { MBEDTLS_ECP_DP_SECP256R1,    23,     256,    "secp256r1"         },
#endif
#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
    { MBEDTLS_ECP_DP_SECP256K1,    22,     256,    "secp256k1"         },
#endif
#if defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)
    { MBEDTLS_ECP_DP_BP256R1,      26,     256,    "brainpoolP256r1"   },
#endif
#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
    { MBEDTLS_ECP_DP_SECP224R1,    21,     224,    "secp224r1"         },
#endif
#if defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
    { MBEDTLS_ECP_DP_SECP224K1,    20,     224,    "secp224k1"         },
#endif
#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
    { MBEDTLS_ECP_DP_SECP192R1,    19,     192,    "secp192r1"         },
#endif
#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
    { MBEDTLS_ECP_DP_SECP192K1,    18,     192,    "secp192k1"         },
#endif
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED) && defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
    { MBEDTLS_ECP_DP_CURVE25519,   29,     256,    "x25519"            },
#endif
    { MBEDTLS_ECP_DP_NONE,          0,     0,      NULL                },
};


#define ECP_NB_CURVES   sizeof( ecp_supported_curves ) /    \
                        sizeof( ecp_supported_curves[0] )

static mbedtls_ecp_group_id ecp_supported_grp_id[ECP_NB_CURVES];

/*==================================================================================================
*                                      GLOBAL VARIABLES
==================================================================================================*/

/*==================================================================================================
*                                   LOCAL FUNCTION PROTOTYPES
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL FUNCTIONS
==================================================================================================*/

#if !defined(MBEDTLS_ECP_NO_INTERNAL_RNG)
/*
 * Currently ecp_mul() takes a RNG function as an argument, used for
 * side-channel protection, but it can be NULL. The initial reasoning was
 * that people will pass non-NULL RNG when they care about side-channels, but
 * unfortunately we have some APIs that call ecp_mul() with a NULL RNG, with
 * no opportunity for the user to do anything about it.
 *
 * The obvious strategies for addressing that include:
 * - change those APIs so that they take RNG arguments;
 * - require a global RNG to be available to all crypto modules.
 *
 * Unfortunately those would break compatibility. So what we do instead is
 * have our own internal DRBG instance, seeded from the secret scalar.
 *
 * The following is a light-weight abstraction layer for doing that with
 * HMAC_DRBG (first choice) or CTR_DRBG.
 */

#if defined(MBEDTLS_HMAC_DRBG_C)

/* DRBG context type */
typedef mbedtls_hmac_drbg_context ecp_drbg_context;

/* DRBG context init */
static inline void ecp_drbg_init( ecp_drbg_context *ctx )
{
    mbedtls_hmac_drbg_init( ctx );
}

/* DRBG context free */
static inline void ecp_drbg_free( ecp_drbg_context *ctx )
{
    mbedtls_hmac_drbg_free( ctx );
}

/* DRBG function */
static inline int ecp_drbg_random( void *p_rng,
                                   unsigned char *output, size_t output_len )
{
    return( mbedtls_hmac_drbg_random( p_rng, output, output_len ) );
}

/* DRBG context seeding */
static int ecp_drbg_seed( ecp_drbg_context *ctx,
                   const mbedtls_mpi *secret, size_t secret_len )
{
    int ret;
    unsigned char secret_bytes[MBEDTLS_ECP_MAX_BYTES];
    /* The list starts with strong hashes */
    const mbedtls_md_type_t md_type = mbedtls_md_list()[0];
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type( md_type );

    if( secret_len > MBEDTLS_ECP_MAX_BYTES )
    {
        ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( secret,
                                               secret_bytes, secret_len ) );

    ret = mbedtls_hmac_drbg_seed_buf( ctx, md_info, secret_bytes, secret_len );

cleanup:
    mbedtls_platform_zeroize( secret_bytes, secret_len );

    return( ret );
}

#elif defined(MBEDTLS_CTR_DRBG_C)

/* DRBG context type */
typedef mbedtls_ctr_drbg_context ecp_drbg_context;

/* DRBG context init */
static inline void ecp_drbg_init( ecp_drbg_context *ctx )
{
    mbedtls_ctr_drbg_init( ctx );
}

/* DRBG context free */
static inline void ecp_drbg_free( ecp_drbg_context *ctx )
{
    mbedtls_ctr_drbg_free( ctx );
}

/* DRBG function */
static inline int ecp_drbg_random( void *p_rng,
                                   unsigned char *output, size_t output_len )
{
    return( mbedtls_ctr_drbg_random( p_rng, output, output_len ) );
}

/*
 * Since CTR_DRBG doesn't have a seed_buf() function the way HMAC_DRBG does,
 * we need to pass an entropy function when seeding. So we use a dummy
 * function for that, and pass the actual entropy as customisation string.
 * (During seeding of CTR_DRBG the entropy input and customisation string are
 * concatenated before being used to update the secret state.)
 */
static int ecp_ctr_drbg_null_entropy(void *ctx, unsigned char *out, size_t len)
{
    (void) ctx;
    memset( out, 0, len );
    return( 0 );
}

/* DRBG context seeding */
static int ecp_drbg_seed( ecp_drbg_context *ctx,
                   const mbedtls_mpi *secret, size_t secret_len )
{
    int ret;
    unsigned char secret_bytes[MBEDTLS_ECP_MAX_BYTES];

    if( secret_len > MBEDTLS_ECP_MAX_BYTES )
    {
        ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( secret,
                                               secret_bytes, secret_len ) );

    ret = mbedtls_ctr_drbg_seed( ctx, ecp_ctr_drbg_null_entropy, NULL,
                                 secret_bytes, secret_len );

cleanup:
    mbedtls_platform_zeroize( secret_bytes, secret_len );

    return( ret );
}

#else
#error "Invalid configuration detected. Include check_config.h to ensure that the configuration is valid."
#endif /* DRBG modules */
#endif /* MBEDTLS_ECP_NO_INTERNAL_RNG */

#define ECP_RS_ENTER( sub )     (void) rs_ctx;
#define ECP_RS_LEAVE( sub )     (void) rs_ctx;

/*
 * Wrapper around fast quasi-modp functions, with fall-back to mbedtls_mpi_mod_mpi.
 * See the documentation of struct mbedtls_ecp_group.
 *
 * This function is in the critial loop for mbedtls_ecp_mul, so pay attention to perf.
 */
static int ecp_modp( mbedtls_mpi *N, const mbedtls_ecp_group *grp )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( grp->modp == NULL )
        return( mbedtls_mpi_mod_mpi( N, N, &grp->P ) );

    /* N->s < 0 is a much faster test, which fails only if N is 0 */
    if( ( N->s < 0 && mbedtls_mpi_cmp_int( N, 0 ) != 0 ) ||
        mbedtls_mpi_bitlen( N ) > 2 * grp->pbits )
    {
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    }

    MBEDTLS_MPI_CHK( grp->modp( N ) );

    /* N->s < 0 is a much faster test, which fails only if N is 0 */
    while( N->s < 0 && mbedtls_mpi_cmp_int( N, 0 ) != 0 )
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( N, N, &grp->P ) );

    while( mbedtls_mpi_cmp_mpi( N, &grp->P ) >= 0 )
        /* we known P, N and the result are positive */
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_abs( N, N, &grp->P ) );

cleanup:
    return( ret );
}

static inline int mbedtls_mpi_mul_mod( const mbedtls_ecp_group *grp,
                                       mbedtls_mpi *X,
                                       const mbedtls_mpi *A,
                                       const mbedtls_mpi *B )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( X, A, B ) );
    MOD_MUL( *X );
cleanup:
    return( ret );
}

/*
 * Reduce a mbedtls_mpi mod p in-place, to use after mbedtls_mpi_sub_mpi
 * N->s < 0 is a very fast test, which fails only if N is 0
 */
#define MOD_SUB( N )                                                    \
    while( (N).s < 0 && mbedtls_mpi_cmp_int( &(N), 0 ) != 0 )           \
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &(N), &(N), &grp->P ) )

static inline int mbedtls_mpi_sub_mod( const mbedtls_ecp_group *grp,
                                       mbedtls_mpi *X,
                                       const mbedtls_mpi *A,
                                       const mbedtls_mpi *B )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( X, A, B ) );
    MOD_SUB( *X );
cleanup:
    return( ret );
}

/*
 * Reduce a mbedtls_mpi mod p in-place, to use after mbedtls_mpi_add_mpi and mbedtls_mpi_mul_int.
 * We known P, N and the result are positive, so sub_abs is correct, and
 * a bit faster.
 */
#define MOD_ADD( N )                                                    \
    while( mbedtls_mpi_cmp_mpi( &(N), &grp->P ) >= 0 )                  \
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_abs( &(N), &(N), &grp->P ) )

static inline int mbedtls_mpi_add_mod( const mbedtls_ecp_group *grp,
                                       mbedtls_mpi *X,
                                       const mbedtls_mpi *A,
                                       const mbedtls_mpi *B )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( X, A, B ) );
    MOD_ADD( *X );
cleanup:
    return( ret );
}

static inline int mbedtls_mpi_shift_l_mod( const mbedtls_ecp_group *grp,
                                           mbedtls_mpi *X,
                                           size_t count )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( X, count ) );
    MOD_ADD( *X );
cleanup:
    return( ret );
}

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
/*
 * For curves in short Weierstrass form, we do all the internal operations in
 * Jacobian coordinates.
 *
 * For multiplication, we'll use a comb method with coutermeasueres against
 * SPA, hence timing attacks.
 */

/*
 * Normalize jacobian coordinates so that Z == 0 || Z == 1  (GECC 3.2.1)
 * Cost: 1N := 1I + 3M + 1S
 */
static int ecp_normalize_jac( const mbedtls_ecp_group *grp, mbedtls_ecp_point *pt )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi Zi, ZZi;

    if( mbedtls_mpi_cmp_int( &pt->Z, 0 ) == 0 )
        return( 0 );

#if defined(MBEDTLS_ECP_NORMALIZE_JAC_ALT)
    if( mbedtls_internal_ecp_grp_capable( grp ) )
        return( mbedtls_internal_ecp_normalize_jac( grp, pt ) );
#endif /* MBEDTLS_ECP_NORMALIZE_JAC_ALT */

    mbedtls_mpi_init( &Zi ); mbedtls_mpi_init( &ZZi );

    /*
     * X = X / Z^2  mod p
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &Zi,      &pt->Z,     &grp->P ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &ZZi,     &Zi,        &Zi     ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &pt->X,   &pt->X,     &ZZi    ) );

    /*
     * Y = Y / Z^3  mod p
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &pt->Y,   &pt->Y,     &ZZi    ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &pt->Y,   &pt->Y,     &Zi     ) );

    /*
     * Z = 1
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &pt->Z, 1 ) );

cleanup:

    mbedtls_mpi_free( &Zi ); mbedtls_mpi_free( &ZZi );

    return( ret );
}

/*
 * Normalize jacobian coordinates of an array of (pointers to) points,
 * using Montgomery's trick to perform only one inversion mod P.
 * (See for example Cohen's "A Course in Computational Algebraic Number
 * Theory", Algorithm 10.3.4.)
 *
 * Warning: fails (returning an error) if one of the points is zero!
 * This should never happen, see choice of w in ecp_mul_comb().
 *
 * Cost: 1N(t) := 1I + (6t - 3)M + 1S
 */
static int ecp_normalize_jac_many( const mbedtls_ecp_group *grp,
                                   mbedtls_ecp_point *T[], size_t T_size )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i;
    mbedtls_mpi *c, u, Zi, ZZi;

    if( T_size < 2 )
        return( ecp_normalize_jac( grp, *T ) );

#if defined(MBEDTLS_ECP_NORMALIZE_JAC_MANY_ALT)
    if( mbedtls_internal_ecp_grp_capable( grp ) )
        return( mbedtls_internal_ecp_normalize_jac_many( grp, T, T_size ) );
#endif

    if( ( c = mbedtls_calloc( T_size, sizeof( mbedtls_mpi ) ) ) == NULL )
        return( MBEDTLS_ERR_ECP_ALLOC_FAILED );

    for( i = 0; i < T_size; i++ )
        mbedtls_mpi_init( &c[i] );

    mbedtls_mpi_init( &u ); mbedtls_mpi_init( &Zi ); mbedtls_mpi_init( &ZZi );

    /*
     * c[i] = Z_0 * ... * Z_i
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &c[0], &T[0]->Z ) );
    for( i = 1; i < T_size; i++ )
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &c[i], &c[i-1], &T[i]->Z ) );
    }

    /*
     * u = 1 / (Z_0 * ... * Z_n) mod P
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &u, &c[T_size-1], &grp->P ) );

    for( i = T_size - 1; ; i-- )
    {
        /*
         * Zi = 1 / Z_i mod p
         * u = 1 / (Z_0 * ... * Z_i) mod P
         */
        if( i == 0 ) {
            MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &Zi, &u ) );
        }
        else
        {
            MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &Zi, &u, &c[i-1]  ) );
            MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &u,  &u, &T[i]->Z ) );
        }

        /*
         * proceed as in normalize()
         */
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &ZZi,     &Zi,      &Zi  ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T[i]->X, &T[i]->X, &ZZi ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T[i]->Y, &T[i]->Y, &ZZi ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T[i]->Y, &T[i]->Y, &Zi  ) );

        /*
         * Post-precessing: reclaim some memory by shrinking coordinates
         * - not storing Z (always 1)
         * - shrinking other coordinates, but still keeping the same number of
         *   limbs as P, as otherwise it will too likely be regrown too fast.
         */
        MBEDTLS_MPI_CHK( mbedtls_mpi_shrink( &T[i]->X, grp->P.n ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_shrink( &T[i]->Y, grp->P.n ) );
        mbedtls_mpi_free( &T[i]->Z );

        if( i == 0 )
            break;
    }

cleanup:

    mbedtls_mpi_free( &u ); mbedtls_mpi_free( &Zi ); mbedtls_mpi_free( &ZZi );
    for( i = 0; i < T_size; i++ )
        mbedtls_mpi_free( &c[i] );
    mbedtls_free( c );

    return( ret );
}

/*
 * Conditional point inversion: Q -> -Q = (Q.X, -Q.Y, Q.Z) without leak.
 * "inv" must be 0 (don't invert) or 1 (invert) or the result will be invalid
 */
static int ecp_safe_invert_jac( const mbedtls_ecp_group *grp,
                            mbedtls_ecp_point *Q,
                            unsigned char inv )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char nonzero;
    mbedtls_mpi mQY;

    mbedtls_mpi_init( &mQY );

    /* Use the fact that -Q.Y mod P = P - Q.Y unless Q.Y == 0 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &mQY, &grp->P, &Q->Y ) );
    nonzero = mbedtls_mpi_cmp_int( &Q->Y, 0 ) != 0;
    MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_assign( &Q->Y, &mQY, inv & nonzero ) );

cleanup:
    mbedtls_mpi_free( &mQY );

    return( ret );
}

/*
 * Point doubling R = 2 P, Jacobian coordinates
 *
 * Based on http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-1998-cmo-2 .
 *
 * We follow the variable naming fairly closely. The formula variations that trade a MUL for a SQR
 * (plus a few ADDs) aren't useful as our bignum implementation doesn't distinguish squaring.
 *
 * Standard optimizations are applied when curve parameter A is one of { 0, -3 }.
 *
 * Cost: 1D := 3M + 4S          (A ==  0)
 *             4M + 4S          (A == -3)
 *             3M + 6S + 1a     otherwise
 */
static int ecp_double_jac( const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                           const mbedtls_ecp_point *P )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi M, S, T, U;

#if defined(MBEDTLS_SELF_TEST)
    dbl_count++;
#endif

#if defined(MBEDTLS_ECP_DOUBLE_JAC_ALT)
    if( mbedtls_internal_ecp_grp_capable( grp ) )
        return( mbedtls_internal_ecp_double_jac( grp, R, P ) );
#endif /* MBEDTLS_ECP_DOUBLE_JAC_ALT */

    mbedtls_mpi_init( &M ); mbedtls_mpi_init( &S ); mbedtls_mpi_init( &T ); mbedtls_mpi_init( &U );

    /* Special case for A = -3 */
    if( grp->A.p == NULL )
    {
        /* M = 3(X + Z^2)(X - Z^2) */
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &S,  &P->Z,  &P->Z   ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mod( grp, &T,  &P->X,  &S      ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &U,  &P->X,  &S      ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &S,  &T,     &U      ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_int( &M,  &S,     3       ) ); MOD_ADD( M );
    }
    else
    {
        /* M = 3.X^2 */
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &S,  &P->X,  &P->X   ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_int( &M,  &S,     3       ) ); MOD_ADD( M );

        /* Optimize away for "koblitz" curves with A = 0 */
        if( mbedtls_mpi_cmp_int( &grp->A, 0 ) != 0 )
        {
            /* M += A.Z^4 */
            MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &S,  &P->Z,  &P->Z   ) );
            MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T,  &S,     &S      ) );
            MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &S,  &T,     &grp->A ) );
            MBEDTLS_MPI_CHK( mbedtls_mpi_add_mod( grp, &M,  &M,     &S      ) );
        }
    }

    /* S = 4.X.Y^2 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T,  &P->Y,  &P->Y   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l_mod( grp, &T,  1               ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &S,  &P->X,  &T      ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l_mod( grp, &S,  1               ) );

    /* U = 8.Y^4 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &U,  &T,     &T      ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l_mod( grp, &U,  1               ) );

    /* T = M^2 - 2.S */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T,  &M,     &M      ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &T,  &T,     &S      ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &T,  &T,     &S      ) );

    /* S = M(S - T) - U */
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &S,  &S,     &T      ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &S,  &S,     &M      ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &S,  &S,     &U      ) );

    /* U = 2.Y.Z */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &U,  &P->Y,  &P->Z   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l_mod( grp, &U,  1               ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &R->X, &T ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &R->Y, &S ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &R->Z, &U ) );

cleanup:
    mbedtls_mpi_free( &M ); mbedtls_mpi_free( &S ); mbedtls_mpi_free( &T ); mbedtls_mpi_free( &U );

    return( ret );
}

/*
 * Addition: R = P + Q, mixed affine-Jacobian coordinates (GECC 3.22)
 *
 * The coordinates of Q must be normalized (= affine),
 * but those of P don't need to. R is not normalized.
 *
 * Special cases: (1) P or Q is zero, (2) R is zero, (3) P == Q.
 * None of these cases can happen as intermediate step in ecp_mul_comb():
 * - at each step, P, Q and R are multiples of the base point, the factor
 *   being less than its order, so none of them is zero;
 * - Q is an odd multiple of the base point, P an even multiple,
 *   due to the choice of precomputed points in the modified comb method.
 * So branches for these cases do not leak secret information.
 *
 * We accept Q->Z being unset (saving memory in tables) as meaning 1.
 *
 * Cost: 1A := 8M + 3S
 */
static int ecp_add_mixed( const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                          const mbedtls_ecp_point *P, const mbedtls_ecp_point *Q )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi T1, T2, T3, T4, X, Y, Z;

#if defined(MBEDTLS_SELF_TEST)
    add_count++;
#endif

#if defined(MBEDTLS_ECP_ADD_MIXED_ALT)
    if( mbedtls_internal_ecp_grp_capable( grp ) )
        return( mbedtls_internal_ecp_add_mixed( grp, R, P, Q ) );
#endif /* MBEDTLS_ECP_ADD_MIXED_ALT */

    /*
     * Trivial cases: P == 0 or Q == 0 (case 1)
     */
    if( mbedtls_mpi_cmp_int( &P->Z, 0 ) == 0 )
        return( mbedtls_ecp_copy( R, Q ) );

    if( Q->Z.p != NULL && mbedtls_mpi_cmp_int( &Q->Z, 0 ) == 0 )
        return( mbedtls_ecp_copy( R, P ) );

    /*
     * Make sure Q coordinates are normalized
     */
    if( Q->Z.p != NULL && mbedtls_mpi_cmp_int( &Q->Z, 1 ) != 0 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    mbedtls_mpi_init( &T1 ); mbedtls_mpi_init( &T2 ); mbedtls_mpi_init( &T3 ); mbedtls_mpi_init( &T4 );
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Z );

    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T1,  &P->Z,  &P->Z ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T2,  &T1,    &P->Z ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T1,  &T1,    &Q->X ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T2,  &T2,    &Q->Y ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &T1,  &T1,    &P->X ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &T2,  &T2,    &P->Y ) );

    /* Special cases (2) and (3) */
    if( mbedtls_mpi_cmp_int( &T1, 0 ) == 0 )
    {
        if( mbedtls_mpi_cmp_int( &T2, 0 ) == 0 )
        {
            ret = ecp_double_jac( grp, R, P );
            goto cleanup;
        }
        else
        {
            ret = mbedtls_ecp_set_zero( R );
            goto cleanup;
        }
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &Z,   &P->Z,  &T1   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T3,  &T1,    &T1   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T4,  &T3,    &T1   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T3,  &T3,    &P->X ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &T1, &T3 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l_mod( grp, &T1,  1     ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &X,   &T2,    &T2   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &X,   &X,     &T1   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &X,   &X,     &T4   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &T3,  &T3,    &X    ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T3,  &T3,    &T2   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T4,  &T4,    &P->Y ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &Y,   &T3,    &T4   ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &R->X, &X ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &R->Y, &Y ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &R->Z, &Z ) );

cleanup:

    mbedtls_mpi_free( &T1 ); mbedtls_mpi_free( &T2 ); mbedtls_mpi_free( &T3 ); mbedtls_mpi_free( &T4 );
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Z );

    return( ret );
}

/*
 * Randomize jacobian coordinates:
 * (X, Y, Z) -> (l^2 X, l^3 Y, l Z) for random l
 * This is sort of the reverse operation of ecp_normalize_jac().
 *
 * This countermeasure was first suggested in [2].
 */
static int ecp_randomize_jac( const mbedtls_ecp_group *grp, mbedtls_ecp_point *pt,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi l, ll;
    size_t p_size;
    int count = 0;

#if defined(MBEDTLS_ECP_RANDOMIZE_JAC_ALT)
    if( mbedtls_internal_ecp_grp_capable( grp ) )
        return( mbedtls_internal_ecp_randomize_jac( grp, pt, f_rng, p_rng ) );
#endif /* MBEDTLS_ECP_RANDOMIZE_JAC_ALT */

    p_size = ( grp->pbits + 7 ) / 8;
    mbedtls_mpi_init( &l ); mbedtls_mpi_init( &ll );

    /* Generate l such that 1 < l < p */
    do
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &l, p_size, f_rng, p_rng ) );

        while( mbedtls_mpi_cmp_mpi( &l, &grp->P ) >= 0 )
            MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &l, 1 ) );

        if( count++ > 10 )
        {
            ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
            goto cleanup;
        }
    }
    while( mbedtls_mpi_cmp_int( &l, 1 ) <= 0 );

    /* Z = l * Z */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &pt->Z,   &pt->Z,     &l  ) );

    /* X = l^2 * X */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &ll,      &l,         &l  ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &pt->X,   &pt->X,     &ll ) );

    /* Y = l^3 * Y */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &ll,      &ll,        &l  ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &pt->Y,   &pt->Y,     &ll ) );

cleanup:
    mbedtls_mpi_free( &l ); mbedtls_mpi_free( &ll );

    return( ret );
}

/*
 * Check and define parameters used by the comb method (see below for details)
 */
#if MBEDTLS_ECP_WINDOW_SIZE < 2 || MBEDTLS_ECP_WINDOW_SIZE > 7
#error "MBEDTLS_ECP_WINDOW_SIZE out of bounds"
#endif

/* d = ceil( n / w ) */
#define COMB_MAX_D      ( MBEDTLS_ECP_MAX_BITS + 1 ) / 2

/* number of precomputed points */
#define COMB_MAX_PRE    ( 1 << ( MBEDTLS_ECP_WINDOW_SIZE - 1 ) )

/*
 * Compute the representation of m that will be used with our comb method.
 *
 * The basic comb method is described in GECC 3.44 for example. We use a
 * modified version that provides resistance to SPA by avoiding zero
 * digits in the representation as in [3]. We modify the method further by
 * requiring that all K_i be odd, which has the small cost that our
 * representation uses one more K_i, due to carries, but saves on the size of
 * the precomputed table.
 *
 * Summary of the comb method and its modifications:
 *
 * - The goal is to compute m*P for some w*d-bit integer m.
 *
 * - The basic comb method splits m into the w-bit integers
 *   x[0] .. x[d-1] where x[i] consists of the bits in m whose
 *   index has residue i modulo d, and computes m * P as
 *   S[x[0]] + 2 * S[x[1]] + .. + 2^(d-1) S[x[d-1]], where
 *   S[i_{w-1} .. i_0] := i_{w-1} 2^{(w-1)d} P + ... + i_1 2^d P + i_0 P.
 *
 * - If it happens that, say, x[i+1]=0 (=> S[x[i+1]]=0), one can replace the sum by
 *    .. + 2^{i-1} S[x[i-1]] - 2^i S[x[i]] + 2^{i+1} S[x[i]] + 2^{i+2} S[x[i+2]] ..,
 *   thereby successively converting it into a form where all summands
 *   are nonzero, at the cost of negative summands. This is the basic idea of [3].
 *
 * - More generally, even if x[i+1] != 0, we can first transform the sum as
 *   .. - 2^i S[x[i]] + 2^{i+1} ( S[x[i]] + S[x[i+1]] ) + 2^{i+2} S[x[i+2]] ..,
 *   and then replace S[x[i]] + S[x[i+1]] = S[x[i] ^ x[i+1]] + 2 S[x[i] & x[i+1]].
 *   Performing and iterating this procedure for those x[i] that are even
 *   (keeping track of carry), we can transform the original sum into one of the form
 *   S[x'[0]] +- 2 S[x'[1]] +- .. +- 2^{d-1} S[x'[d-1]] + 2^d S[x'[d]]
 *   with all x'[i] odd. It is therefore only necessary to know S at odd indices,
 *   which is why we are only computing half of it in the first place in
 *   ecp_precompute_comb and accessing it with index abs(i) / 2 in ecp_select_comb.
 *
 * - For the sake of compactness, only the seven low-order bits of x[i]
 *   are used to represent its absolute value (K_i in the paper), and the msb
 *   of x[i] encodes the sign (s_i in the paper): it is set if and only if
 *   if s_i == -1;
 *
 * Calling conventions:
 * - x is an array of size d + 1
 * - w is the size, ie number of teeth, of the comb, and must be between
 *   2 and 7 (in practice, between 2 and MBEDTLS_ECP_WINDOW_SIZE)
 * - m is the MPI, expected to be odd and such that bitlength(m) <= w * d
 *   (the result will be incorrect if these assumptions are not satisfied)
 */
static void ecp_comb_recode_core( unsigned char x[], size_t d,
                                  unsigned char w, const mbedtls_mpi *m )
{
    size_t i, j;
    unsigned char c, cc, adjust;

    memset( x, 0, d+1 );

    /* First get the classical comb values (except for x_d = 0) */
    for( i = 0; i < d; i++ )
        for( j = 0; j < w; j++ )
            x[i] |= mbedtls_mpi_get_bit( m, i + d * j ) << j;

    /* Now make sure x_1 .. x_d are odd */
    c = 0;
    for( i = 1; i <= d; i++ )
    {
        /* Add carry and update it */
        cc   = x[i] & c;
        x[i] = x[i] ^ c;
        c = cc;

        /* Adjust if needed, avoiding branches */
        adjust = 1 - ( x[i] & 0x01 );
        c   |= x[i] & ( x[i-1] * adjust );
        x[i] = x[i] ^ ( x[i-1] * adjust );
        x[i-1] |= adjust << 7;
    }
}

/*
 * Precompute points for the adapted comb method
 *
 * Assumption: T must be able to hold 2^{w - 1} elements.
 *
 * Operation: If i = i_{w-1} ... i_1 is the binary representation of i,
 *            sets T[i] = i_{w-1} 2^{(w-1)d} P + ... + i_1 2^d P + P.
 *
 * Cost: d(w-1) D + (2^{w-1} - 1) A + 1 N(w-1) + 1 N(2^{w-1} - 1)
 *
 * Note: Even comb values (those where P would be omitted from the
 *       sum defining T[i] above) are not needed in our adaption
 *       the comb method. See ecp_comb_recode_core().
 *
 * This function currently works in four steps:
 * (1) [dbl]      Computation of intermediate T[i] for 2-power values of i
 * (2) [norm_dbl] Normalization of coordinates of these T[i]
 * (3) [add]      Computation of all T[i]
 * (4) [norm_add] Normalization of all T[i]
 *
 * Step 1 can be interrupted but not the others; together with the final
 * coordinate normalization they are the largest steps done at once, depending
 * on the window size. Here are operation counts for P-256:
 *
 * step     (2)     (3)     (4)
 * w = 5    142     165     208
 * w = 4    136      77     160
 * w = 3    130      33     136
 * w = 2    124      11     124
 *
 * So if ECC operations are blocking for too long even with a low max_ops
 * value, it's useful to set MBEDTLS_ECP_WINDOW_SIZE to a lower value in order
 * to minimize maximum blocking time.
 */
static int ecp_precompute_comb( const mbedtls_ecp_group *grp,
                                mbedtls_ecp_point T[], const mbedtls_ecp_point *P,
                                unsigned char w, size_t d,
                                mbedtls_ecp_restart_ctx *rs_ctx )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char i;
    size_t j = 0;
    const unsigned char T_size = 1U << ( w - 1 );
    mbedtls_ecp_point *cur, *TT[COMB_MAX_PRE - 1];

    (void) rs_ctx;

    /*
     * Set T[0] = P and
     * T[2^{l-1}] = 2^{dl} P for l = 1 .. w-1 (this is not the final value)
     */
    MBEDTLS_MPI_CHK( mbedtls_ecp_copy( &T[0], P ) );

	j = 0;

    for( ; j < d * ( w - 1 ); j++ )
    {
        MBEDTLS_ECP_BUDGET( MBEDTLS_ECP_OPS_DBL );

        i = 1U << ( j / d );
        cur = T + i;

        if( j % d == 0 )
            MBEDTLS_MPI_CHK( mbedtls_ecp_copy( cur, T + ( i >> 1 ) ) );

        MBEDTLS_MPI_CHK( ecp_double_jac( grp, cur, cur ) );
    }

    /*
     * Normalize current elements in T. As T has holes,
     * use an auxiliary array of pointers to elements in T.
     */
    j = 0;
    for( i = 1; i < T_size; i <<= 1 )
        TT[j++] = T + i;

    MBEDTLS_ECP_BUDGET( MBEDTLS_ECP_OPS_INV + 6 * j - 2 );

    MBEDTLS_MPI_CHK( ecp_normalize_jac_many( grp, TT, j ) );

    /*
     * Compute the remaining ones using the minimal number of additions
     * Be careful to update T[2^l] only after using it!
     */
    MBEDTLS_ECP_BUDGET( ( T_size - 1 ) * MBEDTLS_ECP_OPS_ADD );

    for( i = 1; i < T_size; i <<= 1 )
    {
        j = i;
        while( j-- )
            MBEDTLS_MPI_CHK( ecp_add_mixed( grp, &T[i + j], &T[j], &T[i] ) );
    }

    /*
     * Normalize final elements in T. Even though there are no holes now, we
     * still need the auxiliary array for homogeneity with the previous
     * call. Also, skip T[0] which is already normalised, being a copy of P.
     */
    for( j = 0; j + 1 < T_size; j++ )
        TT[j] = T + j + 1;

    MBEDTLS_ECP_BUDGET( MBEDTLS_ECP_OPS_INV + 6 * j - 2 );

    MBEDTLS_MPI_CHK( ecp_normalize_jac_many( grp, TT, j ) );

cleanup:

    return( ret );
}

/*
 * Select precomputed point: R = sign(i) * T[ abs(i) / 2 ]
 *
 * See ecp_comb_recode_core() for background
 */
static int ecp_select_comb( const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                            const mbedtls_ecp_point T[], unsigned char T_size,
                            unsigned char i )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char ii, j;

    /* Ignore the "sign" bit and scale down */
    ii =  ( i & 0x7Fu ) >> 1;

    /* Read the whole table to thwart cache-based timing attacks */
    for( j = 0; j < T_size; j++ )
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_assign( &R->X, &T[j].X, j == ii ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_assign( &R->Y, &T[j].Y, j == ii ) );
    }

    /* Safely invert result if i is "negative" */
    MBEDTLS_MPI_CHK( ecp_safe_invert_jac( grp, R, i >> 7 ) );

cleanup:
    return( ret );
}

/*
 * Core multiplication algorithm for the (modified) comb method.
 * This part is actually common with the basic comb method (GECC 3.44)
 *
 * Cost: d A + d D + 1 R
 */
static int ecp_mul_comb_core( const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                              const mbedtls_ecp_point T[], unsigned char T_size,
                              const unsigned char x[], size_t d,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng,
                              mbedtls_ecp_restart_ctx *rs_ctx )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point Txi;
    size_t i;

    mbedtls_ecp_point_init( &Txi );

#if !defined(MBEDTLS_ECP_RESTARTABLE)
    (void) rs_ctx;
#endif

        /* Start with a non-zero point and randomize its coordinates */
	i = d;
	MBEDTLS_MPI_CHK( ecp_select_comb( grp, R, T, T_size, x[i] ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &R->Z, 1 ) );
#if defined(MBEDTLS_ECP_NO_INTERNAL_RNG)
        if( f_rng != 0 )
#endif
	MBEDTLS_MPI_CHK( ecp_randomize_jac( grp, R, f_rng, p_rng ) );


    while( i != 0 )
    {
        MBEDTLS_ECP_BUDGET( MBEDTLS_ECP_OPS_DBL + MBEDTLS_ECP_OPS_ADD );
        --i;

        MBEDTLS_MPI_CHK( ecp_double_jac( grp, R, R ) );
        MBEDTLS_MPI_CHK( ecp_select_comb( grp, &Txi, T, T_size, x[i] ) );
        MBEDTLS_MPI_CHK( ecp_add_mixed( grp, R, R, &Txi ) );
    }

cleanup:

    mbedtls_ecp_point_free( &Txi );

    return( ret );
}

/*
 * Recode the scalar to get constant-time comb multiplication
 *
 * As the actual scalar recoding needs an odd scalar as a starting point,
 * this wrapper ensures that by replacing m by N - m if necessary, and
 * informs the caller that the result of multiplication will be negated.
 *
 * This works because we only support large prime order for Short Weierstrass
 * curves, so N is always odd hence either m or N - m is.
 *
 * See ecp_comb_recode_core() for background.
 */
static int ecp_comb_recode_scalar( const mbedtls_ecp_group *grp,
                                   const mbedtls_mpi *m,
                                   unsigned char k[COMB_MAX_D + 1],
                                   size_t d,
                                   unsigned char w,
                                   unsigned char *parity_trick )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi M, mm;

    mbedtls_mpi_init( &M );
    mbedtls_mpi_init( &mm );

    /* N is always odd (see above), just make extra sure */
    if( mbedtls_mpi_get_bit( &grp->N, 0 ) != 1 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    /* do we need the parity trick? */
    *parity_trick = ( mbedtls_mpi_get_bit( m, 0 ) == 0 );

    /* execute parity fix in constant time */
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &M, m ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &mm, &grp->N, m ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_assign( &M, &mm, *parity_trick ) );

    /* actual scalar recoding */
    ecp_comb_recode_core( k, d, w, &M );

cleanup:
    mbedtls_mpi_free( &mm );
    mbedtls_mpi_free( &M );

    return( ret );
}

/*
 * Perform comb multiplication (for short Weierstrass curves)
 * once the auxiliary table has been pre-computed.
 *
 * Scalar recoding may use a parity trick that makes us compute -m * P,
 * if that is the case we'll need to recover m * P at the end.
 */
static int ecp_mul_comb_after_precomp( const mbedtls_ecp_group *grp,
                                mbedtls_ecp_point *R,
                                const mbedtls_mpi *m,
                                const mbedtls_ecp_point *T,
                                unsigned char T_size,
                                unsigned char w,
                                size_t d,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng,
                                mbedtls_ecp_restart_ctx *rs_ctx )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char parity_trick;
    unsigned char k[COMB_MAX_D + 1];
    mbedtls_ecp_point *RR = R;

    MBEDTLS_MPI_CHK( ecp_comb_recode_scalar( grp, m, k, d, w,
                                            &parity_trick ) );
    MBEDTLS_MPI_CHK( ecp_mul_comb_core( grp, RR, T, T_size, k, d,
                                        f_rng, p_rng, rs_ctx ) );
    MBEDTLS_MPI_CHK( ecp_safe_invert_jac( grp, RR, parity_trick ) );

    /*
     * Knowledge of the jacobian coordinates may leak the last few bits of the
     * scalar [1], and since our MPI implementation isn't constant-flow,
     * inversion (used for coordinate normalization) may leak the full value
     * of its input via side-channels [2].
     *
     * [1] https://eprint.iacr.org/2003/191
     * [2] https://eprint.iacr.org/2020/055
     *
     * Avoid the leak by randomizing coordinates before we normalize them.
     */
#if defined(MBEDTLS_ECP_NO_INTERNAL_RNG)
    if( f_rng != 0 )
#endif
        MBEDTLS_MPI_CHK( ecp_randomize_jac( grp, RR, f_rng, p_rng ) );

    MBEDTLS_MPI_CHK( ecp_normalize_jac( grp, RR ) );

cleanup:
    return( ret );
}

/*
 * Pick window size based on curve size and whether we optimize for base point
 */
static unsigned char ecp_pick_window_size( const mbedtls_ecp_group *grp,
                                           unsigned char p_eq_g )
{
    unsigned char w;

    /*
     * Minimize the number of multiplications, that is minimize
     * 10 * d * w + 18 * 2^(w-1) + 11 * d + 7 * w, with d = ceil( nbits / w )
     * (see costs of the various parts, with 1S = 1M)
     */
    w = grp->nbits >= 384 ? 5 : 4;

    /*
     * If P == G, pre-compute a bit more, since this may be re-used later.
     * Just adding one avoids upping the cost of the first mul too much,
     * and the memory cost too.
     */
    if( p_eq_g )
        w++;

    /*
     * Make sure w is within bounds.
     * (The last test is useful only for very small curves in the test suite.)
     */
#if( MBEDTLS_ECP_WINDOW_SIZE < 6 )
    if( w > MBEDTLS_ECP_WINDOW_SIZE )
        w = MBEDTLS_ECP_WINDOW_SIZE;
#endif
    if( w >= grp->nbits )
        w = 2;

    return( w );
}

/*
 * Multiplication using the comb method - for curves in short Weierstrass form
 *
 * This function is mainly responsible for administrative work:
 * - managing the restart context if enabled
 * - managing the table of precomputed points (passed between the below two
 *   functions): allocation, computation, ownership tranfer, freeing.
 *
 * It delegates the actual arithmetic work to:
 *      ecp_precompute_comb() and ecp_mul_comb_with_precomp()
 *
 * See comments on ecp_comb_recode_core() regarding the computation strategy.
 */
static int ecp_mul_comb( mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                         const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         mbedtls_ecp_restart_ctx *rs_ctx )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char w, p_eq_g, i;
    size_t d;
    unsigned char T_size = 0, T_ok = 0;
    mbedtls_ecp_point *T = NULL;
#if !defined(MBEDTLS_ECP_NO_INTERNAL_RNG)
    ecp_drbg_context drbg_ctx;

    ecp_drbg_init( &drbg_ctx );
#endif

    ECP_RS_ENTER( rsm );

#if !defined(MBEDTLS_ECP_NO_INTERNAL_RNG)
    if( f_rng == NULL )
    {
        /* Adjust pointers */
        f_rng = &ecp_drbg_random;
		p_rng = &drbg_ctx;

        /* Initialize internal DRBG if necessary */
		const size_t m_len = ( grp->nbits + 7 ) / 8;
		MBEDTLS_MPI_CHK( ecp_drbg_seed( p_rng, m, m_len ) );
    }
#endif /* !MBEDTLS_ECP_NO_INTERNAL_RNG */

    /* Is P the base point ? */
#if MBEDTLS_ECP_FIXED_POINT_OPTIM == 1
    p_eq_g = ( mbedtls_mpi_cmp_mpi( &P->Y, &grp->G.Y ) == 0 &&
               mbedtls_mpi_cmp_mpi( &P->X, &grp->G.X ) == 0 );
#else
    p_eq_g = 0;
#endif

    /* Pick window size and deduce related sizes */
    w = ecp_pick_window_size( grp, p_eq_g );
    T_size = 1U << ( w - 1 );
    d = ( grp->nbits + w - 1 ) / w;

    /* Pre-computed table: do we have it already for the base point? */
    if( p_eq_g && grp->T != NULL )
    {
        /* second pointer to the same table, will be deleted on exit */
        T = grp->T;
        T_ok = 1;
    }
    else
    /* Allocate table if we didn't have any */
    {
        T = mbedtls_calloc( T_size, sizeof( mbedtls_ecp_point ) );
        if( T == NULL )
        {
            ret = MBEDTLS_ERR_ECP_ALLOC_FAILED;
            goto cleanup;
        }

        for( i = 0; i < T_size; i++ )
            mbedtls_ecp_point_init( &T[i] );

        T_ok = 0;
    }

    /* Compute table (or finish computing it) if not done already */
    if( !T_ok )
    {
        MBEDTLS_MPI_CHK( ecp_precompute_comb( grp, T, P, w, d, rs_ctx ) );

        if( p_eq_g )
        {
            /* almost transfer ownership of T to the group, but keep a copy of
             * the pointer to use for calling the next function more easily */
            grp->T = T;
            grp->T_size = T_size;
        }
    }

    /* Actual comb multiplication using precomputed points */
    MBEDTLS_MPI_CHK( ecp_mul_comb_after_precomp( grp, R, m,
                                                 T, T_size, w, d,
                                                 f_rng, p_rng, rs_ctx ) );

cleanup:

#if !defined(MBEDTLS_ECP_NO_INTERNAL_RNG)
    ecp_drbg_free( &drbg_ctx );
#endif

    /* does T belong to the group? */
    if( T == grp->T )
        T = NULL;

    /* did T belong to us? then let's destroy it! */
    if( T != NULL )
    {
        for( i = 0; i < T_size; i++ )
            mbedtls_ecp_point_free( &T[i] );
        mbedtls_free( T );
    }

    /* prevent caller from using invalid value */
    if( ret != 0 )
        mbedtls_ecp_point_free( R );

    ECP_RS_LEAVE( rsm );

    return( ret );
}

#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
/*
 * For Montgomery curves, we do all the internal arithmetic in projective
 * coordinates. Import/export of points uses only the x coordinates, which is
 * internaly represented as X / Z.
 *
 * For scalar multiplication, we'll use a Montgomery ladder.
 */

/*
 * Normalize Montgomery x/z coordinates: X = X/Z, Z = 1
 * Cost: 1M + 1I
 */
static int ecp_normalize_mxz( const mbedtls_ecp_group *grp, mbedtls_ecp_point *P )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

#if defined(MBEDTLS_ECP_NORMALIZE_MXZ_ALT)
    if( mbedtls_internal_ecp_grp_capable( grp ) )
        return( mbedtls_internal_ecp_normalize_mxz( grp, P ) );
#endif /* MBEDTLS_ECP_NORMALIZE_MXZ_ALT */

    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &P->Z, &P->Z, &grp->P ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &P->X, &P->X, &P->Z ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &P->Z, 1 ) );

cleanup:
    return( ret );
}

/*
 * Randomize projective x/z coordinates:
 * (X, Z) -> (l X, l Z) for random l
 * This is sort of the reverse operation of ecp_normalize_mxz().
 *
 * This countermeasure was first suggested in [2].
 * Cost: 2M
 */
static int ecp_randomize_mxz( const mbedtls_ecp_group *grp, mbedtls_ecp_point *P,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi l;
    size_t p_size;
    int count = 0;

#if defined(MBEDTLS_ECP_RANDOMIZE_MXZ_ALT)
    if( mbedtls_internal_ecp_grp_capable( grp ) )
        return( mbedtls_internal_ecp_randomize_mxz( grp, P, f_rng, p_rng );
#endif /* MBEDTLS_ECP_RANDOMIZE_MXZ_ALT */

    p_size = ( grp->pbits + 7 ) / 8;
    mbedtls_mpi_init( &l );

    /* Generate l such that 1 < l < p */
    do
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &l, p_size, f_rng, p_rng ) );

        while( mbedtls_mpi_cmp_mpi( &l, &grp->P ) >= 0 )
            MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &l, 1 ) );

        if( count++ > 10 )
        {
            ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
            goto cleanup;
        }
    }
    while( mbedtls_mpi_cmp_int( &l, 1 ) <= 0 );

    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &P->X, &P->X, &l ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &P->Z, &P->Z, &l ) );

cleanup:
    mbedtls_mpi_free( &l );

    return( ret );
}

/*
 * Double-and-add: R = 2P, S = P + Q, with d = X(P - Q),
 * for Montgomery curves in x/z coordinates.
 *
 * http://www.hyperelliptic.org/EFD/g1p/auto-code/montgom/xz/ladder/mladd-1987-m.op3
 * with
 * d =  X1
 * P = (X2, Z2)
 * Q = (X3, Z3)
 * R = (X4, Z4)
 * S = (X5, Z5)
 * and eliminating temporary variables tO, ..., t4.
 *
 * Cost: 5M + 4S
 */
static int ecp_double_add_mxz( const mbedtls_ecp_group *grp,
                               mbedtls_ecp_point *R, mbedtls_ecp_point *S,
                               const mbedtls_ecp_point *P, const mbedtls_ecp_point *Q,
                               const mbedtls_mpi *d )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi A, AA, B, BB, E, C, D, DA, CB;

#if defined(MBEDTLS_ECP_DOUBLE_ADD_MXZ_ALT)
    if( mbedtls_internal_ecp_grp_capable( grp ) )
        return( mbedtls_internal_ecp_double_add_mxz( grp, R, S, P, Q, d ) );
#endif /* MBEDTLS_ECP_DOUBLE_ADD_MXZ_ALT */

    mbedtls_mpi_init( &A ); mbedtls_mpi_init( &AA ); mbedtls_mpi_init( &B );
    mbedtls_mpi_init( &BB ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &C );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &DA ); mbedtls_mpi_init( &CB );

    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mod( grp, &A,    &P->X,   &P->Z ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &AA,   &A,      &A    ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &B,    &P->X,   &P->Z ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &BB,   &B,      &B    ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &E,    &AA,     &BB   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mod( grp, &C,    &Q->X,   &Q->Z ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &D,    &Q->X,   &Q->Z ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &DA,   &D,      &A    ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &CB,   &C,      &B    ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mod( grp, &S->X, &DA,     &CB   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &S->X, &S->X,   &S->X ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &S->Z, &DA,     &CB   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &S->Z, &S->Z,   &S->Z ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &S->Z, d,       &S->Z ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &R->X, &AA,     &BB   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &R->Z, &grp->A, &E    ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mod( grp, &R->Z, &BB,     &R->Z ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &R->Z, &E,      &R->Z ) );

cleanup:
    mbedtls_mpi_free( &A ); mbedtls_mpi_free( &AA ); mbedtls_mpi_free( &B );
    mbedtls_mpi_free( &BB ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &C );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &DA ); mbedtls_mpi_free( &CB );

    return( ret );
}

/*
 * Multiplication with Montgomery ladder in x/z coordinates,
 * for curves in Montgomery form
 */
static int ecp_mul_mxz( mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                        const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i;
    unsigned char b;
    mbedtls_ecp_point RP;
    mbedtls_mpi PX;
#if !defined(MBEDTLS_ECP_NO_INTERNAL_RNG)
    ecp_drbg_context drbg_ctx;

    ecp_drbg_init( &drbg_ctx );
#endif
    mbedtls_ecp_point_init( &RP ); mbedtls_mpi_init( &PX );

#if !defined(MBEDTLS_ECP_NO_INTERNAL_RNG)
    if( f_rng == NULL )
    {
        const size_t m_len = ( grp->nbits + 7 ) / 8;
        MBEDTLS_MPI_CHK( ecp_drbg_seed( &drbg_ctx, m, m_len ) );
        f_rng = &ecp_drbg_random;
        p_rng = &drbg_ctx;
    }
#endif /* !MBEDTLS_ECP_NO_INTERNAL_RNG */

    /* Save PX and read from P before writing to R, in case P == R */
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &PX, &P->X ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_copy( &RP, P ) );

    /* Set R to zero in modified x/z coordinates */
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &R->X, 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &R->Z, 0 ) );
    mbedtls_mpi_free( &R->Y );

    /* RP.X might be sligtly larger than P, so reduce it */
    MOD_ADD( RP.X );

    /* Randomize coordinates of the starting point */
#if defined(MBEDTLS_ECP_NO_INTERNAL_RNG)
    if( f_rng != NULL )
#endif
        MBEDTLS_MPI_CHK( ecp_randomize_mxz( grp, &RP, f_rng, p_rng ) );

    /* Loop invariant: R = result so far, RP = R + P */
    i = mbedtls_mpi_bitlen( m ); /* one past the (zero-based) most significant bit */
    while( i-- > 0 )
    {
        b = mbedtls_mpi_get_bit( m, i );
        /*
         *  if (b) R = 2R + P else R = 2R,
         * which is:
         *  if (b) double_add( RP, R, RP, R )
         *  else   double_add( R, RP, R, RP )
         * but using safe conditional swaps to avoid leaks
         */
        MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_swap( &R->X, &RP.X, b ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_swap( &R->Z, &RP.Z, b ) );
        MBEDTLS_MPI_CHK( ecp_double_add_mxz( grp, R, &RP, R, &RP, &PX ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_swap( &R->X, &RP.X, b ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_swap( &R->Z, &RP.Z, b ) );
    }

    /*
     * Knowledge of the projective coordinates may leak the last few bits of the
     * scalar [1], and since our MPI implementation isn't constant-flow,
     * inversion (used for coordinate normalization) may leak the full value
     * of its input via side-channels [2].
     *
     * [1] https://eprint.iacr.org/2003/191
     * [2] https://eprint.iacr.org/2020/055
     *
     * Avoid the leak by randomizing coordinates before we normalize them.
     */
#if defined(MBEDTLS_ECP_NO_INTERNAL_RNG)
    if( f_rng != NULL )
#endif
        MBEDTLS_MPI_CHK( ecp_randomize_mxz( grp, R, f_rng, p_rng ) );

    MBEDTLS_MPI_CHK( ecp_normalize_mxz( grp, R ) );

cleanup:
#if !defined(MBEDTLS_ECP_NO_INTERNAL_RNG)
    ecp_drbg_free( &drbg_ctx );
#endif

    mbedtls_ecp_point_free( &RP ); mbedtls_mpi_free( &PX );

    return( ret );
}

#endif /* MBEDTLS_ECP_MONTGOMERY_ENABLED */

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
/*
 * Check that an affine point is valid as a public key,
 * short weierstrass curves (SEC1 3.2.3.1)
 */
static int ecp_check_pubkey_sw( const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pt )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi YY, RHS;

    /* pt coordinates must be normalized for our checks */
    if( mbedtls_mpi_cmp_int( &pt->X, 0 ) < 0 ||
        mbedtls_mpi_cmp_int( &pt->Y, 0 ) < 0 ||
        mbedtls_mpi_cmp_mpi( &pt->X, &grp->P ) >= 0 ||
        mbedtls_mpi_cmp_mpi( &pt->Y, &grp->P ) >= 0 )
        return( MBEDTLS_ERR_ECP_INVALID_KEY );

    mbedtls_mpi_init( &YY ); mbedtls_mpi_init( &RHS );

    /*
     * YY = Y^2
     * RHS = X (X^2 + A) + B = X^3 + A X + B
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &YY,  &pt->Y,   &pt->Y  ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &RHS, &pt->X,   &pt->X  ) );

    /* Special case for A = -3 */
    if( grp->A.p == NULL )
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &RHS, &RHS, 3       ) );  MOD_SUB( RHS );
    }
    else
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mod( grp, &RHS, &RHS, &grp->A ) );
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &RHS, &RHS,     &pt->X  ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mod( grp, &RHS, &RHS,     &grp->B ) );

    if( mbedtls_mpi_cmp_mpi( &YY, &RHS ) != 0 )
        ret = MBEDTLS_ERR_ECP_INVALID_KEY;

cleanup:

    mbedtls_mpi_free( &YY ); mbedtls_mpi_free( &RHS );

    return( ret );
}
#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
/*
 * R = m * P with shortcuts for m == 1 and m == -1
 * NOT constant-time - ONLY for short Weierstrass!
 */
static int mbedtls_ecp_mul_shortcuts( mbedtls_ecp_group *grp,
                                      mbedtls_ecp_point *R,
                                      const mbedtls_mpi *m,
                                      const mbedtls_ecp_point *P,
                                      mbedtls_ecp_restart_ctx *rs_ctx )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( mbedtls_mpi_cmp_int( m, 1 ) == 0 )
    {
        MBEDTLS_MPI_CHK( mbedtls_ecp_copy( R, P ) );
    }
    else if( mbedtls_mpi_cmp_int( m, -1 ) == 0 )
    {
        MBEDTLS_MPI_CHK( mbedtls_ecp_copy( R, P ) );
        if( mbedtls_mpi_cmp_int( &R->Y, 0 ) != 0 )
            MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &R->Y, &grp->P, &R->Y ) );
    }
    else
    {
        MBEDTLS_MPI_CHK( mbedtls_ecp_mul_restartable( grp, R, m, P,
                                                      NULL, NULL, rs_ctx ) );
    }

cleanup:
    return( ret );
}
#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
/*
 * Check validity of a public key for Montgomery curves with x-only schemes
 */
static int ecp_check_pubkey_mx( const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pt )
{
    /* [Curve25519 p. 5] Just check X is the correct number of bytes */
    /* Allow any public value, if it's too big then we'll just reduce it mod p
     * (RFC 7748 sec. 5 para. 3). */
    if( mbedtls_mpi_size( &pt->X ) > ( grp->nbits + 7 ) / 8 )
        return( MBEDTLS_ERR_ECP_INVALID_KEY );

    return( 0 );
}
#endif /* MBEDTLS_ECP_MONTGOMERY_ENABLED */

#if defined(MBEDTLS_SELF_TEST)

/* Adjust the exponent to be a valid private point for the specified curve.
 * This is sometimes necessary because we use a single set of exponents
 * for all curves but the validity of values depends on the curve. */
static int self_test_adjust_exponent( const mbedtls_ecp_group *grp,
                                      mbedtls_mpi *m )
{
    int ret = 0;
    switch( grp->id )
    {
        /* If Curve25519 is available, then that's what we use for the
         * Montgomery test, so we don't need the adjustment code. */
#if ! defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
#if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
        case MBEDTLS_ECP_DP_CURVE448:
            /* Move highest bit from 254 to N-1. Setting bit N-1 is
             * necessary to enforce the highest-bit-set constraint. */
            MBEDTLS_MPI_CHK( mbedtls_mpi_set_bit( m, 254, 0 ) );
            MBEDTLS_MPI_CHK( mbedtls_mpi_set_bit( m, grp->nbits, 1 ) );
            /* Copy second-highest bit from 253 to N-2. This is not
             * necessary but improves the test variety a bit. */
            MBEDTLS_MPI_CHK(
                mbedtls_mpi_set_bit( m, grp->nbits - 1,
                                     mbedtls_mpi_get_bit( m, 253 ) ) );
            break;
#endif
#endif /* ! defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED) */
        default:
            /* Non-Montgomery curves and Curve25519 need no adjustment. */
            (void) grp;
            (void) m;
            goto cleanup;
    }
cleanup:
    return( ret );
}

/* Calculate R = m.P for each m in exponents. Check that the number of
 * basic operations doesn't depend on the value of m. */
static int self_test_point( int verbose,
                            mbedtls_ecp_group *grp,
                            mbedtls_ecp_point *R,
                            mbedtls_mpi *m,
                            const mbedtls_ecp_point *P,
                            const char *const *exponents,
                            size_t n_exponents )
{
    int ret = 0;
    size_t i = 0;
    unsigned long add_c_prev, dbl_c_prev, mul_c_prev;
    add_count = 0;
    dbl_count = 0;
    mul_count = 0;

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( m, 16, exponents[0] ) );
    MBEDTLS_MPI_CHK( self_test_adjust_exponent( grp, m ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mul( grp, R, m, P, NULL, NULL ) );

    for( i = 1; i < n_exponents; i++ )
    {
        add_c_prev = add_count;
        dbl_c_prev = dbl_count;
        mul_c_prev = mul_count;
        add_count = 0;
        dbl_count = 0;
        mul_count = 0;

        MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( m, 16, exponents[i] ) );
        MBEDTLS_MPI_CHK( self_test_adjust_exponent( grp, m ) );
        MBEDTLS_MPI_CHK( mbedtls_ecp_mul( grp, R, m, P, NULL, NULL ) );

        if( add_count != add_c_prev ||
            dbl_count != dbl_c_prev ||
            mul_count != mul_c_prev )
        {
            ret = 1;
            break;
        }
    }

cleanup:
    if( verbose != 0 )
    {
        if( ret != 0 )
            mbedtls_printf( "failed (%u)\n", (unsigned int) i );
        else
            mbedtls_printf( "passed\n" );
    }
    return( ret );
}
#endif /* MBEDTLS_SELF_TEST */
/*==================================================================================================
*                                       GLOBAL FUNCTIONS
==================================================================================================*/
/*
 * List of supported curves and associated info
 */
const mbedtls_ecp_curve_info *mbedtls_ecp_curve_list( void )
{
    return( ecp_supported_curves );
}

/*
 * List of supported curves, group ID only
 */
const mbedtls_ecp_group_id *mbedtls_ecp_grp_id_list( void )
{
    static int init_done = 0;

    if( ! init_done )
    {
        size_t i = 0;
        const mbedtls_ecp_curve_info *curve_info;

        for( curve_info = mbedtls_ecp_curve_list();
             curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
             curve_info++ )
        {
            ecp_supported_grp_id[i++] = curve_info->grp_id;
        }
        ecp_supported_grp_id[i] = MBEDTLS_ECP_DP_NONE;

        init_done = 1;
    }

    return( ecp_supported_grp_id );
}

/*
 * Get the curve info for the internal identifier
 */
const mbedtls_ecp_curve_info *mbedtls_ecp_curve_info_from_grp_id( mbedtls_ecp_group_id grp_id )
{
    const mbedtls_ecp_curve_info *curve_info;

    for( curve_info = mbedtls_ecp_curve_list();
         curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
         curve_info++ )
    {
        if( curve_info->grp_id == grp_id )
            return( curve_info );
    }

    return( NULL );
}

/*
 * Get the curve info from the TLS identifier
 */
const mbedtls_ecp_curve_info *mbedtls_ecp_curve_info_from_tls_id( uint16_t tls_id )
{
    const mbedtls_ecp_curve_info *curve_info;

    for( curve_info = mbedtls_ecp_curve_list();
         curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
         curve_info++ )
    {
        if( curve_info->tls_id == tls_id )
            return( curve_info );
    }

    return( NULL );
}

/*
 * Get the curve info from the name
 */
const mbedtls_ecp_curve_info *mbedtls_ecp_curve_info_from_name( const char *name )
{
    const mbedtls_ecp_curve_info *curve_info;

    if( name == NULL )
        return( NULL );

    for( curve_info = mbedtls_ecp_curve_list();
         curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
         curve_info++ )
    {
        if( strcmp( curve_info->name, name ) == 0 )
            return( curve_info );
    }

    return( NULL );
}

/*
 * Get the type of a curve
 */
mbedtls_ecp_curve_type mbedtls_ecp_get_type( const mbedtls_ecp_group *grp )
{
    if( grp->G.X.p == NULL )
        return( MBEDTLS_ECP_TYPE_NONE );

    if( grp->G.Y.p == NULL )
        return( MBEDTLS_ECP_TYPE_MONTGOMERY );
    else
        return( MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS );
}

/*
 * Initialize (the components of) a point
 */
void mbedtls_ecp_point_init( mbedtls_ecp_point *pt )
{
    ECP_VALIDATE( pt != NULL );

    mbedtls_mpi_init( &pt->X );
    mbedtls_mpi_init( &pt->Y );
    mbedtls_mpi_init( &pt->Z );
}

/*
 * Initialize (the components of) a group
 */
void mbedtls_ecp_group_init( mbedtls_ecp_group *grp )
{
    ECP_VALIDATE( grp != NULL );

    grp->id = MBEDTLS_ECP_DP_NONE;
    mbedtls_mpi_init( &grp->P );
    mbedtls_mpi_init( &grp->A );
    mbedtls_mpi_init( &grp->B );
    mbedtls_ecp_point_init( &grp->G );
    mbedtls_mpi_init( &grp->N );
    grp->pbits = 0;
    grp->nbits = 0;
    grp->h = 0;
    grp->modp = NULL;
    grp->T = NULL;
    grp->T_size = 0;

    /*TODO: Need to remove it from here as grp will not contain
     * key handle */
    grp->keyHandle = HSE_INVALID_KEY_HANDLE;
}

/*
 * Initialize (the components of) a key pair
 */
void mbedtls_ecp_keypair_init( mbedtls_ecp_keypair *key )
{
    ECP_VALIDATE( key != NULL );

    mbedtls_ecp_group_init( &key->grp );
    mbedtls_mpi_init( &key->d );
    mbedtls_ecp_point_init( &key->Q );
}

/*
 * Unallocate (the components of) a point
 */
void mbedtls_ecp_point_free( mbedtls_ecp_point *pt )
{
    if( pt == NULL )
        return;

    mbedtls_mpi_free( &( pt->X ) );
    mbedtls_mpi_free( &( pt->Y ) );
    mbedtls_mpi_free( &( pt->Z ) );
}

/*
 * Unallocate (the components of) a group
 */
void mbedtls_ecp_group_free( mbedtls_ecp_group *grp )
{
    size_t i;

    if( grp == NULL )
        return;

    if( grp->h != 1 )
    {
        mbedtls_mpi_free( &grp->P );
        mbedtls_mpi_free( &grp->A );
        mbedtls_mpi_free( &grp->B );
        mbedtls_ecp_point_free( &grp->G );
        mbedtls_mpi_free( &grp->N );
    }

    if( grp->T != NULL )
    {
        for( i = 0; i < grp->T_size; i++ )
            mbedtls_ecp_point_free( &grp->T[i] );
        mbedtls_free( grp->T );
    }

    /*TODO: Need to remove it from here as grp will not contain
     * key handle */
	nxp_hse_ecc_free(grp);

    mbedtls_platform_zeroize( grp, sizeof( mbedtls_ecp_group ) );
}

/*
 * Unallocate (the components of) a key pair
 */
void mbedtls_ecp_keypair_free( mbedtls_ecp_keypair *key )
{
    if( key == NULL )
        return;

    mbedtls_ecp_group_free( &key->grp );
    /*TODO: Free Private key handle */
    mbedtls_mpi_free( &key->d );
    mbedtls_ecp_point_free( &key->Q );
}

/*
 * Copy the contents of a point
 */
int mbedtls_ecp_copy( mbedtls_ecp_point *P, const mbedtls_ecp_point *Q )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ECP_VALIDATE_RET( P != NULL );
    ECP_VALIDATE_RET( Q != NULL );

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &P->X, &Q->X ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &P->Y, &Q->Y ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &P->Z, &Q->Z ) );

cleanup:
    return( ret );
}

/*
 * Copy the contents of a group object
 */
int mbedtls_ecp_group_copy( mbedtls_ecp_group *dst, const mbedtls_ecp_group *src )
{
    ECP_VALIDATE_RET( dst != NULL );
    ECP_VALIDATE_RET( src != NULL );

    return( mbedtls_ecp_group_load( dst, src->id ) );
}

/*
 * Set point to zero
 */
int mbedtls_ecp_set_zero( mbedtls_ecp_point *pt )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ECP_VALIDATE_RET( pt != NULL );

    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &pt->X , 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &pt->Y , 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &pt->Z , 0 ) );

cleanup:
    return( ret );
}

/*
 * Tell if a point is zero
 */
int mbedtls_ecp_is_zero( mbedtls_ecp_point *pt )
{
    ECP_VALIDATE_RET( pt != NULL );

    return( mbedtls_mpi_cmp_int( &pt->Z, 0 ) == 0 );
}

/*
 * Compare two points lazily
 */
int mbedtls_ecp_point_cmp( const mbedtls_ecp_point *P,
                           const mbedtls_ecp_point *Q )
{
    ECP_VALIDATE_RET( P != NULL );
    ECP_VALIDATE_RET( Q != NULL );

    if( mbedtls_mpi_cmp_mpi( &P->X, &Q->X ) == 0 &&
        mbedtls_mpi_cmp_mpi( &P->Y, &Q->Y ) == 0 &&
        mbedtls_mpi_cmp_mpi( &P->Z, &Q->Z ) == 0 )
    {
        return( 0 );
    }

    return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
}

/*
 * Import a non-zero point from ASCII strings
 */
int mbedtls_ecp_point_read_string( mbedtls_ecp_point *P, int radix,
                           const char *x, const char *y )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ECP_VALIDATE_RET( P != NULL );
    ECP_VALIDATE_RET( x != NULL );
    ECP_VALIDATE_RET( y != NULL );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &P->X, radix, x ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &P->Y, radix, y ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &P->Z, 1 ) );

cleanup:
    return( ret );
}

/*
 * Export a point into unsigned binary data (SEC1 2.3.3 and RFC7748)
 */
int mbedtls_ecp_point_write_binary( const mbedtls_ecp_group *grp,
                                    const mbedtls_ecp_point *P,
                                    int format, size_t *olen,
                                    unsigned char *buf, size_t buflen )
{
    int ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    size_t plen;
    ECP_VALIDATE_RET( grp  != NULL );
    ECP_VALIDATE_RET( P    != NULL );
    ECP_VALIDATE_RET( olen != NULL );
    ECP_VALIDATE_RET( buf  != NULL );
    ECP_VALIDATE_RET( format == MBEDTLS_ECP_PF_UNCOMPRESSED ||
                      format == MBEDTLS_ECP_PF_COMPRESSED );

    plen = mbedtls_mpi_size( &grp->P );

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    (void) format; /* Montgomery curves always use the same point format */
    if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_MONTGOMERY )
    {
        *olen = plen;
        if( buflen < *olen )
            return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

        MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary_le( &P->X, buf, plen ) );
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
    {
        /*
         * Common case: P == 0
         */
        if( mbedtls_mpi_cmp_int( &P->Z, 0 ) == 0 )
        {
            if( buflen < 1 )
                return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

            buf[0] = 0x00;
            *olen = 1;

            return( 0 );
        }

        if( format == MBEDTLS_ECP_PF_UNCOMPRESSED )
        {
            *olen = 2 * plen + 1;

            if( buflen < *olen )
                return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

            buf[0] = 0x04;
            MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &P->X, buf + 1, plen ) );
            MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &P->Y, buf + 1 + plen, plen ) );
        }
        else if( format == MBEDTLS_ECP_PF_COMPRESSED )
        {
            *olen = plen + 1;

            if( buflen < *olen )
                return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

            buf[0] = 0x02 + mbedtls_mpi_get_bit( &P->Y, 0 );
            MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &P->X, buf + 1, plen ) );
        }
    }
#endif

cleanup:
    return( ret );
}

/*
 * Import a point from unsigned binary data (SEC1 2.3.4 and RFC7748)
 */
int mbedtls_ecp_point_read_binary( const mbedtls_ecp_group *grp,
                                   mbedtls_ecp_point *pt,
                                   const unsigned char *buf, size_t ilen )
{
    int ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    size_t plen;
    ECP_VALIDATE_RET( grp != NULL );
    ECP_VALIDATE_RET( pt  != NULL );
    ECP_VALIDATE_RET( buf != NULL );

    if( ilen < 1 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    plen = mbedtls_mpi_size( &grp->P );

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_MONTGOMERY )
    {
        if( plen != ilen )
            return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

        MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary_le( &pt->X, buf, plen ) );
        mbedtls_mpi_free( &pt->Y );

        if( grp->id == MBEDTLS_ECP_DP_CURVE25519 )
            /* Set most significant bit to 0 as prescribed in RFC7748 §5 */
            MBEDTLS_MPI_CHK( mbedtls_mpi_set_bit( &pt->X, plen * 8 - 1, 0 ) );

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

/*
 * Import a point from a TLS ECPoint record (RFC 4492)
 *      struct {
 *          opaque point <1..2^8-1>;
 *      } ECPoint;
 */
int mbedtls_ecp_tls_read_point( const mbedtls_ecp_group *grp,
                                mbedtls_ecp_point *pt,
                                const unsigned char **buf, size_t buf_len )
{
    unsigned char data_len;
    const unsigned char *buf_start;
    ECP_VALIDATE_RET( grp != NULL );
    ECP_VALIDATE_RET( pt  != NULL );
    ECP_VALIDATE_RET( buf != NULL );
    ECP_VALIDATE_RET( *buf != NULL );

    /*
     * We must have at least two bytes (1 for length, at least one for data)
     */
    if( buf_len < 2 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    data_len = *(*buf)++;
    if( data_len < 1 || data_len > buf_len - 1 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    /*
     * Save buffer start for read_binary and update buf
     */
    buf_start = *buf;
    *buf += data_len;

    return( mbedtls_ecp_point_read_binary( grp, pt, buf_start, data_len ) );
}

/*
 * Export a point as a TLS ECPoint record (RFC 4492)
 *      struct {
 *          opaque point <1..2^8-1>;
 *      } ECPoint;
 */
int mbedtls_ecp_tls_write_point( const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pt,
                         int format, size_t *olen,
                         unsigned char *buf, size_t blen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ECP_VALIDATE_RET( grp  != NULL );
    ECP_VALIDATE_RET( pt   != NULL );
    ECP_VALIDATE_RET( olen != NULL );
    ECP_VALIDATE_RET( buf  != NULL );
    ECP_VALIDATE_RET( format == MBEDTLS_ECP_PF_UNCOMPRESSED ||
                      format == MBEDTLS_ECP_PF_COMPRESSED );

    /*
     * buffer length must be at least one, for our length byte
     */
    if( blen < 1 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = mbedtls_ecp_point_write_binary( grp, pt, format,
                    olen, buf + 1, blen - 1) ) != 0 )
        return( ret );

    /*
     * write length to the first byte and update total length
     */
    buf[0] = (unsigned char) *olen;
    ++*olen;

    return( 0 );
}

/*
 * Set a group from an ECParameters record (RFC 4492)
 */
int mbedtls_ecp_tls_read_group( mbedtls_ecp_group *grp,
                                const unsigned char **buf, size_t len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_group_id grp_id;
    ECP_VALIDATE_RET( grp  != NULL );
    ECP_VALIDATE_RET( buf  != NULL );
    ECP_VALIDATE_RET( *buf != NULL );

    if( ( ret = mbedtls_ecp_tls_read_group_id( &grp_id, buf, len ) ) != 0 )
        return( ret );

    return( mbedtls_ecp_group_load( grp, grp_id ) );
}

/*
 * Read a group id from an ECParameters record (RFC 4492) and convert it to
 * mbedtls_ecp_group_id.
 */
int mbedtls_ecp_tls_read_group_id( mbedtls_ecp_group_id *grp,
                                   const unsigned char **buf, size_t len )
{
    uint16_t tls_id;
    const mbedtls_ecp_curve_info *curve_info;
    ECP_VALIDATE_RET( grp  != NULL );
    ECP_VALIDATE_RET( buf  != NULL );
    ECP_VALIDATE_RET( *buf != NULL );

    /*
     * We expect at least three bytes (see below)
     */
    if( len < 3 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    /*
     * First byte is curve_type; only named_curve is handled
     */
    if( *(*buf)++ != MBEDTLS_ECP_TLS_NAMED_CURVE )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    /*
     * Next two bytes are the namedcurve value
     */
    tls_id = *(*buf)++;
    tls_id <<= 8;
    tls_id |= *(*buf)++;

    if( ( curve_info = mbedtls_ecp_curve_info_from_tls_id( tls_id ) ) == NULL )
        return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );

    *grp = curve_info->grp_id;

    return( 0 );
}

/*
 * Write the ECParameters record corresponding to a group (RFC 4492)
 */
int mbedtls_ecp_tls_write_group( const mbedtls_ecp_group *grp, size_t *olen,
                         unsigned char *buf, size_t blen )
{
    const mbedtls_ecp_curve_info *curve_info;
    ECP_VALIDATE_RET( grp  != NULL );
    ECP_VALIDATE_RET( buf  != NULL );
    ECP_VALIDATE_RET( olen != NULL );

    if( ( curve_info = mbedtls_ecp_curve_info_from_grp_id( grp->id ) ) == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    /*
     * We are going to write 3 bytes (see below)
     */
    *olen = 3;
    if( blen < *olen )
        return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

    /*
     * First byte is curve_type, always named_curve
     */
    *buf++ = MBEDTLS_ECP_TLS_NAMED_CURVE;

    /*
     * Next two bytes are the namedcurve value
     */
    buf[0] = curve_info->tls_id >> 8;
    buf[1] = curve_info->tls_id & 0xFF;

    return( 0 );
}

/*
 * Restartable multiplication R = m * P
 */
int mbedtls_ecp_mul_restartable( mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
             const mbedtls_mpi *m, const mbedtls_ecp_point *P,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
             mbedtls_ecp_restart_ctx *rs_ctx )
{
    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
#if defined(MBEDTLS_ECP_INTERNAL_ALT)
    char is_grp_capable = 0;
#endif
    ECP_VALIDATE_RET( grp != NULL );
    ECP_VALIDATE_RET( R   != NULL );
    ECP_VALIDATE_RET( m   != NULL );
    ECP_VALIDATE_RET( P   != NULL );

    (void) rs_ctx;

#if defined(MBEDTLS_ECP_INTERNAL_ALT)
    if( ( is_grp_capable = mbedtls_internal_ecp_grp_capable( grp ) ) )
        MBEDTLS_MPI_CHK( mbedtls_internal_ecp_init( grp ) );
#endif /* MBEDTLS_ECP_INTERNAL_ALT */

	/* check_privkey is free */
	MBEDTLS_ECP_BUDGET( MBEDTLS_ECP_OPS_CHK );

	/* Common sanity checks */
	MBEDTLS_MPI_CHK( mbedtls_ecp_check_privkey( grp, m ) );
	MBEDTLS_MPI_CHK( mbedtls_ecp_check_pubkey( grp, P ) );

    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_MONTGOMERY )
        MBEDTLS_MPI_CHK( ecp_mul_mxz( grp, R, m, P, f_rng, p_rng ) );
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
        MBEDTLS_MPI_CHK( ecp_mul_comb( grp, R, m, P, f_rng, p_rng, rs_ctx ) );
#endif

cleanup:

#if defined(MBEDTLS_ECP_INTERNAL_ALT)
    if( is_grp_capable )
        mbedtls_internal_ecp_free( grp );
#endif /* MBEDTLS_ECP_INTERNAL_ALT */

    return( ret );
}

/*
 * Multiplication R = m * P
 */
int mbedtls_ecp_mul( mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
             const mbedtls_mpi *m, const mbedtls_ecp_point *P,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    ECP_VALIDATE_RET( grp != NULL );
    ECP_VALIDATE_RET( R   != NULL );
    ECP_VALIDATE_RET( m   != NULL );
    ECP_VALIDATE_RET( P   != NULL );
    return( mbedtls_ecp_mul_restartable( grp, R, m, P, f_rng, p_rng, NULL ) );
}

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
/*
 * Restartable linear combination
 * NOT constant-time
 */
int mbedtls_ecp_muladd_restartable(
             mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
             const mbedtls_mpi *m, const mbedtls_ecp_point *P,
             const mbedtls_mpi *n, const mbedtls_ecp_point *Q,
             mbedtls_ecp_restart_ctx *rs_ctx )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point mP;
    mbedtls_ecp_point *pmP = &mP;
    mbedtls_ecp_point *pR = R;
#if defined(MBEDTLS_ECP_INTERNAL_ALT)
    char is_grp_capable = 0;
#endif
    ECP_VALIDATE_RET( grp != NULL );
    ECP_VALIDATE_RET( R   != NULL );
    ECP_VALIDATE_RET( m   != NULL );
    ECP_VALIDATE_RET( P   != NULL );
    ECP_VALIDATE_RET( n   != NULL );
    ECP_VALIDATE_RET( Q   != NULL );

    if( mbedtls_ecp_get_type( grp ) != MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
        return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );

    mbedtls_ecp_point_init( &mP );

    ECP_RS_ENTER( ma );

    MBEDTLS_MPI_CHK( mbedtls_ecp_mul_shortcuts( grp, pmP, m, P, rs_ctx ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mul_shortcuts( grp, pR,  n, Q, rs_ctx ) );

#if defined(MBEDTLS_ECP_INTERNAL_ALT)
    if( ( is_grp_capable = mbedtls_internal_ecp_grp_capable( grp ) ) )
        MBEDTLS_MPI_CHK( mbedtls_internal_ecp_init( grp ) );
#endif /* MBEDTLS_ECP_INTERNAL_ALT */

    MBEDTLS_ECP_BUDGET( MBEDTLS_ECP_OPS_ADD );
    MBEDTLS_MPI_CHK( ecp_add_mixed( grp, pR, pmP, pR ) );
    MBEDTLS_ECP_BUDGET( MBEDTLS_ECP_OPS_INV );
    MBEDTLS_MPI_CHK( ecp_normalize_jac( grp, pR ) );

cleanup:
#if defined(MBEDTLS_ECP_INTERNAL_ALT)
    if( is_grp_capable )
        mbedtls_internal_ecp_free( grp );
#endif /* MBEDTLS_ECP_INTERNAL_ALT */

    mbedtls_ecp_point_free( &mP );

    ECP_RS_LEAVE( ma );

    return( ret );
}

/*
 * Linear combination
 * NOT constant-time
 */
int mbedtls_ecp_muladd( mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
             const mbedtls_mpi *m, const mbedtls_ecp_point *P,
             const mbedtls_mpi *n, const mbedtls_ecp_point *Q )
{
    ECP_VALIDATE_RET( grp != NULL );
    ECP_VALIDATE_RET( R   != NULL );
    ECP_VALIDATE_RET( m   != NULL );
    ECP_VALIDATE_RET( P   != NULL );
    ECP_VALIDATE_RET( n   != NULL );
    ECP_VALIDATE_RET( Q   != NULL );
    return( mbedtls_ecp_muladd_restartable( grp, R, m, P, n, Q, NULL ) );
}
#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */

/*
 * Check that a point is valid as a public key
 */
int mbedtls_ecp_check_pubkey( const mbedtls_ecp_group *grp,
                              const mbedtls_ecp_point *pt )
{
    ECP_VALIDATE_RET( grp != NULL );
    ECP_VALIDATE_RET( pt  != NULL );

    /* Must use affine coordinates */
    if( mbedtls_mpi_cmp_int( &pt->Z, 1 ) != 0 )
        return( MBEDTLS_ERR_ECP_INVALID_KEY );

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_MONTGOMERY )
        return( ecp_check_pubkey_mx( grp, pt ) );
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
        return( ecp_check_pubkey_sw( grp, pt ) );
#endif
    return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
}

/*
 * Check that an mbedtls_mpi is valid as a private key
 */
int mbedtls_ecp_check_privkey( const mbedtls_ecp_group *grp,
                               const mbedtls_mpi *d )
{
    ECP_VALIDATE_RET( grp != NULL );
    ECP_VALIDATE_RET( d   != NULL );

    /* Check if d contains key handle */
    if(KEYMGMT_ERR_SUCCESS != KeyStoreMgmt_CheckKey(*d->p))
    {
#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
		if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_MONTGOMERY )
		{
			/* see RFC 7748 sec. 5 para. 5 */
			if( mbedtls_mpi_get_bit( d, 0 ) != 0 ||
				mbedtls_mpi_get_bit( d, 1 ) != 0 ||
				mbedtls_mpi_bitlen( d ) - 1 != grp->nbits ) /* mbedtls_mpi_bitlen is one-based! */
				return( MBEDTLS_ERR_ECP_INVALID_KEY );

			/* see [Curve25519] page 5 */
			if( grp->nbits == 254 && mbedtls_mpi_get_bit( d, 2 ) != 0 )
				return( MBEDTLS_ERR_ECP_INVALID_KEY );

			return( 0 );
		}
#endif /* MBEDTLS_ECP_MONTGOMERY_ENABLED */
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
		if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
		{
			/* see SEC1 3.2 */
			if( mbedtls_mpi_cmp_int( d, 1 ) < 0 ||
				mbedtls_mpi_cmp_mpi( d, &grp->N ) >= 0 )
				return( MBEDTLS_ERR_ECP_INVALID_KEY );
			else
				return( 0 );
		}

#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */
    }
    else
    {
    	hseSrvResponse_t srvResponse = HSE_SRV_RSP_KEY_INVALID;
    	hseKeyInfo_t reqKeyInfo = {0};
    	uint16_t keyBitLen = 0U;
    	if((grp->id == MBEDTLS_ECP_DP_CURVE25519) || (grp->id == MBEDTLS_ECP_DP_CURVE448))
    	{
    		keyBitLen = BYTES_TO_BITS(mbedtls_mpi_size( &grp->P ));
    	}
    	else
    	{
    		keyBitLen = grp->nbits;
    	}

    	srvResponse = HSE_GetKeyInfo(*d->p, &reqKeyInfo);
    	if((srvResponse == HSE_SRV_RSP_OK) && (reqKeyInfo.keyBitLen == keyBitLen))
    	{
    		return ( 0 );
    	}
    	else
    	{
    		return( MBEDTLS_ERR_ECP_INVALID_KEY );
    	}
    }

    return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
}

/*
 * Generate a private key
 */
int mbedtls_ecp_gen_privkey( const mbedtls_ecp_group *grp,
                     mbedtls_mpi *d,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
    ECP_VALIDATE_RET( grp   != NULL );
    ECP_VALIDATE_RET( d     != NULL );
    ECP_VALIDATE_RET( f_rng != NULL );

	(void) f_rng;
	(void) p_rng;

	return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
}

/*
 * Generate a keypair with configurable base point
 */
int mbedtls_ecp_gen_keypair_base( mbedtls_ecp_group *grp,
                     const mbedtls_ecp_point *G,
                     mbedtls_mpi *d, mbedtls_ecp_point *Q,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	uint8_t *pN = NULL;
	uint32_t size_pN = 0U;
	uint8_t hseEccCurveId = 0U;
	hseKeyHandle_t keyHandle = HSE_INVALID_KEY_HANDLE;
	key_import_param_t key_import_param = {0};
	key_gen_param_t key_gen_param = {0};

    ECP_VALIDATE_RET( grp   != NULL );
    ECP_VALIDATE_RET( d     != NULL );
    ECP_VALIDATE_RET( G     != NULL );
    ECP_VALIDATE_RET( Q     != NULL );
    ECP_VALIDATE_RET( f_rng != NULL );

	(void) p_rng;

	memset(&key_import_param, 0x00, sizeof(key_import_param_t));

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
				goto cleanup;
			}
			else
			{
				/* Load User Curve Id into hseEccCurveId */
				hseEccCurveId = grp->userCurveId;
			}
            break;
		default:
			return MBEDTLS_ERR_ECP_BAD_INPUT_DATA ;
	}

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_MONTGOMERY )
    {
        /* Allocate memory of Public key length */
        size_pN = mbedtls_mpi_size( &grp->P );
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
    {
        /* Allocate memory of Public key length + 1 (for uncompressed key format) */
        size_pN = 2 * BITS_TO_BYTES(grp->pbits) + 1;
    }
#endif
	pN = mbedtls_calloc(1, size_pN);
	if(pN == NULL)
	{
		/* Return Error */
		return MBEDTLS_ERR_MPI_ALLOC_FAILED;
	}

    /* Get Key Pair handle from Key Store */
	key_import_param.key_type = HSE_KEY_TYPE_ECC_PAIR;
	key_import_param.key_catalog = HSE_KEY_CATALOG_ID_RAM;
	key_import_param.key_param.ecc_keypair_param.size_Q = grp->nbits;

	if(KEYMGMT_ERR_SUCCESS != KeystoreMgmt_FindAllocateSlot(&key_import_param, &keyHandle))
	{
		/* Unable to get key pair handle */
		ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
		goto cleanup;
	}

	/* Call HSE Service to generate Key Pair in RAM Key Slot */
	key_gen_param.key_catalog = HSE_KEY_CATALOG_ID_RAM;
	key_gen_param.key_type = HSE_KEY_TYPE_ECC_PAIR;
	key_gen_param.key_param.ecc_keypair_gen_param.eccCurveId = hseEccCurveId;
#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_MONTGOMERY )
    {
    	key_gen_param.key_param.ecc_keypair_gen_param.pN = pN;
    	key_gen_param.key_param.ecc_keypair_gen_param.keybitlen = BYTES_TO_BITS(size_pN);
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
    {
    	key_gen_param.key_param.ecc_keypair_gen_param.pN = &pN[1];
    	key_gen_param.key_param.ecc_keypair_gen_param.keybitlen = grp->nbits;
    }
#endif

    /* Send command to HSE to generate keys */
	if(KEYMGMT_ERR_SUCCESS == KeystoreMgmt_Genkey(keyHandle, &key_gen_param))
	{
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
		if( mbedtls_ecp_get_type( grp ) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
		{
			/* Set First byte as 4 for uncompressed Public Key */
			pN[0] = 0x04;
		}
#endif
		/* Copy Public key to Q */
		ret = nxp_hse_ecp_point_read_binary(grp, Q, pN, size_pN);
		if(NO_ERROR != ret)
		{
			/* Unload keypair handle */
			nxp_hse_ecc_unloadkey(keyHandle);

			ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

#if defined (MBEDTLS_DEBUG_C)
			mbedtls_printf("mbedtls_ecp_point_read_binary() returned %d (-0x%04x)\n", ret, (unsigned int) -ret );
#endif
			goto cleanup;
		}

		/* Copy Private key handle to Private key mpi d */
		MBEDTLS_MPI_CHK(mbedtls_mpi_lset(d, (mbedtls_mpi_sint)keyHandle));

#if defined (MBEDTLS_DEBUG_C)
		mbedtls_printf("Private keyHandle 0x%02x\n", *((hseKeyHandle_t *)(d->p)));
		mbedtls_printf("Public key:\n");
		for(uint32_t index = 0; index < size_pN; index++)
		{
			mbedtls_printf("%02x ", pN[index]);
			if(!((index + 1) % 8))
			{
				mbedtls_printf("\n");
			}
		}
#endif

	}
	else
	{
		/* Unload private key handle */
		nxp_hse_ecc_unloadkey(keyHandle);

		ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
#if defined (MBEDTLS_DEBUG_C)
		mbedtls_printf("KeystoreMgmt_Genkey() returned %d (-0x%04x)\n", ret, (unsigned int) -ret );
#endif
	}

cleanup:

	if(NULL != pN)
	{
		/* Zeroize Public Key */
		mbedtls_platform_zeroize(pN, size_pN);
		/* Free Memory Buffer */
		mbedtls_free(pN);
		/* Initialize to NULL */
		pN= NULL;
	}

    return( ret );
}

/*
 * Generate key pair, wrapper for conventional base point
 */
int mbedtls_ecp_gen_keypair( mbedtls_ecp_group *grp,
                             mbedtls_mpi *d, mbedtls_ecp_point *Q,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng )
{
    ECP_VALIDATE_RET( grp   != NULL );
    ECP_VALIDATE_RET( d     != NULL );
    ECP_VALIDATE_RET( Q     != NULL );
    ECP_VALIDATE_RET( f_rng != NULL );

    return( mbedtls_ecp_gen_keypair_base( grp, &grp->G, d, Q, f_rng, p_rng ) );
}

/*
 * Generate a keypair, prettier wrapper
 */
int mbedtls_ecp_gen_key( mbedtls_ecp_group_id grp_id, mbedtls_ecp_keypair *key,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ECP_VALIDATE_RET( key   != NULL );
    ECP_VALIDATE_RET( f_rng != NULL );

    if( ( ret = mbedtls_ecp_group_load( &key->grp, grp_id ) ) != 0 )
        return( ret );

    return( mbedtls_ecp_gen_keypair( &key->grp, &key->d, &key->Q, f_rng, p_rng ) );
}

#define ECP_CURVE25519_KEY_SIZE 32
/*
 * Read a private key.
 */
int mbedtls_ecp_read_key( mbedtls_ecp_group_id grp_id, mbedtls_ecp_keypair *key,
                          const unsigned char *buf, size_t buflen )
{
    int ret = 0;

    ECP_VALIDATE_RET( key  != NULL );
    ECP_VALIDATE_RET( buf  != NULL );

    if( ( ret = mbedtls_ecp_group_load( &key->grp, grp_id ) ) != 0 )
        return( ret );

    ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;

    /* Check if D contains key handle or key*/
	if(buflen > 4)
	{
#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
		if( mbedtls_ecp_get_type( &key->grp ) == MBEDTLS_ECP_TYPE_MONTGOMERY )
		{
			/*
			 * If it is Curve25519 curve then mask the key as mandated by RFC7748
			 */
			if( grp_id == MBEDTLS_ECP_DP_CURVE25519 )
			{
				if( buflen != ECP_CURVE25519_KEY_SIZE )
					return MBEDTLS_ERR_ECP_INVALID_KEY;

				MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary_le( &key->d, buf, buflen ) );

				/* Set the three least significant bits to 0 */
				MBEDTLS_MPI_CHK( mbedtls_mpi_set_bit( &key->d, 0, 0 ) );
				MBEDTLS_MPI_CHK( mbedtls_mpi_set_bit( &key->d, 1, 0 ) );
				MBEDTLS_MPI_CHK( mbedtls_mpi_set_bit( &key->d, 2, 0 ) );

				/* Set the most significant bit to 0 */
				MBEDTLS_MPI_CHK(
						mbedtls_mpi_set_bit( &key->d,
											 ECP_CURVE25519_KEY_SIZE * 8 - 1, 0 )
						);

				/* Set the second most significant bit to 1 */
				MBEDTLS_MPI_CHK(
						mbedtls_mpi_set_bit( &key->d,
											 ECP_CURVE25519_KEY_SIZE * 8 - 2, 1 )
						);
			}
			else
				ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
		}

#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
		if( mbedtls_ecp_get_type( &key->grp ) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
		{
			MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &key->d, buf, buflen ) );

			MBEDTLS_MPI_CHK( mbedtls_ecp_check_privkey( &key->grp, &key->d ) );
		}
#endif
	}
	else
	{
		/* Copy Private key handle to Private key mpi d */
		MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &key->d, buf, buflen ) );
		MBEDTLS_MPI_CHK( mbedtls_ecp_check_privkey( &key->grp, &key->d ) );
	}

cleanup:

    if( ret != 0 )
        mbedtls_mpi_free( &key->d );

    return( ret );
}

/*
 * Write a private key.
 */
int mbedtls_ecp_write_key( mbedtls_ecp_keypair *key,
                           unsigned char *buf, size_t buflen )
{
    int ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
	uint32_t keySize = 0;

    ECP_VALIDATE_RET( key != NULL );
    ECP_VALIDATE_RET( buf != NULL );

    keySize = mbedtls_mpi_size(&key->d);

    /* Check if D contains key handle or key*/
	if(keySize > 4)
	{
#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)

		if( mbedtls_ecp_get_type( &key->grp ) == MBEDTLS_ECP_TYPE_MONTGOMERY )
		{
			if( key->grp.id == MBEDTLS_ECP_DP_CURVE25519 )
			{
				if( buflen < ECP_CURVE25519_KEY_SIZE )
					return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;

				MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary_le( &key->d, buf, buflen ) );
			}
			else
				ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
		}

#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
		if( mbedtls_ecp_get_type( &key->grp ) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
		{
			MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &key->d, buf, buflen ) );
		}
#endif
	}
	else
	{
		/* Get Private key handle from private key mpi d */
		if(keySize > buflen)
		{
			return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
		}
		else
		{
			/* Exporting private key handle */
			MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&key->d, buf, buflen));
			ret = 0;
		}
	}

cleanup:

    return( ret );
}

/*
 * Check a public-private key pair
 */
int mbedtls_ecp_check_pub_priv( const mbedtls_ecp_keypair *pub, const mbedtls_ecp_keypair *prv )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point Q;
    mbedtls_ecp_group grp;
    ECP_VALIDATE_RET( pub != NULL );
    ECP_VALIDATE_RET( prv != NULL );

    if( pub->grp.id == MBEDTLS_ECP_DP_NONE ||
        pub->grp.id != prv->grp.id ||
        mbedtls_mpi_cmp_mpi( &pub->Q.X, &prv->Q.X ) ||
        mbedtls_mpi_cmp_mpi( &pub->Q.Y, &prv->Q.Y ) ||
        mbedtls_mpi_cmp_mpi( &pub->Q.Z, &prv->Q.Z ) )
    {
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    }

    mbedtls_ecp_point_init( &Q );
    mbedtls_ecp_group_init( &grp );

    /* mbedtls_ecp_mul() needs a non-const group... */
    mbedtls_ecp_group_copy( &grp, &prv->grp );

    /* Check if D contains key handle or key*/
    if(mbedtls_mpi_size(&prv->d) > sizeof(hseKeyHandle_t))
    {
        /* Also checks d is valid */
        MBEDTLS_MPI_CHK( mbedtls_ecp_mul( &grp, &Q, &prv->d, &prv->grp.G, NULL, NULL ) );
    }
    else
    {
    	MBEDTLS_MPI_CHK(nxp_hse_ecc_export_public_key(&grp, *prv->d.p, &Q));
    }

	if( mbedtls_mpi_cmp_mpi( &Q.X, &prv->Q.X ) ||
		mbedtls_mpi_cmp_mpi( &Q.Y, &prv->Q.Y ) ||
		mbedtls_mpi_cmp_mpi( &Q.Z, &prv->Q.Z ) )
	{
		ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
		goto cleanup;
	}

cleanup:
    mbedtls_ecp_point_free( &Q );
    mbedtls_ecp_group_free( &grp );

    return( ret );
}

#if defined(MBEDTLS_SELF_TEST)

/*
 * Checkup routine
 */
int mbedtls_ecp_self_test( int verbose )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R, P;
    mbedtls_mpi m;

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    /* Exponents especially adapted for secp192k1, which has the lowest
     * order n of all supported curves (secp192r1 is in a slightly larger
     * field but the order of its base point is slightly smaller). */
    const char *sw_exponents[] =
    {
        "000000000000000000000000000000000000000000000001", /* one */
        "FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8C", /* n - 1 */
        "5EA6F389A38B8BC81E767753B15AA5569E1782E30ABE7D25", /* random */
        "400000000000000000000000000000000000000000000000", /* one and zeros */
        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", /* all ones */
        "555555555555555555555555555555555555555555555555", /* 101010... */
    };
#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */
#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    const char *m_exponents[] =
    {
        /* Valid private values for Curve25519. In a build with Curve448
         * but not Curve25519, they will be adjusted in
         * self_test_adjust_exponent(). */
        "4000000000000000000000000000000000000000000000000000000000000000",
        "5C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C30",
        "5715ECCE24583F7A7023C24164390586842E816D7280A49EF6DF4EAE6B280BF8",
        "41A2B017516F6D254E1F002BCCBADD54BE30F8CEC737A0E912B4963B6BA74460",
        "5555555555555555555555555555555555555555555555555555555555555550",
        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF8",
    };
#endif /* MBEDTLS_ECP_MONTGOMERY_ENABLED */

    mbedtls_ecp_group_init( &grp );
    mbedtls_ecp_point_init( &R );
    mbedtls_ecp_point_init( &P );
    mbedtls_mpi_init( &m );

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    /* Use secp192r1 if available, or any available curve */
#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
    MBEDTLS_MPI_CHK( mbedtls_ecp_group_load( &grp, MBEDTLS_ECP_DP_SECP192R1 ) );
#else
    MBEDTLS_MPI_CHK( mbedtls_ecp_group_load( &grp, mbedtls_ecp_curve_list()->grp_id ) );
#endif

    if( verbose != 0 )
        mbedtls_printf( "  ECP SW test #1 (constant op_count, base point G): " );
    /* Do a dummy multiplication first to trigger precomputation */
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &m, 2 ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mul( &grp, &P, &m, &grp.G, NULL, NULL ) );
    ret = self_test_point( verbose,
                           &grp, &R, &m, &grp.G,
                           sw_exponents,
                           sizeof( sw_exponents ) / sizeof( sw_exponents[0] ));
    if( ret != 0 )
        goto cleanup;

    if( verbose != 0 )
        mbedtls_printf( "  ECP SW test #2 (constant op_count, other point): " );
    /* We computed P = 2G last time, use it */
    ret = self_test_point( verbose,
                           &grp, &R, &m, &P,
                           sw_exponents,
                           sizeof( sw_exponents ) / sizeof( sw_exponents[0] ));
    if( ret != 0 )
        goto cleanup;

    mbedtls_ecp_group_free( &grp );
    mbedtls_ecp_point_free( &R );
#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if( verbose != 0 )
        mbedtls_printf( "  ECP Montgomery test (constant op_count): " );
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
    MBEDTLS_MPI_CHK( mbedtls_ecp_group_load( &grp, MBEDTLS_ECP_DP_CURVE25519 ) );
#elif defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
    MBEDTLS_MPI_CHK( mbedtls_ecp_group_load( &grp, MBEDTLS_ECP_DP_CURVE448 ) );
#else
#error "MBEDTLS_ECP_MONTGOMERY_ENABLED is defined, but no curve is supported for self-test"
#endif
    ret = self_test_point( verbose,
                           &grp, &R, &m, &grp.G,
                           m_exponents,
                           sizeof( m_exponents ) / sizeof( m_exponents[0] ));
    if( ret != 0 )
        goto cleanup;
#endif /* MBEDTLS_ECP_MONTGOMERY_ENABLED */

cleanup:

    if( ret < 0 && verbose != 0 )
        mbedtls_printf( "Unexpected error, return code = %08X\n", (unsigned int) ret );

    mbedtls_ecp_group_free( &grp );
    mbedtls_ecp_point_free( &R );
    mbedtls_ecp_point_free( &P );
    mbedtls_mpi_free( &m );

    if( verbose != 0 )
        mbedtls_printf( "\n" );

    return( ret );
}

#endif /* MBEDTLS_SELF_TEST */
#endif /* MBEDTLS_ECP_ALT */
#endif /* MBEDTLS_ECP_C */
