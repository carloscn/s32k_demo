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
#ifndef NXP_HSE_ECC_H_
#define NXP_HSE_ECC_H_

#ifdef __cplusplus
extern "C"{
#endif

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

#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "keystore_mgmt.h"
#include "hse_host_global.h"
#include "global_defs.h"
#include "device.h"
#include "hse_host_km_export_key.h"
#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

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

/*==================================================================================================
*											  ENUMS
==================================================================================================*/
typedef enum nxp_hse_ecc_ops
{
	EC_OPS_MIN 			= 	0	,	/* !< Minimum ECC operations */
	EC_OPS_SIGN 		= 	1	,	/* !< ECC Sign operation */
	EC_OPS_VERIFY 		= 	2	,	/* !< ECC Verify operation */
	EC_OPS_SHAREDSECRET	= 	3	,	/* !< ECC Compute shared secret operation */
	EC_OPS_MAX					,	/* !< Maximum ECC operations */
}nxp_hse_ecc_ops_t;

/*==================================================================================================
								 STRUCTURES AND OTHER TYPEDEFS
==================================================================================================*/

/*==================================================================================================
                                 GLOBAL VARIABLE DECLARATIONS
==================================================================================================*/

/*==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================*/
/**
 * 	@brief		This function loads ECC key-pair, returns
 * 				public and private key-handles
 *
 * 	@param[in]	ops
 * 				ECC operation
 * 				- EC_OPS_SIGN
 * 				- EC_OPS_VERIFY
 * 				- EC_OPS_SHAREDSECRET
 *
 *	@param[in] 	hseEccCurveId
 *				HSE ECC Curve ID
 *
 *	@param[in]	grp
 *				The ECP group to generate a key pair for.
 *              This must be initialized and have group parameters
 *              set, for example through mbedtls_ecp_group_load().
 *
 * 	@param[in]	Qp
 * 				The Peer Public key.
 *
 * 	@param[in]	Q
 * 				The Public key.
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
 * @param[in]	f_rng
 *              The RNG function. This must not be \c NULL.
 *
 * @param[in]	p_rng
 * 			    The RNG context to be passed to \p f_rng. This may be
 *              \c NULL if \p f_rng doesn't need a context parameter.
 *
 *	@return		\c 0 on success.
 *
 * 	@return     #MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE error operation is
 * 				invalid
 *
 */
extern int nxp_hse_ecc_loadkey(nxp_hse_ecc_ops_t ops, uint8_t hseEccCurveId, mbedtls_ecp_group *grp,
        						const mbedtls_ecp_point *Qp, const mbedtls_ecp_point *Q,
								const mbedtls_mpi *d, hseKeyHandle_t *pubKeyHandle,
								hseKeyHandle_t *prvKeyHandle, int (*f_rng)(void *, unsigned char *, size_t),
								void *p_rng );

/**
 * 	@brief		This function Exports ECC Public Key using Private key handle.
 *
 *	@param[in]	grp
 *				The ECP group to generate a key for.
 *              This must be initialized and have group parameters
 *              set, for example through mbedtls_ecp_group_load().
 *
 *  @param[in]	KeyHandle
 *  			Private Key handle of hseKeyHandle_t type
 *
 * 	@param[out]	pt
 * 				The destination point (public key).
 * 				This must be initialized.
 *
 *	@return		\c 0 on success.
 *
 * 	@return     #MBEDTLS_ERR_ECP_HW_ACCEL_FAILED error if Export fails.
 * 	@return     Another negative error code on different kinds of failure..
 *
 */
extern int nxp_hse_ecc_export_public_key(mbedtls_ecp_group *grp, hseKeyHandle_t KeyHandle , mbedtls_ecp_point *pt);

/**
 * 	@brief		Unload ECC RAM key
 *
 * 	@param[in]	KeyHandle
 * 				Key-handle to RAM key
 *
 * 	@param[out]	None
 *
 *	@return		void
 *
 */
extern void nxp_hse_ecc_unloadkey( hseKeyHandle_t KeyHandle );

/**
 * 	@brief		Unload ECC RAM key from group
 *
 * 	@param[in]	grp
 * 				The ECP group containing Key-handle to RAM key
 *
 * 	@param[out]	None
 *
 *	@return		void
 *
 */
extern void nxp_hse_ecc_free(mbedtls_ecp_group *grp);

/**
 * 	@brief		Load User curve on HSE from ecp grp
 *
 * 	@param[in]	grp
 * 				The ECP group to use
 *
 * 	@param[out]	None
 *
 *	@param[out]	eccCurveId
 *				The ECC curve ID for user defined curve
 *
 *  @return		\c 0 on success.
 *
 *	@return		#MBEDTLS_ERR_MPI_ALLOC_FAILED if memory allocation
 *	  			failed.
 *	@return		#MBEDTLS_ERR_ECP_BAD_INPUT_DATA for invalid input
 *	@return		#MBEDTLS_ERR_ECP_HW_ACCEL_FAILED if user curve ID
 *	  			is invalid.
 *
 */
extern int nxp_hse_ecc_loadusercurve(mbedtls_ecp_group *grp);

/**
 * \brief           This function imports a point from unsigned binary data.
 *
 * \note            This function does not check that the point actually
 *                  belongs to the given group, see mbedtls_ecp_check_pubkey()
 *                  for that.
 *
 * @param[in] grp   The group to which the point should belong.
 *                  This must be initialized and have group parameters
 *                  set, for example through mbedtls_ecp_group_load().
 *
 * @param[out] pt   The destination context to import the point to.
 *                  This must be initialized.
 *
 * @param[in] buf   The input buffer. This must be a readable buffer
 *                  of length \p ilen Bytes.
 *
 * @param[in] ilen  The length of the input buffer \p buf in Bytes.
 *
 * @return          \c 0 on success.
 * @return          #MBEDTLS_ERR_ECP_BAD_INPUT_DATA if the input is invalid.
 * @return          #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 * @return          #MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE if the import for the
 *                  given group is not implemented.
 */

extern int nxp_hse_ecp_point_read_binary( const mbedtls_ecp_group *grp,
                                   	      mbedtls_ecp_point *pt,
										  const unsigned char *buf, size_t ilen );

#endif /* MBEDTLS_ECP_ALT && MBEDTLS_USE_NXP_HSE_CRYPTO */

#ifdef __cplusplus
}
#endif

#endif /* NXP_HSE_ECC_H_ */
