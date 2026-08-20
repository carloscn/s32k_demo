/**
 *   @file    		hse_host_hash.h
 *
 *   @brief   		This files contains services for hash services
 *
 *   @addtogroup 	[HSE_DAL]
 *   @{
 */
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

#ifndef HSE_HOST_HASH_H
#define HSE_HOST_HASH_H

#ifdef __cplusplus
extern "C"{
#endif

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/

#include "Hse_Ip.h"
#include "hse_interface.h"

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
*                                             ENUMS
==================================================================================================*/

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
 * 	@brief		Blocking hash request
 *
 *	@param[in]	hashAlgo
 *				Specifies the hash algorithm
 *
 * 	@param[in]	pInput
 *				Address of the input message
 *				STREAMING USAGE: Used in all steps (except if inputLength is zero)
 *
 *	@param[in]	inputLength
 *				MD5, SHA1, SHA2_224, SHA2_256: 64
 *              - SHA2_384, SHA2_512, SHA2_512_224, SHA2_512_256: 128
 *              - SHA3: no limitation (can be any size)
 *
 *	@param[out]	pHash
 *			    The address of the output buffer where the resulting hash will be stored. <br>
 *              STREAMING USAGE: MANDATORY for FINISH
 *
 *	@param[out/in]	pHashLength
 *				Pointer to a uint32_t location in which the hash length in bytes is stored
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_Hash
(
    hseHashAlgo_t hashAlgo,
    const uint8_t *pInput,
    uint32_t inputLength,
    uint8_t *pHash,
    uint32_t *pHashLength
);

/**
 * 	@brief		Blocking hash stream start request
 *
 *  @param[in]	streamId
 *				Specifies the stream to use for START, UPDATE, FINISH access modes
 *
 *	@param[in]	hashAlgo
 *				Specifies the hash algorithm
 *
 * 	@param[in]	pInput
 *				Address of the input message
 *				STREAMING USAGE: Used in all steps (except if inputLength is zero)
 *
 *	@param[in]	inputLength
 *				MD5, SHA1, SHA2_224, SHA2_256: 64
 *              - SHA2_384, SHA2_512, SHA2_512_224, SHA2_512_256: 128
 *              - SHA3: no limitation (can be any size)
 *
 *	@param[out]	pHash
 *			    The address of the output buffer where the resulting hash will be stored. <br>
 *              STREAMING USAGE: MANDATORY for FINISH
 *
 *	@param[out/in]	pHashLength
 *				Pointer to a uint32_t location in which the hash length in bytes is stored
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_HashStreamStart
(
    uint32_t streamId,
    hseHashAlgo_t hashAlgo,
    const uint8_t *pInput,
    uint32_t inputLength,
    uint8_t *pHash,
    uint32_t *pHashLength
);

/**
 * 	@brief		Blocking hash stream update request
 *
 *  @param[in]	streamId
 *				Specifies the stream to use for START, UPDATE, FINISH access modes
 *
 *	@param[in]	hashAlgo
 *				Specifies the hash algorithm
 *
 * 	@param[in]	pInput
 *				Address of the input message
 *				STREAMING USAGE: Used in all steps (except if inputLength is zero)
 *
 *	@param[in]	inputLength
 *				MD5, SHA1, SHA2_224, SHA2_256: 64
 *              - SHA2_384, SHA2_512, SHA2_512_224, SHA2_512_256: 128
 *              - SHA3: no limitation (can be any size)
 *
 *	@param[out]	pHash
 *			    The address of the output buffer where the resulting hash will be stored. <br>
 *              STREAMING USAGE: MANDATORY for FINISH
 *
 *	@param[out/in]	pHashLength
 *				Pointer to a uint32_t location in which the hash length in bytes is stored
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_HashStreamUpdate
(
    uint32_t streamId,
    hseHashAlgo_t hashAlgo,
    const uint8_t *pInput,
    uint32_t inputLength,
    uint8_t *pHash,
    uint32_t *pHashLength
);

/**
 * 	@brief		Blocking hash stream finish request
 *
 *  @param[in]	streamId
 *				Specifies the stream to use for START, UPDATE, FINISH access modes
 *
 *	@param[in]	hashAlgo
 *				Specifies the hash algorithm
 *
 * 	@param[in]	pInput
 *				Address of the input message
 *				STREAMING USAGE: Used in all steps (except if inputLength is zero)
 *
 *	@param[in]	inputLength
 *				MD5, SHA1, SHA2_224, SHA2_256: 64
 *              - SHA2_384, SHA2_512, SHA2_512_224, SHA2_512_256: 128
 *              - SHA3: no limitation (can be any size)
 *
 *	@param[out]	pHash
 *			    The address of the output buffer where the resulting hash will be stored. <br>
 *              STREAMING USAGE: MANDATORY for FINISH
 *
 *	@param[out/in]	pHashLength
 *				Pointer to a uint32_t location in which the hash length in bytes is stored
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_HashStreamFinish
(
    uint32_t streamId,
    hseHashAlgo_t hashAlgo,
    const uint8_t *pInput,
    uint32_t inputLength,
    uint8_t *pHash,
    uint32_t *pHashLength
);

#ifdef __cplusplus
}
#endif

#endif /* HSE_HOST_HASH_H */
