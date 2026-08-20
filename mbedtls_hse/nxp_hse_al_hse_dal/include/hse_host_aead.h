/**
*   @file    	hse_host_aead.h
*
*   @brief   	This file contains AEAD services: CCM, GCM.
*
*   @addtogroup [HSE_DAL]
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

#ifndef HSE_HOST_AEAD_H
#define HSE_HOST_AEAD_H

#ifdef __cplusplus
extern "C"{
#endif

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/

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
 * 	@brief		AEAD GCM Encrypt One Shot
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation
 *
 *	@param[in]	pIv
 *				Initialization Vector/Nonce
 *
 *	@param[in]	ivLen
 *				The length of the IV/Nonce (in bytes).
 *              - CCM valid IV sizes 7, 8, 9, 10, 11, 12, 13 bytes
 *              - GCM: 1<= ivLength <= 2^32-1. Recommended 12 bytes or greater.
 *
 *	@param[in]	pAad
 *				The AAD Header data. Ignored if aadLength is zero
 *
 *	@param[in]	aadLen
 *				The length of AAD Header data (in bytes). Can be zero.
 *
 * 	@param[in]	pInput
 *				The plaintext for "authenticated encryption"; the ciphertext for "authenticated decryption"
 *
 *	@param[in]	inputLen
 *				The length of the plaintext and ciphertext (in bytes).
 *              Can be zero (compute/verify the tag without input message)
 *
 *	@param[in]	tagLen
 *				The length of tag (in bytes).
 *              - GCM valid Tag sizes 4, 8, 12, 13, 14, 15, 16 bytes
 *
 *	@param[out/in]	pTag
 *				The output tag for "authenticated encryption" or
 *              the input tag for "authenticated decryption".
 *
 *	@param[out]	pOutput
 *				The ciphertext for "authenticated encryption"; the plaintext for "authenticated decryption".
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_AeadGcmEncrypt
(
    const hseKeyHandle_t keyHandle,
    const uint8_t *pIv,
    const uint32_t ivLen,
    const uint8_t *pAad,
    const uint32_t aadLen,
    const uint8_t *pInput,
    const uint32_t inputLen,
    const uint32_t tagLen,
    uint8_t *pTag,
    uint8_t *pOutput
);

/**
 * 	@brief		AEAD GCM Decrypt One Shot
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation
 *
 *	@param[in]	pIv
 *				Initialization Vector/Nonce
 *
 *	@param[in]	ivLen
 *				The length of the IV/Nonce (in bytes).
 *              - GCM: 1<= ivLength <= 2^32-1. Recommended 12 bytes or greater.
 *
 *	@param[in]	pAad
 *				The AAD Header data. Ignored if aadLength is zero
 *
 *	@param[in]	aadLen
 *				The length of AAD Header data (in bytes). Can be zero.
 *              - CCM: Restricted to lengths less than or equal to (2^16 - 2^8) bytes.
 *
 * 	@param[in]	pInput
 *				The plaintext for "authenticated encryption"; the ciphertext for "authenticated decryption"
 *
 *	@param[in]	inputLen
 *				The length of the plaintext and ciphertext (in bytes).
 *              Can be zero (compute/verify the tag without input message)
 *
 *	@param[in]	tagLen
 *				The length of tag (in bytes).
 *              - GCM valid Tag sizes 4, 8, 12, 13, 14, 15, 16 bytes
 *
 *	@param[out/in]	pTag
 *				The output tag for "authenticated encryption" or
 *              the input tag for "authenticated decryption".
 *
 *	@param[out]	pOutput
 *				The ciphertext for "authenticated encryption"; the plaintext for "authenticated decryption".
 *
 *  @return     The HSE Service response
 *
 */

hseSrvResponse_t HSE_AeadGcmDecrypt
(
    const hseKeyHandle_t keyHandle,
    const uint8_t *pIv,
    const uint32_t ivLen,
    const uint8_t *pAad,
    const uint32_t aadLen,
    const uint8_t *pInput,
    const uint32_t inputLen,
    const uint32_t tagLen,
    uint8_t *pTag,
    uint8_t *pOutput
);

/**
 * 	@brief		AEAD GCM Encrypt/Decrypt Stream Start
 *
 * 	@param[in]	cipherDir
 *				Specifies the cipher direction: encryption/decryption
 *
 *  @param[in]	streamId
 *				Specifies the cipher direction: encryption/decryption
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation
 *
 *	@param[in]	pIv
 *				Initialization Vector/Nonce. STREAMING USAGE: Used in START
 *
 *	@param[in]	ivLen
 *				The length of the IV/Nonce (in bytes).
 *              - GCM: 1<= ivLength <= 2^32-1. Recommended 12 bytes or greater.
 *              STREAMING USAGE: Used in START
 *
 *	@param[in]	pAad
 *				The AAD Header data. Ignored if aadLength is zero. STREAMING USAGE: Used in START
 *
 *	@param[in]	aadLen
 *				The length of AAD Header data (in bytes). Can be zero.
 *
 *              STREAMING USAGE: Used in START
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_AeadGcmStreamStart
(
	const hseStreamId_t streamId,
	const hseCipherDir_t cipherDir,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pIv,
    const uint32_t ivLen,
    const uint8_t *pAad,
    const uint32_t aadLen
);

/**
 * 	@brief		AEAD GCM Encrypt/Decrypt Stream Update
 *
 *  @param[in]	streamId
 *				Specifies the cipher direction: encryption/decryption
 *
 * 	@param[in]	pInput
 *				The plaintext for "authenticated encryption"; the ciphertext for "authenticated decryption"
 *
 *	@param[in]	inputLen
 *				The length of the plaintext and ciphertext (in bytes).
 *              Can be zero (compute/verify the tag without input message)
 *              STREAMING USAGE:
 *             - START:  The input length is ignored.
 *             - UPDATE: Must be a multiple of block length. Cannot be zero. Refrain from issuing the service request,
 *                      instead of passing zero.
 *             - FINISH: All lengths are allowed.
 *
 *	@param[out]	pOutput
 *				The ciphertext for "authenticated encryption"; the plaintext for "authenticated decryption".
 *				STREAMING USAGE: Used in UPDATE and FINISH step.
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_AeadGcmStreamUpdate
(
	const hseStreamId_t streamId,
	const hseCipherDir_t cipherDir,
    const uint8_t *pInput,
    const uint32_t inputLen,
    uint8_t *pOutput
);

/**
 * 	@brief		AEAD GCM Encrypt/Decrypt Stream Finish
 *
 *  @param[in]	streamId
 *				Specifies the cipher stream
 *
 *  @param[in]	cipherDir
 *				Specifies the cipher direction: encryption/decryption
 *
 * 	@param[in]	pInput
 *				The plaintext for "authenticated encryption"; the ciphertext for "authenticated decryption"
 *
 *	@param[in]	inputLen
 *				The length of the plaintext and ciphertext (in bytes).
 *              Can be zero (compute/verify the tag without input message)
 *              STREAMING USAGE:
 *             - START:  The input length is ignored.
 *             - UPDATE: Must be a multiple of block length. Cannot be zero. Refrain from issuing the service request,
 *                      instead of passing zero.
 *             - FINISH: All lengths are allowed.
 *
 *	@param[in]	tagLen
 *				The length of tag (in bytes).
 *              - GCM valid Tag sizes 4, 8, 12, 13, 14, 15, 16 bytes
 *              STREAMING USAGE: Used in FINISH step.
 *
 *	@param[out/in]	pTag
 *				The output tag for "authenticated encryption" or
 *              the input tag for "authenticated decryption".
 *				STREAMING USAGE: Used in FINISH step.
 *
 *	@param[out]	pOutput
 *				The ciphertext for "authenticated encryption"; the plaintext for "authenticated decryption".
 *				STREAMING USAGE: Used in UPDATE and FINISH step.
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_AeadGcmStreamFinish
(
	const hseStreamId_t streamId,
	const hseCipherDir_t cipherDir,
    const uint8_t *pInput,
    const uint32_t inputLen,
    const uint32_t tagLen,
    uint8_t *pTag,
	uint8_t *pOutput
);

/**
 * 	@brief		AEAD CCM Encrypt One Shot
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation
 *
 *	@param[in]	pIv
 *				Initialization Vector/Nonce
 *
 *	@param[in]	ivLen
 *				The length of the IV/Nonce (in bytes).
 *              - CCM valid IV sizes 7, 8, 9, 10, 11, 12, 13 bytes
 *
 *	@param[in]	pAad
 *				The AAD Header data. Ignored if aadLength is zero
 *
 *	@param[in]	aadLen
 *				The length of AAD Header data (in bytes). Can be zero.
 *              - CCM: Restricted to lengths less than or equal to (2^16 - 2^8) bytes.
 *
 * 	@param[in]	pInput
 *				The plaintext for "authenticated encryption"; the ciphertext for "authenticated decryption"
 *
 *	@param[in]	inputLen
 *				The length of the plaintext and ciphertext (in bytes).
 *              Can be zero (compute/verify the tag without input message)
 *
 *	@param[in]	tagLen
 *				The length of tag (in bytes).
 *              - CCM valid Tag sizes 4, 6, 8, 10, 12, 14, 16 bytes
 *
 *	@param[out/in]	pTag
 *				The output tag for "authenticated encryption" or
 *              the input tag for "authenticated decryption".
 *
 *	@param[out]	pOutput
 *				The ciphertext for "authenticated encryption"; the plaintext for "authenticated decryption".
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_AeadCcmEncrypt
(
    const hseKeyHandle_t keyHandle,
    const uint8_t *pIv,
    const uint32_t ivLen,
    const uint8_t *pAad,
    const uint32_t aadLen,
    const uint8_t *pInput,
    const uint32_t inputLen,
    const uint32_t tagLen,
    uint8_t *pTag,
    uint8_t *pOutput
);

/**
 * 	@brief		AEAD CCM Decrypt One Shot
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation
 *
 *	@param[in]	pIv
 *				Initialization Vector/Nonce
 *
 *	@param[in]	ivLen
 *				The length of the IV/Nonce (in bytes).
 *              - CCM valid IV sizes 7, 8, 9, 10, 11, 12, 13 bytes
 *
 *	@param[in]	pAad
 *				The AAD Header data. Ignored if aadLength is zero
 *
 *	@param[in]	aadLen
 *				The length of AAD Header data (in bytes). Can be zero.
 *              - CCM: Restricted to lengths less than or equal to (2^16 - 2^8) bytes.
 *
 * 	@param[in]	pInput
 *				The plaintext for "authenticated encryption"; the ciphertext for "authenticated decryption"
 *
 *	@param[in]	inputLen
 *				The length of the plaintext and ciphertext (in bytes).
 *              Can be zero (compute/verify the tag without input message)
 *
 *	@param[in]	tagLen
 *				The length of tag (in bytes).
 *              - CCM valid Tag sizes 4, 6, 8, 10, 12, 14, 16 bytes
 *
 *	@param[out/in]	pTag
 *				The output tag for "authenticated encryption" or
 *              the input tag for "authenticated decryption".
 *
 *	@param[out]	pOutput
 *				The ciphertext for "authenticated encryption"; the plaintext for "authenticated decryption".
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_AeadCcmDecrypt
(
    const hseKeyHandle_t keyHandle,
    const uint8_t *pIv,
    const uint32_t ivLen,
    const uint8_t *pAad,
    const uint32_t aadLen,
    const uint8_t *pInput,
    const uint32_t inputLen,
    const uint32_t tagLen,
    uint8_t *pTag,
    uint8_t *pOutput
);

#ifdef __cplusplus
}
#endif

#endif /* HSE_HOST_AEAD_H */
