/**
 *   @file    		hse_host_sign.h
 *
 *   @brief   		This file use verify signature operation
 *   @details 		This file will generate & verify signatures.
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

#ifndef HSE_HOST_SIGN_H
#define HSE_HOST_SIGN_H

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
 * 	@brief		ECDSA GEN/VER with hash done in ONE_SHOT (or not at all, depending on bInputIsHashed - pre-hashed)
 *
 * 	@param[in]	authDir
 *				Specifies the direction: generate/verify. STREAMING USAGE: Used in FINISH
 *
 * 	@param[in]	hashAlgo
 *				The hash algorithm used to hash the input before applying the ECDSA operation
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation
 *
 *	@param[in]	pInput
 *				The address of the message to be signed/verify.
 *
 *	@param[in]	inputLength
 *              The length of the message
 *
 *  @param[in]	bInputIsHashed
 *				Specifies that the input is already hashed with the algorithm in specified in the sign scheme
 *
 *	@param[out]	pR
 *				Where the signature components must be stored.  It is output for "generate" and input for "verify
 *				ECDSA and EDDSA signature format as (r,s), with r at index 0
 *
 *	@param[out]	pS
 *				Where the signature components must be stored.  It is output for "generate" and input for "verify
 *				ECDSA and EDDSA signature format as (r,s), with s at index 1
 *
 *	@param[in/out]	pRLen
 *				An array of two addresses of two uint32_t values containing signature lengths. It is input/output for "generate" and input for "verify"
 *
 *	@param[in/out]	pSLen
 *				An array of two addresses of two uint32_t values containing signature lengths. It is input/output for "generate" and input for "verify"
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_Ecdsa
(
    const hseAuthDir_t authDir,
    const hseHashAlgo_t hashAlgo,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLength,
    const bool_t bInputIsHashed,
    uint8_t *pR,
    uint8_t *pS,
    uint32_t *pRLen,
    uint32_t *pSLen
);

/**
 * 	@brief		RSA PSS GEN/VER with hash done in ONE_SHOT (or not at all, depending on bInputIsHashed - pre-hashed)
 *
 * 	@param[in]	authDir
 *				Specifies the direction: generate/verify. STREAMING USAGE: Used in FINISH
 *
 * 	@param[in]	hashAlgo
 *				The hash algorithm used to hash the input
 *
 * @param[in]	saltLength
 *				The length of the salt
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation
 *
 *	@param[in]	pInput
 *				The address of the message to be signed/verify.
 *
 *	@param[in]	inputLength
 *              The length of the message
 *
 *  @param[in]	bInputIsHashed
 *				Specifies that the input is already hashed with the algorithm in specified in the sign scheme
 *
 *	@param[out]	pSignature
 *				Where the signature components must be stored.  It is output for "generate" and input for "verify"
 *				RSA has a single signature component, at index 0, and the size of buffer must be at least the byteLength(public modulus n)
 *
 *	@param[in/out]	pSignLen
 *				An array of two addresses of two uint32_t values containing signature lengths. It is input/output for "generate" and input for "verify"
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_RsaSaPss
(
    const hseAuthDir_t authDir,
    const hseHashAlgo_t hashAlgo,
    const uint32_t saltLength,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLength,
    const bool_t bInputIsHashed,
    uint8_t *pSignature,
    uint32_t *pSignLen
);

/**
 * 	@brief		RSA PKCS 1V15 GEN/VER with hash done in ONE_SHOT (or not at all, depending on bInputIsHashed - pre-hashed)
 *
 * 	@param[in]	authDir
 *				Specifies the direction: generate/verify. STREAMING USAGE: Used in FINISH
 *
 * 	@param[in]	hashAlgo
 *				The hash algorithm used to hash the input
 *
 * @param[in]	saltLength
 *				The length of the salt
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation
 *
 *	@param[in]	pInput
 *				The address of the message to be signed/verify.
 *
 *	@param[in]	inputLength
 *              The length of the message
 *
 *  @param[in]	bInputIsHashed
 *				Specifies that the input is already hashed with the algorithm in specified in the sign scheme
 *
 *	@param[out]	pSignature
 *				Where the signature components must be stored.  It is output for "generate" and input for "verify"
 *				RSA has a single signature component, at index 0, and the size of buffer must be at least the byteLength(public modulus n)
 *
 *	@param[in/out]	pSignLen
 *				An array of two addresses of two uint32_t values containing signature lengths. It is input/output for "generate" and input for "verify"
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_RsaSaPkcs_v1_5
(
    const hseAuthDir_t authDir,
    const hseHashAlgo_t hashAlgo,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLength,
    const bool_t bInputIsHashed,
    uint8_t *pSignature,
    uint32_t *pSignLen
);

/**
 * 	@brief		RSA RSAES - ENC/DEC in ONE_SHOT (or not at all, depending on bInputIsHashed - pre-hashed)
 *
 * 	@param[in]	cipherDir
 *				Specifies the cipher direction: encryption/decryption
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation
 *
 *  @param[in]	inputLength
 *				The input length (plaintext or ciphertext)
 *
 *	@param[in]	pInput
 *				The plaintext for encryption or the ciphertext for decryption
 *
 *	@param[in/out]	pOutputLength
 *				Holds the address to a location (an uint32_t variable) in which the output length in bytes is stored
 *
 *	@param[out]	pOutput
 *				The address of the Output. The plaintext for decryption or ciphertext for encryption
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_RsaEsNoPadding
(
	const hseCipherDir_t cipherDir,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLength,
    uint8_t *pOutput,
    uint32_t *pOutputLength
);

/**
 * 	@brief		RSA RSAES-PKCS1-v1_5 ENC/DEC in ONE_SHOT (or not at all, depending on bInputIsHashed - pre-hashed)
 *
 * 	@param[in]	cipherDir
 *				Specifies the cipher direction: encryption/decryption
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation
 *
 *  @param[in]	inputLength
 *				The input length (plaintext or ciphertext)
 *
 *	@param[in]	pInput
 *				The plaintext for encryption or the ciphertext for decryption
 *
 *	@param[in/out]	pOutputLength
 *				Holds the address to a location (an uint32_t variable) in which the output length in bytes is stored
 *
 *	@param[out]	pOutput
 *				The address of the Output. The plaintext for decryption or ciphertext for encryption
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_RsaEsPkcs_v1_5
(
	const hseCipherDir_t cipherDir,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLength,
    uint8_t *pOutput,
    uint32_t *pOutputLength
);

/**
 * 	@brief		RSA RSAES-OAEP ENC/DEC in ONE_SHOT (or not at all, depending on bInputIsHashed - pre-hashed)
 *
 * @param[in]	hashAlgo
 *				The hash algorithm used to hash the input
 *
 * 	@param[in]	cipherDir
 *				Specifies the cipher direction: encryption/decryption
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation
 *
 * @param[in]	pLabel
 *				Optional OAEP label (it can be NULL if label length is 0). Must be less than 128 bytes long
 *
 * 	@param[in]	labelLength
 *				Optional OAEP label length (it can be 0). Must be less than 128
 *
 *  @param[in]	inputLength
 *				The input length (plaintext or ciphertext)
 *
 *	@param[in]	pInput
 *				The plaintext for encryption or the ciphertext for decryption
 *
 *	@param[in/out]	pOutputLength
 *				Holds the address to a location (an uint32_t variable) in which the output length in bytes is stored
 *
 *	@param[out]	pOutput
 *				The address of the Output. The plaintext for decryption or ciphertext for encryption
 *
 *  @return     The HSE Service response
 *
 */
/*************************************************************************************************
*  Description:
************************************************************************************************/
hseSrvResponse_t HSE_RsaEsOaep
(
	const hseHashAlgo_t hashAlgo,
	const hseCipherDir_t cipherDir,
	const hseKeyHandle_t keyHandle,
	const uint8_t *pLabel,
	const uint32_t labelLength,
	const uint8_t *pInput,
	const uint32_t inputLength,
	uint8_t *pOutput,
	uint32_t *pOutputLength
);

#ifdef __cplusplus
}
#endif

#endif /* HSE_HOST_SIGN_H */
