/**
*   @file    	hse_host_cipher.h
*
*   @brief   	This file contains cipher services.
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

#ifndef HSE_HOST_CIPHER_H
#define HSE_HOST_CIPHER_H

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
 * 	@brief		AES Encryption request
 *
 *	@param[in]	cipherBlockMode
 *				Specifies the cipher mode.
 *              STREAMING USAGE: Used in START

 *	@param[in]	keyHandle
 *				The key to be used for the operation.
 *              STREAMING USAGE: Used in START step.
 *
 *	@param[in]	pIV
 *				Initialization Vector/Nonce. Ignored for NULL & ECB cipher block modes.
 *              IV length is 16 bytes. (AES cipher block size).
 *              STREAMING USAGE: Used in START.
 *
 * 	@param[in]	ivLength
 *				none
 *
 *  @param[in]	pInput
 *				The plaintext for encryption or the ciphertext for decryption.
 *              STREAMING USAGE: Used in START, UPDATE and FINISH. Ignored in START if #inputLength is zero
 *
 *	@param[in]	inputLen
 *				The plaintext and ciphertext length. For ECB, CBC & CFB cipher block modes,
 *              must be a multiple of block length. Cannot be zero.
 *           	STREAMING USAGE: MANDATORY for all steps.
 *              - START: Must be a multiple of block length. Can be zero.
 *              - UPDATE: Must be a multiple of block length. Cannot be zero. Refrain from issuing the service request, instead of passing zero.
 *              - FINISH: For ECB, CBC & CFB cipher block modes, must be a multiple of block length. Cannot be zero.
 *              For remaining cipher block modes, can be any value except zero.
 *              AES block lengths: 16
 *
 *	@param[out]	pOutput
 *				The plaintext for decryption or ciphertext for encryption.
 *              STREAMING USAGE: Used in START, UPDATE and FINISH. Ignored in START if #inputLength is zero.
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_AesEncrypt
(
    hseCipherBlockMode_t cipherBlockMode,
    hseKeyHandle_t keyHandle,
    const uint8_t *pIV,
    uint32_t ivLength,
    const uint8_t* pInput,
    uint32_t inputLength,
    uint8_t* pOutput
);

/**
 * 	@brief		AES Decryption request
 *
 *	@param[in]	cipherBlockMode
 *				Specifies the cipher mode.
 *              STREAMING USAGE: Used in START
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation.
 *              STREAMING USAGE: Used in START step.
 *
 *	@param[in]	pIV
 *				Initialization Vector/Nonce. Ignored for NULL & ECB cipher block modes.
 *              IV length is 16 bytes. (AES cipher block size).
 *              STREAMING USAGE: Used in START.
 *
 * 	@param[in]	ivLength
 *				none
 *
 *  @param[in]	pInput
 *				The plaintext for encryption or the ciphertext for decryption.
 *              STREAMING USAGE: Used in START, UPDATE and FINISH. Ignored in START if #inputLength is zero
 *
 *	@param[in]	inputLen
 *				The plaintext and ciphertext length. For ECB, CBC & CFB cipher block modes,
 *              must be a multiple of block length. Cannot be zero.
 *           	STREAMING USAGE: MANDATORY for all steps.
 *              - START: Must be a multiple of block length. Can be zero.
 *              - UPDATE: Must be a multiple of block length. Cannot be zero. Refrain from issuing the service request, instead of passing zero.
 *              - FINISH: For ECB, CBC & CFB cipher block modes, must be a multiple of block length. Cannot be zero.
 *              For remaining cipher block modes, can be any value except zero.
 *              AES block lengths: 16
 *
 *	@param[out]	pOutput
 *				The plaintext for decryption or ciphertext for encryption.
 *              STREAMING USAGE: Used in START, UPDATE and FINISH. Ignored in START if #inputLength is zero.
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_AesDecrypt
(
    hseCipherBlockMode_t cipherBlockMode,
    hseKeyHandle_t keyHandle,
    const uint8_t *pIV,
    uint32_t ivLength,
    const uint8_t* pInput,
    uint32_t inputLength,
    uint8_t* pOutput
);

#ifdef HSE_SPT_XTS_AES
/**
 * 	@brief		HSE_AesXTS
 *
 * 	@param[in]	cipherDir
 * 				Specifies the cipher direction: encryption/decryption
 *
 * 	@param[in]	cipherKeyHandle
 * 				The key to be used for the operation
 *
 * 	@param[in]	tweakKeyHandle
 * 				The XTS Tweak key
 *
 * 	@param[in]	sectorNumber
 * 				The sector number
 *
 * 	@param[in]	sectorSize
 * 				Sector size. Must be a multiple of 16 bytes
 *
 * 	@param[in]	inputLength
 * 				The plaintext and ciphertext length. Must be above or equal to 16
 *
 * 	@param[in]	pInput
 * 				The plaintext for encryption or the ciphertext for decryption
 *
 * 	@param[out]	pOutput
 * 				The plaintext for decryption or ciphertext for encryption
 *
 *	@return		The HSE Service response
 */
hseSrvResponse_t HSE_AesXTS
(
	hseCipherDir_t   cipherDir,
	hseKeyHandle_t   cipherKeyHandle,
	hseKeyHandle_t   tweakKeyHandle,
	uint64_t         sectorNumber,
	uint16_t         sectorSize,
	uint32_t         inputLength,
	const uint8_t*   pInput,
	uint8_t*         pOutput
);
#endif /* HSE_SPT_XTS_AES */

#ifdef __cplusplus
}
#endif

#endif /* HSE_HOST_CIPHER_H */
