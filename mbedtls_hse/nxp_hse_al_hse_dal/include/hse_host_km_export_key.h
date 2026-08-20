/**
*   @file    	hse_host_km_export_key.c
*
*   @brief   	This file implements wrappers for key export.
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

#ifndef HSE_HOST_KM_EXPORT_KEY_H
#define HSE_HOST_KM_EXPORT_KEY_H

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
#include "hse_host_global.h"

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
 * 	@brief			Export a key
 *
 * 	@param[in]		targetKeyHandle
 *					The key handle for the key to be exported
 *
 * 	@param[in-out]	pKeyLen0
 * 					Pointer to the uint32_t value of the length (in bytes) for the pKey0 buffer (INPUT).
 * 					As output, it provides the length of the encrypted or plain (only for public) key
 *
 * 	@param[in-out]	pKeyLen1
 * 					Pointer to the uint32_t value of the length (in bytes) for the pKey1 buffer  (INPUT).
 * 					As output, it provides the length of the encrypted or plain (only for public) key
 *
 * 	@param[in-out]	pKeyLen2
 * 					Pointer to the uint32_t value of the length (in bytes) for the pKey2 buffer  (INPUT).
 * 					As output, it provides the length of the encrypted or plain (only for public) key
 *
 * 	@param[out]		pKeyInfo
 * 					pointer the hseKeyInfo_t structure to Export the key information (see hseKeyInfo_t)
 *
 * 	@param[out]		pKey0
 * 					Pointer to the buffer where to fill the key value
 * 					- RSA public modulus n.
 * 					- ECC the x- and y-coordinate of the public key must be passed one after another
 * 					(the byte length of the stored value of the public key must be twice the byte
 * 						length of the prime p)
 * 					- ED25519 point x
 *
 * 	@param[out]		pKey1
 * 					Pointer to the buffer where to fill the key value
 * 					- RSA public exponent e.
 *
 * 	@param[out]		pKey2
 * 					Pointer to the buffer where to fill the key value
 * 					- The symmetric key (e.g AES, HMAC).
 *
 *
 *  @return			HSE service response.
 */
extern hseSrvResponse_t HSE_ExportKey
(
    hseKeyHandle_t targetKeyHandle,
    hseKeyInfo_t *pKeyInfo,
    uint8_t *pKey0, uint32_t *pKeyLen0,
    uint8_t *pKey1, uint32_t *pKeyLen1,
    uint8_t *pKey2, uint32_t *pKeyLen2
);

/**
 * 	@brief			Exports an ECC key Public given
 *
 * 	@param[in]		handle
 *					The key handle for the key to be exported
 *
 * 	@param[in]		eccCurveId
 * 					Specific for ECC key - curve ID
 *
 * 	@param[in]		keyBitLen
 *					Base length in bits of the key - for ECC corresponds to Curve bit length
 *
 *	@param[out]	 	pPubKey
 * 					Pointer to the buffer where to fill the key value
 * 					- ECC the x- and y-coordinate of the public key must be passed one after another
 * 					(the byte length of the stored value of the public key must be twice the byte
 * 						length of the prime p)
 *
 *  @return		HSE service response.
 */
extern hseSrvResponse_t HSE_ExportEccPubKey
(
    hseKeyHandle_t handle,
    hseEccCurveId_t eccCurveId,
	uint16_t keyBitLen,
    uint8_t* pPubKey
);

/**
 * 	@brief			Exports an encrypted/authenticated key
 *
 * 	@param[in]		targetKeyHandle
 *					The key handle for the key to be exported
 *
 *	@param[in]		cipherParam
 *					Cipher parameters, to encrypt the key
 *
 *	@param[in-out]	keyContainerParam
 *					key Container parameters, to export an authenticated key
 *
 * 	@param[in-out]	pKeyLen0
 * 					Pointer to the uint32_t value of the length (in bytes) for the pKey0 buffer (INPUT).
 * 					As output, it provides the length of the encrypted or plain (only for public) key
 *
 * 	@param[in-out]	pKeyLen1
 * 					Pointer to the uint32_t value of the length (in bytes) for the pKey1 buffer  (INPUT).
 * 					As output, it provides the length of the encrypted or plain (only for public) key
 *
 * 	@param[in-out]	pKeyLen2
 * 					Pointer to the uint32_t value of the length (in bytes) for the pKey2 buffer  (INPUT).
 * 					As output, it provides the length of the encrypted or plain (only for public) key
 *
 * 	@param[out]		pKeyInfo
 * 					pointer the hseKeyInfo_t structure to Export the key information (see hseKeyInfo_t)
 *
 * 	@param[out]		pKey0
 * 					Pointer to the buffer where to fill the key value
 * 					- RSA public modulus n.
 * 					- ECC the x- and y-coordinate of the public key must be passed one after another
 * 					(the byte length of the stored value of the public key must be twice the byte
 * 						length of the prime p)
 * 					- ED25519 point x
 *
 * 	@param[out]		pKey1
 * 					Pointer to the buffer where to fill the key value
 * 					- RSA public exponent e.
 *
 * 	@param[out]		pKey2
 * 					Pointer to the buffer where to fill the key value
 * 					- The symmetric key (e.g AES, HMAC).
 *
 *
 *  @return			HSE service response.
 */
hseSrvResponse_t HSE_ExportEncKey
(
    hseKeyHandle_t targetKeyHandle,
    hseKeyInfo_t *pKeyInfo,
	cipher_t *cipherParam,
	keyContainer_t *keyContainerParam,
    uint8_t *pKey0, uint32_t *pKeyLen0,
    uint8_t *pKey1, uint32_t *pKeyLen1,
    uint8_t *pKey2, uint32_t *pKeyLen2
);

/**
 * 	@brief			Encrypt and export pre-master secret
 *
 * 	@param[in]		targetKeyHandle
 *					The key handle for the key to be exported
 *
 * 	@param[in]		cipherParam
 *					Cipher parameters, to encrypt the key
 *
 * 	@param[out]		pOutEncPms
 *					Pointer to buffer where to fill encrypted pre-master secret
 *
 *	@param[in-out]	encPmsLen
 *					Pointer to the uint32_t value of the length (in bytes) for the pKey2 buffer  (INPUT).
 * 					As output, it provides the length of the encrypted or plain (only for public) key
 *
 *  @return			HSE service response.
 */
hseSrvResponse_t HSE_EncryptPms
(
	hseKeyHandle_t targetKeyHandle,
	cipher_t *cipherParam,
	uint8_t *pOutEncPms, uint32_t *encPmsLen
);
#endif /* HSE_HOST_KM_EXPORT_KEY_H */
