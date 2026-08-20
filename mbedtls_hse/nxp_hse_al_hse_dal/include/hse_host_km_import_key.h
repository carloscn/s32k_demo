/**
*   @file    	hse_host_km_import_key.h
*
*   @brief   	This file implements wrappers for key import.
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

#ifndef HSE_HOST_KM_IMPORT_KEY_H
#define HSE_HOST_KM_IMPORT_KEY_H

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
 * 	@brief		Imports a key given the key handle, key info and key value(s)
 *
 * 	@param[in]	u8MuInstance
 *				MU Instance number
 *
 * 	@param[in]	targetKeyHandle
 *				Specifies the slot where to add or updated a key
 *
 * 	@param[in]	pKeyInfo
 *				Specifies usage flags, restriction access, key length in bits, etc for the key
 *
 * 	@param[in]	pKey[3]
 *				Pointer to key values
 * 	            A asymmetric private key should always be imported together with the public key.
 *           - pKey[0]:
 *              - RSA public modulus n (big-endian).
 *              - ECC the x- and y-coordinate of the public key must be passed one after another
 *                    (the byte length of the stored value of the public key must be twice the byte length of the prime p)
 *              - ED25519 point x.
 *              - Classic DH prime modulus p
 *           - pKey[1]:
 *              - RSA public exponent e (big-endian).
 *              - Classic DH public key
 *           - pKey[2]:
 *              - RSA private exponent d (big-endian).
 *              - ECC/ED25519 private scalar (big-endian).
 *              - The symmetric key (e.g AES, HMAC).
 *              - Classic DH private key
 *
 * 	@param[in]	keyLen[3]
 *				The length in bytes for the above key values in the same order.
 *
 *  @return		HSE service response.
 */
extern hseSrvResponse_t HSE_ImportKey
(
    uint8_t u8MuInstance,
    hseKeyHandle_t targetKeyHandle,
    hseKeyInfo_t *pKeyInfo,
    const uint8_t *pKey0, uint32_t keyLen0,
    const uint8_t *pKey1, uint32_t keyLen1,
    const uint8_t *pKey2, uint32_t keyLen2
);

/**
 * 	@brief		Imports a symmetric key given the key handle, type (AES/HMAC) and key flags
 *
 * 	@param[in]	handle
 *				Specifies the slot where to add or updated a key
 *
 * 	@param[in]	type
 *				The key type
 *
 * 	@param[in]	flags
 *				The key flags
 *
 * 	@param[in]	len
 *				The length in bytes for the key value
 *
 *  @return		HSE service response.
 */
extern hseSrvResponse_t HSE_ImportSymKey
(
    hseKeyHandle_t handle,
    hseKeyType_t type,
    hseKeyFlags_t flags,
    const uint8_t *pKey,
    uint32_t len
);

/**
 * 	@brief		HSE_ImportEccKey
 *
 * 	@param[in]	handle
 *				Specifies the slot where to add or updated a key
 *
 * 	@param[in]	type
 *				Specifies the Key type. It provides information about the interpretation of key data
 *
 * 	@param[in]	flags
 *				Usage flags for this key (e.g. SIGN/VERIFY/PROVISION/EXCHANGE)
 *
 * 	@param[in]	keyBitLen
 * 				Base length in bits of the key - for ECC corresponds to Curve bit length
 *
 * 	@param[in]	eccCurveId
 * 				Specific for ECC key - curve ID
 *
 * 	@param[in]	pPubKey
 * 				ECC the x- and y-coordinate of the public key must be passed one after another
 * 				(the byte length of the stored value of the public key must be twice the byte length of the prime p)
 *
 * 	@param[in]	pPrivKey
 * 				ECC/ED25519 private scalar (big-endian)
 *
 * 	@param[out]	None
 *
 *  @return		HSE service response.
 */
extern hseSrvResponse_t HSE_ImportEccKey
(
    hseKeyHandle_t handle,
    hseKeyType_t type,
    hseKeyFlags_t flags,
	uint16_t keyBitLen,
    hseEccCurveId_t eccCurveId,
    const uint8_t* pPubKey,
    const uint8_t* pPrivKey
);

/**
 * 	@brief		Imports a RSA key (pub/pair) given the key handle, type (PUB/PAIR),
 * 				flags and public exponent length
 *
 * 	@param[in]	handle
 *				Specifies the slot where to add or updated a key
 *
 * 	@param[in]	type
 *				Specifies the Key type. It provides information about the interpretation of key data
 *
 * 	@param[in]	flags
 *				Usage flags for this key (e.g. SIGN/VERIFY/PROVISION/EXCHANGE)
 *
 * 	@param[in]	pN
 *				RSA public modulus n (big-endian).
 *
 * 	@param[in]	modLen
 *				The length in bytes for the modulus n.
 *
 * 	@param[in]	pE
 *				RSA public exponent e (big-endian).
 *
 * 	@param[in]	eLen
 *				The length in bytes for the modulus e.
 *
 * @param[in]	pD
 *				RSA private exponent d (big-endian)
 *
 *  @return		HSE service response.
 */
extern hseSrvResponse_t HSE_ImportRsaKey
(
    hseKeyHandle_t handle,
    hseKeyType_t type,
    hseKeyFlags_t flags,
    const uint8_t* pN,
    uint16_t modLen,
    const uint8_t* pE,
    uint16_t eLen,
    const uint8_t* pD
);

/**
 * 	@brief		Imports a Symmetric key in an authenticated key container
 *
 * 	@param[in]	targetHandle
 *				Specifies the slot where to add or updated a key
 *
 * 	@param[in]	authHandle
 *				Authentication key handle (#HSE_KF_USAGE_KEY_PROVISION and #HSE_KF_USAGE_VERIFY flags are set)
 *
 * 	@param[in]	pAuthScheme
 *				Authentication scheme
 *
 * 	@param[in]	pKeyContainer
 *				Address of the key container; includes the key value(s) and other information used to authenticate the key
 *
 * 	@param[in]	containerLen
 *				The container length. The container includes only the signed block (without the signature)
 *
 * 	@param[in]	keyInfoOffset
 *				Specifies usage flags, restriction access, key length in bits, etc for the key.
 *              @note
 *              - Only keys that are not write protected can be updated with this service.
 *              - NVM keys are secured against replay attacks by including a counter value stored within HSE.
 *                The anti-replay attack counter included in the key info header should be greater than
 *                the counter of the HSE key that will be updated (in case of key update).
 *                This mean that keyInfo MUST be included in the signed key container (when the Life Cycle is IN_FIELD).
 *              - For RAM keys the key counter is ignored (keyInfo may not be in the key container).
 *
 * 	@param[in]	keyDataOffset
 *				Pointer to key values
 * 	            A asymmetric private key should always be imported together with the public key.
 *           - pKey[0]:
 *              - RSA public modulus n (big-endian).
 *              - ECC the x- and y-coordinate of the public key must be passed one after another
 *                    (the byte length of the stored value of the public key must be twice the byte length of the prime p)
 *              - ED25519 point x.
 *           - pKey[1]:
 *              - RSA public exponent e (big-endian).
 *           - pKey[2]:
 *              - RSA private exponent d (big-endian).
 *              - ECC/ED25519 private scalar (big-endian).
 *              - The symmetric key (e.g AES, HMAC).
 *
 *  @param[in]	keyLen
 *				The length in bytes for the above key values in the same order
 *
 *	@param[in]  authLen[2]
 *				Byte length(s) of the authentication tag(s).
 *              @note
 *              - For MAC and RSA signature,  only authLen[0] is used.
 *              - Both lengths are used for (R,S) (ECC or ED25519).
 *
 * @param[in]   pAuth[2]
 *              Address(es) to authentication tag.
 *              @note
 *             - For MAC and RSA signature,  only pAuth[0] is used.
 *             - Both pointers are used for (R,S) (ECC or ED25519).
 *
 *  @return		HSE service response.
 */
#if defined (S32N55)
extern hseSrvResponse_t HSE_ImportAuthSymKey
(
    const hseKeyHandle_t targetHandle,
    const hseKeyHandle_t authHandle,
    const hseAuthScheme_t *pAuthScheme,
    const uint8_t *pKeyContainer,
    const uint16_t containerLen,
    const uint16_t keyInfoOffset,
    const uint16_t keyDataOffset,
    const uint16_t keyLen,
    const uint8_t *pAuth,
    const uint16_t authLen

);
#else

extern hseSrvResponse_t HSE_ImportAuthSymKey
(
    const hseKeyHandle_t targetHandle,
    const hseKeyHandle_t authHandle,
    const hseAuthScheme_t *pAuthScheme,
    const uint8_t *pKeyContainer,
    const uint16_t containerLen,
    const uint16_t keyInfoOffset,
    const uint16_t keyDataOffset,
    const uint16_t keyLen,
    const uint8_t *pAuth0,
    const uint8_t *pAuth1,
    const uint16_t authLen0,
    const uint16_t authLen1
);
#endif
/**
 * 	@brief			Imports an encrypted/authenticated key
 *
 * 	@param[in]		targetKeyHandle
 *					The key handle for the key to be imported
 *
 * 	@param[in]		pKeyInfo
 *					Specifies usage flags, restriction access, key length in bits, etc for the key
 *
 *	@param[in]		cipherParam
 *					Cipher parameters, to decrypt the key
 *
 *	@param[in]		keyContainerParam
 *					key Container parameters, to authenticate the key
 *
 * 	@param[in]		keyLen0
 * 					uint32_t value of the length (in bytes) for the pKey0 buffer
 *
 * 	@param[in]		keyLen1
 * 					uint32_t value of the length (in bytes) for the pKey1 buffer
 *
 * 	@param[in]		keyLen2
 * 					uint32_t value of the length (in bytes) for the pKey2 buffer
 *
 * 	@param[in]		pKeyInfo
 * 					Specifies usage flags, restriction access, key length in bits, etc for the key
 *
 * 	@param[in]		pKey0
 * 					Pointer to key value
 * 					- RSA public modulus n (big-endian).
 *              	- ECC the x- and y-coordinate of the public key must be passed one after another
 *                    (the byte length of the stored value of the public key must be twice the byte length of the prime p)
 *              	- ED25519 point x.
 *
 * 	@param[in]		pKey1
 * 					Pointer to the buffer where to fill the key value
 * 					- RSA public exponent e (big-endian).
 *
 * 	@param[in]		pKey2
 * 					Pointer to the buffer where to fill the key value
 *              	- RSA private exponent d (big-endian).
 *              	- ECC/ED25519 private scalar (big-endian).
 *              	- The symmetric key (e.g AES, HMAC).
 *
 *  @return			HSE service response.
 */
hseSrvResponse_t HSE_ImportEncAuthKey
(
	hseKeyHandle_t targetKeyHandle,
	cipher_t *cipherParam,
	uint32_t PmskeyLen,
	keyContainer_t *authKeyContainer,
	uint16_t keyInfoOffset, uint16_t keyDataOffset
);

#ifdef HSE_SPT_CLASSIC_DH
/**
 * 	@brief		Imports a DH key (pub/pair) given the key handle
 *
 * 	@param[in]	handle
 *				Specifies the slot where to add or updated a key
 *
 * 	@param[in]	type
 *				Specifies the Key type. It provides information about the interpretation of key data
 *
 * 	@param[in]	flags
 *				Usage flags for this key (e.g. SIGN/VERIFY/PROVISION/EXCHANGE)
 *
 * 	@param[in]	keyLen
 *				DH prime modulus p length in bytes
 *
 * 	@param[in]	pPrimeMod
 *				Pointer to the DH prime modulus p
 *
 * 	@param[in]	pPubKey
 *				Pointer to the DH public key.
 *
 * 	@param[in]	pPrivKey
 *				Pointer to the DH private key.
 *
 * @param[in]	privKeyLen
 *				DH private key length in bytes.
 *
 *  @return		HSE service response.
 */
hseSrvResponse_t HSE_ImportDhKey
(
    hseKeyHandle_t handle,
    hseKeyType_t type,
    hseKeyFlags_t flags,
	uint16_t keyLen,
	const uint8_t* pPrimeMod,
    const uint8_t* pPubKey,
    const uint8_t* pPrivKey,
	uint16_t privKeyLen
);
#endif/* HSE_SPT_CLASSIC_DH */

/**
 * 	@brief		Imports on-going stream context
 *
 * 	@param[in]	streamId
 *				Specifies the stream to be exported or overwritten if imported
 *
 * 	@param[in/out]	pStreamCtx
 *				The output buffer where the streaming context will be copied (export) or
 *              the input buffer from which HSE will copy the streaming context (import).
 *               Length of the buffer should be at least #MAX_STREAMING_CONTEXT_SIZE bytes
 *
 *  @return		HSE service response.
 */
extern hseSrvResponse_t HSE_ImportStream(hseStreamId_t streamId, void* pStreamCtx);

/**
 * 	@brief		Exports on-going stream context
 *
 * 	@param[in]	streamId
 *				Specifies the stream to be exported or overwritten if imported
 *
 * 	@param[in/out]	pStreamCtx
 *				The output buffer where the streaming context will be copied (export) or
 *              the input buffer from which HSE will copy the streaming context (import).
 *               Length of the buffer should be at least #MAX_STREAMING_CONTEXT_SIZE bytes
 *
 *  @return		HSE service response.
 */
hseSrvResponse_t HSE_ExportStream(hseStreamId_t streamId, void* pStreamCtx);

#ifdef __cplusplus
}
#endif

#endif /* HSE_HOST_KM_IMPORT_KEY_H */
