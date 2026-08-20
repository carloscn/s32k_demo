/**
*   @file    	hse_host_gen_key.h
*
*   @brief   	This file implements wrappers for key generation service (AES/ECC/RSA) and ECDH.
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

#ifndef HSE_HOST_KM_GEN_KEY_H
#define HSE_HOST_KM_GEN_KEY_H

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
#include "Hse_Ip.h"

#ifdef HSE_SPT_KEY_GEN
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
#ifdef HSE_SPT_TLS12_RSA_PRE_MASTER_SECRET_GEN
#define TLS12_PROTOCOL_VERSION_LENGTH 	2U	/**< @brief Length of TLS/DTLS protocol version */
#endif
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

#if defined(HSE_SPT_ECDH) || defined(HSE_SPT_CLASSIC_DH)
/**
 * 	@brief		Generate a Shared Secret via DH
 *
 * 	@param[in]	privKeyHandle
 *				The private key
 *
 * 	@param[in]	pubKeyHandle
 *				The peer public key handle. Must be previously imported into the HSE
 *
 * 	@param[in]	targetKeyHandle
 *				The target key handle (where to store the shared secret)
 *
 *  @return		HSE service response.
 */
hseSrvResponse_t HSE_GenerateDhSharedSecret
(
    hseKeyHandle_t privKeyHandle,
    hseKeyHandle_t pubKeyHandle,
    hseKeyHandle_t targetKeyHandle
);
#endif /* HSE_SPT_ECDH || HSE_SPT_CLASSIC_DH */

#ifdef HSE_SPT_SYM_RND_KEY_GEN
/**
 * 	@brief		Generate a symmetric random key
 *
 * 	@param[in]	keyHandle
 *				The target key handle (where to store the new key)
 *
 * 	@param[in]	keyInfo
 * 				Specifies usage flags, restriction access, key bit length etc for the key.
 *              @note
 *              - For random symmetric key, the key length in bits should be specified by keyBitLen.
 *              - For RSA, keyBitLen specifies the bit length of the public modulus which shall be generated.
 *              - For ECC, the keyInfo should specify the ECC curve ID and the length of the base point order.
 *              - For classic DH, the keyBitLen specifies the bit length of the public modulus.
 *
 *  @return		HSE service response.
 */
hseSrvResponse_t HSE_GenerateSymKey
(
    hseKeyHandle_t keyHandle,
    hseKeyInfo_t keyInfo
);
#endif /* HSE_SPT_SYM_RND_KEY_GEN */

#ifdef HSE_SPT_ECC_KEY_PAIR_GEN
/**
 * 	@brief		Generate ECC key pair
 *
 * 	@param[in]	keyHandle
 *				The target key handle (where to store the new key)
 *
 * 	@param[in]	keyInfo
 * 				Specifies usage flags, restriction access, key bit length etc for the key.
 *              @note
 *              - For random symmetric key, the key length in bits should be specified by keyBitLen.
 *              - For RSA, keyBitLen specifies the bit length of the public modulus which shall be generated.
 *              - For ECC, the keyInfo should specify the ECC curve ID and the length of the base point order.
 *              - For classic DH, the keyBitLen specifies the bit length of the public modulus.
 *
 * @param[out]	pGeneratedPub
 *				Where to store the public key. If the public key is not needed at this point, pass a NULL pointer.
 *              The x- and y-coordinate of the public key will be passed concatenated one after another, as big-endian
 *              strings. The size of the buffer must be double the byte length of the prime n
 *
 *  @return		HSE service response.
 */
hseSrvResponse_t HSE_GenerateEccKey
(
    hseKeyHandle_t keyHandle,
    hseKeyInfo_t keyInfo,
    uint8_t *pGeneratedPub
);
#endif /* HSE_SPT_ECC_KEY_PAIR_GEN */

#ifdef HSE_SPT_RSA_KEY_PAIR_GEN
/**
 * 	@brief		Generate a RSA key pair with the given public exponent e
 *
 * 	@param[in]	keyHandle
 *				The target key handle (where to store the new key)
 *
 * 	@param[in]	keyInfo
 *				Specifies usage flags, restriction access, key bit length etc for the key
 *
 * 	@param[in]	eLen
 *				The length of public exponent "e". Should not be more than 16 bytes
 *
 * 	@param[in]	pE
 *				The public exponent "e"
 *
 * 	@param[out]	pN
 * 				The public modulus n. It can be NULL (the modulus is not provided using this service).
 *           	The size of this memory area must be at least the byte length of the public modulus.
 *
 * 	@param[in]	pfnCallback
 *				The callback for asynchronous request
 *
 * 	@param[in]	pCallbackParam
 *				Parameter used to call the asynchronous callback(can be NULL)
 *
 *  @return		HSE service response.
 */
hseSrvResponse_t HSE_GenerateRsaKey
(
    hseKeyHandle_t keyHandle,

    hseKeyInfo_t keyInfo,
    uint32_t eLen,
    uint8_t *pE,
    uint8_t *pN,
	Hse_Ip_pfResponseCallbackType pfnCallback,
	void* pCallbackParam
);
#endif /* HSE_SPT_RSA_KEY_PAIR_GEN */

#ifdef HSE_SPT_ECC
/**
 * 	@brief		Hse_LoadEccUserCurve
 *
 * 	@param[in]	eccCurveId
 *				The ECC curve ID. Must be a user allocated curve ID (i.e. HSE_ECC_CURVEx)
 *
 * 	@param[in]	pBitLen
 *				The bit length of the prime p
 *
 * 	@param[in]	nBitLen
 *				The bit length of the order n
 *
 * 	@param[in]	pA
 * 				Elliptic curve parameter a. Must be represented as
 * 				a big endian number, in the form of a byte array of length HSE_BITS_TO_BYTES(pBitLen),
 * 				e.g. 256 bit curves need 32 byte arrays, 521 bit curves need 66 byte arrays
 *
 * 	@param[in]	pB
 *				Elliptic curve parameter b. Must be represented as
 * 				a big endian number, in the form of a byte array of length HSE_BITS_TO_BYTES(pBitLen),
 * 				e.g. 256 bit curves need 32 byte arrays, 521 bit curves need 66 byte arrays
 *
 * 	@param[in]	pP
 *				Elliptic curve prime p. Must be represented as
 * 				a big endian number, in the form of a byte array of length HSE_BITS_TO_BYTES(pBitLen),
 * 				e.g. 256 bit curves need 32 byte arrays, 521 bit curves need 66 byte arrays.
 *
 * 	@param[in]	pN
 *				Elliptic curve order n. Must be represented as
 * 				a big endian number, in the form of a byte array of length HSE_BITS_TO_BYTES(nBitLen),
 * 				e.g. 256 bit curves need 32 byte arrays, 521 bit curves need 66 byte arrays.
 *
 * 	@param[in]	pG
 * 				Elliptic curve generator point. The x and y coordinates of the generator,
 * 				represented as big endian numbers, each in the form of a byte array of
 * 				length HSE_BITS_TO_BYTES(pBitLen), then concatenated. The HSE expects
 * 				an array of size 2 * HSE_BITS_TO_BYTES(pBitLen).
 *
 * 	@param[out]	None
 *
 *  @return		HSE service response.
 */
hseSrvResponse_t Hse_LoadEccUserCurve
(
	hseEccCurveId_t eccCurveId,
	hseKeyBits_t pBitLen,
	hseKeyBits_t nBitLen,
	const uint8_t    *pA,
	const uint8_t    *pB,
	const uint8_t    *pP,
	const uint8_t    *pN,
	const uint8_t    *pG
);
#endif /* HSE_SPT_ECC */

#ifdef HSE_SPT_TLS12_RSA_PRE_MASTER_SECRET_GEN
/**
 * 	@brief		Generate Shared Secret
 *
 * 	@param[in]	keyHandle
 *				The target key handle (where to store the new key)
 *
 * 	@param[in]	protocolVersion
 *				The TLS or DTLS version
 *				E.g. for TLS1.2 must be {3, 3}; for DTLS1.2 must be { 254, 253 }
 *
 * 	@param[in]	keyInfo
 *				Specifies usage flags, restriction access, key bit length etc for the key
 *
 *	@return		HSE service response.
 *
 */
hseSrvResponse_t HSE_GenSharedSecret
(
    hseKeyHandle_t keyHandle,
	uint8_t protocolVersion[TLS12_PROTOCOL_VERSION_LENGTH],
    hseKeyInfo_t keyInfo
);
#endif /* HSE_SPT_TLS12_RSA_PRE_MASTER_SECRET_GEN */

#ifdef HSE_SPT_CLASSIC_DH_KEY_PAIR_GEN
/**
 * 	@brief		Generate DH key pair
 *
 * 	@param[in]	keyHandle
 *				The target key handle (where to store the new key)
 *
 * 	@param[in]	keyInfo
 * 				Specifies usage flags, restriction access, key bit length etc for the key.
 *              @note
 *              - For random symmetric key, the key length in bits should be specified by keyBitLen.
 *              - For RSA, keyBitLen specifies the bit length of the public modulus which shall be generated.
 *              - For ECC, the keyInfo should specify the ECC curve ID and the length of the base point order.
 *              - For classic DH, the keyBitLen specifies the bit length of the public modulus.
 *
 * 	@param[in]	pG
 * 				Pointer to the base g.
 *
 * 	@param[in]	gLen
 *				The length of public base g.
 *
 * 	@param[in]	pMod
 * 				Pointer to the modulus p.
 *
 * 	@param[in]	modLen
 * 				The length of modulus p.
 *
 * 	@param[out]	pPub
 *				Where to store the public key. If the public key is not needed at this point, pass a NULL pointer.
 *
 *	@return		HSE service response.
 *
 */
hseSrvResponse_t HSE_GenerateDhKeyPair
(
	hseKeyHandle_t keyHandle,
	hseKeyInfo_t keyInfo,
	const uint8_t *pG,
	uint32_t gLen,
	const uint8_t *pMod,
	uint32_t modLen,
	uint8_t *pPub
);
#endif/* HSE_SPT_CLASSIC_DH_KEY_PAIR_GEN */
#endif /* HSE_SPT_KEY_GEN */

#ifdef __cplusplus
}
#endif

#endif /* HSE_HOST_KM_GEN_KEY_H */
