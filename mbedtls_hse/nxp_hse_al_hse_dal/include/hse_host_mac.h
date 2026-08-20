/**
 *   @file    	hse_host_mac.h
 *
 *   @brief   	This file use verify MAC operation
 *   @details 	This file will generate & verify CMAC & GMAC.
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

#ifndef HSE_HOST_MAC_H
#define HSE_HOST_MAC_H

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
 * 	@brief	    Process CMAC request in one shot
 *
 *	@param[in]	authDir
 *				Specifies the direction: generate/verify
 *
 *	@param[in]	inputSgtType
 *				HSE_SGT_OPTION_NONE
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation.
 *
 *	@param[in]	pInput
 *				Used in all steps, but ignored when #inputLength is zero
 *
 * 	@param[in]	inputLen
 *				Input length
 *
 *	@param[in/out]	pTag
 *				The output tag for "generate"; the input tag for "verify"
 *
 *	@param[in/out]	pTagLen
 *				Holds the address to a memory location (an uint32_t variable) in which the tag length in bytes is stored
 *				GENERATE:
 *              - For CMAC valid tag lengths are [4, cipher-block-length]. Tag-lengths greater than cipher-block-length will be
 *                truncated to cipher-block-length.
 *              - When the request has finished (output), the actual length of the returned value shall be stored.
 *              - VERIFY:
 *              - For CMAC valid tag lengths are [4, cipher block-length].
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_Cmac
(
    const hseAuthDir_t authDir,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLen,
    uint8_t *pTag,
    uint32_t *pTagLen
);

/**
 * 	@brief	    Process CMAC stream start request
 *
 * 	@param[in]	streamId
 *				Specifies the stream to use for START, UPDATE, FINISH access modes. Each interface supports
 *              a limited number of streams per interface, up to #HSE_STREAM_COUNT
 *
 * 	@param[in]	streamId
 *				Specifies the stream to use for START, UPDATE, FINISH access modes. Each interface supports
 *              a limited number of streams per interface, up to #HSE_STREAM_COUNT
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation.
 *
 *	@param[in]	pInput
 *				Used in all steps, but ignored when #inputLength is zero
 *
 * 	@param[in]	inputLen
 * 				STREAMING USAGE: Used in all steps.
 *            - START: Must be a multiple of block length (for HMAC-hash or AES), or zero.
 *
 *              Algorithm block lengths (for STREAMING USAGE):
 *            - CMAC : 16
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_CmacStart
(
	const hseStreamId_t streamId,
    const hseAuthDir_t authDir,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLen
);

/**
 * 	@brief	    Process CMAC stream update request
 *
 * 	@param[in]	streamId
 *				Specifies the stream to use for START, UPDATE, FINISH access modes. Each interface supports
 *              a limited number of streams per interface, up to #HSE_STREAM_COUNT
 *
 *	@param[in]	authDir
 *				Specifies the direction: generate/verify
 *
 *	@param[in]	pInput
 *				Used in all steps, but ignored when #inputLength is zero
 *
 * 	@param[in]	inputLen
 * 				STREAMING USAGE: Used in all steps.
 *            - UPDATE: Must be a multiple of block length (for HMAC-hash or AES). Cannot be zero.
 *              Refrain from issuing the service request, instead of passing zero.
 *
 *              Algorithm block lengths (for STREAMING USAGE):
 *            - CMAC : 16
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_CmacUpdate
(
	const hseStreamId_t streamId,
    const hseAuthDir_t authDir,
    const uint8_t *pInput,
    const uint32_t inputLen
);

/**
 * 	@brief	    Process CMAC stream finish request
 *
 * 	@param[in]	streamId
 *				Specifies the stream to use for START, UPDATE, FINISH access modes. Each interface supports
 *              a limited number of streams per interface, up to #HSE_STREAM_COUNT
 *
 *	@param[in]	authDir
 *				Specifies the direction: generate/verify
 *
 *	@param[in]	pInput
 *				Used in all steps, but ignored when #inputLength is zero
 *
 * 	@param[in]	inputLen
 * 				STREAMING USAGE: Used in all steps.
 *            - FINISH: Can be any value (For CMAC zero length is invalid).
 *
 *              Algorithm block lengths (for STREAMING USAGE):
 *            - CMAC : 16
 *
 *	@param[in/out]	pTag
 *				The output tag for "generate"; the input tag for "verify"
 *
 *	@param[in/out]	pTagLen
 *				Holds the address to a memory location (an uint32_t variable) in which the tag length in bytes is stored
 *				GENERATE:
 *             - For CMAC valid tag lengths are [4, cipher-block-length]. Tag-lengths greater than cipher-block-length will be
 *              truncated to cipher-block-length.
 *             - When the request has finished (output), the actual length of the returned value shall be stored.
 *             - VERIFY:
 *             - For CMAC valid tag lengths are [4, cipher block-length].
 *             STREAMING USAGE: Used in FINISH.
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_CmacFinish
(
	const hseStreamId_t streamId,
    const hseAuthDir_t authDir,
    const uint8_t *pInput,
    const uint32_t inputLen,
    uint8_t *pTag,
    uint32_t *pTagLen
);

/**
 * 	@brief		Process GMAC one shot request
 *
 *	@param[in]	authDir
 *				Specifies the direction: generate/verify
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation.
 *
 *	@param[in]	pInput
 *				Used in all steps, but ignored when #inputLength is zero
 *
 * 	@param[in]	inputLen
 * 				STREAMING USAGE: Used in all steps.
 *            - START: Must be a multiple of block length (for HMAC-hash or AES), or zero. Cannot be zero for HMAC.
 *            - UPDATE: Must be a multiple of block length (for HMAC-hash or AES). Cannot be zero.
 *                  Refrain from issuing the service request, instead of passing zero.
 *            - FINISH: Can be any value
 *
 *              Algorithm block lengths (for STREAMING USAGE):
 *            - GMAC 16
 *
 *  @param[in]	pIv
 *				Initialization Vector/Nonce
 *
 *	@param[in]	ivLen
 *				Initialization Vector length. Zero is not allowed
 *
 *	@param[in/out]	pTag
 *				The output tag for "generate"; the input tag for "verify"
 *
 *	@param[in/out]	pTagLen
 *				Holds the address to a memory location (an uint32_t variable) in which the tag length in bytes is stored
 *				GENERATE:
 *              - On calling service (input), this parameter shall contain the size of the buffer provided by #pTag.
 *              - For GMAC, valid tag lengths are 4, 8, 12, 13, 14, 15 and 16. Tag-lengths greater than 16 will be truncated to 16.
 *              - When the request has finished (output), the actual length of the returned value shall be stored.
 *              - VERIFY:
 *              - On calling service (input), this parameter shall contain the tag-length to be verified.
 *              - For GMAC, valid tag lengths are 4, 8, 12, 13, 14, 15 and 16.
 *              STREAMING USAGE: Used in FINISH.
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_Gmac
(
    const hseAuthDir_t authDir,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLen,
    const uint8_t *pIv,
    const uint32_t ivLen,
    uint8_t *pTag,
    uint32_t *pTagLen
);

/**
 * 	@brief		Process HMAC stream start request
 *
 * 	@param[in]	streamId
 *				Specifies the stream to use for START  mode. Each interface supports
 *              a limited number of streams per interface, up to #HSE_STREAM_COUNT
 *
 *	@param[in]	authDir
 *				Specifies the direction: generate/verify
 *
 *	@param[in]	hashAlgo
 *				The hash algorithm. Must not be HSE_HASH_ALGO_NULL or HSE_HASH_ALGO_MD5
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation.
 *
 *	@param[in]	pInput
 *				 Used in all steps, but ignored when #inputLength is zero
 *
 * 	@param[in]	inputLen
 * 				STREAMING USAGE: Used in all steps.
 *            - START: Must be a multiple of block length (for HMAC-hash or AES), or zero. Cannot be zero for HMAC.
 *
 *              Algorithm block lengths (for STREAMING USAGE):
 *            - HMAC, depends on underlying hash:
 *            - MD5, SHA1, SHA2_224, SHA2_256: 64
 *            - SHA2_512_224, SHA2_512_256, SHA2_384, SHA2_512: 128
 *            - SHA3: not supported for HMAC
 *
 *	@param[in/out]	pTag
 *				The output tag for "generate"; the input tag for "verify"
 *
 *	@param[in/out]	pTagLen
 *				Holds the address to a memory location (an uint32_t variable) in which the tag length in bytes is stored
 *				GENERATE:
 *              - On calling service (input), this parameter shall contain the size of the buffer provided by #pTag.
 *              - For HMAC, valid tag lengths are [1, hash-length]. Tag-lengths greater than hash-length will be truncated to hash-length.
 *              - When the request has finished (output), the actual length of the returned value shall be stored.
 *              - VERIFY:
 *              - On calling service (input), this parameter shall contain the tag-length to be verified.
 *              - For HMAC, valid tag lengths are [1, hash-length].
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_HmacStart
(
	const hseStreamId_t streamId,
    const hseAuthDir_t authDir,
    const hseHashAlgo_t hashAlgo,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLen,
    uint8_t *pTag,
    uint32_t *pTagLen
);

/**
 * 	@brief		Process HMAC stream update request
 *
 * 	@param[in]	streamId
 *				Specifies the stream to use for START, UPDATE, FINISH access modes. Each interface supports
 *              a limited number of streams per interface, up to #HSE_STREAM_COUNT
 *
 *	@param[in]	authDir
 *				Specifies the direction: generate/verify
 *
 *	@param[in]	hashAlgo
 *				The hash algorithm. Must not be HSE_HASH_ALGO_NULL or HSE_HASH_ALGO_MD5
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation.
 *
 *	@param[in]	pInput
 *				Used in all steps, but ignored when #inputLength is zero
 *
 * 	@param[in]	inputLen
 * 				STREAMING USAGE: Used in all steps.
 *            - UPDATE: Must be a multiple of block length (for HMAC-hash or AES). Cannot be zero.
 *
 *             Algorithm block lengths (for STREAMING USAGE):
 *            - HMAC, depends on underlying hash:
 *            - MD5, SHA1, SHA2_224, SHA2_256: 64
 *            - SHA2_512_224, SHA2_512_256, SHA2_384, SHA2_512: 128
 *            - SHA3: not supported for HMAC
 *
 *	@param[in/out]	pTag
 *				The output tag for "generate"; the input tag for "verify"
 *
 *	@param[in/out]	pTagLen
 *				Holds the address to a memory location (an uint32_t variable) in which the tag length in bytes is stored
 *				GENERATE:
 *              - On calling service (input), this parameter shall contain the size of the buffer provided by #pTag.
 *              - For HMAC, valid tag lengths are [1, hash-length]. Tag-lengths greater than hash-length will be truncated to hash-length.
 *              - When the request has finished (output), the actual length of the returned value shall be stored.
 *              - VERIFY:
 *              - On calling service (input), this parameter shall contain the tag-length to be verified.
 *              - For HMAC, valid tag lengths are [1, hash-length].
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_HmacUpdate
(
	const hseStreamId_t streamId,
	const hseAuthDir_t authDir,
    const hseHashAlgo_t hashAlgo,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLen,
    uint8_t *pTag,
    uint32_t *pTagLen
);

/**
 * 	@brief		Process HMAC stream finish request
 *
 * 	@param[in]	streamId
 *				Specifies the stream to use for START, UPDATE, FINISH access modes. Each interface supports
 *              a limited number of streams per interface, up to #HSE_STREAM_COUNT
 *
 *	@param[in]	authDir
 *				Specifies the direction: generate/verify
 *
 *	@param[in]	hashAlgo
 *				The hash algorithm. Must not be HSE_HASH_ALGO_NULL or HSE_HASH_ALGO_MD5
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation.
 *
 *	@param[in]	pInput
 *				Used in all steps, but ignored when #inputLength is zero
 *
 * 	@param[in]	inputLen
 * 				STREAMING USAGE: Used in all steps.
 *            - FINISH: Can be any value
 *
 *              Algorithm block lengths (for STREAMING USAGE):
 *            - HMAC, depends on underlying hash:
 *            - MD5, SHA1, SHA2_224, SHA2_256: 64
 *            - SHA2_512_224, SHA2_512_256, SHA2_384, SHA2_512: 128
 *            - SHA3: not supported for HMAC
 *
 *	@param[in/out]	pTag
 *				The output tag for "generate"; the input tag for "verify"
 *
 *	@param[in/out]	pTagLen
 *				Holds the address to a memory location (an uint32_t variable) in which the tag length in bytes is stored
 *				GENERATE:
 *              - On calling service (input), this parameter shall contain the size of the buffer provided by #pTag.
 *              - For HMAC, valid tag lengths are [1, hash-length]. Tag-lengths greater than hash-length will be truncated to hash-length.
 *              - When the request has finished (output), the actual length of the returned value shall be stored.
 *              - VERIFY:
 *              - On calling service (input), this parameter shall contain the tag-length to be verified.
 *              - For HMAC, valid tag lengths are [1, hash-length].
 *              STREAMING USAGE: Used in FINISH.
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_HmacFinish
(
	const hseStreamId_t streamId,
	const hseAuthDir_t authDir,
    const hseHashAlgo_t hashAlgo,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLen,
    uint8_t *pTag,
    uint32_t *pTagLen
);

/**
 * 	@brief		Process HMAC one shot request
 *
 *	@param[in]	authDir
 *				Specifies the direction: generate/verify
 *
 *	@param[in]	hashAlgo
 *				The hash algorithm. Must not be HSE_HASH_ALGO_NULL or HSE_HASH_ALGO_MD5
 *
 *	@param[in]	keyHandle
 *				The key to be used for the operation.
 *
 *	@param[in]	pInput
 *				Pointer to input
 *
 * 	@param[in]	inputLen
 * 				Input length
 *
 *	@param[in/out]	pTag
 *				The output tag for "generate"; the input tag for "verify"
 *
 *	@param[in/out]	pTagLen
 *				Holds the address to a memory location (an uint32_t variable) in which the tag length in bytes is stored
 *				GENERATE:
 *              - On calling service (input), this parameter shall contain the size of the buffer provided by #pTag.
 *              - For HMAC, valid tag lengths are [1, hash-length]. Tag-lengths greater than hash-length will be truncated to hash-length.
 *              - When the request has finished (output), the actual length of the returned value shall be stored.
 *              - VERIFY:
 *              - On calling service (input), this parameter shall contain the tag-length to be verified.
 *              - For HMAC, valid tag lengths are [1, hash-length].
 *
 *  @return     The HSE Service response
 *
 */
hseSrvResponse_t HSE_Hmac
(
    const hseAuthDir_t authDir,
    const hseHashAlgo_t hashAlgo,
    const hseKeyHandle_t keyHandle,
    const uint8_t *pInput,
    const uint32_t inputLen,
    uint8_t *pTag,
    uint32_t *pTagLen
);

#ifdef __cplusplus
}
#endif

#endif /* HSE_HOST_MAC_H */
