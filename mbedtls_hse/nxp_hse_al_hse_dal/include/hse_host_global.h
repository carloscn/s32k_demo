/**
*   @file    	hse_host_global.h
*
*   @brief   	This file contains
*
*   @addtogroup [HSE_DAL]
*   @{
*/
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

#ifndef HSE_HOST_GLOBAL_H_
#define HSE_HOST_GLOBAL_H_

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

/* List of identifiers for the MU instances */
#define MU0_INSTANCE_U8                     ((uint8)0U)
#define MU1_INSTANCE_U8                     ((uint8)1U)

/* Identifier for the only MU instance used in this example */
#define APP_MU_INSTANCE_U8                  (MU0_INSTANCE_U8)

/* Timeout for the Hse_Ip layer while waiting for a response from HSE for a synchronous request.
   As the Hse component is configured in this example to have the type of Timeout Counter set to 'TICKS',
the timeout in the variable below will be expressed in ticks */
#define TIMEOUT_TICKS_U32                   ((uint32)10000000U)

#define MU_CH0                     (0U)
#define MU_CH1                     (1U)

/* Check whether a HSE status is set */
#define CHECK_HSE_STATUS(hseStatus) ((hseStatus) == ((hseStatus) & Hse_Ip_GetHseStatus(MU_CH0)))
/*==================================================================================================
*                                             ENUMS
==================================================================================================*/

/*==================================================================================================
                                 STRUCTURES AND OTHER TYPEDEFS
==================================================================================================*/


#if defined ( D_CACHE_ENABLE_MBEDTLS )
#if defined (CPU_SAF8544) || defined(S32N55)
#define CRYPTO_43_HSE_START_SEC_VAR_SHARED_CLEARED_UNSPECIFIED_NO_CACHEABLE
#include "Crypto_43_HSE_MemMap.h"

extern hseSrvDescriptor_t   MbedTLS_aSrvDescriptor[HSE_NUM_OF_CHANNELS_PER_MU];
/* Global variable for tracking HSE service request - was missing from this
 * branch in the vendor header; hse_host_sign.c/hse_host_rng.c/hse_host_cipher.c
 * (and others) reference MbedTLS_aRequest unconditionally regardless of
 * D_CACHE_ENABLE_MBEDTLS, so it must be declared here too. */
extern Hse_Ip_ReqType MbedTLS_aRequest[HSE_NUM_OF_CHANNELS_PER_MU];

#define CRYPTO_43_HSE_STOP_SEC_VAR_SHARED_CLEARED_UNSPECIFIED_NO_CACHEABLE
#include "Crypto_43_HSE_MemMap.h"
#else
#define CRYPTO_START_SEC_VAR_SHARED_CLEARED_UNSPECIFIED_NO_CACHEABLE
#include "Crypto_MemMap.h"

extern hseSrvDescriptor_t   MbedTLS_aSrvDescriptor[HSE_NUM_OF_CHANNELS_PER_MU];
/* Same fix as the CPU_SAF8544/S32N55 branch above - see comment there. */
extern Hse_Ip_ReqType MbedTLS_aRequest[HSE_NUM_OF_CHANNELS_PER_MU];

#define CRYPTO_STOP_SEC_VAR_SHARED_CLEARED_UNSPECIFIED_NO_CACHEABLE
#include "Crypto_MemMap.h"
#endif
#else
#define CRYPTO_43_HSE_START_SEC_VAR_CLEARED_UNSPECIFIED_NO_CACHEABLE
#include "Crypto_43_HSE_MemMap.h"
extern hseSrvDescriptor_t   MbedTLS_aSrvDescriptor[HSE_NUM_OF_CHANNELS_PER_MU];
/* Global variable for tracking HSE service request */
extern Hse_Ip_ReqType MbedTLS_aRequest[HSE_NUM_OF_CHANNELS_PER_MU];
#define CRYPTO_43_HSE_STOP_SEC_VAR_CLEARED_UNSPECIFIED_NO_CACHEABLE
#include "Crypto_43_HSE_MemMap.h"
#endif
/** @brief   INPUT: Cipher parameters.
 *                  @note
 *                  - Only the private keys are encrypted and the encrypted value length is specified by the corresponding private key length (in bytes).
 *                  - For AES-block cipher, if the keyBitLen of the exported is not multiple of AES block size (128bits), the key value will be padded with zeros.
 *                  - For RSAES NO PADDING, the keyBitLen of the exported key must be less than or equal to #HSE_BITS_TO_BYTES(cipherKey_keyBitLen), and the key is considered a big-endian integer.
 *                  - For RSAES-PKCS1-v1_5, the keyBitLen of the exported key shall not be greater than #HSE_BITS_TO_BYTES(cipherKey_keyBitLen) -11 bytes.
 *                  - For RSAES-OAEP, the keyBitLen of the exported key shall not be greater than #HSE_BITS_TO_BYTES(cipherKey_keyBitLen) - 2 * hashLen - 2 bytes.
 * */
typedef struct
{
    /** @brief   INPUT: Encryption key handle.
     *                  The cipherKeyHandle can only be a provisioning key (#HSE_KF_USAGE_KEY_PROVISION and #HSE_KF_USAGE_ENCRYPT flags are set). <br>
     *                  Note that the key handle will identifies the cipher scheme below.
     *                  Must be set to #HSE_INVALID_KEY_HANDLE if not used. */
    hseKeyHandle_t    cipherKeyHandle;
    /** @brief Symmetric, asymmetric  and AEAD cipher scheme.
               @note
               - Only the private keys are encrypted.*/
    hseCipherScheme_t cipherScheme;
}cipher_t;

/** @brief   INPUT: The keyContainer parameters should be used when the key have to be exported in a key container that will be authenticated:
 *                  pointers to where key values will be exported should be provided within the key container. Optionally,
 *                  the pKeyInfo may point inside the key container. The signature/tag is done over the key container. */

typedef struct
{
    /** @brief   INPUT: The container length.
     *           @note  The container includes only the signed block (without the signature). */
    uint16_t          keyContainerLen;
    uint8_t           reserved[2];
    /** @brief   INPUT: Address of the key container; includes the key value(s) and other information used to authenticate the key.
     *                  (e.g. TBSCertificate for a X.509 certificate). */
    HOST_ADDR         pKeyContainer;
    /** @brief   INPUT: Authentication key handle (#HSE_KF_USAGE_KEY_PROVISION and #HSE_KF_USAGE_VERIFY flags are set).
     *                  Must be set to #HSE_INVALID_KEY_HANDLE if not used. An encrypted key can be imported only authenticated.*/
    hseKeyHandle_t    authKeyHandle;
    /** @brief   INPUT: Authentication scheme. <br>
     *                  Note that the key handle identifies the authentication scheme below. */
    hseAuthScheme_t   authScheme;
    /** @brief   INPUT: Byte length(s) of the authentication tag(s).
     *                   @note
     *                   - For MAC and RSA signature,  only authLen[0] is used.
     *                   - Both lengths are used for (R,S) (ECC or ED25519).
     *                   - The MAC tag size must be minimum 16 bytes.
     *                   - RSA signature size must be #HSE_BYTES_TO_BITS(keyBitLength);
     *                   - R or S size for ECDSA/EDDSA signature must be #HSE_BYTES_TO_BITS(keyBitLength)*/
#if defined (S32N55)
    uint16_t          authLen;
    /** @brief   INPUT: Address(es) to authentication tag.
     *                   @note
     *                   - For MAC and RSA signature,  only pAuth[0] is used.
     *                   - Both pointers are used for (R,S) (ECC or ED25519). */
    HOST_ADDR         pAuth;
#else

    uint16_t          authLen[2];
    /** @brief   INPUT: Address(es) to authentication tag.
     *                   @note
     *                   - For MAC and RSA signature,  only pAuth[0] is used.
     *                   - Both pointers are used for (R,S) (ECC or ED25519). */
    HOST_ADDR         pAuth[2];
#endif
}keyContainer_t;

/*==================================================================================================
                                 GLOBAL VARIABLE DECLARATIONS
==================================================================================================*/

/*==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================*/


#ifdef __cplusplus
}
#endif

#endif /* HSE_HOST_GLOBAL_H_ */
