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

#ifndef NXP_HSE_TLS_SSL_H
#define NXP_HSE_TLS_SSL_H

#ifdef __cplusplus
extern "C"{
#endif

#if defined (MBEDTLS_USE_NXP_HSE_CRYPTO)

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/
#include "hse_interface.h"
#include "hse_host_kdf.h"
#include "hse_host_km_import_key.h"
#include "hse_host_km_utils.h"
#include "aes_alt.h"
#include "nxp_hse_ecc.h"
#include "hse_host_mac.h"
#include "nxp_hse_debug.h"
#include "hmac_alt.h"
#include "mbedtls/md_internal.h"
#include "mbedtls/md.h"
#include "mbedtls/ccm.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/certs.h"
#include "mbedtls/timing.h"
#include "mbedtls/debug.h"
#include "mbedtls/rsa.h"

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
#define KEY_EXCHANGE_TYPE_POSITION	(2 * (sizeof(hseKeyHandle_t)))	/* PMS key_handle + PSK key_handle */
/*==================================================================================================
*											  ENUMS
==================================================================================================*/

/*==================================================================================================
								 STRUCTURES AND OTHER TYPEDEFS
==================================================================================================*/
typedef struct{
	hseKeyHandle_t client_write_MAC_key;		/*Hold the keyhandle for MAC encryption for client*/
	hseKeyHandle_t server_write_MAC_key;		/*Hold the keyhandle for MAC encryption for server */
	hseKeyHandle_t client_write_key;			/*Hold the keyhandle for data encryption for client*/
	hseKeyHandle_t server_write_key;			/*Hold the keyhandle for data encryption for server*/
}TlsPRFKeys_t;

typedef struct TlsPrfKeyHandle
{
	hseKeyHandle_t src_keyhandle;	/*Hold the premaster/master keyhandle*/
	hseKeyHandle_t psk_keyhandle;	/*Hold the psk keyhandle*/
}Tls_Prf_KeyHandle_T;

/* Type for the TLS PRF */
typedef int ssl_tls_prf_t(const unsigned char *, size_t, const char *,
                          const unsigned char *, size_t,
                          unsigned char *, size_t);
/*==================================================================================================
                                 GLOBAL VARIABLE DECLARATIONS
==================================================================================================*/

/*==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================*/
/**
 * @brief				nxp_hse_tls_prf_generic
 * @details				compute the keyhandle using key material
 *
 * @param[in]			md_type
 *						message digest algo.
 *
 * @param[in]			secret
 * 						hold the key material information
 *
 * @param[in]			slen
 * 						length of key material
 *
 * @param[in]			label
 * 						The label of the TLS1.2 PRF operations
 *
 * @param[in]			random
 * 						The seed for TLS 1.2 PRF.
 *
 * @parm[in]			rlen
 * 						length of seed
 *
 * @param[out]			dstbuf
 * 						pointer to output buffer.
 *
 * @param[in]			dlen
 * 						length of output buffer
 *
 * 	@return				return type		: int
 *
 *	@return				\c 0 on success.
 *
 * 	@return     		#MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE if failed
 *
 */
int nxp_hse_tls_prf_generic( mbedtls_md_type_t md_type,
                            const unsigned char *secret, size_t slen,
                            const char *label,
                            const unsigned char *random, size_t rlen,
                            unsigned char *dstbuf, size_t dlen );

/*
 * @brief				nxp_hse_ssl_populate_transform
 * @details 			Populate a transform structure with session keys and all the other necessary information.
 *
 * @param[in/out]: 		transform: structure to populate
 *      				[in] must be just initialised with mbedtls_ssl_transform_init()
 *      				[out] fully populated, ready for use by mbedtls_ssl_{en,de}crypt_buf()
 *
 * @param[in] 			ciphersuite
 * 						cipher id
 *
 * @param[in] 			master
 * 						Hold the master keyhandle
 *
 * @param[in] 			encrypt_then_mac
 * 						flag for EtM activation
 *
 * @param[in] 			trunc_hmac
 * 						flag for HMAC truncated activation
 *
 * @param[in] 			compression
 * @param[in] 			tls_prf
 * 						pointer to PRF to use for key derivation
 *
 * @param[in] 			randbytes
 * 						buffer holding ServerHello.random + ClientHello.random
 *
 * @param[in] 			minor_ver
 * 						SSL/TLS minor version
 *
 * @param[in] 			endpoint
 * 						client or server
 *
 * @param[in] 			ssl
 * 						optionally used for:
 *        				- MBEDTLS_SSL_HW_RECORD_ACCEL: whole context (non-const)
 *       				- MBEDTLS_SSL_EXPORT_KEYS: ssl->conf->{f,p}_export_keys
 *        				- MBEDTLS_DEBUG_C: ssl->conf->{f,p}_dbg
 */

int nxp_hse_ssl_populate_transform( mbedtls_ssl_transform *transform,
                                   int ciphersuite,
                                   const unsigned char master[48],
#if defined(MBEDTLS_SSL_SOME_MODES_USE_MAC)
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
                                   int encrypt_then_mac,
#endif /* MBEDTLS_SSL_ENCRYPT_THEN_MAC */
#if defined(MBEDTLS_SSL_TRUNCATED_HMAC)
                                   int trunc_hmac,
#endif /* MBEDTLS_SSL_TRUNCATED_HMAC */
#endif /* MBEDTLS_SSL_SOME_MODES_USE_MAC */
                                   ssl_tls_prf_t tls_prf,
                                   const unsigned char randbytes[64],
                                   int minor_ver,
                                   unsigned endpoint,
#if !defined(MBEDTLS_SSL_HW_RECORD_ACCEL)
                                   const
#endif
                                   mbedtls_ssl_context *ssl );

/**
 * @brief				nxp_hse_mbedtls_ssl_psk_derive_premaster
 * @details				compute the psk and premaster keyhandle using key material
 *
 * @param[in/out]		ssl
 * 						[in]pointer to ssl context used
 * 						[out]fully populated,with premaster and psk keyhandle
 *
 * @param[in]			key_ex
 * 						Key exchange type used
 *
 * 	@return				return type		: int
 *
 *	@return				\c 0 on success.
 *
 * 	@return     		#MBEDTLS_ERR_SSL_INTERNAL_ERROR if failed
 * 						to derive psk and premaster
 *
 */
int nxp_hse_mbedtls_ssl_psk_derive_premaster( mbedtls_ssl_context *ssl, mbedtls_key_exchange_type_t key_ex );

/**
 * @brief				nxp_hse_mbedtls_ssl_cf_hmac
 * @details				Compute HMAC of variable-length data with constant flow
 *
 * @param[in]			ctx
 * 						The generic message-digest context
 *
 * @param[in]			add_data
 * 						pointer to metadata
 *
 * @param[in]			add_data_len
 * 						length of metadata
 *
 * @param[in]			data
 * 						pointer to actual data
 *
 * @param[in]			data_len_secret
 * 						length of data
 *
 * @param[out]			output
 * 						pointer to output buffer.
 *
 * 	@return				return type		: int
 *
 *	@return				\c 0 on success.
 *
 * 	@return     		\c -1 on failure.
 *
 */
int nxp_hse_mbedtls_ssl_cf_hmac( mbedtls_md_context_t *ctx, const unsigned char *add_data, size_t add_data_len,
		const unsigned char *data, size_t data_len_secret, unsigned char *output);

/**
 * @brief				nxp_hse_load_psk
 * @details				Import PSK to the HSE and return PSK key handle
 *
 * @param[in/out]		psk
 * 						[in] The pointer to the pre-shared key to import
 * 						[out] PSK keyhandle
 *
 * @param[in]			psk_len
 * 						The length of the pre-shared key in bytes
 *
 * 	@return				return type		: int
 *
 *	@return				\c 0 on success.
 *
 * 	@return     		#MBEDTLS_ERR_SSL_BAD_INPUT_DATA if key len is
 * 						invalid
 * 	@return				#KEYMGMT_ERR_SLOT_NOT_FOUND error if the key
 *              		slot is unavailable.
 * 	@return     		#KEYMGMT_ERR_KEY_IMPORT_FAILED if PSK key
 * 						import failed.
 *
 */
int nxp_hse_load_psk(unsigned char *psk, size_t psk_len);

/**
 * @brief				nxp_hse_cipher_get_keyhandle
 * @details				fetch the keyhandle from cipher context
 *
 * @param[out]			ctx
 * 						cipher context
 *
 * 	@return				return type		: hseKeyHandle_t
 *
 *	@return				\c keyhandle on success
 *
 *	@return				INVALID_KEYHANDLE if failed
 *
 */
hseKeyHandle_t nxp_hse_cipher_get_keyhandle(mbedtls_cipher_context_t *ctx);

/**
 * @brief				nxp_hse_hmac_get_keyhandle
 * @details				fetch the keyhandle from message-digest context
 *
 * @param[out]			ctx
 * 						message-digest context
 *
 * 	@return				return type		: hseKeyHandle_t
 *
 *	@return				\c keyhandle on success
 *
 *	@return				INVALID_KEYHANDLE if failed
 *
 */
hseKeyHandle_t nxp_hse_hmac_get_keyhandle( mbedtls_md_context_t *ctx );

/**
 * @brief				nxp_hse_hmac_set_keyhandle
 * @details				Set the keyhandle to INVALID_KEYHANDLE in cipher context
 *
 * @param[out]			ctx
 * 						cipher context
 *
 * 	@return				return type		: void
 *
 */
void nxp_hse_cipher_set_keyhandle(mbedtls_cipher_context_t *ctx);

/**
 * @brief				nxp_hse_hmac_set_keyhandle
 * @details				Set the keyhandle to INVALID_KEYHANDLE in message-digest context
 *
 * @param[out]			ctx
 * 						message-digest context
 *
 * 	@return				return type		: void
 *
 */
void nxp_hse_hmac_set_keyhandle( mbedtls_md_context_t *ctx );

/**
 * @brief				nxp_hse_free_keyhandle
 * @details				free the keyhandle form HSE
 *
 * @param[in]			pKeyhandle
 * 						pointer to keyhandle
 *
 * 	@return				return type		: void
 *
 */
void nxp_hse_FreeKeyhandle(const uint8_t* pKeyhandle);

/**
 * @brief				nxp_hse_FreeKeys
 * @details				free the keyhandle form HSE
 *
 * @param[in]			key1
 * 						variable to hold the keyhandle
 *
 * @param[in]			key2
 * 						variable to hold the keyhandle
 *
 * 	@return				return type		: void
 *
 */
void nxp_hse_FreeKeys(const hseKeyHandle_t key1, const hseKeyHandle_t key2);

#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)

/**
 * @brief				nxp_hse_ssl_write_encrypted_pms
 * @details				Generate a pre-master secret and encrypt it with the server's RSA key
 *
 * @param[in/out]		ssl
 * 						[in]pointer to ssl context used
 * 						[out]populate with Pre-Master Secret
 *
 * @param[in]			offset
 *						offset to the out encrypted pms buffer
 *
 * @param[out]			olen
 * 						encrypted Pre-Master Secret length
 *
 * @param[in]			pms_offset
 *						offset to the in pms buffer
 *
 * 	@return				return type		: int
 *
 *	@return				\c 0 on success.
 *
 * 	@return     		#MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL if out buff is
 * 						small
 * 	@return				#MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH if the key
 *              		type mismatched.
 * 	@return     		#MBEDTLS_ERR_SSL_INTERNAL_ERROR.
 */
int nxp_hse_ssl_write_encrypted_pms(mbedtls_ssl_context *ssl,
        size_t offset, size_t *olen, size_t pms_offset );

/**
 * @brief				nxp_hse_ssl_decrypt_encrypted_pms
 * @details				Decrypt encrypted pre-master secret
 *
 * @param[in/out]		ssl
 * 						[in]pointer to ssl context used
 * 						[out]populate with Pre-Master Secret
 *
 * @param[in]			p
 *						pointer to the encrypted pms buffer
 *
 * @param[in]			end
 * 						pointer to the end of encrypted pms buffer
 *
 * @param[out]			pms_pms
 *						pointer to the out pms buffer
 *
 * @param[out]			peer_pmslen
 * 						decrypted Pre-Master Secret length
 *
 * @param[in]			peer_pmssize
 *						Pre-Master Secret length
 *
 * 	@return				return type		: int
 *
 *	@return				\c 0 on success.
 *
 * 	@return     		#MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE if
 * 						bad client key exchange message
 * 	@return				#MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED if no
 *              		RSA private key found.
 * 	@return     		#MBEDTLS_ERR_SSL_INTERNAL_ERROR.
 */
int nxp_hse_ssl_decrypt_encrypted_pms(	mbedtls_ssl_context *ssl,
        								const unsigned char *p,
										const unsigned char *end,
										unsigned char *peer_pms,
										size_t *peer_pmslen,
										size_t peer_pmssize);

#endif /* MBEDTLS_KEY_EXCHANGE_RSA_ENABLED ||  MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED*/

#if defined(MBEDTLS_SSL_PROTO_TLS1) || defined(MBEDTLS_SSL_PROTO_TLS1_1)
/**
 * @brief				tls1_prf
 * @details				compute the keyhandle
 *
 * @param[in]			secret
 * 						hold the key material information
 *
 * @param[in]			slen
 * 						length of key material
 *
 * @param[in]			label
 * 						The label of the TLS1.0 and TLS1.1 PRF operations
 *
 * @param[in]			random
 * 						The seed for TLS1.0 and TLS1.1 PRF.
 *
 * @parm[in]			rlen
 * 						length of seed
 *
 * @param[out]			dstbuf
 * 						pointer to output buffer.
 *
 * @param[in]			dlen
 * 						length of output buffer
 *
 * 	@return				return type		: int
 *
 *	@return				\c 0 on success.
 *
 *	@return				\c -1 on failure.
 *
 * 	Note: TBD
 *
 */
int tls1_prf( const unsigned char *secret, size_t slen,
                     const char *label,
                     const unsigned char *random, size_t rlen,
                     unsigned char *dstbuf, size_t dlen );
#endif

#endif /* MBEDTLS_USE_NXP_HSE_CRYPTO */

#ifdef __cplusplus
}
#endif

#endif /* NXP_HSE_TLS_SSL_H */
