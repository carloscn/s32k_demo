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

#ifndef TRUSTEDKEYSTORE_INTERFACE_H
#define TRUSTEDKEYSTORE_INTERFACE_H

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_USE_NXP_HSE_TRUSTED_KEYSTORE)

#ifdef __cplusplus
extern "C" {
#endif

#include "std_typedefs.h"
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

#define TRUSTED_KEYFILE_HEADER		(0x5A5A5A5AU)
#define TRUSTED_KEYFILE_STR			"TrustedKeyStore"
#define TRUSTED_KEYFILE_STR_SIZE	(16U)
#define TRUSTED_KEYFILE_MAC_SIZE	(16U)

#define TRUSTED_KEYSTORE_CERT_ISSUER_NAME_TAG		('N')
#define TRUSTED_KEYSTORE_CERT_SERIAL_TAG			('S')
#define TRUSTED_KEYSTORE_PSK_HINT_TAG				('H')
#define TRUSTED_KEYSTORE_PSK_IDENTITY_TAG			('I')

/*==================================================================================================
*                                             ENUMS
==================================================================================================*/

/*==================================================================================================
                                 STRUCTURES AND OTHER TYPEDEFS
==================================================================================================*/

typedef struct __attribute__((packed)) trusted_keyfile_element_s
{
	unsigned int len;
	unsigned int  keyhandle;
	unsigned int  flag;
	unsigned char type;
	unsigned char data[1];
}trusted_keyfile_element_t;

typedef struct  __attribute__((packed)) trusted_keyfile_s
{
	unsigned int hdr;
	unsigned int len;
	unsigned char filestr[TRUSTED_KEYFILE_STR_SIZE];
	unsigned int numelem;
	unsigned char mac[TRUSTED_KEYFILE_MAC_SIZE];
	trusted_keyfile_element_t element[1];
}trusted_keyfile_t;


typedef enum 
{
	SEARCH_TYPE_KEYHANDLE,
	SEARCH_TYPE_CERT,
	SEARCH_TYPE_PSK_HINT,
	SEARCH_TYPE_PSK_IDENTITY,
	SEARCH_TYPE_MAX
}trusted_keystore_query_type_t;

typedef struct trusted_cert_id_s
{
    mbedtls_x509_buf issuer_raw;        /**< The raw issuer data (DER). Used for quick comparison. */
    mbedtls_x509_buf serial;            /**< Unique id for certificate issued by a specific CA. */
}trusted_cert_id_t;

typedef struct trusted_psk_id_s
{
    mbedtls_x509_buf psk_hint;            /**< Unique id for certificate issued by a specific CA. */
    mbedtls_x509_buf psk_identity;        /**< The raw issuer data (DER). Used for quick comparison. */
}trusted_psk_id_t;

typedef union {
	trusted_cert_id_t cert_id;
	trusted_psk_id_t psk_id;
}key_param_t;
typedef enum
{
	KEY_TYPE_CERT,
	KEY_TYPE_PSK,
}key_type_t;

typedef union
{
	unsigned int keyhandle;
	trusted_cert_id_t cert_id;
	trusted_psk_id_t psk_id;
}trusted_keystore_query_param_t;
typedef struct trusted_keystore_query_s
{
	trusted_keystore_query_type_t type;
	trusted_keystore_query_param_t param;	
}trusted_keystore_query_t;

typedef struct trusted_keystore_param_s
{
	key_type_t keytype;			/**< Key Type */
    unsigned int keyhandle;			/**< HSE-NVM Key Handle */
	unsigned int key_flags;
	key_param_t key_param;
}trusted_keystore_param_t;

typedef enum
{
	TRUSTED_KEYSTR_ERR_SUCCESS,
	TRUSTED_KEYSTR_ERR_NOT_SUPPORTED = -1,
	TRUSTED_KEYSTR_ERR_KEYSTORE_NOT_INITIALIZED = -2,
	TRUSTED_KEYSTR_ERR_IMPORT_FAILED = -4,
	TRUSTED_KEYSTR_ERR_INVALID_PARAM = -7,
	TRUSTED_KEYSTR_ERR_MEMALLOC_FAILED = -8,
	TRUSTED_KEYSTR_ERR_INSTALL_FAILED = -10,
}TrustedKeyStoreErrCodeT;

/*==================================================================================================
                                 GLOBAL VARIABLE DECLARATIONS
==================================================================================================*/

/*==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================*/

extern void TrustedKeystoreMgmt_Init(void);
extern void TrustedKeystoreMgmt_Free(void);

extern unsigned int TrustedKeystoreMgmt_GetFileSize(void);

extern TrustedKeyStoreErrCodeT TrustedKeyStore_AddKeyStoreElement(const trusted_keystore_param_t *param);
extern TrustedKeyStoreErrCodeT TrustedKeyStore_RemoveKeyStoreElement(
		const trusted_keystore_query_t *query);
extern void* TrustedKeystoreMgmt_ExportStore(void);
extern TrustedKeyStoreErrCodeT TrustedKeystoreMgmt_ImportStore(const trusted_keyfile_t *keyfile);
extern unsigned int TrustedKeyStoreMgmt_GetKeyHandle(const trusted_keystore_query_t *query);
extern TrustedKeyStoreErrCodeT TrustedKeyStoreMgmt_GetPskIdentity(
		const trusted_keystore_query_t *query,
		unsigned char **buff,
		unsigned int *len);
#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_USE_NXP_HSE_TRUSTED_KEYSTORE */
#endif /* #ifndef TRUSTEDKEYSTORE_INTERFACE_H */
