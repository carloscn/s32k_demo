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

#ifndef KEYSTORE_MGMT_H
#define KEYSTORE_MGMT_H

#ifdef __cplusplus
extern "C"{
#endif

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/

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

#define KEYLOADED_FLAG     		((uint32_t)(0x1UL<<31)) /**< Key Loaded Flag : To identify if the
																 key is already loaded or to be loaded */

#define INVALID_STREAM_ID	(hseStreamId_t)(-1)
#define INVALID_KEYHANDLE 	HSE_INVALID_KEY_HANDLE
#define INVALID_GRP_HANDLE	(hseEccCurveId_t)(-1)

/*==================================================================================================
*                                             ENUMS
==================================================================================================*/

/*==================================================================================================
                                 STRUCTURES AND OTHER TYPEDEFS
==================================================================================================*/

/**
 * \brief The Keystore configuration structure.
 */
#if defined(S32N55)
extern hseSheCatalogFormat_t mHseSheCatalogCfg;
typedef struct
{
	unsigned char mumask;							/* !< Specifies the MU Instance(s) for the key group */
	const hseStdKeyGroupCfgEntry_t* ram_key_catalog;	/* !< RAM key catalog configurations */
	const hseStdKeyGroupCfgEntry_t* nvm_key_catalog;	/* !< NVM key catalog configurations */
}keystore_config_t;
#else
typedef struct
{
	unsigned char mumask;							/* !< Specifies the MU Instance(s) for the key group */
	const hseKeyGroupCfgEntry_t* ram_key_catalog;	/* !< RAM key catalog configurations */
	const hseKeyGroupCfgEntry_t* nvm_key_catalog;	/* !< NVM key catalog configurations */

}keystore_config_t;
#endif
/**
 * \brief The Keystore supported error codes.
 */
typedef enum
{
	KEYMGMT_ERR_SUCCESS,						/**<  Keystore operation successfully executed with no error. */
	KEYMGMT_ERR_NOT_SUPPORTED = -1,				/**<  The operation or feature not supported. */
	KEYMGMT_ERR_KEYSTORE_NOT_INITIALIZED = -2,	/**<  Keystore is not initialized. */
	KEYMGMT_ERR_SLOT_NOT_FOUND = -3,			/**<  Key slot not found. */
	KEYMGMT_ERR_KEY_IMPORT_FAILED = -4,			/**<  Key import operation failed. */
	KEYMGMT_ERR_KEY_ERASE_FAIL = -5,			/**<  Key erase operation failed. */
	KEYMGMT_ERR_STREAM_BUSY = -6,				/**<  All Stream slots are busy */
	KEYMGMT_ERR_INVALID_PARAM = -7,				/**<  Keystore input parameters are invalid */
	KEYMGMT_ERR_MEMALLOC_FAILED = -8,			/**<  Memory allocation failed */
	KEYMGMT_ERR_KEY_GEN_FAILED = -9,			/**<  Key generation failed */
	KEYMGMT_ERR_INSTALL_FAILED = -10,			/**<  Install key catalog operation failed */
	KEYMGMT_ERR_KEY_IN_USE = -11,				/**<  Requested key is in use */
	KEYMGMT_ERR_KEY_INVALID_STATE = -12,		/**<  Invalid key state */
	KEYMGMT_ERR_INSUFFICIENT_PERM = -13,		/**<  Keystore operation failed due to insufficient permissions */
	KEYMGMT_ERR_KEY_WRITE_PROTECTED = -14,		/**<  The key is write protected and cannot change anymore */
	KEYMGMT_ERR_INVALID_STATE = -15,
	KEYMGMT_ERR_ALREADY_INITIALIZED = -16,		/**<  Keystore already initialized*/
}KeymgmtErrCodeT;
/**
 * \brief The user defined curve IDs .
// */
typedef enum
{
	SECP192R1,	/*!< 192-bit curve defined by FIPS 186-4 and SEC1. */
	SECP224R1,	/*!< 224-bit curve defined by FIPS 186-4 and SEC1. */
	SECP192K1,	/*!< 192-bit "Koblitz" curve */
	SECP224K1,	/*!< 224-bit "Koblitz" curve */
	SECP256K1,	/*!< 256-bit "Koblitz" curve */
}KeymgmtUserCurveIdT;

/**
 * \brief Symmetric key parameters structure.
 */
typedef struct symmetric_key_param_s
{
	 const uint8_t *key;
	 uint32_t  size;

} symmetric_key_param_t;

/**
 * \brief RSA public key parameters structure.
 */
typedef struct rsa_pubkey_param_s
{
	const uint8_t *N;
	uint32_t   size_N;
	const uint8_t *E;
	uint32_t  size_E;

} rsa_pubkey_param_t;

/**
 * \brief RSA key pair parameters structure.
 */
typedef struct rsa_keypair_param_s
{
	unsigned char const *N; uint32_t  N_len;
	unsigned char const *D; uint32_t  D_len;
	unsigned char const *E; uint32_t  E_len;

} rsa_keypair_param_t;

/**
 * \brief ECC public key parameters structure.
 */
typedef struct ecc_pubkey_param_s
{
	uint8_t eccCurveId;						/*!< Ecc Curve Id */
	const uint8_t *Q;
	uint32_t  size_Q;

} ecc_pubkey_param_t;

/**
 * \brief ECC key pair parameters structure.
 */
typedef struct ecc_keypair_param_s
{
	uint8_t eccCurveId;						/*!< Ecc Curve Id */
	const uint8_t *Q;
	uint32_t  size_Q;
	const uint8_t *D;
	uint32_t  size_D;

} ecc_keypair_param_t;

#ifdef HSE_SPT_CLASSIC_DH
/**
 * \brief DH public key parameters structure.
 */
typedef struct dh_public_param_s
{
	const uint8_t *pModulus;	/*!< DH Prime modulus */
	uint32_t  modulusLength;	/*!< DH Prime modulus length */
	const uint8_t *pPubKey;		/*!< DH Public Key */
	uint32_t  pubLen;			/*!< DH Public Key length */
}dh_public_param_t;

/**
 * \brief DH key pair parameters structure.
 */
typedef struct dh_keypair_param_s
{
	const uint8_t *pModulus;	/*!< DH Prime modulus */
	uint32_t  modulusLength;	/*!< DH Prime modulus length */
	const uint8_t *pPubKey;		/*!< DH Public Key */
	uint32_t  pubLen;			/*!< DH Public Key length */
	const uint8_t *pPrvKey;		/*!< DH Private Key */
	uint32_t  prvLen;			/*!< DH Private Key length */
}dh_keypair_param_t;
#endif /* HSE_SPT_CLASSIC_DH */

/**
 * \brief Key import parameters structure.
 */
typedef struct key_import_param_s
{
	hseKeyType_t key_type; 					/*!< symmetric/RSA-Public/ RSA-Private/ RSA-Pair/ ECC-Public/ ECC-Private/ ECC-Pair */
	hseKeyCatalogId_t key_catalog;
	hseKeyFlags_t key_flag;
	union {
		/* Symmetric Key import */
		symmetric_key_param_t sym_key_param;

		/* RSA Key import */
		rsa_pubkey_param_t rsa_pubkey_param;
		rsa_keypair_param_t rsa_keypair_param;

		/* ECC Key import */
		ecc_pubkey_param_t ecc_pubkey_param;
		ecc_keypair_param_t ecc_keypair_param;

#ifdef HSE_SPT_CLASSIC_DH
		/* DH Key Import */
		dh_public_param_t dh_public_param;
		dh_keypair_param_t dh_keypair_param;
#endif /* HSE_SPT_CLASSIC_DH */
	}key_param;

} key_import_param_t;

/**
 * \brief RSA key pair generation parameters structure.
 */
typedef struct
{
	uint32_t keybitlen;						/*!< Public Key Modulus size */
	uint32_t eLen;							/*!< Exponent length */
	const uint8_t *pE; 						/*!< Input Exponent Parameter */
	uint8_t *pN;							/*!< Optional Output Parameter */

}rsa_keypair_gen_param_t;

/**
 * \brief ECC key pair generation parameters structure.
 */
typedef struct
{
	uint32_t keybitlen;						/*!< Public Key Modulus size */
	hseEccCurveId_t eccCurveId;				/*!< Ecc Curve Id */
	uint8_t *pN;							/*!< Optional Output Parameter */

}ecc_keypair_gen_param_t;

/**
 * \brief Symmetric key generation parameters structure.
 */
typedef struct 
{
	uint32_t keybitlen;						/*!< Public Key Modulus size */

}sym_key_gen_param_t;

#ifdef HSE_SPT_TLS12_RSA_PRE_MASTER_SECRET_GEN
/**
 * \brief Shared secret key generation type.
 */
typedef enum
{
	KEYMGMT_SHARED_SEC_KEY_GEN_TYPE_RSA_PMS = 0x00
}shared_sec_type_t;

/**
 * \brief Shared secret key generation parameters structure.
 */
typedef struct
{
	shared_sec_type_t shared_sec_type;		/*!< Shared secret key type */
	uint32_t keybitlen;						/*!< Shared secret key size */
	union {
		/*!< RSA Pre-master secret generation */
		hseKeyGenTls12RsaPreMaster_t rsa_pms_gen_param;
	}pms_param;

}shared_sec_gen_param_t;
#endif /* HSE_SPT_TLS12_RSA_PRE_MASTER_SECRET_GEN */

#ifdef HSE_SPT_CLASSIC_DH_KEY_PAIR_GEN
/**
 * \brief DH key pair generation parameters structure.
 */
typedef struct
{

    uint32_t baseGLength;	/*!< The length of public base "g". */
    uint8_t  *pBaseG;		/*!< The base g as big-endian integer. */
    uint32_t modulusLength;	/*!< The length of modulus "p". */
    uint8_t  *pModulus;		/*!< The modulus p as big-endian integer. */
    uint8_t  *pPubKey;		/*!< The public Key. */

}dh_keypair_gen_param_t;
#endif /* HSE_SPT_CLASSIC_DH_KEY_PAIR_GEN */

/**
 * \brief Key generation parameters structure.
 */
typedef struct key_gen_param_s
{
	hseKeyCatalogId_t key_catalog;
	hseKeyType_t key_type;
	hseKeyFlags_t key_flag;
	union {
		/* Symmetric Key generate */
		sym_key_gen_param_t sym_key_gen_param;

		/* RSA Key pair generate */
		rsa_keypair_gen_param_t rsa_keypair_gen_param;

		/* ECC Key pair generate */
		ecc_keypair_gen_param_t ecc_keypair_gen_param;

#ifdef HSE_SPT_TLS12_RSA_PRE_MASTER_SECRET_GEN
		/* Generate RSA Pre-Master Secret */
		shared_sec_gen_param_t shared_sec_gen_param;
#endif /* HSE_SPT_TLS12_RSA_PRE_MASTER_SECRET_GEN */

		/* DH Key pair generate */
#ifdef HSE_SPT_CLASSIC_DH_KEY_PAIR_GEN
		dh_keypair_gen_param_t dh_keypair_gen_param;
#endif /* HSE_SPT_CLASSIC_DH_KEY_PAIR_GEN */
	}key_param;

}key_gen_param_t;

/**
 * \brief ECC User curve parameters structure.
 */
typedef struct
{
	uint16_t   pBitLen;
	uint16_t   nBitLen;
	uint8_t    eccCurveId;
    uint8_t    *pA;
    uint8_t    *pB;
    uint8_t    *pP;
    uint8_t    *pN;
    uint8_t    *pG;
}ecc_load_user_curve_param_t;

/**
 * \brief User defined curve structure.
 */
typedef struct
{
	ecc_load_user_curve_param_t  ecc_load_user_curve_param;
	hseEccCurveId_t hseEccCurveId;
	KeymgmtUserCurveIdT EccCurveId;
}load_ecc_group_param_t;
/*==================================================================================================
                                 GLOBAL VARIABLE DECLARATIONS
==================================================================================================*/

/*==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================*/

/*************************************************************************************************
* Description: Initialize KeyStore based upon user configuration.
************************************************************************************************/
KeymgmtErrCodeT KeystoreMgmt_Init(keystore_config_t *keystorecfg);

/*************************************************************************************************
* Description: Free all in use RAM keys
************************************************************************************************/
void KeystoreMgmt_Free(void);
/* Description: Formats key catalogs based upon user configuration
************************************************************************************************/
KeymgmtErrCodeT KeystoreMgmt_InstallKeyCatalog(keystore_config_t *keystorecfg);
/*************************************************************************************************
* Description: Allocates key slot as per the key type
************************************************************************************************/
KeymgmtErrCodeT KeystoreMgmt_FindAllocateSlot(key_import_param_t *key_import_param,
												hseKeyHandle_t *keyhandle);

/*************************************************************************************************
* Description: Allocates key slot if not allocated and import key to the slot
************************************************************************************************/
KeymgmtErrCodeT KeystoreMgmt_FindImportSlot(key_import_param_t *key_import_param,
												hseKeyHandle_t *keyhandle);

/*************************************************************************************************
* Description: Allocates memory upto maximum stream context  size
************************************************************************************************/
extern void* KeyStoreMgmt_AllocateStreamCtx(void);

/*************************************************************************************************
* Description: Imports an on-going stream context
************************************************************************************************/
extern KeymgmtErrCodeT KeyStoreMgmt_ImportStreamCtx(hseStreamId_t streamId,
														void* pstream_ctx);

/*************************************************************************************************
* Description: Exports an on-going stream context
************************************************************************************************/
extern KeymgmtErrCodeT KeyStoreMgmt_ExportStreamCtx(hseStreamId_t streamId,
														void* pstream_ctx);

/*************************************************************************************************
* Description: Finds if any stream slot is available
************************************************************************************************/
KeymgmtErrCodeT KeystoreMgmt_FindAllocateStreamSlot(hseStreamId_t *streamId);

/*************************************************************************************************
* Description: Free key as per its type
************************************************************************************************/
KeymgmtErrCodeT KeyStoreMgmt_FreeKey(hseKeyHandle_t keyhandle);

/*************************************************************************************************
* Description: Free stream slot as per stream status
************************************************************************************************/
KeymgmtErrCodeT KeystoreMgmt_FreeStreamSlot(hseStreamId_t streamId);

/*************************************************************************************************
* Description: Imports key to the key slot as per the key type
************************************************************************************************/
KeymgmtErrCodeT KeyStoreMgmt_ImportKey(hseKeyHandle_t keyhandle,
											key_import_param_t *key_import_param);

/*************************************************************************************************
* Description: Generates the key as per the key type
************************************************************************************************/
KeymgmtErrCodeT KeystoreMgmt_Genkey(hseKeyHandle_t keyhandle,
											key_gen_param_t *key_gen_param );

/*************************************************************************************************
* Description: Free NVM key from NVM keyslot
************************************************************************************************/
KeymgmtErrCodeT KeyStoreMgmt_EraseNvmKey(hseKeyHandle_t handle);

/*************************************************************************************************
* Description: Free all NVM keys from NVM keyslot
************************************************************************************************/
KeymgmtErrCodeT KeyStoreMgmt_EraseNvmKeyStore(void);

/*************************************************************************************************
* Description: Free all RAM keys from NVM keyslot
************************************************************************************************/
KeymgmtErrCodeT KeyStoreMgmt_EraseRamKeyStore(void);

/*************************************************************************************************
* Description: Checks if the key type allocated to the input keyhandle is valid
************************************************************************************************/
KeymgmtErrCodeT KeyStoreMgmt_CheckKey(const hseKeyHandle_t keyhandle);

/*************************************************************************************************
* Description: Returns the key type allocated to the input keyhandle
************************************************************************************************/
hseKeyType_t KeystoreMgmt_GetKeyType(const hseKeyHandle_t keyhandle);

/*************************************************************************************************
* Description: Returns the user defined curve ID
************************************************************************************************/
hseEccCurveId_t KeystoreMgmt_UserECCGroupGetHandle(load_ecc_group_param_t *EccUserCurve);

/*************************************************************************************************
* Description: Load the user defined curve on HSE
************************************************************************************************/
KeymgmtErrCodeT KeystoreMgmt_UserECCGroupAllocate(load_ecc_group_param_t group_param);

#ifdef __cplusplus
}
#endif

#endif /* #ifndef KEYSTORE_MGMT_H */
