/*==================================================================================================
*
*   (c) Copyright 2022 NXP.
*
*   This software is owned or controlled by NXP and may only be used strictly in accordance with
*   the applicable license terms. By expressly accepting such terms or by downloading, installing,
*   activating and/or otherwise using the software, you are agreeing that you have read, and that
*   you agree to comply with and are bound by, such license terms. If you do not agree to
*   be bound by the applicable license terms, then you may not retain, install, activate or
*   otherwise use the software.
==================================================================================================*/

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/

#include <string.h>
#include "mbedtls/platform.h"
#include "trustedkeystore_internal.h"
#include "trustedkeystore_interface.h"

/*==================================================================================================
*                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL MACROS
==================================================================================================*/

#if defined(MBEDTLS_USE_NXP_HSE_TRUSTED_KEYSTORE)

#define GET_TAG(data)	((data)[0])
#define SET_TAG(val, data)	(*data++ = (val) & 0xff)
#define GET_LENGTH(data) 		\
		(((data)[0]<<24)|((data)[1]<<16)|((data)[2]<<8)|((data)[3]))
#define SET_LENGTH(val,data)	\
{								\
	*data++ = (((val) >> 24) & 0xFFU);\
	*data++ = (((val) >> 16) & 0xFFU);\
	*data++ = (((val) >> 8) & 0xFFU);\
	*data++ = ((val) & 0xFFU);\
}

#define INT_CPU_TO_BE(val)	\
	(										\
		(((val) >> 24) & 0x000000FFU)	|	\
		(((val) >>  8) & 0x0000FF00U)	|	\
		(((val) <<  8) & 0x00FF0000U)	|	\
		(((val) << 24) & 0xFF000000U)		\
	)
#define INT_BE_TO_CPU(val)	INT_CPU_TO_BE(val)

#define TRUSTED_FILE_CERT_ELEM_MIN_SIZE 	(2*(sizeof(unsigned char)+sizeof(unsigned int)))
#define TRUSTED_FILE_PSK_ELEM_MIN_SIZE 	(2*(sizeof(unsigned char)+sizeof(unsigned int)))
#define TRUSTED_FILE_KEYSTORE_ELEMENT_MIN_SIZE	(sizeof(unsigned char)+3*sizeof(unsigned int))
#define TRUSTED_FILE_HEADER_MIN_SIZE	\
	(3*sizeof(unsigned int) + TRUSTED_KEYFILE_STR_SIZE + TRUSTED_KEYFILE_MAC_SIZE)

/*==================================================================================================
*                                      LOCAL CONSTANTS
==================================================================================================*/

/*==================================================================================================
*                                      LOCAL VARIABLES
==================================================================================================*/

static trusted_keystore_t gTrustedKeyStore;

/*==================================================================================================
*                                      GLOBAL CONSTANTS
==================================================================================================*/

/*==================================================================================================
*                                      GLOBAL VARIABLES
==================================================================================================*/

/*==================================================================================================
*                                   LOCAL FUNCTION PROTOTYPES
==================================================================================================*/
static trusted_keystore_element_t * AllocateKeyStoreFileElement(
	const trusted_keyfile_element_t *file_elem);
static void FreeKeyStoreElement(trusted_keystore_element_t *element);
static unsigned int GetKeystoreElementSize(
	const trusted_keystore_element_t *pelem);
static trusted_keystore_element_t* GetKeystoreElement(	
	const trusted_keystore_query_type_t search_type, 
	const trusted_keystore_query_param_t *param);
static unsigned int ExportKeyStoreElement(
	trusted_keystore_element_t *ptrusted_element, 
	trusted_keyfile_element_t *pkeyfile);
static trusted_keystore_element_t * AllocateKeyStoreElement(
	const trusted_keystore_param_t *param);


static TrustedKeyStoreErrCodeT AddFileCertElement(
	trusted_cert_id_t *cert_id, unsigned char *data);
static void FreeCertElement(trusted_cert_id_t *cert_id);
static unsigned int ExportCertParam(
	const trusted_cert_id_t *pcert_id, unsigned char *pdata);
static unsigned int GetCertElementSize(const trusted_cert_id_t *pcert_id);
static unsigned int GetCertElementByType(
	const trusted_keystore_query_type_t type,
	const trusted_cert_id_t *pstore, 
	const trusted_cert_id_t *param);
static TrustedKeyStoreErrCodeT AddCertElement(trusted_cert_id_t *pcert_id, 
	const trusted_cert_id_t* param);

static TrustedKeyStoreErrCodeT AddFilePskElement(
	trusted_psk_id_t *psk_id, unsigned char *data);
static void FreePskElement(trusted_psk_id_t *ppsk_id);
static unsigned int ExportPskParam(
	const trusted_psk_id_t *ppsk_id, 
	unsigned char *pdata);
unsigned int GetPskElementSize(const trusted_psk_id_t *ppsk_id);
static unsigned int GetPskElementByType(
	const trusted_keystore_query_type_t type,
	const trusted_psk_id_t *pstore, 
	const trusted_psk_id_t *param);
static TrustedKeyStoreErrCodeT AddPskElement(trusted_psk_id_t *ppsk_id, 
	const trusted_psk_id_t* param);

static TrustedKeyStoreErrCodeT GenerateKeyFileMac(trusted_keyfile_t *pkeyfile);
static TrustedKeyStoreErrCodeT VerifyKeyFileMac(const trusted_keyfile_t *pkeyfile);

static TrustedKeyStoreErrCodeT ImportFileElement(
	const trusted_keyfile_element_t *file_elem);

static void AddElementToList(trusted_keystore_element_t *element);
static void RemoveElementFromList(trusted_keystore_element_t *element);

/*==================================================================================================
*                                       LOCAL FUNCTIONS
==================================================================================================*/

static trusted_keystore_element_t * AllocateKeyStoreFileElement(
	const trusted_keyfile_element_t *file_elem)
{
	trusted_keystore_element_t *element = NULL;
	TrustedKeyStoreErrCodeT err = TRUSTED_KEYSTR_ERR_MEMALLOC_FAILED;
 	element = (trusted_keystore_element_t *)mbedtls_calloc(1, \
		sizeof(trusted_keystore_element_t));

	if(NULL == element)
	{
		return element;
	}

	/* Fill Structure Parameters */
	element->next = NULL;
	element->prev = NULL;
	element->keytype = file_elem->type;
	element->keyhandle = INT_BE_TO_CPU(file_elem->keyhandle);
	element->key_flags = INT_BE_TO_CPU(file_elem->flag);

	switch(file_elem->type)
	{
		case KEY_TYPE_CERT:
			err = AddFileCertElement(&element->key_param.cert_id, (unsigned char*)file_elem->data);
			break;
		case KEY_TYPE_PSK:
			err = AddFilePskElement(&element->key_param.psk_id, (unsigned char*)file_elem->data);
			break;
		default:
			break;
	}

	if(err != TRUSTED_KEYSTR_ERR_SUCCESS)
	{
		FreeKeyStoreElement(element);
		return NULL;
	}
	return (element); 
}
static trusted_keystore_element_t * AllocateKeyStoreElement(
	const trusted_keystore_param_t *param)
{
	trusted_keystore_element_t *element = NULL;
	TrustedKeyStoreErrCodeT err = TRUSTED_KEYSTR_ERR_MEMALLOC_FAILED;
 	element = (trusted_keystore_element_t *)mbedtls_calloc(1, \
		sizeof(trusted_keystore_element_t));

	if(NULL == element)
	{
		return element;
	}

	/* Fill Structure Parameters */
	element->next = NULL;
	element->prev = NULL;
	element->keyhandle =(param->keyhandle);
	element->keytype = (param->keytype);
	element->key_flags = (param->key_flags);

	
	switch(param->keytype)
	{
		case KEY_TYPE_CERT:
			err = AddCertElement(&element->key_param.cert_id, &param->key_param.cert_id);
			break;
		case KEY_TYPE_PSK:
			err = AddPskElement(&element->key_param.psk_id, &param->key_param.psk_id);
			break;
		default:
			break;
	}

	if(err != TRUSTED_KEYSTR_ERR_SUCCESS)
	{
		FreeKeyStoreElement(element);
		return NULL;
	}
	return (element); 
}

static void FreeKeyStoreElement(trusted_keystore_element_t *element)
{
	if(element == NULL)
	{
		/* Return when element is null */
		return;
	}
	if(element->keytype == KEY_TYPE_CERT)
	{
		/* Free Certificate Element */
		FreeCertElement(&element->key_param.cert_id);
	}
	else
	{
		/* Free PSK Element */
		FreePskElement(&element->key_param.psk_id);
	}
	/* Zeroize element */
	memset(element, 0, sizeof(trusted_keystore_element_t));
	/* Free Element */
	mbedtls_free(element);
	return;
}

static unsigned int GetKeystoreElementSize(const trusted_keystore_element_t *pelem)
{
	unsigned int elem_size = TRUSTED_FILE_KEYSTORE_ELEMENT_MIN_SIZE;
	switch(pelem->keytype)
	{
		case KEY_TYPE_CERT:
			elem_size += GetCertElementSize(&pelem->key_param.cert_id);
			break;
		case KEY_TYPE_PSK:
			elem_size += GetPskElementSize(&pelem->key_param.psk_id);
			break;
	}
	return elem_size;
}

static TrustedKeyStoreErrCodeT AddFileCertElement(trusted_cert_id_t *cert_id, unsigned char *data)
{
	unsigned char *p = data;
	mbedtls_x509_buf *temp = &cert_id->issuer_raw;

	/* Copy Issuer Data */
	temp->tag = GET_TAG(p);
	p += sizeof(unsigned char);
	temp->len = GET_LENGTH(p);
	p += sizeof(size_t);
	if(0 != temp->len)
	{
		temp->p = (unsigned char *)mbedtls_calloc(1, temp->len );
		if(temp->p == NULL)
		{
			return TRUSTED_KEYSTR_ERR_MEMALLOC_FAILED;
		}
		memcpy(temp->p, p, temp->len);
		p += temp->len;
	}
	/* Copy Serial Number Data */
	temp = &cert_id->serial;
	temp->tag = GET_TAG(p);
	p += sizeof(unsigned char);
	temp->len = GET_LENGTH(p);
	p += sizeof(size_t);
	if(0 != temp->len)
	{
		temp->p = (unsigned char *)mbedtls_calloc(1, temp->len );
		if(temp->p == NULL)
		{
			/* Free-up will be called from upper layer nothing to be done from here */
			return TRUSTED_KEYSTR_ERR_MEMALLOC_FAILED;
		}
		memcpy(temp->p, p, temp->len);
	}
	return TRUSTED_KEYSTR_ERR_SUCCESS;	
}

static TrustedKeyStoreErrCodeT AddCertElement(trusted_cert_id_t *pcert_id, const trusted_cert_id_t* param)
{
	mbedtls_x509_buf *temp = &pcert_id->issuer_raw;

	/* Copy Issuer Data */
	temp->tag = param->issuer_raw.tag;
	temp->len = param->issuer_raw.len;
	if(0 != temp->len)
	{
		temp->p = (unsigned char *)mbedtls_calloc(1, temp->len );
		if(temp->p == NULL)
		{
			return TRUSTED_KEYSTR_ERR_MEMALLOC_FAILED;
		}
		memcpy(temp->p, param->issuer_raw.p, temp->len);
	}
	/* Copy Serial Number Data */
	temp = &pcert_id->serial;
	temp->tag = param->serial.tag;
	temp->len = param->serial.len;
	if(0 != temp->len)
	{
		temp->p = (unsigned char *)mbedtls_calloc(1, temp->len );
		if(temp->p == NULL)
		{
			/* Free-up will be called from upper layer nothing to be done from here */
			return TRUSTED_KEYSTR_ERR_MEMALLOC_FAILED;
		}
		memcpy(temp->p, param->serial.p, temp->len);
	}
	return TRUSTED_KEYSTR_ERR_SUCCESS;
}

static void FreeCertElement(trusted_cert_id_t *cert_id)
{
	if(cert_id == NULL)
	{
		return;
	}
	if(cert_id->issuer_raw.p != NULL)
	{
		mbedtls_free(cert_id->issuer_raw.p);
		cert_id->issuer_raw.p = NULL;
	}
	if(cert_id->serial.p != NULL)
	{
		mbedtls_free(cert_id->serial.p);
		cert_id->serial.p = NULL;
	}
	return;
}

static unsigned int ExportKeyStoreElement(
	trusted_keystore_element_t *ptrusted_element, 
	trusted_keyfile_element_t *pkeyfile)
{
	trusted_keyfile_element_t *pkeyfile_element = pkeyfile;
	unsigned int element_size = TRUSTED_FILE_KEYSTORE_ELEMENT_MIN_SIZE;
	pkeyfile_element->keyhandle = INT_CPU_TO_BE(ptrusted_element->keyhandle);
	pkeyfile_element->flag = INT_CPU_TO_BE(ptrusted_element->key_flags);		
	pkeyfile_element->type = (unsigned char)ptrusted_element->keytype;

	switch(ptrusted_element->keytype)
	{
		case KEY_TYPE_CERT:
			element_size += ExportCertParam(
				&ptrusted_element->key_param.cert_id, 
				&pkeyfile_element->data[0]);
			break;
		case KEY_TYPE_PSK:
			element_size += ExportPskParam(
				&ptrusted_element->key_param.psk_id, 
				&pkeyfile_element->data[0]);
			break;
	}

	pkeyfile->len = INT_CPU_TO_BE(element_size);

	return (element_size);
}

static unsigned int ExportCertParam(
	const trusted_cert_id_t *pcert_id, 
	unsigned char *pdata)
{
	unsigned char *p = pdata;

	/* Fill Issuer Data */
	SET_TAG(pcert_id->issuer_raw.tag, p);
	SET_LENGTH(pcert_id->issuer_raw.len, p);
	memcpy(p,pcert_id->issuer_raw.p,pcert_id->issuer_raw.len);
	p += pcert_id->issuer_raw.len;

	/* Fill Serial Data */
	SET_TAG(pcert_id->serial.tag, p);
	SET_LENGTH(pcert_id->serial.len, p);
	memcpy(p,pcert_id->serial.p,pcert_id->serial.len);
	p += pcert_id->serial.len;
	return ((unsigned int)p-(unsigned int)pdata);
}

static unsigned int GetCertElementSize(const trusted_cert_id_t *pcert_id)
{
	
	unsigned int element_size = TRUSTED_FILE_CERT_ELEM_MIN_SIZE;
	element_size += pcert_id->issuer_raw.len + pcert_id->serial.len;
	return element_size;
}

static TrustedKeyStoreErrCodeT AddFilePskElement(trusted_psk_id_t *ppsk_id, unsigned char *data)
{
	unsigned char *p = data;
	mbedtls_x509_buf *temp = &ppsk_id->psk_hint;

	/* Copy PSK Hint Data */
	temp->tag = GET_TAG(p);
	p += sizeof(unsigned char);
	temp->len = GET_LENGTH(p);
	p += sizeof(size_t);
	if(0 != temp->len)
	{
		temp->p = (unsigned char *)mbedtls_calloc(1, temp->len );
		if(temp->p == NULL)
		{
			return TRUSTED_KEYSTR_ERR_MEMALLOC_FAILED;
		}
		memcpy(temp->p, p, temp->len);
		p += temp->len;
	}
	/* Copy Serial Number Data */
	temp = &ppsk_id->psk_identity;
	temp->tag = GET_TAG(p);
	p += sizeof(unsigned char);
	temp->len = GET_LENGTH(p);
	p += sizeof(size_t);

	if(0 != temp->len)
	{
		temp->p = (unsigned char *)mbedtls_calloc(1, temp->len );
		if(temp->p == NULL)
		{
			/* Free-up will be called from upper layer nothing to be done from here */
			return TRUSTED_KEYSTR_ERR_MEMALLOC_FAILED;
		}
		memcpy(temp->p, p, temp->len);
	}
	return TRUSTED_KEYSTR_ERR_SUCCESS;
}

static TrustedKeyStoreErrCodeT AddPskElement(trusted_psk_id_t *ppsk_id, 
	const trusted_psk_id_t* param)
{
	mbedtls_x509_buf *temp = &ppsk_id->psk_hint;

	/* Copy PSK Hint Data */
	temp->tag = param->psk_hint.tag;
	temp->len = param->psk_hint.len;
	if(0 != temp->len)
	{
		temp->p = mbedtls_calloc(1, temp->len);
		if(temp->p == NULL)
		{
			return TRUSTED_KEYSTR_ERR_MEMALLOC_FAILED;
		}
		memcpy(temp->p, param->psk_hint.p, temp->len);
	}
	/* Copy Identity Data */
	temp = &ppsk_id->psk_identity;
	temp->tag = param->psk_identity.tag;
	temp->len = param->psk_identity.len;
	if(0 != temp->len)
	{
		temp->p = (unsigned char *)mbedtls_calloc(1, temp->len );
		if(temp->p == NULL)
		{
			/* Free-up will be called from upper layer nothing to be done from here */
			return TRUSTED_KEYSTR_ERR_MEMALLOC_FAILED;
		}
		memcpy(temp->p, param->psk_identity.p, temp->len);
	}
	return TRUSTED_KEYSTR_ERR_SUCCESS;
	
}

static void FreePskElement(trusted_psk_id_t *ppsk_id)
{
	if(ppsk_id == NULL)
	{
		return;
	}
	if(ppsk_id->psk_hint.p != NULL)
	{
		mbedtls_free(ppsk_id->psk_hint.p);
		ppsk_id->psk_hint.p = NULL;
	}
	if(ppsk_id->psk_identity.p != NULL)
	{
		mbedtls_free(ppsk_id->psk_identity.p);
		ppsk_id->psk_identity.p = NULL;
	}
	return;
}

static unsigned int ExportPskParam(const trusted_psk_id_t *ppsk_id, unsigned char *pdata)
{
	unsigned char *p = pdata;

	/* Fill Issuer Data */
	SET_TAG(ppsk_id->psk_hint.tag, p);
	SET_LENGTH(ppsk_id->psk_hint.len, p);
	memcpy(p,ppsk_id->psk_hint.p,ppsk_id->psk_hint.len);
	p += ppsk_id->psk_hint.len;

	/* Fill Serial Data */
	SET_TAG(ppsk_id->psk_identity.tag, p);
	SET_LENGTH(ppsk_id->psk_identity.len, p);
	memcpy(p,ppsk_id->psk_identity.p,ppsk_id->psk_identity.len);
	p += ppsk_id->psk_identity.len;
	return ((unsigned int)p-(unsigned int)pdata);
}

unsigned int GetPskElementSize(const trusted_psk_id_t *ppsk_id)
{
	unsigned int element_size = TRUSTED_FILE_PSK_ELEM_MIN_SIZE;
	element_size += ppsk_id->psk_hint.len + ppsk_id->psk_identity.len;
	return element_size;
}

static TrustedKeyStoreErrCodeT GenerateKeyFileMac(trusted_keyfile_t *pkeyfile)
{
	(void)pkeyfile;
	TrustedKeyStoreErrCodeT err = TRUSTED_KEYSTR_ERR_SUCCESS;
	return err;
}

static TrustedKeyStoreErrCodeT VerifyKeyFileMac(const trusted_keyfile_t *pkeyfile)
{
	(void)pkeyfile;
	TrustedKeyStoreErrCodeT err = TRUSTED_KEYSTR_ERR_SUCCESS;
	return err;
}


static TrustedKeyStoreErrCodeT ImportFileElement(const trusted_keyfile_element_t *file_elem)
{
	TrustedKeyStoreErrCodeT err = TRUSTED_KEYSTR_ERR_INVALID_PARAM;
	trusted_keystore_element_t *element;
	unsigned int size;

	if(NULL == file_elem)
	{
		return err;
	}
	
	if((file_elem->type != KEY_TYPE_CERT) && (file_elem->type != KEY_TYPE_PSK))
	{
		return TRUSTED_KEYSTR_ERR_INVALID_PARAM;
	}
	size = INT_CPU_TO_BE(file_elem->len);
	if(size < (TRUSTED_FILE_KEYSTORE_ELEMENT_MIN_SIZE+TRUSTED_FILE_CERT_ELEM_MIN_SIZE))
	{
		return TRUSTED_KEYSTR_ERR_INVALID_PARAM;
	}

	/* Prepare element to be added */
	element = AllocateKeyStoreFileElement(file_elem);

	if(element == NULL)
	{
		return TRUSTED_KEYSTR_ERR_MEMALLOC_FAILED;
	}
	
	/* Add Element to the end of list */
	AddElementToList(element);
	err = TRUSTED_KEYSTR_ERR_SUCCESS;
	return err;
}

static void RemoveElementFromList(trusted_keystore_element_t *element)
{
	if (element == gTrustedKeyStore.element_head)
	{
		/* First Element */
		gTrustedKeyStore.element_head = element->next;
		if(element == gTrustedKeyStore.element_tail)
		{
			/* Only Element in list */
			gTrustedKeyStore.element_tail = NULL;
		}
	}
	else if (element == gTrustedKeyStore.element_tail)
	{
		/* Last Element */
		gTrustedKeyStore.element_tail = element->prev;
		gTrustedKeyStore.element_tail->next = NULL;
	}
	else 
	{
		/* In the middle */
		element->prev->next = element->next;
		element->next->prev = element->prev;
	}
	gTrustedKeyStore.numkeys--;	
	return;
}

static void AddElementToList(trusted_keystore_element_t *element)
{
	/* Add Element to the end of list */
	if(gTrustedKeyStore.element_head == NULL)
	{
		/* Add to First element to Head and Tail */
		gTrustedKeyStore.element_head = element;
		gTrustedKeyStore.element_tail = element;
		element->next = NULL;
		element->prev = NULL;
	}
	else
	{
		/* Add to the tail */
		gTrustedKeyStore.element_tail->next = element;
		element->prev = gTrustedKeyStore.element_tail;
		element->next = NULL;
		gTrustedKeyStore.element_tail = element;
	}
	gTrustedKeyStore.numkeys++;	
	return;
}

static unsigned int GetCertElementByType(
	const trusted_keystore_query_type_t type,
	const trusted_cert_id_t *pstore, 
	const trusted_cert_id_t *param)
{
	unsigned int issuer_match = FALSE, serial_match = FALSE;

	(void)type;
	if ((pstore->issuer_raw.tag == param->issuer_raw.tag) &&	\
		(pstore->issuer_raw.len == param->issuer_raw.len) &&	\
		(memcmp(pstore->issuer_raw.p, param->issuer_raw.p, pstore->issuer_raw.len) == 0))
	{
		issuer_match = TRUE;
	}
	if ((pstore->serial.tag == param->serial.tag) &&	\
		(pstore->serial.len == param->serial.len) &&	\
		(memcmp(pstore->serial.p, param->serial.p, pstore->serial.len) == 0))
	{
		serial_match = TRUE;
	}

	return (serial_match && issuer_match);
}

static unsigned int GetPskElementByType(
	const trusted_keystore_query_type_t type,
	const trusted_psk_id_t *pstore, 
	const trusted_psk_id_t *param)
{
	unsigned int hint_match = FALSE, identity_match = FALSE;

	if ((type == SEARCH_TYPE_PSK_HINT) && \
		(pstore->psk_hint.tag == param->psk_hint.tag) &&	\
		(pstore->psk_hint.len == param->psk_hint.len) &&	\
		(memcmp(pstore->psk_hint.p, param->psk_hint.p, pstore->psk_hint.len) == 0))
	{
		hint_match = TRUE;
	}
	if ((type == SEARCH_TYPE_PSK_IDENTITY) && \
		(pstore->psk_identity.tag == param->psk_identity.tag) &&	\
		(pstore->psk_identity.len == param->psk_identity.len) &&	\
		(memcmp(pstore->psk_identity.p, param->psk_identity.p, pstore->psk_identity.len) == 0))
	{
		identity_match = TRUE;
	}

	return (hint_match || identity_match);
}

static trusted_keystore_element_t* GetKeystoreElement(	
	const trusted_keystore_query_type_t search_type, 
	const trusted_keystore_query_param_t *param)
{
	trusted_keystore_element_t *pelement = gTrustedKeyStore.element_head;

	while(pelement != NULL)
	{
		if ((search_type == SEARCH_TYPE_KEYHANDLE) && \
			(pelement->keyhandle == *(unsigned int*)param))
		{
			break;
		}
		else if((search_type == SEARCH_TYPE_CERT) && \
			(TRUE == GetCertElementByType(search_type, &pelement->key_param.cert_id, 
						(const trusted_cert_id_t *)param)))
		{
			break;
		} 
		else if((search_type == SEARCH_TYPE_PSK_HINT) && \
			(TRUE == GetPskElementByType(search_type, &pelement->key_param.psk_id, 
						(const trusted_psk_id_t *)param)))
		{
			break;
		} 
		else if((search_type == SEARCH_TYPE_PSK_IDENTITY) && \
			(TRUE == GetPskElementByType(search_type, &pelement->key_param.psk_id, 
						(const trusted_psk_id_t *)param)))
		{
			break;
		} 
		pelement = pelement->next;
	}
	return pelement;
}

/*==================================================================================================
*                                       GLOBAL FUNCTIONS
==================================================================================================*/
void TrustedKeystoreMgmt_Init(void)
{
	memset(&gTrustedKeyStore, 0, sizeof(gTrustedKeyStore));	
}
void TrustedKeystoreMgmt_Free(void)
{
	unsigned int numkeys = gTrustedKeyStore.numkeys;
	trusted_keystore_element_t *pelement = gTrustedKeyStore.element_tail;
	trusted_keystore_element_t *prev;
	while(numkeys && pelement)
	{
		prev = pelement->prev;
		FreeKeyStoreElement(pelement);
		pelement = prev;
		numkeys--;
	}
	memset(&gTrustedKeyStore, 0, sizeof(gTrustedKeyStore));
	return;
}

TrustedKeyStoreErrCodeT TrustedKeystoreMgmt_ImportStore(const trusted_keyfile_t *keyfile)
{
	TrustedKeyStoreErrCodeT err = TRUSTED_KEYSTR_ERR_SUCCESS;
	uint32_t numkeys;
	trusted_keyfile_element_t *file_elem;
	if(NULL == keyfile)
	{
		return TRUSTED_KEYSTR_ERR_INVALID_PARAM;
	}

	/* Verify File Header */
	if(INT_CPU_TO_BE(TRUSTED_KEYFILE_HEADER) != keyfile->hdr)
	{
		return TRUSTED_KEYSTR_ERR_INVALID_PARAM;
	}

	/* Verify File length for minimum size */
	if (INT_CPU_TO_BE(keyfile->len) < TRUSTED_FILE_HEADER_MIN_SIZE)
	{
		return TRUSTED_KEYSTR_ERR_INVALID_PARAM;		
	}

	/* Verify File String */
	if(memcmp(keyfile->filestr, TRUSTED_KEYFILE_STR, TRUSTED_KEYFILE_STR_SIZE)!= 0)
	{
		return TRUSTED_KEYSTR_ERR_INVALID_PARAM;
	}

	/* Verify MAC */
	if(TRUSTED_KEYSTR_ERR_SUCCESS != VerifyKeyFileMac(keyfile))
	{
		return TRUSTED_KEYSTR_ERR_INVALID_PARAM;
	}
	
	numkeys = INT_CPU_TO_BE(keyfile->numelem);
	file_elem = (trusted_keyfile_element_t *)keyfile->element;
	while(numkeys)
	{
	
		/* Allocate KeyStore Container */
		err = ImportFileElement(file_elem);
		if(err != TRUSTED_KEYSTR_ERR_SUCCESS)
		{
			break;
		}
		file_elem = (trusted_keyfile_element_t *)((unsigned char*)file_elem + INT_BE_TO_CPU(file_elem->len));
		numkeys--;
	}
	if(err != TRUSTED_KEYSTR_ERR_SUCCESS)
	{
		TrustedKeystoreMgmt_Free();
	}
	return err;
}

void* TrustedKeystoreMgmt_ExportStore(void)
{
	unsigned int filesize = TrustedKeystoreMgmt_GetFileSize();
	trusted_keyfile_t *pkeyfile;
	trusted_keyfile_element_t *pkeyfile_element;
	trusted_keystore_element_t *ptrusted_element;

	/* */
	pkeyfile = (trusted_keyfile_t *)mbedtls_calloc(1, filesize);
	if(NULL == pkeyfile)
	{
		return pkeyfile;
	}

	pkeyfile->hdr = INT_CPU_TO_BE(TRUSTED_KEYFILE_HEADER);
	pkeyfile->len = INT_CPU_TO_BE(filesize);
	memcpy(pkeyfile->filestr, TRUSTED_KEYFILE_STR, TRUSTED_KEYFILE_STR_SIZE);
	pkeyfile->numelem = INT_CPU_TO_BE(gTrustedKeyStore.numkeys);

	/* Fill data in the file */
	pkeyfile_element = &pkeyfile->element[0];
	ptrusted_element = gTrustedKeyStore.element_head;

	while(ptrusted_element != NULL)
	{
		unsigned int element_len;
		element_len = ExportKeyStoreElement(ptrusted_element, pkeyfile_element);
		pkeyfile_element = (trusted_keyfile_element_t *)((unsigned char*)pkeyfile_element + element_len);
		ptrusted_element = ptrusted_element->next;
	}

	if(TRUSTED_KEYSTR_ERR_SUCCESS != GenerateKeyFileMac(pkeyfile))
	{
		mbedtls_free(pkeyfile);
		pkeyfile = NULL;
	}
	return (pkeyfile);
}

unsigned int TrustedKeystoreMgmt_GetFileSize(void)
{
	unsigned int filesize = TRUSTED_FILE_HEADER_MIN_SIZE;
	trusted_keystore_element_t *pelem = gTrustedKeyStore.element_head;
	unsigned int numkeys = gTrustedKeyStore.numkeys;
	while(numkeys)
	{
		filesize += GetKeystoreElementSize(pelem);
		pelem = pelem->next;
		numkeys--;	
	}
	
	return filesize;
}

TrustedKeyStoreErrCodeT TrustedKeyStore_AddKeyStoreElement(const trusted_keystore_param_t *param)
{
	trusted_keystore_element_t *element;

	if(NULL == param)
	{
		return TRUSTED_KEYSTR_ERR_INVALID_PARAM;
	}
	switch(param->keytype)
	{
		case KEY_TYPE_CERT:
		case KEY_TYPE_PSK:
			break;
		default:
			return TRUSTED_KEYSTR_ERR_INVALID_PARAM;
	}
	element = AllocateKeyStoreElement(param);
	if(element == NULL)
	{
		return TRUSTED_KEYSTR_ERR_MEMALLOC_FAILED;
	}
	
	/* Add Element to the end of list */
	AddElementToList(element);				
	return TRUSTED_KEYSTR_ERR_SUCCESS;
}

TrustedKeyStoreErrCodeT TrustedKeyStore_RemoveKeyStoreElement(
	const trusted_keystore_query_t *query)
{
	trusted_keystore_element_t *ptrusted_elem = \
		(trusted_keystore_element_t *)NULL;
	if(NULL == query)
	{
		return TRUSTED_KEYSTR_ERR_INVALID_PARAM;
	}

	if(query->type >= SEARCH_TYPE_MAX)
	{
		return TRUSTED_KEYSTR_ERR_INVALID_PARAM;
	}
	
	ptrusted_elem = GetKeystoreElement(query->type, &query->param);

	RemoveElementFromList(ptrusted_elem);
	FreeKeyStoreElement(ptrusted_elem);
	return TRUSTED_KEYSTR_ERR_SUCCESS;
}

unsigned int TrustedKeyStoreMgmt_GetKeyHandle(
	const trusted_keystore_query_t *query)
{
	const trusted_keystore_element_t *ptrusted_elem = \
		(const trusted_keystore_element_t *)NULL;

	/* Check Input Parameters */
	if(NULL == query)
	{
		return (unsigned int)-1;
	}

	if(query->type >= SEARCH_TYPE_MAX)
	{
		return (unsigned int)-1;
	}
	
	/* Get Trusted Key Element */
	ptrusted_elem = GetKeystoreElement(query->type, &query->param);

	/* Return KeyHandle */
	return ptrusted_elem->keyhandle;
}

TrustedKeyStoreErrCodeT TrustedKeyStoreMgmt_GetPskIdentity(
	const trusted_keystore_query_t *query,
	unsigned char **buff,
	unsigned int *len)
{
	unsigned int id_length;
	const trusted_keystore_element_t *ptrusted_elem = \
		(const trusted_keystore_element_t *)NULL;

	/* Check Input Parameters */
	if((NULL == query) || (NULL == len) || (NULL == buff))
	{
		return TRUSTED_KEYSTR_ERR_INVALID_PARAM;
	}
	
	if(query->type != SEARCH_TYPE_PSK_HINT)
	{
		return TRUSTED_KEYSTR_ERR_INVALID_PARAM;
	}
	
	/* Get Trusted Key Element */
	ptrusted_elem = GetKeystoreElement(query->type, &query->param);

	if(NULL != ptrusted_elem)
	{
		id_length = ptrusted_elem->key_param.psk_id.psk_identity.len;
		*buff = mbedtls_calloc(1, id_length);
		if(NULL == *buff)
		{
			return TRUSTED_KEYSTR_ERR_MEMALLOC_FAILED;
		}
		memcpy(*buff, ptrusted_elem->key_param.psk_id.psk_identity.p, id_length);
		/* Update len parameter */
		*len = id_length;
	}
	/* Return PSK Identity */
	return TRUSTED_KEYSTR_ERR_SUCCESS;
}

#endif /* MBEDTLS_USE_NXP_HSE_TRUSTED_KEYSTORE */

