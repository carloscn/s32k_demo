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

/*==================================================================================================
*                                        INCLUDE FILES
* 1) system and project includes
* 2) needed interfaces from external units
* 3) internal and external interfaces from this unit
==================================================================================================*/

#include <string.h>
#include "mbedtls/error.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/platform.h"
#include "pk_load_file.h"
#include "cert_table.h"

/*==================================================================================================
*                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL MACROS
==================================================================================================*/

/* Parameter validation macros based on platform_util.h */
#define PK_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_PK_BAD_INPUT_DATA )
#define PK_VALIDATE( cond )        \
    MBEDTLS_INTERNAL_VALIDATE( cond )

/*==================================================================================================
*                                      LOCAL CONSTANTS
==================================================================================================*/

/*==================================================================================================
*                                      LOCAL VARIABLES
==================================================================================================*/

/*==================================================================================================
*                                      GLOBAL CONSTANTS
==================================================================================================*/

/*==================================================================================================
*                                      GLOBAL VARIABLES
==================================================================================================*/

/*==================================================================================================
*                                   LOCAL FUNCTION PROTOTYPES
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL FUNCTIONS
==================================================================================================*/

/*==================================================================================================
*                                       GLOBAL FUNCTIONS
==================================================================================================*/

#if !defined (MBEDTLS_FS_IO)

/*************************************************************************************************
* Description: Load data from file
************************************************************************************************/
int nxp_hse_pk_load_file( const char *path, unsigned char **buf, size_t *n )
{
    unsigned int size = 0U;
    int ret = 0;

    PK_VALIDATE_RET( path != NULL );
    PK_VALIDATE_RET( buf != NULL );
    PK_VALIDATE_RET( n != NULL );

    for(uint16_t i = 0; i < TOTAL_CERTS; i++)
    {
    	/* Find the required certificate from certificate table */
    	if(strcmp(path, gcerttable[i].filename) == 0)
    	{
    		/* Get the certificate starting address */
    		unsigned char *pCertBegin = gcerttable[i].X509certificate_start;

    		/* Find the certificate size */
    		size = gcerttable[i].X509certificate_end - gcerttable[i].X509certificate_start;

    		/* Allocate memory for the certificate to copy */
    		*buf = mbedtls_calloc(1, size + 1);
    		if(*buf != NULL)
    		{
    			/* Copy certificate to the out buffer */
        		memcpy(*buf, pCertBegin, size);
        		*n = (size_t)size;
    		}
    		else
    		{
    			/* Memory allocation failed */
    			 ret  =  MBEDTLS_ERR_PK_ALLOC_FAILED;
    			 goto exit;
    		}

    		ret = 0;
    		break;
    	}
    	else
    	{
    		/* Error if certificate not found */
    		 ret = MBEDTLS_ERR_PK_FILE_IO_ERROR;
    	}
    }

    /* Check for the certificate format */
    if( strstr( (const char *) *buf, "-----BEGIN " ) != NULL )
        ++*n;

exit:
    return( ret );
}

/*************************************************************************************************
* Description: Load and parse a private key
************************************************************************************************/
int nxp_hse_pk_parse_keyfile( mbedtls_pk_context *ctx,
                      const char *path, const char *pwd )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n = 0U;
    unsigned char *buf = NULL;

    PK_VALIDATE_RET( ctx != NULL );
    PK_VALIDATE_RET( path != NULL );

    /* Load certificate */
    if( ( ret = nxp_hse_pk_load_file( path, &buf, &n ) ) != 0 )
    	goto exit;

    /* Parse the key file */
    if( pwd == NULL )
        ret = mbedtls_pk_parse_key( ctx, buf, n, NULL, 0 );
    else
        ret = mbedtls_pk_parse_key( ctx, buf, n,
                (const unsigned char *) pwd, strlen( pwd ) );

exit:
    /* Zeroize the buf data */
    mbedtls_platform_zeroize( buf, n );

    /* Free allocated memory */
    mbedtls_free( buf );

    return( ret );
}

/*************************************************************************************************
* Description: Load and parse a public key
************************************************************************************************/
int nxp_hse_pk_parse_public_keyfile( mbedtls_pk_context *ctx, const char *path )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n = 0U;
    unsigned char *buf = NULL;

    PK_VALIDATE_RET( ctx != NULL );
    PK_VALIDATE_RET( path != NULL );

    /* Load certificate */
    if( ( ret = nxp_hse_pk_load_file( path, &buf, &n ) ) != 0 )
    	goto exit;

    /* Parse the Public key file */
    ret = mbedtls_pk_parse_public_key( ctx, buf, n );

exit:
    /* Zeroize the buf data */
    mbedtls_platform_zeroize( buf, n );

    /* Free allocated memory */
    mbedtls_free( buf );

    return( ret );
}

#endif /* MBEDTLS_FS_IO */
