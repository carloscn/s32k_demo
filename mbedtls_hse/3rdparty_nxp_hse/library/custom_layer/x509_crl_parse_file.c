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

#if !defined (MBEDTLS_FS_IO)
#include "pk_load_file.h"
#include "x509_crl_parse_file.h"

/*==================================================================================================
*                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
==================================================================================================*/

/*==================================================================================================
*                                       LOCAL MACROS
==================================================================================================*/

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

/*************************************************************************************************
* Description: Load one or more CRLs and add them to the chained list
************************************************************************************************/
int nxp_hse_x509_crl_parse_file( mbedtls_x509_crl *chain, const char *path )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n = 0U;
    unsigned char *buf = NULL;

    /* Load certificate */
    if( ( ret = nxp_hse_pk_load_file( path, &buf, &n ) ) != 0 )
    	goto exit;

    /* Parse the CRL file */
    ret = mbedtls_x509_crl_parse( chain, buf, n );

exit:
	/* Zeroize the buf data */
    mbedtls_platform_zeroize( buf, n );

    /* Free allocated memory */
    mbedtls_free( buf );

    return( ret );
}

#endif /* MBEDTLS_FS_IO */

