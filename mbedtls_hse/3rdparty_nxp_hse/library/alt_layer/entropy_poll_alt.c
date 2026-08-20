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

#include "entropy_poll_alt.h"

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
#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)
#if defined(MBEDTLS_USE_NXP_HSE_CRYPTO)
#if defined(MBEDTLS_RNG_DRG3)
/*************************************************************************************************
* Description:  RNG-DRG3 class random number generator.
************************************************************************************************/
int mbedtls_drg3_poll( void *data, unsigned char *output,
		size_t len, size_t *olen )
{
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;
	((void) data);

	if(NULL == olen)
	{
		return ( 0 );
	}

	srvResponse = HSE_RngDRG3((uint8_t*)output, (uint32_t) len);
	if( HSE_SRV_RSP_OK != srvResponse)
	{
		return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
	}

	/* Update Output Length */
	*olen = len;
	return ( 0 );
}
#endif /* MBEDTLS_RNG_DRG3 */

#if defined(MBEDTLS_RNG_DRG4)
/*************************************************************************************************
* Description:  RNG-DRG4 class random number generator.
************************************************************************************************/
int mbedtls_drg4_poll( void *data, unsigned char *output,
		size_t len, size_t *olen )
{
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;
	((void) data);

	if(NULL == olen)
	{
		return ( 0 );
	}

	srvResponse = HSE_RngDRG4((uint8_t*)output, (uint32_t) len);
	if( HSE_SRV_RSP_OK != srvResponse)
	{
		return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
	}

	/* Update Output Length */
	*olen = len;
	return ( 0 );
}
#endif /* MBEDTLS_RNG_DRG4 */

#if defined(MBEDTLS_RNG_PTG3)
/*************************************************************************************************
* Description:  RNG-PTG3 class random number generator.
************************************************************************************************/
int mbedtls_ptg3_poll( void *data, unsigned char *output,
		size_t len, size_t *olen )
{
	hseSrvResponse_t srvResponse = HSE_SRV_RSP_GENERAL_ERROR;
	((void) data);

	if(NULL == olen)
	{
		return ( 0 );
	}

	srvResponse = HSE_RngPTG3((uint8_t*)output, (uint32_t) len);
	if( HSE_SRV_RSP_OK != srvResponse)
	{
		return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
	}

	/* Update Output Length */
	*olen = len;
	return ( 0 );
}
#endif /* MBEDTLS_RNG_PTG3 */
#endif /* MBEDTLS_USE_NXP_HSE_CRYPTO */

/*************************************************************************************************
* Description:  Entropy poll callback for a hardware source
************************************************************************************************/
int mbedtls_hardware_poll( void *data, unsigned char *output,
		size_t len, size_t *olen )
{

#if defined(MBEDTLS_USE_NXP_HSE_CRYPTO)

#if defined(MBEDTLS_RNG_DRG3) && (MBEDTLS_USE_NXP_HSE_HW_ENTROPY_SRC == DRG3 )
	{
		return mbedtls_ptg3_poll(data, output, len, olen);
	}
#endif /* MBEDTLS_RNG_DRG3 */

#if defined(MBEDTLS_RNG_DRG4) && (MBEDTLS_USE_NXP_HSE_HW_ENTROPY_SRC == DRG4)
	{
		return mbedtls_drg4_poll(data, output, len, olen);
	}
#endif /* MBEDTLS_RNG_DRG4 */

#if defined(MBEDTLS_RNG_PTG3) && (MBEDTLS_USE_NXP_HSE_HW_ENTROPY_SRC == PTG3 )
	{
		return mbedtls_ptg3_poll(data, output, len, olen);
	}
#endif /* MBEDTLS_RNG_PTG3 */
#endif /* MBEDTLS_USE_NXP_HSE_CRYPTO */
}

#endif /* MBEDTLS_ENTROPY_HARDWARE_ALT */
