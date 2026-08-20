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

#ifndef NXP_HSE_PLATFORM_UTIL_H_
#define NXP_HSE_PLATFORM_UTIL_H_

#ifdef __cplusplus
extern "C"{
#endif

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

#include "mbedtls/platform_time.h"
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
#if defined(MBEDTLS_PLATFORM_MEMORY)
#if defined (NXP_HSE_MALLOC_DEBUG)
#define MAX_MALLOC_COUNT	300
#endif/*NXP_HSE_MALLOC_DEBUG*/
#endif/*MBEDTLS_PLATFORM_MEMORY*/
/*==================================================================================================
*                                             ENUMS
==================================================================================================*/

/*==================================================================================================
                                 STRUCTURES AND OTHER TYPEDEFS
==================================================================================================*/
#if !defined (RTC_ENABLED)
typedef uint16_t StbM_SynchronizedTimeBaseType ;
typedef uint8_t StbM_TimeBaseStatusType;

/* StbM_TimeStampType - Structure definition */
typedef struct
{
	StbM_TimeBaseStatusType timeBaseStatus;
	uint32_t nanoseconds;
	uint32_t seconds;
	uint16_t secondsHi;
}StbM_TimeStampType;

/* StbM_UserDataType - structure definition */
typedef struct
{
	uint8_t userDataLength;
	uint8_t userByte0;
	uint8_t userByte1;
	uint8_t userByte2;
}StbM_UserDataType;
#endif
/*==================================================================================================
                                 GLOBAL VARIABLE DECLARATIONS
==================================================================================================*/

/*==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================*/
#if defined(MBEDTLS_PLATFORM_TIME_ALT)
#if defined(MBEDTLS_HAVE_TIME_DATE) && defined(MBEDTLS_PLATFORM_GMTIME_R_ALT)

#if !defined (RTC_ENABLED)
Std_ReturnType StbM_GetCurrentTime(StbM_SynchronizedTimeBaseType timeBaseId, StbM_TimeStampType* timeStamp, StbM_UserDataType* userData);
#endif
/*!
 * @brief Get the date and time, converts into seconds and return.
 *
 * @param[in]    time  	Pointer to an object of mbedtls_time_t time where converted
 * 						date and time in seconds to be stored.
 *
 * @return		Date and time in seconds of mbedtls_time_t type.
 */
extern mbedtls_time_t nxp_hse_time(mbedtls_time_t* time );

#endif /* MBEDTLS_HAVE_TIME_DATE && MBEDTLS_PLATFORM_GMTIME_R_ALT */
#endif /* MBEDTLS_PLATFORM_TIME_ALT */

#if defined(MBEDTLS_PLATFORM_MEMORY)

/**
 * @brief				nxp_hse_calloc
 * @details				This function allocates memory of n elements of size bytes each
 * 				   		and returns a pointer to the allocated memory. The memory is
 * 				   		set to zero. If n or size is 0,then function returns either NULL.
 *
 * @param[in]			n
 * 						number of blocks to be allocated
 *
 * @param[in]			size
 * 						size of each block
 *
 * 	@return				return type		: void*
 *
 * 	@retval				Success			: stating address of memory allocated (HEAP)
 *
 * 	@retval				Failed			: NULL
 *
 */
extern void *nxp_hse_calloc( size_t n, size_t size );
extern void *nxp_hse_callocH( size_t n, size_t size );
extern void *nxp_hse_calloc_32BAligned( size_t n,size_t size );


/**
 * @brief				nxp_hse_free
 * @details				This function frees the memory space pointed to by ptr
 *
 * @param[in]			ptr
 * 						pointer to memory location to be free
 *
 * 	@return				return type		: void
 *
 */
extern void nxp_hse_free ( void * ptr );
extern void nxp_hse_freeH ( void * ptr );
#endif /* MBEDTLS_PLATFORM_MEMORY */

#if defined(MBEDTLS_PLATFORM_EXIT_ALT)

/**
 * @brief				nxp_hse_exit
 * @details				Print the exit status of API
 *
 * @param[in]			status
 * 						exit status of API
 *
 * 	@return				return type		: void
 *
 */
void nxp_hse_exit(int status);
#endif

#if defined (NXP_HSE_MALLOC_DEBUG) && defined(MBEDTLS_PLATFORM_MEMORY)
/**
 * @brief				nxp_hse_calloc_new
 * @details				Debug malloc which will allocate memory and print the additional info
 *
 * @param[in]			n
 * 						number of blocks to be allocated
 *
 * @param[in]			size
 * 						size of each block
 *
 * @param[in]			file_name
 * 						relative path of file where malloc is called
 *
 * @param[in]			line
 * 						line number where malloc is called
 *
 * 	@return				return type		: void*
 *
 * 	@retval				Success			: stating address of memory allocated (HEAP)
 *
 * 	@retval				Failed			: NULL
 *
 */
extern void* nxp_hse_calloc_new(size_t n, size_t size, char const *file_name, int line);

/**
 * @brief				nxp_hse_free_new
 * @details				Debug free which will deallocate memory and print the additional info
 *
 * @param[in]			ptr
 * 						pointer to memory location to be free
 *
 * @param[in]			file_name
 * 						relative path of file where malloc is called
 *
 * @param[in]			line
 * 						line number where malloc is called
 *
 * 	@return				return type		: void
 *
 */
extern void nxp_hse_free_new(void *ptr, char const *file_name, int line);

/**
 * @brief				nxp_hse_get_malloc_count
 * @details				get the number of time malloc is called
 *
 * 	@return				return type		: uint32_t
 *
 * 	@retval				Success			: number of time calloc count
 */
extern uint32_t nxp_hse_get_malloc_count(void);

/**
 * @brief				nxp_hse_get_malloc_data
 * @details				get the pointer to data structure which hold the memory allocated during heap
 *
 * 	@return				return type		: uint32_t
 *
 * 	@retval				Success			: number of time calloc count
 */
extern void * nxp_hse_get_malloc_data(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NXP_HSE_PLATFORM_UTIL_H_ */
