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

/*==================================================================================================

*                                        INCLUDE FILES

* 1) system and project includes

* 2) needed interfaces from external units

* 3) internal and external interfaces from this unit

==================================================================================================*/

#include <stddef.h>

#include <string.h>

#include "Osif.h"

#include "mbedtls/platform_util.h"

#include "mbedtls/platform.h"

#include "mbedtls/threading.h"

#if defined(USING_OS_FREERTOS)

#include "FreeRTOS.h"

#include "task.h"

#endif /* USING_OS_FREERTOS */

#if defined(MBEDTLS_PLATFORM_TIME_ALT)

#if defined(MBEDTLS_HAVE_TIME_DATE) && defined(MBEDTLS_PLATFORM_GMTIME_R_ALT)

#if defined (RTC_ENABLED)

#include "Rtc_Ip.h"

#endif

#include "nxp_hse_platform_util.h"

/*==================================================================================================

*                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)

==================================================================================================*/

#if !defined(RTC_ENABLED)

typedef struct

{

    uint16                  year;      /**< @brief Year       */

    uint16                  month;     /**< @brief Month      */

    uint16                  day;       /**< @brief Day        */

    uint16                  hour;      /**< @brief Hour       */

    uint16                  minutes;   /**< @brief Minutes    */

    uint8                   seconds;   /**< @brief Seconds    */

} TimedateType;

#endif

/*==================================================================================================

*                                       LOCAL MACROS

==================================================================================================*/

#define     RTC_0_CH_0                 ((uint8)0x00U)

/*==================================================================================================

*                                      LOCAL CONSTANTS

==================================================================================================*/

#if !defined(RTC_ENABLED)

/** @brief  Table of month length (in days) for the Un-leap-year*/

static const uint8 ULY[] = {0U, 31U, 28U, 31U, 30U, 31U, 30U, 31U, 31U, 30U, 31U, 30U, 31U};

/** @brief Table of month length (in days) for the Leap-year*/

static const uint8 LY[] = {0U, 31U, 29U, 31U, 30U, 31U, 30U, 31U, 31U, 30U, 31U, 30U, 31U};

#endif

/*==================================================================================================

*                                      LOCAL VARIABLES

==================================================================================================*/

#if defined (NXP_HSE_MALLOC_DEBUG) && defined(MBEDTLS_PLATFORM_MEMORY)

static uint32_t malloc_count = 0;

static void *memTestArr[MAX_MALLOC_COUNT] = {0};
#else
static uint32_t malloc_count=0;
#endif


static uint32_t malloc_count_test = 0;

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

#if !defined(RTC_ENABLED)

static void ConvertSecondsToTimeDate(const uint32 *seconds, TimedateType * const timeDate)

{

	/* Declare the variables needed */

	uint8 index  = 0;

	boolean yearLeap = FALSE;

	uint32 numberOfDays = 0U;

	uint32 tempSeconds = 0U;

	uint16 daysInYear = 0U;

	/* Because the starting year(1970) is not leap, set the daysInYear

	 * variable with the number of the days in a normal year

	 */

	daysInYear = 365;

	/* Set the year to the beginning of the range */

	timeDate->year = 1970U;

	/* Get the number of days */

	numberOfDays = (*seconds) / 86400;

	/* Get the number of seconds remaining */

	tempSeconds = (*seconds) % 86400;

	/* Get the current hour */

	timeDate->hour        = (uint16)(tempSeconds / 3600);

	/* Get the remaining seconds */

	tempSeconds           = tempSeconds % 3600;

	/* Get the minutes */

	timeDate->minutes     = (uint16)(tempSeconds / 60);

	/* Get seconds */

	timeDate->seconds     = (uint8)(tempSeconds % 60);

	/* Get the current year */

	while (numberOfDays >= daysInYear)

	{

		/* Increment year if the number of days is greater than the ones in

		 * one year

		 */

		timeDate->year++;

		/* Subtract the number of the days */

		numberOfDays -= daysInYear;

		/* Check if the year is leap or unleap */

		if ((((timeDate->year % 4U) == 0U) && ((timeDate->year % 100U) != 0U)) || ((timeDate->year % 400U) == 0U))

		{

			/* Set the number of leap year to the current year number

			 * of days.

			 */

			yearLeap=TRUE;

			daysInYear = 366;

		}

		else

		{

			/* Set the number of non leap year to the current year number

			 * of days.

			 */

			yearLeap=FALSE;

			daysInYear = 365;

		}

	}

	/* Add the current day */

	numberOfDays += 1U;

	/* Get the month */

	for (index = 1U; index <= 12U; index++)

	{

		uint32 daysInCurrentMonth = ((yearLeap == TRUE) ? (uint32)LY[index] : (uint32)ULY[index]);

		if (numberOfDays <= daysInCurrentMonth)

		{

			timeDate->month = (uint16)index;

			break;

		}

		else

		{

			numberOfDays -= daysInCurrentMonth;

		}

	}

	/* Set the current day */

	timeDate->day = (uint16)numberOfDays;

	return;

}

__attribute__((weak)) Std_ReturnType StbM_GetCurrentTime(StbM_SynchronizedTimeBaseType timeBaseId, StbM_TimeStampType* timeStamp, StbM_UserDataType* userData)

{

	/*Fill in dummy data for prototype implementation*/

	//timeStamp->seconds=0x61D0343B;
	timeStamp->seconds=0x66BE464B;
	timeStamp->nanoseconds=0x0;

	timeStamp->secondsHi=0x0;

	userData->userByte0=0x0;

	userData->userByte1=0x0;

	userData->userByte2=0x0;

	userData->userDataLength=0x0;

	(void)timeBaseId;

	return 0;

}

#endif

/*==================================================================================================

*                                       GLOBAL FUNCTIONS

==================================================================================================*/

/*************************************************************************************************

* Description: Converts given time since epoch (a mbedtls_time_t value pointed

* 				to by time) into calendar time,  expressed in Coordinated

* 				Universal Time (UTC) and stored in user-provided storage buffer

************************************************************************************************/

struct tm *mbedtls_platform_gmtime_r( const mbedtls_time_t *tt,

                                      struct tm *tm_buf )

{

	uint32_t seconds;

#if defined (RTC_ENABLED)

	Rtc_Ip_TimedateType getTime;

#else

	TimedateType getTime;

	memset(&getTime, 0x00, sizeof(getTime));

#endif

	if(NULL == tt)

		return NULL;

	switch((sizeof(mbedtls_time_t)))

	{

		case sizeof(seconds):

		{

			seconds = *tt;

			break;

		}

		case sizeof(uint64_t):

		{

			seconds = (uint32_t)((uint64_t)(*tt) & ((uint32_t)(-1)));

			break;

		}

	}

#if defined (RTC_ENABLED)

	/* Convert Time in seconds to gmtime using RTC */

	Rtc_Ip_ConvertSecondsToTimeDate(&seconds, &getTime);

#else

	ConvertSecondsToTimeDate(&seconds,&getTime);

#endif

	if (NULL != tm_buf)

	{

		tm_buf->tm_year = getTime.year - 1900;

		tm_buf->tm_mon = getTime.month - 1;

		tm_buf->tm_mday = getTime.day;

		tm_buf->tm_hour = getTime.hour;

		tm_buf->tm_min = getTime.minutes;

		tm_buf->tm_sec = getTime.seconds;

	}

	return tm_buf ;

}

/*************************************************************************************************

* Description: Get the date and time, converts into seconds and return.

************************************************************************************************/

mbedtls_time_t nxp_hse_time(mbedtls_time_t* time )

{

	uint32_t seconds;

#if defined (RTC_ENABLED)

	Rtc_Ip_TimedateType getTime;

	Rtc_Ip_GetTimeDate(RTC_0_CH_0, &getTime);

	Rtc_Ip_ConvertTimeDateToSeconds(&getTime, &seconds);

#else

	StbM_SynchronizedTimeBaseType timeBaseId=0x0; /*Dummy data*/

	StbM_TimeStampType timeStamp;

	StbM_UserDataType userData;

	StbM_GetCurrentTime(timeBaseId,&timeStamp,&userData); /*function to return dummy seconds until STBm implementation is available*/

	seconds=timeStamp.seconds;

#endif

	if(time != NULL)

	{

		time = (mbedtls_time_t *)seconds;

	}

	return (mbedtls_time_t)seconds;

}

#endif /* MBEDTLS_HAVE_TIME_DATE && MBEDTLS_PLATFORM_GMTIME_R_ALT */

#endif /* MBEDTLS_PLATFORM_TIME_ALT */

#if defined(MBEDTLS_PLATFORM_MEMORY)

#if defined (NXP_HSE_MALLOC_DEBUG)

/*************************************************************************************************

* Description: Debug malloc which will allocate memory and print the additional info

************************************************************************************************/

void* nxp_hse_calloc_new(size_t n, size_t size, char const *file_name, int line)

{

	mbedtls_printf("Calloc: Calling :%s:%d\n", file_name, line);

	return nxp_hse_calloc(n, size);

}

#endif/*NXP_HSE_MALLOC_DEBUG*/

/*************************************************************************************************

* Description: This function allocates memory of n elements of size bytes each

* 				and returns a pointer to the allocated memory. The memory is

* 				set to zero. If n or size is 0,then function returns either NULL.

************************************************************************************************/

#if defined(D_CACHE_ENABLE_MBEDTLS) & !(defined(USING_OS_FREERTOS))

#define SIZE_OF_CIRCULAR_BUFF 		(100)

static uint32_t testArray[SIZE_OF_CIRCULAR_BUFF][2];

static uint8_t countVar=0;

void PushInCircBuff(uint32_t AlignedAddr , uint32_t origalAddr)

{

	testArray[countVar][0] = AlignedAddr;

	testArray[countVar][1] =  origalAddr;

	countVar++;

	if(countVar>=SIZE_OF_CIRCULAR_BUFF){

		countVar=0;

	}

}

uint32_t PopFromCircBuffer(uint32_t address)

{

	uint32_t retVal = address;

	uint8_t countVal;

	for(countVal = 0;countVal<SIZE_OF_CIRCULAR_BUFF;countVal++)

	{

		if(testArray[countVal][0] == address)

		{

			retVal = testArray[countVal][1];

			testArray[countVal][0] = 0;

			testArray[countVal][1] = 0;

			break;

		}

	}

	return retVal;

}

#endif

void *nxp_hse_calloc_32BAligned( size_t n,size_t size )

{

	size_t allocationSize;

	allocationSize = n*size+31;

	return (nxp_hse_calloc( allocationSize,1 ));

}


void *nxp_hse_callocH( size_t n, size_t size )

{

	char *p;


	/* If either is zero just return NULL */

	if (n == 0 || size == 0)

	{

		return NULL;

	}

	else

	{

#if defined(USING_OS_FREERTOS)

		p = pvPortMalloc( n * size );

#else

#if defined(D_CACHE_ENABLE_MBEDTLS) & !(defined(USING_OS_FREERTOS))

		p = malloc( (n * size) + 31);

		malloc_count++;

		// nishant : testing for D- CACHE ALIGNMENT OF 32 BYTES

			volatile uint32_t testVar = (uint32_t)p;

			if((testVar%32)!=0) // if unaligned

			{

				p = (p + (32 - (testVar%32))); // checking for alignment

				PushInCircBuff((uint32_t)p,testVar);

			}

			// nishant : testing ends

			malloc_count_test++;

#else

		p = malloc( (n * size));

#endif

#endif

		if(NULL != p)

		{

			memset(p, 0, n*size);

#if defined (NXP_HSE_MALLOC_DEBUG)

			malloc_count++;

			mbedtls_printf("Allocated: address allocated: 0x%02x\n", p);

			int i = 0;

			for(; i < MAX_MALLOC_COUNT; i++)

			{

				if(memTestArr[i] == NULL)

				{

					break;

				}

			}

			if(i != MAX_MALLOC_COUNT)

			{

				memTestArr[i] = p;

			}

#endif /*NXP_HSE_MALLOC_DEBUG*/

			return p;

		}

		else

		{

#if defined (NXP_HSE_MALLOC_DEBUG)

			mbedtls_printf("calloc: Memory not Allocated\n");

#endif/*NXP_HSE_MALLOC_DEBUG*/

			return NULL;

		}

	}

}

void *nxp_hse_calloc( size_t n, size_t size )

{

	char *p;


	/* If either is zero just return NULL */

	if (n == 0 || size == 0)

	{

		return NULL;

	}

	else

	{

#if defined(USING_OS_FREERTOS)

		p = pvPortMalloc( n * size );

#else

		p = malloc( (n * size));

#endif

		if(NULL != p)

		{

			memset(p, 0, n*size);

#if defined (NXP_HSE_MALLOC_DEBUG)

			malloc_count++;

			mbedtls_printf("Allocated: address allocated: 0x%02x\n", p);

			int i = 0;

			for(; i < MAX_MALLOC_COUNT; i++)

			{

				if(memTestArr[i] == NULL)

				{

					break;

				}

			}

			if(i != MAX_MALLOC_COUNT)

			{

				memTestArr[i] = p;

			}

#endif /*NXP_HSE_MALLOC_DEBUG*/

			return p;

		}

		else

		{

#if defined (NXP_HSE_MALLOC_DEBUG)

			mbedtls_printf("calloc: Memory not Allocated\n");

#endif/*NXP_HSE_MALLOC_DEBUG*/

			return NULL;

		}

	}

}


#if defined (NXP_HSE_MALLOC_DEBUG)

/*************************************************************************************************

* Description: Debug free which will deallocate memory and print the additional info

************************************************************************************************/

void nxp_hse_free_new(void *ptr, char const *file_name, int line)

{

	mbedtls_printf("Free: Calling :%s:%d\n", file_name, line);

	nxp_hse_free( ptr);

}

#endif/*NXP_HSE_MALLOC_DEBUG*/

/*************************************************************************************************

* Description: This function frees the memory space pointed to by ptr

************************************************************************************************/

void nxp_hse_freeH ( void * ptr )

{

	if(ptr == NULL)

		return;

#if defined (NXP_HSE_MALLOC_DEBUG)

	int i = 0;

	for(; i < MAX_MALLOC_COUNT; i++)

	{

		if(memTestArr[i] == ptr)

		{

			memTestArr[i] = NULL;

			break;

		}

	}

	if(i == MAX_MALLOC_COUNT)

	{

		mbedtls_printf("Free: Address Not found: 0x%02x\n", ptr);

	}

	else{

		mbedtls_printf("Free: Address deallocated: 0x%02x\n", ptr);

	}

	malloc_count--;

#endif/*NXP_HSE_MALLOC_DEBUG*/

#if defined(USING_OS_FREERTOS)

	vPortFree( ptr );

#else

#if defined(D_CACHE_ENABLE_MBEDTLS) & !(defined(USING_OS_FREERTOS))

	malloc_count_test--;

	malloc_count--;

	free(PopFromCircBuffer((uint32_t)ptr));

#else

	free(ptr);

#endif

	return;

#endif /* USING_OS_FREERTOS */

}

void nxp_hse_free ( void * ptr )

{

	if(ptr == NULL)

		return;

#if defined (NXP_HSE_MALLOC_DEBUG)

	int i = 0;

	for(; i < MAX_MALLOC_COUNT; i++)

	{

		if(memTestArr[i] == ptr)

		{

			memTestArr[i] = NULL;

			break;

		}

	}

	if(i == MAX_MALLOC_COUNT)

	{

		mbedtls_printf("Free: Address Not found: 0x%02x\n", ptr);

	}

	else{

		mbedtls_printf("Free: Address deallocated: 0x%02x\n", ptr);

	}

	malloc_count--;

#endif/*NXP_HSE_MALLOC_DEBUG*/

#if defined(USING_OS_FREERTOS)

	vPortFree( ptr );

#else

	free(ptr);

	return;

#endif /* USING_OS_FREERTOS */

}

#endif

#if defined (NXP_HSE_MALLOC_DEBUG)

/*************************************************************************************************

* Description: Get the number of time malloc is called

************************************************************************************************/

uint32_t nxp_hse_get_malloc_count(void)

{

	return malloc_count;

}

/*************************************************************************************************

* Description: Get the pointer to data structure which hold the memory allocated during heap

************************************************************************************************/

void * nxp_hse_get_malloc_data(void)

{

	return memTestArr;

}

#endif/*NXP_HSE_MALLOC_DEBUG*/

//#endif /* MBEDTLS_PLATFORM_MEMORY */

#if defined(MBEDTLS_PLATFORM_EXIT_ALT)

/*************************************************************************************************

* Description: print the exit status of API

************************************************************************************************/

void nxp_hse_exit(int status)

{

	int fail_status = 1;

	if(status == fail_status)

		mbedtls_printf("Failed\r\n");

	return;

}

#endif
