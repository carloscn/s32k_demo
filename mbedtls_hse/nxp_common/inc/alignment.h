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
#ifndef ALIGNMENT_H_
#define ALIGNMENT_H_

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
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif /*MBEDTLS_CONFIG_FILE*/
#include "nxp_hse_lwipconfig.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "global_defs.h"
#include "mbedtls/error.h"
#include "mbedtls/platform_util.h"
#include "nxp_hse_platform_util.h"

#if defined (MBEDTLS_USE_NXP_HSE_CRYTPO)
#include "std_typedefs.h"
#endif
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc     calloc
#define mbedtls_free       free
#endif /* MBEDTLS_PLATFORM_C */

#if defined (D_CACHE_ENABLE_MBEDTLS)

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

#define FRONT		0						/* !< Front buffer index for SGT table */
#define MID			1						/* !< Middle buffer index for SGT table */
#define REAR		2						/* !< Rear buffer index for SGT table */

#define NO_BUFF_ALLOC		0x00			/* !< No buffer allocated */
#define FRONT_BUFF_ALLOC	0x01			/* !< Only Front buffer allocated */
#define MID_BUFF_ALLOC		0x02			/* !< Only Mid buffer allocated */
#define REAR_BUFF_ALLOC		0x04			/* !< Only Rear buffer allocated */

#define SGT_SET_FINAL_BIT_MASK              (0x40000000UL)	/* Set the 30th bit of data buffer len */

/** @brief Host address to pointer */
#ifndef NXP_HSE_HOST_ADDR_TO_PTR
#define NXP_HSE_HOST_ADDR_TO_PTR(ptr)   ((uint8_t *)(uintptr_t)(ptr))
#endif

/*==================================================================================================
*                                             ENUMS
==================================================================================================*/



typedef enum hseSrvSGTBuffAlocFlag{
	SGT_NO_BUFF_ALLOC 				= 0x00,		/* !< No SGT buffer allocated */
	SGT_FRONT_BUFF_ALLOC 			= 0x01,		/* !< Only Front SGT buffer allocated */
	SGT_MID_BUFF_ALLOC 				= 0x02,		/* !< Only Mid SGT buffer allocated */
	SGT_FRONT_MID_BUFF_ALLOC 		= 0x03,		/* !< Front and Mid SGT buffers allocated */
	SGT_REAR_BUFF_ALLOC 			= 0x04,		/* !< Only Rear SGT buffer allocated */
	SGT_FRONT_REAR_BUFF_ALLOC 		= 0x05,		/* !< Front and Rear SGT buffers allocated */
	SGT_MID_REAR_BUFF_ALLOC 		= 0x06,		/* !< Mid and Rear SGT buffers allocated */
	SGT_FRONT_MID_REAR_BUFF_ALLOC				/* !< Front, Mid and Rear SGT buffers allocated */
}hseSrvSGTBuffAlocFlag_t;

/*==================================================================================================
                                 STRUCTURES AND OTHER TYPEDEFS
==================================================================================================*/
typedef struct{
	hseScatterList_t hseSrvSgtList[3] __attribute__((aligned (32)));	/* !< SGT list array */
	uint8_t buffAllocFlag ;												/* !< Buffer allocation flag */
}hseSrvSGTNode_t;

/*==================================================================================================
                                 GLOBAL VARIABLE DECLARATIONS
==================================================================================================*/

/*==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================*/

/*!
 * @brief Check if alignment is required.
 *
 * This function checks if input/output buffer requires cache alignment.
 * It will called when scatter-gather table needs to be create for the
 * buffer.
 *
 * @param[in]	dataAddr 		Pointer to the data buffer (input/output).
 *
 * @param[in]	inDataLen		data buffer length
 *
 * @param[in]	alignmentSize	Cache bus line size.
 *
 * @param[out]	sgtTable		Pointer to the scatter-gather table of
 * 								hseSrvSGTNode_t type.
 *
 * @return 		uint8_t 		#NO_BUFF_ALLOC in case no cache aligned
 * 								buffer is required to allocate
 */
uint8_t checkAlignmentReq(const uint8_t *dataAddr, uint32_t inDataLen, uint8_t alignmentSize, hseSrvSGTNode_t *sgtTable );

/*!
 * @brief Align input data buffer
 *
 * This function creates scatter-gather table based on sgtTable->buffAllocFlag
 * flag for input data buffer in case of input data buffer is not cache aligned.
 * It allocates cache aligned memory, copy input data buffer to SGT table and
 * do input buffer cache operation on it.
 *
 * @param[in]		inDataAddr	Pointer to the data buffer.
 *
 * @param[in-out]	sgtTable	Pointer to the scatter-gather table of
 * 								hseSrvSGTNode_t type.
 *
 * @return 			void
 */
void alignInBuff(uint8_t *inDataAddr, hseSrvSGTNode_t *sgtTable);

/*!
 * @brief Align output data buffer
 *
 * This function creates scatter-gather table based on sgtTable->buffAllocFlag
 * flag for output data buffer in case of output data buffer is not cache aligned.
 * It allocates cache aligned memory and do output buffer cache operation on it.
 *
 * @param[in]		outDataAddr	Pointer to the data buffer.
 *
 * @param[in-out]	sgtTable	Pointer to the scatter-gather table of
 * 								hseSrvSGTNode_t type.
 *
 * @return 			void
 */
void alignOutBuff(uint8_t *outDataAddr, hseSrvSGTNode_t *sgtTable );

/*!
 * @brief Store input/output buffer to SGT table
 *
 * This function stores the inpt/output data buffer and its length
 * to SGt table when buffer is cache aligned.
 *
 * @param[in]	dataAddr	Pointer to the input/output data buffer.
 *
 * @param[out]	sgtTable	Pointer to the scatter-gather table of
 * 							hseSrvSGTNode_t type.
 *
 * @return 			void
 */
void storeAlignBufptr( uint8_t *dataAddr, uint32_t dataLen, hseSrvSGTNode_t *sgtTable);

/*!
 * @brief Check if alignment is required for non-SGT buffers
 *
 * This function checks if input/output buffer requires cache alignment.
 * This function is called for those data buffers for which SGT table is
 * not supported.
 *
 * @param[in]	dataAddr		Pointer to the data buffer (input/output).
 *
 * @param[in]	dataLen			data buffer length
 *
 * @param[in]	alignmentSize	Cache bus line size.
 *
 * @return 		uint16_t 		no of elements of alignmentSize bytes.
 * 								#NO_BUFF_ALLOC in case of buffer is cache aligned.
 */
uint16_t alignNonSgtBuff(const uint8_t *dataAddr, uint32_t dataLen, uint8_t alignmentSize);

/*!
 * @brief Copies the SGT table data to output data buffer.
 *
 * This function copies the SGT table created for output buffer into the
 * output buffer passed by application.
 *
 * @param[in]	sgtTable	Pointer to the output buffer SGT table
 *
 * @param[out]	outDataAddr	Pointer to the application output data buffer.
 *
 * @return 		void
 */
void copySgtDataToLocalBuff(hseSrvSGTNode_t *sgtTable, uint8_t *outDataAddr);

/*!
 * @brief Frees memory allocated for SGT table
 *
 * This function frees the memory allocated while creation of SGT table
 * for input/output data buffer.
 *
 * @param[in]	finalChunkFlag	Flag to check which buffer needs to free from
 * 								SGT table
 *
 * @param[out]	sgtTable		Pointer to the input/output buffer SGT table
 *
 * @return 		void
 */
void alignDataFree(uint8_t finalChunkFlag, hseSrvSGTNode_t *sgtTable );

#ifdef __cplusplus
}
#endif

#endif /* D_CACHE_ENABLE_MBEDTLS */
#endif /* ALIGNMENT_H_ */
