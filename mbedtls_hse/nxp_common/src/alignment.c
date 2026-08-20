/*==================================================================================================
*
*  Copyright 2022, 2024 NXP
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
#include "alignment.h"
#if defined(MBEDTLS_USE_NXP_HSE_CRYPTO)
#include "Hse_Ip.h"
#endif
#include "nxp_hse_platform_util.h"

#if defined (D_CACHE_ENABLE_MBEDTLS)
#include "Cache_Ip.h"

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

/*!
 * @brief Set the bit30 of length of final chunk
 *
 * This function sets the bit30 of length of the final chunk
 * of the SGT table list based on the sgtTable->buffAllocFlag flag.
 *
 * @param[out]	sgtTable	Pointer to the scatter-gather table of
 * 							hseSrvSGTNode_t type.
 *
 * @return 		void
 */
static void setFinalChunkLen(hseSrvSGTNode_t *sgtTable);

/*==================================================================================================
*                                       LOCAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
* Description: Set the bit30 of length of final chunk
************************************************************************************************/
static void setFinalChunkLen(hseSrvSGTNode_t *sgtTable)
{
	uint8_t finalChunkFlag = sgtTable->buffAllocFlag;

	switch(finalChunkFlag)
	{
	case SGT_FRONT_BUFF_ALLOC:
		sgtTable->hseSrvSgtList[FRONT].length |= HSE_SGT_FINAL_CHUNK_BIT_MASK;
		break;

	case SGT_MID_BUFF_ALLOC:
		sgtTable->hseSrvSgtList[MID-1].length |= HSE_SGT_FINAL_CHUNK_BIT_MASK;
		break;

	case SGT_MID_REAR_BUFF_ALLOC:
	case SGT_FRONT_REAR_BUFF_ALLOC:
		sgtTable->hseSrvSgtList[REAR-1].length |= HSE_SGT_FINAL_CHUNK_BIT_MASK;
		break;

	case SGT_FRONT_MID_BUFF_ALLOC:
		sgtTable->hseSrvSgtList[MID].length |= HSE_SGT_FINAL_CHUNK_BIT_MASK;
		break;

	case SGT_FRONT_MID_REAR_BUFF_ALLOC:
		sgtTable->hseSrvSgtList[REAR].length |= HSE_SGT_FINAL_CHUNK_BIT_MASK;
		break;

	case SGT_REAR_BUFF_ALLOC:
	default:
		break;
	}
}

/*==================================================================================================
*                                       GLOBAL FUNCTIONS
==================================================================================================*/

/*************************************************************************************************
* Description: Check if buffer alignment is required
************************************************************************************************/
uint8_t checkAlignmentReq(const uint8_t *dataAddr, uint32_t inDataLen, uint8_t alignmentSize, hseSrvSGTNode_t *sgtTable )
{
	uint32_t addrVal = 0;
	uint32_t res = 0;
	uint32_t  mod_res = 0;

	addrVal = (uint32_t)dataAddr;

	sgtTable->buffAllocFlag = NO_BUFF_ALLOC;

	/* check if start address is 32 byte (cache line size ) aligned or not */
	if((addrVal % alignmentSize) != 0)
	{
		/* start inDataAddr is not aligned */
		mod_res = alignmentSize - (addrVal % alignmentSize);

		/* find the len of first chunk of data */
		if(mod_res < inDataLen)
		{
			if(mod_res < alignmentSize)
			{
				sgtTable->hseSrvSgtList[FRONT].length = mod_res;
			}
			else
			{
				sgtTable->hseSrvSgtList[FRONT].length = alignmentSize;
			}
		}
		else
		{
			sgtTable->hseSrvSgtList[FRONT].length = inDataLen;
		}

		sgtTable->buffAllocFlag |= FRONT_BUFF_ALLOC;
	}
	else if(inDataLen <= alignmentSize)
	{
		/* addr is aligned and data is smaller than alignment size */
		sgtTable->hseSrvSgtList[FRONT].length = inDataLen;
		sgtTable->buffAllocFlag |= FRONT_BUFF_ALLOC;
	}

	/* check if second chunk of data is required */
	if((inDataLen - sgtTable->hseSrvSgtList[FRONT].length) > alignmentSize)
	{
		res = ((uint32_t)(inDataLen - sgtTable->hseSrvSgtList[FRONT].length) / alignmentSize ) * alignmentSize;

		if(res == inDataLen)
		{
			sgtTable->buffAllocFlag = NO_BUFF_ALLOC;
		}
		else
		{
			/* If front buff is allocated */
			if((sgtTable->buffAllocFlag & FRONT_BUFF_ALLOC) == FRONT_BUFF_ALLOC)
			{
				sgtTable->hseSrvSgtList[MID].length =  res;
			}
			else
			{
				/* If front buff is not allocated */
				sgtTable->hseSrvSgtList[MID-1].length =  res;
			}
			sgtTable->buffAllocFlag |= MID_BUFF_ALLOC;
		}
	}

	/* check if third chunk of data is required */
	if(inDataLen > alignmentSize)
	{
		/* If front buff is allocated */
		if((sgtTable->buffAllocFlag & FRONT_BUFF_ALLOC) == FRONT_BUFF_ALLOC)
		{
			if((inDataLen - (sgtTable->hseSrvSgtList[FRONT].length + sgtTable->hseSrvSgtList[MID].length)) > 0)
			{
				/* If mid buff is allocated */
				if((sgtTable->buffAllocFlag & MID_BUFF_ALLOC) == MID_BUFF_ALLOC)
				{
					sgtTable->hseSrvSgtList[REAR].length = inDataLen - (sgtTable->hseSrvSgtList[FRONT].length + sgtTable->hseSrvSgtList[MID].length);
				}
				else
				{
					/* If only front buff is allocated */
					sgtTable->hseSrvSgtList[REAR-1].length = inDataLen - sgtTable->hseSrvSgtList[FRONT].length;
				}

				sgtTable->buffAllocFlag |= REAR_BUFF_ALLOC;
			}
		}
		else
		{
			/* If mid buff is allocated */
			if((sgtTable->buffAllocFlag & MID_BUFF_ALLOC) == MID_BUFF_ALLOC)
			{
				/* mid buff is allocated */
				if((inDataLen - sgtTable->hseSrvSgtList[MID-1].length) > 0)
				{
					/* If only mid buff is allocated */
					sgtTable->hseSrvSgtList[REAR-1].length = inDataLen - sgtTable->hseSrvSgtList[MID-1].length;
					sgtTable->buffAllocFlag |= REAR_BUFF_ALLOC;
				}
			}
		}
	}
	else
	{
		/* if input data < alignment size */
		if((inDataLen - sgtTable->hseSrvSgtList[FRONT].length) > 0)
		{
			/* If only front buff is allocated */
			sgtTable->hseSrvSgtList[REAR-1].length = inDataLen - sgtTable->hseSrvSgtList[FRONT].length;
			sgtTable->buffAllocFlag |= REAR_BUFF_ALLOC;
		}
	}

	return sgtTable->buffAllocFlag;
}

/*************************************************************************************************
* Description: Align input data buffer and perform cache operation
************************************************************************************************/
void alignInBuff(uint8_t *inDataAddr, hseSrvSGTNode_t *sgtTable )
{
	uint8_t flagStatus;

	flagStatus = sgtTable->buffAllocFlag;

	switch(flagStatus)
	{
	case SGT_FRONT_BUFF_ALLOC:
	case SGT_FRONT_MID_BUFF_ALLOC:
	case SGT_FRONT_MID_REAR_BUFF_ALLOC:

		/* Allocate and copy first chunk of data */
		sgtTable->hseSrvSgtList[FRONT].pPtr = HSE_PTR_TO_HOST_ADDR(nxp_hse_callocH(1, 32));
		if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[FRONT].pPtr))
		{
			memcpy(NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[FRONT].pPtr), inDataAddr,
					sgtTable->hseSrvSgtList[FRONT].length);

			/* Flush Input Data Buffer to memory */
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, sgtTable->hseSrvSgtList[FRONT].pPtr,
					32);
		}

		/* Allocate and copy second chunk of data if available */
		if((flagStatus & MID_BUFF_ALLOC ) == MID_BUFF_ALLOC)
		{
			sgtTable->hseSrvSgtList[MID].pPtr = HSE_PTR_TO_HOST_ADDR(inDataAddr + sgtTable->hseSrvSgtList[FRONT].length);

			/* Flush Input Data Buffer to memory */
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, sgtTable->hseSrvSgtList[MID].pPtr,
					sgtTable->hseSrvSgtList[MID].length);
		}

		/* Allocate and copy third chunk of data if available */
		if((flagStatus & REAR_BUFF_ALLOC ) == REAR_BUFF_ALLOC)
		{
			sgtTable->hseSrvSgtList[REAR].pPtr = HSE_PTR_TO_HOST_ADDR( nxp_hse_callocH(1, 32) );
			if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[REAR].pPtr))
			{
				memcpy(NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[REAR].pPtr),
						inDataAddr + sgtTable->hseSrvSgtList[FRONT].length + sgtTable->hseSrvSgtList[MID].length,
						sgtTable->hseSrvSgtList[REAR].length);

				/* Flush Input Data Buffer to memory */
				Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, sgtTable->hseSrvSgtList[REAR].pPtr,
						32);
			}
		}
		break;

	case SGT_MID_REAR_BUFF_ALLOC:

		/* Allocate and copy second chunk of data in first entry of SGT */
		sgtTable->hseSrvSgtList[MID-1].pPtr = HSE_PTR_TO_HOST_ADDR(inDataAddr);

		/* Flush Input Data Buffer to memory */
		Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, sgtTable->hseSrvSgtList[MID-1].pPtr, sgtTable->hseSrvSgtList[MID-1].length);

		/* Allocate and copy third chunk of data in second entry of SGT */
		sgtTable->hseSrvSgtList[REAR-1].pPtr = HSE_PTR_TO_HOST_ADDR( nxp_hse_callocH(1, 32) );
		if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[REAR-1].pPtr))
		{
			memcpy(NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[REAR-1].pPtr),
					inDataAddr + sgtTable->hseSrvSgtList[MID-1].length, sgtTable->hseSrvSgtList[REAR-1].length);

			/* Flush Input Data Buffer to memory */
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, sgtTable->hseSrvSgtList[REAR-1].pPtr,
					32);
		}

		break;

	case SGT_FRONT_REAR_BUFF_ALLOC:

		/* Allocate and copy first chunk of data */
		sgtTable->hseSrvSgtList[FRONT].pPtr = HSE_PTR_TO_HOST_ADDR(nxp_hse_callocH(1, 32));
		if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[FRONT].pPtr))
		{
			memcpy(NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[FRONT].pPtr), inDataAddr,
					sgtTable->hseSrvSgtList[FRONT].length);

			/* Flush Input Data Buffer to memory */
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, sgtTable->hseSrvSgtList[FRONT].pPtr,
					32);
		}

		/* Allocate and copy third chunk of data in second entry of SGT */
		sgtTable->hseSrvSgtList[REAR-1].pPtr = HSE_PTR_TO_HOST_ADDR( nxp_hse_callocH(1, 32) );
		if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[REAR-1].pPtr))
		{
			memcpy(NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[REAR-1].pPtr), inDataAddr +
					sgtTable->hseSrvSgtList[FRONT].length, sgtTable->hseSrvSgtList[REAR-1].length);

			/* Flush Input Data Buffer to memory */
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, sgtTable->hseSrvSgtList[REAR-1].pPtr,
					32);
		}

		break;

	/* In Data buffer is aligned no requirement of alignment */
	case SGT_REAR_BUFF_ALLOC:
	case SGT_NO_BUFF_ALLOC:
	default:
		break;
	}

	/* Set the length of final chunk */
	setFinalChunkLen(sgtTable);

	return;
}

/*************************************************************************************************
* Description: Align output data buffer and perform cache operation
************************************************************************************************/
void alignOutBuff(uint8_t *outDataAddr, hseSrvSGTNode_t *sgtTable )
{
	uint8_t flagStatus;

	flagStatus = sgtTable->buffAllocFlag;

	switch(flagStatus)
	{
	case SGT_FRONT_BUFF_ALLOC:
	case SGT_FRONT_MID_BUFF_ALLOC:
	case SGT_FRONT_MID_REAR_BUFF_ALLOC:

		/* Create first SGT entry for first out chunk */
		sgtTable->hseSrvSgtList[FRONT].pPtr = HSE_PTR_TO_HOST_ADDR(nxp_hse_callocH(1, 32));
		if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[FRONT].pPtr))
		{
    		Cache_Ip_CleanByAddr( CACHE_IP_CORE, CACHE_IP_DATA, FALSE, sgtTable->hseSrvSgtList[FRONT].pPtr, (32));


			/* Invalidate Output Data Buffer */
			Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, sgtTable->hseSrvSgtList[FRONT].pPtr,
					32);
		}

		/* Create second SGT entry for second out chunk */
		if((flagStatus & MID_BUFF_ALLOC ) == MID_BUFF_ALLOC)
		{
			sgtTable->hseSrvSgtList[MID].pPtr = HSE_PTR_TO_HOST_ADDR(outDataAddr +
					sgtTable->hseSrvSgtList[FRONT].length);

    		Cache_Ip_CleanByAddr( CACHE_IP_CORE, CACHE_IP_DATA, FALSE, sgtTable->hseSrvSgtList[MID].pPtr, (sgtTable->hseSrvSgtList[MID].length));

			/* Invalidate Output Data Buffer */
			Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, sgtTable->hseSrvSgtList[MID].pPtr,
					sgtTable->hseSrvSgtList[MID].length);
		}

		/* Create third SGT entry for third out chunk */
		if((flagStatus & REAR_BUFF_ALLOC ) == REAR_BUFF_ALLOC)
		{
			sgtTable->hseSrvSgtList[REAR].pPtr = HSE_PTR_TO_HOST_ADDR( nxp_hse_callocH(1, 32) );
			if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[REAR].pPtr))
			{
	    		Cache_Ip_CleanByAddr( CACHE_IP_CORE, CACHE_IP_DATA, FALSE, sgtTable->hseSrvSgtList[REAR].pPtr, (32));

				/* Invalidate Output Data Buffer */
				Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, sgtTable->hseSrvSgtList[REAR].pPtr,
						32);
			}
		}
		break;

	case SGT_MID_REAR_BUFF_ALLOC:

		/* Create first SGT entry for second out chunk */
		sgtTable->hseSrvSgtList[MID-1].pPtr = HSE_PTR_TO_HOST_ADDR(outDataAddr);

		Cache_Ip_CleanByAddr( CACHE_IP_CORE, CACHE_IP_DATA, FALSE, sgtTable->hseSrvSgtList[MID-1].pPtr, (sgtTable->hseSrvSgtList[MID-1].length));


		/* Invalidate Output Data Buffer */
		Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, sgtTable->hseSrvSgtList[MID-1].pPtr,
				sgtTable->hseSrvSgtList[MID-1].length);

		/* Create second SGT entry for third out chunk */
		sgtTable->hseSrvSgtList[REAR-1].pPtr = HSE_PTR_TO_HOST_ADDR( nxp_hse_callocH(1, 32) );
		if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[REAR-1].pPtr))
		{
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, sgtTable->hseSrvSgtList[REAR-1].pPtr,
								32);

			/* Invalidate Output Data Buffer */
			Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, sgtTable->hseSrvSgtList[REAR-1].pPtr,
					32);
		}

		break;

	case SGT_FRONT_REAR_BUFF_ALLOC:

		/* Create first SGT entry for first out chunk */
		sgtTable->hseSrvSgtList[FRONT].pPtr = HSE_PTR_TO_HOST_ADDR(nxp_hse_callocH(1, 32));
		if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[FRONT].pPtr))
		{

			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, sgtTable->hseSrvSgtList[FRONT].pPtr,
					32);
			/* Invalidate Output Data Buffer */
			Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, sgtTable->hseSrvSgtList[FRONT].pPtr,
					32);
		}

		/* Create second SGT entry for third out chunk */
		sgtTable->hseSrvSgtList[REAR-1].pPtr = HSE_PTR_TO_HOST_ADDR( nxp_hse_callocH(1, 32) );
		if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[REAR-1].pPtr))
		{
			Cache_Ip_CleanByAddr(CACHE_IP_CORE, CACHE_IP_DATA, FALSE, sgtTable->hseSrvSgtList[REAR-1].pPtr,
							32);

			/* Invalidate Output Data Buffer */
			Cache_Ip_InvalidateByAddr(CACHE_IP_CORE, CACHE_IP_DATA, sgtTable->hseSrvSgtList[REAR-1].pPtr,
					32);
		}

		break;

	/* Out Data buffer is aligned no requirement of alignment */
	case SGT_REAR_BUFF_ALLOC:
	case SGT_NO_BUFF_ALLOC:
	default:
		break;
	}

	/* Set the length of final chunk */
	setFinalChunkLen(sgtTable);

	return;
}

/*************************************************************************************************
* Description: Store input/output buffer to SGT table
************************************************************************************************/
void storeAlignBufptr( uint8_t *dataAddr, uint32_t dataLen, hseSrvSGTNode_t *sgtTable)
{
	sgtTable->hseSrvSgtList[FRONT].pPtr = HSE_PTR_TO_HOST_ADDR(dataAddr);
	sgtTable->hseSrvSgtList[FRONT].length = dataLen;
	sgtTable->buffAllocFlag = MID_BUFF_ALLOC;

	/* Set the length of final chunk */
	setFinalChunkLen(sgtTable);
}

/*************************************************************************************************
* Description: Check if alignment is required for Non SGT buffers
************************************************************************************************/
uint16_t alignNonSgtBuff(const uint8_t *dataAddr, uint32_t dataLen, uint8_t alignmentSize)
{
	uint32_t addrVal = 0;
	uint32_t res = 0;

	addrVal = (uint32_t)dataAddr;

	if(dataLen == 0)
	{
		return NO_BUFF_ALLOC;
	}

	/* Address is not aligned */
	if((addrVal % alignmentSize) != 0)
	{
		if(dataLen <= alignmentSize)
		{
			res = 1;
			return res;
		}
		else
		{
			if(( dataLen % alignmentSize) != 0)
			{
				res = ( dataLen / alignmentSize ) + 1;
			}
			else
			{
				res = ( dataLen / alignmentSize );
			}

			return res;
		}
	}
	else
	{
		/* Address is aligned but data is unaligned*/
		if(( dataLen % alignmentSize) != 0)
		{
			res = ( dataLen / alignmentSize ) + 1;
			return res;
		}
		else
		{
			/* Both addr and data is aligned*/
			return NO_BUFF_ALLOC;
		}
	}

	return res;
}

/*************************************************************************************************
* Description: Copies the SGT table data to output data buffer.
************************************************************************************************/
void copySgtDataToLocalBuff(hseSrvSGTNode_t *sgtTable, uint8_t *outDataAddr)
{
	uint8_t flagStatus;

	flagStatus = sgtTable->buffAllocFlag;

	switch(flagStatus)
	{
	case SGT_FRONT_BUFF_ALLOC:
	case SGT_FRONT_MID_BUFF_ALLOC:
	case SGT_FRONT_MID_REAR_BUFF_ALLOC:

		/* Copy first chunk of data */
		if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[FRONT].pPtr))
		{
			memcpy(outDataAddr, NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[FRONT].pPtr),
					(sgtTable->hseSrvSgtList[FRONT].length &(~HSE_SGT_FINAL_CHUNK_BIT_MASK)));
		}

		/* Copy third chunk of data if available */
		if((flagStatus & REAR_BUFF_ALLOC ) == REAR_BUFF_ALLOC)
		{
			if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[REAR].pPtr))
			{
				memcpy(outDataAddr + sgtTable->hseSrvSgtList[FRONT].length + sgtTable->hseSrvSgtList[MID].length,
						NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[REAR].pPtr),
						(sgtTable->hseSrvSgtList[REAR].length &(~HSE_SGT_FINAL_CHUNK_BIT_MASK)));
			}
		}
		break;

	case SGT_MID_REAR_BUFF_ALLOC:

		/* Copy third chunk of data from second entry of SGT */
		if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[REAR-1].pPtr))
		{
			memcpy(outDataAddr + sgtTable->hseSrvSgtList[MID-1].length, NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[REAR-1].pPtr),
					(sgtTable->hseSrvSgtList[REAR-1].length &(~HSE_SGT_FINAL_CHUNK_BIT_MASK)));
		}

		break;

	case SGT_FRONT_REAR_BUFF_ALLOC:

		/* Copy first chunk of data */
		if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[FRONT].pPtr))
		{
			memcpy(outDataAddr, NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[FRONT].pPtr),
					(sgtTable->hseSrvSgtList[FRONT].length &(~HSE_SGT_FINAL_CHUNK_BIT_MASK)));
		}

		/* Copy third chunk of data from second entry of SGT */
		if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[REAR-1].pPtr))
		{
			memcpy(outDataAddr + sgtTable->hseSrvSgtList[FRONT].length,
					NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[REAR-1].pPtr),
					(sgtTable->hseSrvSgtList[REAR-1].length &(~HSE_SGT_FINAL_CHUNK_BIT_MASK)));
		}

		break;

	/* In Data buffer is aligned no requirement of alignment */
	case SGT_REAR_BUFF_ALLOC:
	case SGT_NO_BUFF_ALLOC:
	default:
		break;
	}
}

/*************************************************************************************************
* Description: Frees memory allocated for SGT table
************************************************************************************************/
void alignDataFree(uint8_t finalChunkFlag, hseSrvSGTNode_t *sgtTable )
{

	switch(finalChunkFlag)
	{
	case SGT_FRONT_BUFF_ALLOC:
	case SGT_FRONT_MID_BUFF_ALLOC:
		if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[FRONT].pPtr))
		{
			nxp_hse_freeH(NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[FRONT].pPtr));
		}
		break;

	case SGT_REAR_BUFF_ALLOC:
	case SGT_MID_REAR_BUFF_ALLOC:
		if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[REAR-1].pPtr))
		{
			nxp_hse_freeH(NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[REAR-1].pPtr));
		}
		break;

	case SGT_FRONT_REAR_BUFF_ALLOC:
		if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[FRONT].pPtr))
		{
			nxp_hse_freeH(NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[FRONT].pPtr));
		}

		if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[REAR-1].pPtr))
		{
			nxp_hse_freeH(NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[REAR-1].pPtr));
		}
		break;

	case SGT_FRONT_MID_REAR_BUFF_ALLOC:
		if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[FRONT].pPtr))
		{
			nxp_hse_freeH(NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[FRONT].pPtr));
		}

		if(NULL_PTR != NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[REAR].pPtr))
		{
			nxp_hse_freeH(NXP_HSE_HOST_ADDR_TO_PTR(sgtTable->hseSrvSgtList[REAR].pPtr));
		}

		break;

	default:
		break;
	}
}


/**
 * return 32 byte alligned address from incoming pointer
 */

uint32_t alignIncomingAddr(uint32_t inputAddr)
{
  uint32_t alignedAddress = inputAddr;


	if((alignedAddress%32)!=0) // if unaligned
	{
		alignedAddress = (alignedAddress + (32 - (alignedAddress%32)));
	}

	return alignedAddress;
}

#endif /* D_CACHE_ENABLE_MBEDTLS */
